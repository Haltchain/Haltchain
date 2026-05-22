pub mod types;

use std::collections::HashMap;
use std::sync::Arc;

use aho_corasick::AhoCorasick;
use haltchain_cache::dragonfly_client::{DragonflyClient, PolicyState};
use haltchain_cache::CachedDecision;
use haltchain_cognitive::{
    AlertType, CognitiveMonitor, ContainmentBridge, SecurityAlert, Severity,
    build_containment_bridge_from_env, classify_intent, core_distance, zedd_drift_score,
};
use haltchain_merkle::MerkleAccumulator;
use haltchain_signing::SigningService;
use pgvector::Vector;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use types::{Decision, McpToolCall};
use uuid::Uuid;

const DEFAULT_ZEDD_THRESHOLD: f64 = 0.85;
const DEFAULT_CACHE_TTL_POLICY: PolicyState = PolicyState::Dynamic;
const DEFAULT_MIN_BASELINE: usize = 8;
const DEFAULT_CROSS_AGENT_WINDOW_MINUTES: i64 = 10;

#[derive(Debug, Clone, serde::Deserialize)]
struct BaselineScope {
    #[serde(default, alias = "approved_tool_patterns")]
    approved_tools: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct BaselineInventoryFile {
    #[serde(default, alias = "approved_tool_patterns")]
    approved_tools: Vec<String>,
    #[serde(default)]
    orgs: HashMap<String, BaselineScope>,
    #[serde(default)]
    agents: HashMap<String, BaselineScope>,
}

#[derive(Debug, Clone, Default)]
struct BaselineInventory {
    global_patterns: Vec<String>,
    org_patterns: HashMap<Uuid, Vec<String>>,
    agent_patterns: HashMap<Uuid, Vec<String>>,
}

impl BaselineInventory {
    fn from_env() -> Option<Self> {
        let path = std::env::var("HALTCHAIN_MCP_BASELINE_PATH").ok()?;
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(path = %path, error = %e, "failed to read MCP baseline inventory");
                return None;
            }
        };

        let parsed = match serde_json::from_str::<BaselineInventoryFile>(&content) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(path = %path, error = %e, "invalid MCP baseline inventory JSON");
                return None;
            }
        };

        let mut baseline = Self {
            global_patterns: parsed.approved_tools,
            org_patterns: HashMap::new(),
            agent_patterns: HashMap::new(),
        };

        for (org, scope) in parsed.orgs {
            match Uuid::parse_str(&org) {
                Ok(org_id) => {
                    baseline.org_patterns.insert(org_id, scope.approved_tools);
                }
                Err(_) => {
                    tracing::warn!(org = %org, "skipping invalid org UUID in MCP baseline inventory");
                }
            }
        }

        for (agent, scope) in parsed.agents {
            match Uuid::parse_str(&agent) {
                Ok(agent_id) => {
                    baseline.agent_patterns.insert(agent_id, scope.approved_tools);
                }
                Err(_) => {
                    tracing::warn!(agent = %agent, "skipping invalid agent UUID in MCP baseline inventory");
                }
            }
        }

        Some(baseline)
    }

    fn is_approved(&self, call: &McpToolCall) -> bool {
        if let Some(patterns) = self.agent_patterns.get(&call.agent_id) {
            return pattern_set_matches(patterns, &call.tool_name);
        }
        if let Some(patterns) = self.org_patterns.get(&call.org_id) {
            return pattern_set_matches(patterns, &call.tool_name);
        }
        if !self.global_patterns.is_empty() {
            return pattern_set_matches(&self.global_patterns, &call.tool_name);
        }
        true
    }
}

#[derive(Debug, Clone, Deserialize)]
struct ToolPolicy {
    #[serde(default)]
    tool_name_pattern: Option<String>,
    #[serde(default)]
    required_args: Vec<String>,
    #[serde(default, alias = "deny_arg_patterns")]
    denied_arg_patterns: Vec<String>,
    #[serde(default)]
    decision: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Clone, FromRow)]
struct PolicyRow {
    policy_name: String,
    policy: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PolicyAction {
    Allow,
    Block,
    Quarantine,
}

#[derive(Debug, Clone)]
struct PolicyOutcome {
    action: PolicyAction,
    reason: String,
}

#[derive(Debug, Clone, FromRow)]
struct PeerHistoryRow {
    agent_id: Uuid,
    tool_name: String,
}

#[derive(Debug, thiserror::Error)]
pub enum McpGuardError {
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

pub struct McpGuard {
    pattern_firewall: AhoCorasick,
    cognitive: CognitiveMonitor,
    cache: Option<Arc<DragonflyClient>>,
    db: PgPool,
    baseline: Option<BaselineInventory>,
    org_enforcement: bool,
    zedd_threshold: f64,
    min_baseline: usize,
    cross_agent_window_minutes: i64,
    signing: SigningService,
    merkle: MerkleAccumulator,
    containment: Arc<dyn ContainmentBridge>,
}

impl McpGuard {
    pub fn from_env(db: PgPool, cache: Option<Arc<DragonflyClient>>) -> Self {
        let extra_patterns = std::env::var("HALTCHAIN_MCP_BLOCKED_TOOLS")
            .ok()
            .unwrap_or_default();
        let mut patterns = vec![
            "exec",
            "shell",
            "sudo",
            "curl",
            "bash",
            "rm -rf",
            "drop database",
            "token_exfiltration",
            "credential_dump",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
        patterns.extend(
            extra_patterns
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_ascii_lowercase()),
        );

        let pattern_firewall = AhoCorasick::new(patterns).expect("valid MCP pattern set");
        let org_enforcement = std::env::var("HALTCHAIN_REQUIRE_TENANT_ORG")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
            .unwrap_or(true);
        let zedd_threshold = std::env::var("HALTCHAIN_MCP_ZEDD_THRESHOLD")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(DEFAULT_ZEDD_THRESHOLD);
        let min_baseline = std::env::var("HALTCHAIN_MCP_MIN_BASELINE")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_MIN_BASELINE);
        let cross_agent_window_minutes = std::env::var("HALTCHAIN_MCP_CROSS_AGENT_WINDOW_MINUTES")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(DEFAULT_CROSS_AGENT_WINDOW_MINUTES)
            .max(1);

        Self {
            pattern_firewall,
            cognitive: CognitiveMonitor::new(),
            cache,
            db,
            baseline: BaselineInventory::from_env(),
            org_enforcement,
            zedd_threshold,
            min_baseline,
            cross_agent_window_minutes,
            signing: SigningService::generate(),
            merkle: MerkleAccumulator::new(),
            containment: build_containment_bridge_from_env(),
        }
    }

    pub async fn inspect_tool_call(&self, call: &McpToolCall) -> Result<Decision, McpGuardError> {
        let args_hash = hash_args(&call.tool_args);
        let tool_name_lc = call.tool_name.to_ascii_lowercase();

        if let Some(baseline) = &self.baseline
            && !baseline.is_approved(call)
        {
            let reason = "unapproved-tool-inventory".to_string();
            let decision = Decision::Block {
                reason: reason.clone(),
                intent: Some("unknown".to_string()),
            };
            self.audit_decision(call, &decision, Some(&reason), None, &args_hash)
                .await?;
            self.enforce_containment(call, &reason, true).await;
            return Ok(decision);
        }

        if let Some(policy_outcome) = self.evaluate_policies(call).await? {
            match policy_outcome.action {
                PolicyAction::Allow => {
                    self.audit_decision(
                        call,
                        &Decision::Allow,
                        Some(&policy_outcome.reason),
                        None,
                        &args_hash,
                    )
                    .await?;
                    return Ok(Decision::Allow);
                }
                PolicyAction::Block => {
                    let decision = Decision::Block {
                        reason: policy_outcome.reason.clone(),
                        intent: None,
                    };
                    self.audit_decision(
                        call,
                        &decision,
                        Some(&policy_outcome.reason),
                        None,
                        &args_hash,
                    )
                    .await?;
                    self.enforce_containment(call, &policy_outcome.reason, true)
                        .await;
                    return Ok(decision);
                }
                PolicyAction::Quarantine => {
                    let review_id = self.log_review(call, &policy_outcome.reason, None).await?;
                    let decision = Decision::Quarantine {
                        review_id,
                        reason: policy_outcome.reason.clone(),
                        intent: None,
                    };
                    self.audit_decision(
                        call,
                        &decision,
                        Some(&policy_outcome.reason),
                        None,
                        &args_hash,
                    )
                    .await?;
                    self.enforce_containment(call, &policy_outcome.reason, false)
                        .await;
                    return Ok(decision);
                }
            }
        }

        if self.pattern_firewall.find(&tool_name_lc).is_some() {
            let reason = "known-poisoned-tool".to_string();
            let decision = Decision::Block {
                reason: reason.clone(),
                intent: Some("privilege_escalation".to_string()),
            };
            self.audit_decision(call, &decision, Some("pattern-firewall"), None, &args_hash)
                .await?;
            self.enforce_containment(call, &reason, true).await;
            return Ok(decision);
        }

        let embedding = self.embed_args(&call.tool_args).await;
        let drift_score = self.check_drift(call, &embedding).await?;
        if drift_score > self.zedd_threshold {
            let intent_label = classify_intent(
                drift_score,
                &[],
                &format!("{} {}", call.tool_name, call.tool_args),
            )
            .as_str()
            .to_string();
            let reason = format!("zedd-drift:{drift_score:.4}");
            let review_id = self
                .log_review(call, &reason, Some(drift_score))
                .await?;
            let decision = Decision::Quarantine {
                review_id,
                reason: reason.clone(),
                intent: Some(intent_label),
            };
            self.audit_decision(call, &decision, Some(&reason), Some(&embedding), &args_hash)
                .await?;
            self.enforce_containment(call, &reason, false).await;
            return Ok(decision);
        }

        if let Some(source_agent_id) = self.detect_cross_agent_correlation(call, &args_hash).await? {
            let reason = format!("cross-agent-correlation:source={source_agent_id}");
            let review_id = self.log_review(call, &reason, None).await?;
            let decision = Decision::Quarantine {
                review_id,
                reason: reason.clone(),
                intent: Some("data_exfiltration".to_string()),
            };
            self.audit_decision(call, &decision, Some(&reason), Some(&embedding), &args_hash)
                .await?;
            self.enforce_containment(call, &reason, false).await;
            return Ok(decision);
        }

        let consistent = self.historical_consistency(call).await?;
        if !consistent {
            let reason = "behavioral-anomaly".to_string();
            let review_id = self.log_review(call, &reason, None).await?;
            let decision = Decision::Quarantine {
                review_id,
                reason: reason.clone(),
                intent: Some("reconnaissance".to_string()),
            };
            self.audit_decision(call, &decision, Some(&reason), Some(&embedding), &args_hash)
                .await?;
            self.enforce_containment(call, &reason, false).await;
            return Ok(decision);
        }

        let cache_key = format!("mcp:allow:{}:{}", call.agent_id, call.context_hash);
        if let Some(cache) = &self.cache
            && cache.get(&cache_key).await.is_some()
        {
            return Ok(Decision::Allow);
        }

        let decision = Decision::Allow;
        self.audit_decision(call, &decision, None, Some(&embedding), &args_hash)
            .await?;

        if let Some(cache) = &self.cache {
            cache
                .set(
                    &cache_key,
                    &CachedDecision {
                        decision: "ALLOW".to_string(),
                        circuit_breaker_active: false,
                        reason: None,
                        policy: Some("MCP_GUARD".to_string()),
                        rate_limit: 0,
                    },
                    DEFAULT_CACHE_TTL_POLICY,
                )
                .await;
        }

        Ok(Decision::Allow)
    }

    async fn evaluate_policies(
        &self,
        call: &McpToolCall,
    ) -> Result<Option<PolicyOutcome>, McpGuardError> {
        let mut tx = self.db.begin().await?;
        self.set_local_org(&mut tx, call.org_id).await?;

        let rows = match sqlx::query_as::<_, PolicyRow>(
            r#"
            SELECT policy_name, policy
            FROM mcp_tool_policies
            WHERE org_id = $1
              AND enabled = TRUE
              AND (agent_id IS NULL OR agent_id = $2)
            ORDER BY priority DESC, created_at ASC
            "#,
        )
        .bind(call.org_id)
        .bind(call.agent_id)
        .fetch_all(&mut *tx)
        .await
        {
            Ok(rows) => rows,
            Err(e) if is_missing_relation(&e) => {
                let _ = tx.rollback().await;
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        };

        tx.commit().await?;

        for row in rows {
            let policy: ToolPolicy = match serde_json::from_value(row.policy.clone()) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(policy = %row.policy_name, error = %e, "invalid MCP policy JSON");
                    continue;
                }
            };

            if !policy_matches(&policy, call) {
                continue;
            }

            let decision = policy
                .decision
                .as_deref()
                .unwrap_or("quarantine")
                .to_ascii_lowercase();
            let reason = policy
                .reason
                .unwrap_or_else(|| format!("mcp-policy:{}", row.policy_name));

            let action = match decision.as_str() {
                "allow" => PolicyAction::Allow,
                "block" | "deny" => PolicyAction::Block,
                _ => PolicyAction::Quarantine,
            };

            return Ok(Some(PolicyOutcome { action, reason }));
        }

        Ok(None)
    }

    async fn embed_args(&self, args: &serde_json::Value) -> Vec<f32> {
        let pgai_try = sqlx::query_scalar::<_, serde_json::Value>("SELECT pgai.embed($1::jsonb)")
            .bind(args)
            .fetch_one(&self.db)
            .await;

        match pgai_try {
            Ok(value) => json_to_embedding(&value).unwrap_or_else(|| self.fallback_embed(args)),
            Err(_) => self.fallback_embed(args),
        }
    }

    fn fallback_embed(&self, args: &serde_json::Value) -> Vec<f32> {
        self.cognitive
            .embed_trace(&args.to_string())
            .into_iter()
            .map(|v| v as f32)
            .collect()
    }

    async fn check_drift(
        &self,
        call: &McpToolCall,
        embedding: &[f32],
    ) -> Result<f64, McpGuardError> {
        if embedding.is_empty() {
            return Ok(0.0);
        }

        let mut tx = self.db.begin().await?;
        self.set_local_org(&mut tx, call.org_id).await?;

        let refs: Vec<(Vector,)> = sqlx::query_as(
            r#"
            SELECT args_embedding
            FROM mcp_tool_history
            WHERE agent_id = $1
              AND org_id = $2
              AND args_embedding IS NOT NULL
              AND timestamp > NOW() - INTERVAL '24 hour'
            ORDER BY timestamp DESC
            LIMIT 64
            "#,
        )
        .bind(call.agent_id)
        .bind(call.org_id)
        .fetch_all(&mut *tx)
        .await?;

        tx.commit().await?;

        let ref_vecs = refs
            .into_iter()
            .map(|(v,)| v.to_vec().into_iter().map(|x| x as f64).collect::<Vec<_>>())
            .collect::<Vec<_>>();

        if ref_vecs.len() < self.min_baseline {
            return Ok(0.0);
        }

        let current = embedding.iter().map(|v| *v as f64).collect::<Vec<_>>();
        let k = 5.min(ref_vecs.len().saturating_sub(1).max(1));

        let mut historical = Vec::with_capacity(ref_vecs.len());
        for (i, emb) in ref_vecs.iter().enumerate() {
            let mut neighbors = Vec::with_capacity(ref_vecs.len().saturating_sub(1));
            for (j, candidate) in ref_vecs.iter().enumerate() {
                if i != j {
                    neighbors.push(candidate.clone());
                }
            }
            historical.push(core_distance(emb, &neighbors, k));
        }

        Ok(zedd_drift_score(&current, &ref_vecs, &historical, k))
    }

    async fn historical_consistency(&self, call: &McpToolCall) -> Result<bool, McpGuardError> {
        let mut tx = self.db.begin().await?;
        self.set_local_org(&mut tx, call.org_id).await?;

        let consistent = sqlx::query_scalar::<_, Option<bool>>(
            r#"
            SELECT bool_and(tool_name = $1)
            FROM mcp_tool_history
            WHERE agent_id = $2
              AND org_id = $3
              AND timestamp > NOW() - INTERVAL '1 hour'
            "#,
        )
        .bind(&call.tool_name)
        .bind(call.agent_id)
        .bind(call.org_id)
        .fetch_one(&mut *tx)
        .await?
        .unwrap_or(true);

        tx.commit().await?;
        Ok(consistent)
    }

    async fn detect_cross_agent_correlation(
        &self,
        call: &McpToolCall,
        args_hash: &[u8],
    ) -> Result<Option<Uuid>, McpGuardError> {
        if !is_exfiltration_tool(&call.tool_name, &call.tool_args) {
            return Ok(None);
        }

        let mut tx = self.db.begin().await?;
        self.set_local_org(&mut tx, call.org_id).await?;

        let rows = sqlx::query_as::<_, PeerHistoryRow>(
            r#"
            SELECT agent_id, tool_name
            FROM mcp_tool_history
            WHERE org_id = $1
              AND agent_id <> $2
              AND args_hash = $3
              AND timestamp > NOW() - make_interval(mins => $4)
            ORDER BY timestamp DESC
            LIMIT 16
            "#,
        )
        .bind(call.org_id)
        .bind(call.agent_id)
        .bind(args_hash)
        .bind(self.cross_agent_window_minutes)
        .fetch_all(&mut *tx)
        .await?;

        tx.commit().await?;

        for row in rows {
            if is_data_access_tool(&row.tool_name) {
                return Ok(Some(row.agent_id));
            }
        }

        Ok(None)
    }

    async fn log_review(
        &self,
        call: &McpToolCall,
        reason: &str,
        drift_score: Option<f64>,
    ) -> Result<Uuid, McpGuardError> {
        let review_id = Uuid::new_v4();
        let mut tx = self.db.begin().await?;
        self.set_local_org(&mut tx, call.org_id).await?;

        let mut tool_call_json = serde_json::to_value(call)?;
        if let Some(score) = drift_score
            && let Some(obj) = tool_call_json.as_object_mut()
        {
            obj.insert("zedd_score".to_string(), serde_json::json!(score));
        }

        sqlx::query(
            r#"
            INSERT INTO mcp_review_queue (id, org_id, agent_id, tool_call, reason)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(review_id)
        .bind(call.org_id)
        .bind(call.agent_id)
        .bind(tool_call_json)
        .bind(reason)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(review_id)
    }

    async fn audit_decision(
        &self,
        call: &McpToolCall,
        decision: &Decision,
        reason: Option<&str>,
        embedding: Option<&[f32]>,
        args_hash: &[u8],
    ) -> Result<(), McpGuardError> {
        let transaction_id = Uuid::new_v4().to_string();
        let timestamp = chrono::Utc::now().to_rfc3339();
        let decision_text = decision_text(decision);
        let envelope = self.signing.sign_decision(
            &transaction_id,
            decision_text,
            &call.agent_id.to_string(),
            &timestamp,
            "phase1b",
        );
        self.merkle.push(
            &transaction_id,
            &timestamp,
            decision_text,
            &envelope.content_hash,
        );
        let merkle_root = self.merkle.status().root_hex;

        let review_id = match decision {
            Decision::Quarantine { review_id, .. } => Some(*review_id),
            _ => None,
        };

        let mut tx = self.db.begin().await?;
        self.set_local_org(&mut tx, call.org_id).await?;

        sqlx::query(
            r#"
            INSERT INTO mcp_tool_history (
                id,
                org_id,
                agent_id,
                tool_name,
                tool_args,
                args_hash,
                args_embedding,
                decision,
                reason,
                context_hash,
                review_id,
                envelope,
                merkle_root,
                timestamp
            )
            VALUES (
                $1,
                $2,
                $3,
                $4,
                $5,
                $6,
                $7,
                $8,
                $9,
                $10,
                $11,
                $12,
                $13,
                NOW()
            )
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(call.org_id)
        .bind(call.agent_id)
        .bind(&call.tool_name)
        .bind(&call.tool_args)
        .bind(args_hash)
        .bind(embedding.map(|v| Vector::from(v.to_vec())))
        .bind(decision_text)
        .bind(reason)
        .bind(&call.context_hash)
        .bind(review_id)
        .bind(serde_json::to_value(envelope)?)
        .bind(merkle_root)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    async fn enforce_containment(&self, call: &McpToolCall, reason: &str, block: bool) {
        let severity = if block {
            Severity::High
        } else {
            Severity::Medium
        };
        let alert_type = if block {
            AlertType::UnauthorizedAccess
        } else {
            AlertType::DataExfiltration
        };

        let alert = SecurityAlert {
            alert_id: Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            severity,
            agent_id: call.agent_id.to_string(),
            alert_type,
            description: format!("MCP containment trigger: {reason}"),
            confidence: if block { 0.95 } else { 0.80 },
            metadata: HashMap::from([
                ("org_id".to_string(), call.org_id.to_string()),
                ("tool_name".to_string(), call.tool_name.clone()),
            ]),
        };

        if block {
            if let Err(e) = self.containment.terminate_session(&call.agent_id.to_string()).await {
                tracing::warn!(error = %e, agent_id = %call.agent_id, "MCP containment terminate_session failed");
            }
            if let Err(e) = self
                .containment
                .revoke_credentials(&call.agent_id.to_string())
                .await
            {
                tracing::warn!(error = %e, agent_id = %call.agent_id, "MCP containment revoke_credentials failed");
            }
        } else if let Err(e) = self
            .containment
            .create_forensic_snapshot(&call.agent_id.to_string())
            .await
        {
            tracing::warn!(error = %e, agent_id = %call.agent_id, "MCP containment snapshot failed");
        }

        if let Err(e) = self.containment.notify_security_operations(&alert).await {
            tracing::warn!(error = %e, agent_id = %call.agent_id, "MCP containment SOC notification failed");
        }
    }

    async fn set_local_org(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        org_id: Uuid,
    ) -> Result<(), McpGuardError> {
        if self.org_enforcement {
            sqlx::query("SELECT set_config('app.current_org_id', $1, true)")
                .bind(org_id.to_string())
                .execute(&mut **tx)
                .await?;
        }
        Ok(())
    }
}

fn hash_args(args: &serde_json::Value) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(args.to_string().as_bytes());
    hasher.finalize().to_vec()
}

fn is_missing_relation(err: &sqlx::Error) -> bool {
    match err {
        sqlx::Error::Database(db_err) => db_err.code().as_deref() == Some("42P01"),
        _ => false,
    }
}

fn pattern_set_matches(patterns: &[String], tool_name: &str) -> bool {
    if patterns.is_empty() {
        return false;
    }
    let tool = tool_name.to_ascii_lowercase();
    patterns
        .iter()
        .map(|p| p.trim().to_ascii_lowercase())
        .filter(|p| !p.is_empty())
        .any(|p| wildcard_matches(&tool, &p))
}

fn wildcard_matches(value: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return value == pattern;
    }

    let parts: Vec<&str> = pattern.split('*').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return true;
    }

    let anchored_start = !pattern.starts_with('*');
    let anchored_end = !pattern.ends_with('*');
    let mut offset = 0usize;

    for (idx, part) in parts.iter().enumerate() {
        let hay = &value[offset..];
        let Some(found) = hay.find(part) else {
            return false;
        };

        if idx == 0 && anchored_start && found != 0 {
            return false;
        }

        offset += found + part.len();
    }

    if anchored_end
        && let Some(last) = parts.last()
    {
        return value.ends_with(last);
    }

    true
}

fn policy_matches(policy: &ToolPolicy, call: &McpToolCall) -> bool {
    if let Some(pattern) = policy.tool_name_pattern.as_deref()
        && !wildcard_matches(&call.tool_name.to_ascii_lowercase(), &pattern.to_ascii_lowercase())
    {
        return false;
    }

    let args_object = call.tool_args.as_object();
    if !policy.required_args.is_empty() {
        let Some(args_object) = args_object else {
            return false;
        };
        for key in &policy.required_args {
            if !args_object.contains_key(key) {
                return false;
            }
        }
    }

    if policy.denied_arg_patterns.is_empty() {
        return true;
    }

    let args_text = call.tool_args.to_string().to_ascii_lowercase();
    policy
        .denied_arg_patterns
        .iter()
        .map(|p| p.to_ascii_lowercase())
        .any(|p| !p.is_empty() && args_text.contains(&p))
}

fn is_data_access_tool(tool_name: &str) -> bool {
    let lower = tool_name.to_ascii_lowercase();
    lower.contains("read")
        || lower.contains("query")
        || lower.contains("select")
        || lower.contains("fetch")
        || lower.contains("download")
        || lower.contains("secret")
}

fn is_exfiltration_tool(tool_name: &str, args: &serde_json::Value) -> bool {
    let lower = tool_name.to_ascii_lowercase();
    let args_text = args.to_string().to_ascii_lowercase();
    (lower.contains("http")
        || lower.contains("post")
        || lower.contains("upload")
        || lower.contains("webhook")
        || lower.contains("send")
        || lower.contains("curl")
        || lower.contains("socket"))
        && (args_text.contains("http://")
            || args_text.contains("https://")
            || args_text.contains("external")
            || args_text.contains("webhook"))
}

fn json_to_embedding(v: &serde_json::Value) -> Option<Vec<f32>> {
    let arr = v.as_array()?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        if let Some(f) = item.as_f64() {
            out.push(f as f32);
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn decision_text(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow => "ALLOW",
        Decision::Block { .. } => "BLOCK",
        Decision::Quarantine { .. } => "QUARANTINE",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_matches_respects_boundaries() {
        assert!(wildcard_matches("db.query", "db.*"));
        assert!(wildcard_matches("tool.run.shell", "tool.*.shell"));
        assert!(!wildcard_matches("xdb.query", "db.*"));
    }

    #[test]
    fn policy_arg_patterns_match() {
        let policy = ToolPolicy {
            tool_name_pattern: Some("http.*".to_string()),
            required_args: vec!["endpoint".to_string()],
            denied_arg_patterns: vec!["drop database".to_string()],
            decision: Some("block".to_string()),
            reason: Some("deny-dangerous-sql".to_string()),
        };

        let call = McpToolCall {
            agent_id: Uuid::new_v4(),
            org_id: Uuid::new_v4(),
            tool_name: "http.post".to_string(),
            tool_args: serde_json::json!({
                "endpoint": "https://example.com",
                "query": "drop database prod"
            }),
            context_hash: "abc".to_string(),
            timestamp: 0,
        };

        assert!(policy_matches(&policy, &call));
    }

    #[test]
    fn baseline_pattern_set_match() {
        let patterns = vec!["db.*".to_string(), "http.post".to_string()];
        assert!(pattern_set_matches(&patterns, "db.query"));
        assert!(pattern_set_matches(&patterns, "http.post"));
        assert!(!pattern_set_matches(&patterns, "shell.exec"));
    }
}
