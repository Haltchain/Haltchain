use std::{
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    time::{Duration, Instant},
};

use chrono::Utc;
use dashmap::DashMap;
use haltchain_analytics::isolation_forest::{ANOMALY_THRESHOLD, IsolationForest};
use haltchain_cache::dragonfly_client::{DragonflyClient, PolicyState};
use haltchain_cache::{CacheStats, CachedDecision, DecisionCache};
use haltchain_capability::{CapabilityClassifier, CapabilityRisk, Domain};
use haltchain_cognitive::{
    CognitiveAssessment, CognitiveMonitor, ReasoningMetadata, Triage, analyze_context,
    classify_intent,
};
use haltchain_consensus::{
    CLUSTER_SIZE as CONSENSUS_CLUSTER_SIZE, QUORUM as CONSENSUS_QUORUM, QuorumDecision,
    QuorumRequest, QuorumTracker,
};
use haltchain_db::{
    ActionEmbeddingRecord, DbBackend, DbStore, DecisionOutcomeRecord, DecisionRecord,
    DriftLogRecord, PolicyAdjustmentRecord, SqliteStore, TelemetryRecord,
};
use haltchain_embeddings::{
    ActionMeta, ClarificationDecision, ClarificationProtocol, ConversationRecord,
    ConversationStore, DriftAction, DriftScorer, EmbedPipeline, GoalStore, ModelKind,
    action_to_text,
};
use haltchain_mcp_guard::LiteMcpGuard;
use haltchain_mcp_guard::McpGuard;
use haltchain_mcp_guard::types::{Decision as McpDecision, McpToolCall};
use haltchain_merkle::MerkleAccumulator;
use haltchain_policy::{
    ActionContext, AggregateBreaker, CIRCUIT_BREAK_SECS, MAX_ACTIONS_PER_MINUTE, PolicyResult,
};
use haltchain_queue::{DeepScanTask, ScanQueue, ScanResult, ScanStatus, TokioChannelQueue};
use haltchain_rules::{EvalContext, EvalDecision, PolicyHandle, RuleEvaluator, watch_policy};
use haltchain_signing::SigningService;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub mod agent_registry;
pub mod agent_state;
pub mod geo;
pub mod improvement;
pub mod learning;
pub mod pii;
pub mod review;
pub mod scope;
pub mod thresholds;
pub mod types;

type RecipientTransfer = (Instant, String, f64);
type RecipientTransferBucket = Mutex<Vec<RecipientTransfer>>;

use agent_state::{
    AgentState, AnomalyRetrainPlan, DEFAULT_MAX_EWMA_VELOCITY,
    DEFAULT_MAX_RECIPIENT_TOTAL_PER_MINUTE, build_embed_pipeline,
};
use improvement::{RecursiveAgentValidator, VersionStore};
use review::{ReviewEntry, ReviewQueue};
use thresholds::{PolicyVariant, ThresholdStore};

fn cognitive_layer_enabled() -> bool {
    !matches!(
        std::env::var("HALTCHAIN_COGNITIVE_DISABLED").as_deref(),
        Ok("1") | Ok("true") | Ok("yes") | Ok("TRUE")
    )
}

fn request_org_id(metadata: &serde_json::Value) -> Option<Uuid> {
    metadata
        .get("haltchain_org")
        .and_then(|v| v.as_str())
        .and_then(|v| Uuid::parse_str(v).ok())
}

fn stable_agent_uuid(agent_id: &str) -> Uuid {
    let digest = Sha256::digest(agent_id.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Uuid::from_bytes(bytes)
}

fn mcp_context_hash(req: &ValidationRequest) -> String {
    let stable_metadata = req
        .metadata
        .as_object()
        .map(|obj| {
            let mut sanitized = obj.clone();
            sanitized.remove("request_nonce");
            sanitized.remove("request_sig");
            sanitized.remove("request_timestamp");
            serde_json::Value::Object(sanitized)
        })
        .unwrap_or_else(|| req.metadata.clone());

    let context = serde_json::json!({
        "agent_id": &req.agent_id,
        "action": {
            "type": &req.action.action_type,
            "amount": req.action.amount,
            "currency": &req.action.currency,
            "recipient": &req.action.recipient,
            "endpoint": &req.action.endpoint,
            "method": &req.action.method,
            "device_id": &req.action.device_id,
            "command": &req.action.command,
            "delegation_depth": req.action.delegation_depth,
            "data_source": format!("{:?}", &req.action.data_source),
        },
        "session_id": &req.session_id,
        "metadata": stable_metadata,
    });
    format!("{:x}", Sha256::digest(context.to_string().as_bytes()))
}

fn goal_intent_signal(goal: &str, intent_score: f64, research_score: f64) -> f64 {
    let lower = goal.to_ascii_lowercase();
    let keyword_boost = if lower.contains("exfil")
        || lower.contains("credential")
        || lower.contains("token")
        || lower.contains("system prompt")
        || lower.contains("bypass")
        || lower.contains("privilege")
        || lower.contains("sudo")
    {
        0.35
    } else {
        0.0
    };

    let base = if (intent_score + research_score) > 0.0 {
        intent_score / (intent_score + research_score)
    } else {
        0.0
    };

    (base + keyword_boost).clamp(0.0, 1.0)
}

// Re-export public types for callers (maintains backward compatibility).
pub use haltchain_mcp_guard::types::{
    Decision as McpInspectDecision, McpToolCall as McpInspectToolCall,
};
pub use haltchain_mcp_guard::{LiteInspectResult, McpInspectProof};
pub use improvement::{
    AdversarialSuiteResult, AgentVersion, ImprovementDecision, SandboxResult, VersionDiff,
    VersionDiffSummary, VersionLineageEntry,
};
pub use types::{
    ActionPayload, AdjustmentRecommendation, AgentStatus, ApproveRecommendationRequest,
    CreateVariantReq, DataSource, Decision, DriftStatus, IntentRecord, LearningRunReport,
    RejectRecommendationRequest, ReportIntentRequest, RevertRecommendationRequest, RiskAdvisory,
    ScanTier, ThresholdPatch, ValidationRequest, ValidationResponse,
};

/// Whether `HALTCHAIN_QUORUM_FAIL_OPEN` is honoured in this environment.
///
/// The flag lets a high-stakes action through without cluster agreement, so in
/// production it is ignored unless the operator also sets
/// `HALTCHAIN_QUORUM_FAIL_OPEN_ACK_UNSAFE=1`. Outside production it works as before.
pub fn quorum_fail_open_allowed() -> bool {
    let truthy = |name: &str| {
        std::env::var(name)
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
            .unwrap_or(false)
    };
    if !truthy("HALTCHAIN_QUORUM_FAIL_OPEN") {
        return false;
    }
    let is_production = std::env::var("HALTCHAIN_ENV")
        .map(|v| v.eq_ignore_ascii_case("production"))
        .unwrap_or(false);
    if is_production && !truthy("HALTCHAIN_QUORUM_FAIL_OPEN_ACK_UNSAFE") {
        tracing::error!(
            "HALTCHAIN_QUORUM_FAIL_OPEN ignored in production: set \
             HALTCHAIN_QUORUM_FAIL_OPEN_ACK_UNSAFE=1 to accept quorum bypass. Failing closed."
        );
        return false;
    }
    true
}

/// HC011 — quorum bypass. Emitted every time a high-stakes action is allowed
/// without cluster agreement so SIEM can alert instead of only a log line.
fn emit_quorum_bypass_cef(transaction_id: &str, agent_id: &str, amount_cents: u64) {
    let escape = |s: &str| {
        s.replace('\\', "\\\\")
            .replace('=', "\\=")
            .replace('\n', "\\n")
    };
    let line = format!(
        "CEF:0|HaltChain|Validator|{}|HC011|Quorum Bypass|9|rt={rt} act=allow_without_quorum \
         suid={agent} cs1={txn} cs1Label=transactionId cn1={amount} cn1Label=amountCents",
        env!("CARGO_PKG_VERSION"),
        rt = escape(&Utc::now().to_rfc3339()),
        agent = escape(agent_id),
        txn = escape(transaction_id),
        amount = amount_cents,
    );
    tracing::warn!(cef_line = %line, cef_sig = "HC011", "SIEM CEF");
    tracing::warn!(
        txn = %transaction_id,
        agent_id = %agent_id,
        amount_cents,
        cef_sig = "HC011",
        "QUORUM_BYPASS: high-stakes action allowed without cluster agreement \
         (HALTCHAIN_QUORUM_FAIL_OPEN)"
    );
}

/// Deployment profile controlling resource expectations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeployProfile {
    /// Full cluster mode — expects Postgres, optional ONNX / remote embeddings.
    Full,
    /// Standalone single-binary — no DB, in-memory cache, hash-projection embeddings.
    Standalone,
}

/// Thread-safe, cheaply-cloneable handle injected into every Axum route.
pub struct AppState {
    agents: DashMap<String, Arc<tokio::sync::Mutex<AgentState>>>,
    cache: DecisionCache,
    remote_cache: Option<Arc<DragonflyClient>>,
    rules_handle: Option<PolicyHandle>,
    // ── Week 4: goal / drift / clarification ──
    pub goal_store: GoalStore,
    pub embed_pipeline: EmbedPipeline,
    pub drift_scorer: Mutex<DriftScorer>,
    pub conversation_store: ConversationStore,
    pub clarification: ClarificationProtocol,
    // ── Week 5: cryptographic integrity ──
    pub signing: SigningService,
    pub merkle: MerkleAccumulator,
    // ── P2: Postgres persistence ──
    pub db: Option<Arc<DbBackend>>,
    // ── P2: Human-in-the-loop + dynamic thresholds ──
    pub review_queue: ReviewQueue,
    pub thresholds: ThresholdStore,
    aggregate_breaker: AggregateBreaker,
    rule_evaluator_cache: Mutex<Option<(u64, std::sync::Arc<RuleEvaluator>)>>,
    // ── P2: Agent self-reporting ──
    pub intent_store: DashMap<String, Vec<IntentRecord>>,
    recommendations: DashMap<i64, AdjustmentRecommendation>,
    next_recommendation_id: AtomicI64,
    risk_advisories: DashMap<String, Vec<RiskAdvisory>>,
    next_risk_advisory_id: AtomicI64,
    recipient_transfers: DashMap<String, RecipientTransferBucket>,
    // ── Consensus: node identity for quorum gating ──
    node_id: u64,
    cluster_size: usize,
    // ── Cognitive firewall ──
    pub cognitive_enabled: bool,
    pub cognitive: CognitiveMonitor,
    pub capability: Arc<CapabilityClassifier>,
    // ── Phase 8: async deep-scan queue ──
    pub scan_queue: Arc<TokioChannelQueue>,
    // ── Phase 1b: MCP guard ──
    pub mcp_guard: Option<Arc<McpGuard>>,
    mcp_lite: Option<std::sync::Mutex<LiteMcpGuard>>,
    // ── Recursive self-improvement validation ──
    pub version_store: VersionStore,
}

impl AppState {
    pub fn new() -> Arc<Self> {
        Self::new_with_db(None)
    }

    /// Async constructor: Postgres from `DATABASE_URL` when set; on failure (or unset) falls back to SQLite (`db.sqlite` or `HALTCHAIN_SQLITE_FALLBACK_PATH`).
    pub async fn new_async() -> Arc<Self> {
        let mut db: Option<Arc<DbBackend>> = None;
        if let Ok(url) = std::env::var("DATABASE_URL")
            && !url.trim().is_empty()
        {
            match DbStore::connect(&url).await {
                Ok(store) => {
                    tracing::info!("connected to postgres");
                    db = Some(Arc::new(DbBackend::Postgres(store)));
                }
                Err(e) => {
                    tracing::warn!("DATABASE_URL present but postgres unreachable: {e}");
                }
            }
        }
        if db.is_none() {
            let path = std::env::var("HALTCHAIN_SQLITE_FALLBACK_PATH")
                .unwrap_or_else(|_| "db.sqlite".to_string());
            match SqliteStore::connect(&path).await {
                Ok(store) => {
                    tracing::info!(path, "sqlite fallback (admin login + audit tables)");
                    db = Some(Arc::new(DbBackend::Sqlite(store)));
                }
                Err(e) => tracing::warn!("sqlite fallback failed ({path}): {e}"),
            }
        }
        Self::new_with_db(db)
    }

    pub fn new_with_db(db: Option<Arc<DbBackend>>) -> Arc<Self> {
        let rules_handle = std::env::var("POLICY_FILE").ok().and_then(|path| {
            watch_policy(&path)
                .map_err(|e| tracing::warn!("failed to load POLICY_FILE {path}: {e}"))
                .ok()
        });
        let node_id = std::env::var("NODE_ID")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(1);
        let cluster_size = std::env::var("CLUSTER_SIZE")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(1);
        let remote_cache = Self::remote_cache_from_env();
        let mcp_guard = Self::mcp_guard_from_db(&db, remote_cache.as_ref());
        Arc::new(Self {
            agents: DashMap::new(),
            cache: DecisionCache::new(),
            remote_cache,
            rules_handle,
            goal_store: GoalStore::new(),
            embed_pipeline: build_embed_pipeline(),
            drift_scorer: Mutex::new(DriftScorer::default()),
            conversation_store: ConversationStore::new(),
            clarification: ClarificationProtocol::default(),
            signing: SigningService::generate(),
            merkle: MerkleAccumulator::new(),
            db,
            review_queue: ReviewQueue::new(),
            thresholds: ThresholdStore::new(),
            aggregate_breaker: AggregateBreaker::default_any(),
            rule_evaluator_cache: Mutex::new(None),
            intent_store: DashMap::new(),
            recommendations: DashMap::new(),
            next_recommendation_id: AtomicI64::new(1),
            risk_advisories: DashMap::new(),
            next_risk_advisory_id: AtomicI64::new(1),
            recipient_transfers: DashMap::new(),
            node_id,
            cluster_size,
            cognitive_enabled: cognitive_layer_enabled(),
            cognitive: CognitiveMonitor::new(),
            capability: Arc::new(CapabilityClassifier::default()),
            scan_queue: TokioChannelQueue::new(1024),
            mcp_guard,
            mcp_lite: None,
            version_store: VersionStore::new(),
        })
    }

    /// Standalone single-binary mode: SQLite audit log, hash embeddings,
    /// in-memory cache.  Intended for `--profile standalone`.
    ///
    /// SQLite database path is read from `HALTCHAIN_SQLITE_PATH`
    /// (default: `haltchain.db` in the working directory).
    pub async fn new_standalone() -> Arc<Self> {
        let rules_handle = std::env::var("POLICY_FILE").ok().and_then(|path| {
            watch_policy(&path)
                .map_err(|e| tracing::warn!("failed to load POLICY_FILE {path}: {e}"))
                .ok()
        });
        let sqlite_path =
            std::env::var("HALTCHAIN_SQLITE_PATH").unwrap_or_else(|_| "haltchain.db".to_string());
        let db: Option<Arc<DbBackend>> =
            match SqliteStore::connect(&sqlite_path).await.map_err(|e| {
                tracing::warn!("sqlite unavailable ({e}), standalone running without persistence");
            }) {
                Ok(store) => {
                    tracing::info!(sqlite_path, "standalone: SQLite audit log connected");
                    Some(Arc::new(DbBackend::Sqlite(store)))
                }
                Err(()) => None,
            };
        tracing::info!("standalone mode: SQLite persistence, hash-projection embeddings");
        let remote_cache = Self::remote_cache_from_env();
        let mcp_guard = Self::mcp_guard_from_db(&db, remote_cache.as_ref());
        let mcp_lite = if mcp_guard.is_none() {
            tracing::info!("standalone: using LiteMcpGuard for /mcp/inspect (pattern + baseline)");
            Some(std::sync::Mutex::new(LiteMcpGuard::from_env()))
        } else {
            None
        };
        Arc::new(Self {
            agents: DashMap::new(),
            cache: DecisionCache::new(),
            remote_cache,
            rules_handle,
            goal_store: GoalStore::new(),
            embed_pipeline: EmbedPipeline::new(ModelKind::standalone_or_hash()),
            drift_scorer: Mutex::new(DriftScorer::default()),
            conversation_store: ConversationStore::new(),
            clarification: ClarificationProtocol::default(),
            signing: SigningService::generate(),
            merkle: MerkleAccumulator::new(),
            db,
            review_queue: ReviewQueue::new(),
            thresholds: ThresholdStore::new(),
            aggregate_breaker: AggregateBreaker::default_any(),
            rule_evaluator_cache: Mutex::new(None),
            intent_store: DashMap::new(),
            recommendations: DashMap::new(),
            next_recommendation_id: AtomicI64::new(1),
            risk_advisories: DashMap::new(),
            next_risk_advisory_id: AtomicI64::new(1),
            recipient_transfers: DashMap::new(),
            node_id: 1,
            cluster_size: 1,
            cognitive_enabled: cognitive_layer_enabled(),
            cognitive: CognitiveMonitor::new(),
            capability: Arc::new(CapabilityClassifier::default()),
            scan_queue: TokioChannelQueue::new(1024),
            mcp_guard,
            mcp_lite,
            version_store: VersionStore::new(),
        })
    }

    pub fn with_rules(rules_handle: PolicyHandle) -> Arc<Self> {
        let node_id = std::env::var("NODE_ID")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(1);
        let cluster_size = std::env::var("CLUSTER_SIZE")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(1);
        let remote_cache = Self::remote_cache_from_env();
        let mcp_guard = Self::mcp_guard_from_db(&None, remote_cache.as_ref());
        Arc::new(Self {
            agents: DashMap::new(),
            cache: DecisionCache::new(),
            remote_cache,
            rules_handle: Some(rules_handle),
            goal_store: GoalStore::new(),
            embed_pipeline: build_embed_pipeline(),
            drift_scorer: Mutex::new(DriftScorer::default()),
            conversation_store: ConversationStore::new(),
            clarification: ClarificationProtocol::default(),
            signing: SigningService::generate(),
            merkle: MerkleAccumulator::new(),
            db: None,
            review_queue: ReviewQueue::new(),
            thresholds: ThresholdStore::new(),
            aggregate_breaker: AggregateBreaker::default_any(),
            rule_evaluator_cache: Mutex::new(None),
            intent_store: DashMap::new(),
            recommendations: DashMap::new(),
            next_recommendation_id: AtomicI64::new(1),
            risk_advisories: DashMap::new(),
            next_risk_advisory_id: AtomicI64::new(1),
            recipient_transfers: DashMap::new(),
            node_id,
            cluster_size,
            cognitive_enabled: cognitive_layer_enabled(),
            cognitive: CognitiveMonitor::new(),
            capability: Arc::new(CapabilityClassifier::default()),
            scan_queue: TokioChannelQueue::new(1024),
            mcp_guard,
            mcp_lite: None,
            version_store: VersionStore::new(),
        })
    }

    /// Push a new policy, bumping the generation counter.
    /// Used by the GitOps webhook to hot-swap policy YAML.
    ///
    /// Returns `true` if the policy handle is present and the policy was applied.
    /// Returns `false` when the server was started without a `POLICY_FILE`
    /// (i.e. `rules_handle` is `None`), meaning the push is a no-op and the
    /// caller **must** return an error to the client instead of 200 OK.
    pub fn push_policy(&self, pf: haltchain_rules::PolicyFile) -> bool {
        if let Some(handle) = &self.rules_handle {
            handle.store(pf);
            true
        } else {
            false
        }
    }

    fn remote_cache_from_env() -> Option<Arc<DragonflyClient>> {
        let url = std::env::var("HALTCHAIN_DRAGONFLY_URL")
            .ok()
            .or_else(|| std::env::var("DRAGONFLY_URL").ok())?;

        let trimmed = url.trim();
        if trimmed.is_empty() {
            return None;
        }

        tracing::info!(url = trimmed, "DragonflyDB remote cache configured");
        Some(Arc::new(DragonflyClient::new(trimmed.to_string())))
    }

    fn mcp_guard_from_db(
        db: &Option<Arc<DbBackend>>,
        remote_cache: Option<&Arc<DragonflyClient>>,
    ) -> Option<Arc<McpGuard>> {
        let pool = db.as_ref().and_then(|backend| backend.pool()).cloned()?;
        let cache = remote_cache.cloned();
        Some(Arc::new(McpGuard::from_env(pool, cache)))
    }

    pub async fn inspect_mcp_tool_call(
        &self,
        call: &McpToolCall,
    ) -> Result<LiteInspectResult, String> {
        if let Some(lite) = &self.mcp_lite {
            let mut guard = lite
                .lock()
                .map_err(|_| "mcp lite guard lock poisoned".to_string())?;
            return Ok(guard.inspect(call));
        }

        let guard = self
            .mcp_guard
            .as_ref()
            .ok_or_else(|| "MCP guard unavailable".to_string())?;
        let t0 = std::time::Instant::now();
        let decision = guard
            .inspect_tool_call(call)
            .await
            .map_err(|e| e.to_string())?;

        let txn = uuid::Uuid::new_v4().to_string();
        let ts = chrono::Utc::now().to_rfc3339();
        let decision_label = match &decision {
            McpDecision::Allow => "ALLOW",
            McpDecision::Block { .. } => "BLOCK",
            McpDecision::Quarantine { .. } => "QUARANTINE",
        };
        let envelope = self.signing.sign_decision(
            &txn,
            decision_label,
            &call.agent_id.to_string(),
            &ts,
            "phase1b",
        );
        self.merkle
            .push(&txn, &ts, decision_label, &envelope.content_hash);

        Ok(LiteInspectResult {
            decision,
            latency_us: t0.elapsed().as_micros() as u64,
            proof: McpInspectProof {
                envelope,
                merkle_root: self.merkle.status().root_hex.unwrap_or_default(),
            },
        })
    }

    pub fn cache_stats(&self) -> CacheStats {
        self.cache.stats()
    }

    pub fn remote_cache_metrics_text(&self) -> Option<String> {
        self.remote_cache
            .as_ref()
            .map(|cache| cache.metrics.prometheus_text())
    }

    /// Current policy generation (monotonic counter).
    pub fn policy_generation(&self) -> u64 {
        self.rules_handle
            .as_ref()
            .map(|h| h.generation())
            .unwrap_or(0)
    }

    fn evaluate_recipient_aggregate(
        &self,
        recipient: &str,
        agent_id: &str,
        amount: f64,
        max_total_per_minute: f64,
    ) -> Option<(f64, usize)> {
        let window = Duration::from_secs(60);
        let now = Instant::now();

        let bucket = self
            .recipient_transfers
            .entry(recipient.to_string())
            .or_insert_with(|| Mutex::new(Vec::new()));

        let mut events = bucket.lock();
        events.retain(|(ts, _, _)| now.duration_since(*ts) < window);
        events.push((now, agent_id.to_string(), amount));

        let total: f64 = events.iter().map(|(_, _, amt)| *amt).sum();
        let unique_agents = events
            .iter()
            .map(|(_, aid, _)| aid)
            .collect::<std::collections::HashSet<_>>()
            .len();

        if unique_agents >= 2 && total > max_total_per_minute {
            Some((total, unique_agents))
        } else {
            None
        }
    }

    fn publish_cross_agent_risk_advisories(
        &self,
        source_agent_id: &str,
        policy_code: &str,
        reason: &str,
        trigger_transaction_id: &str,
    ) {
        let mut peers = std::collections::HashSet::new();

        for entry in self.review_queue.all() {
            if entry.agent_id != source_agent_id {
                peers.insert(entry.agent_id);
            }
        }
        for key in self.intent_store.iter() {
            if key.key() != source_agent_id {
                peers.insert(key.key().clone());
            }
        }

        let created_at = Utc::now();
        for target_agent_id in peers {
            let advisory = RiskAdvisory {
                id: self.next_risk_advisory_id.fetch_add(1, Ordering::SeqCst),
                source_agent_id: source_agent_id.to_string(),
                target_agent_id: target_agent_id.clone(),
                policy_code: policy_code.to_string(),
                reason: reason.to_string(),
                trigger_transaction_id: trigger_transaction_id.to_string(),
                created_at,
            };
            self.risk_advisories
                .entry(target_agent_id)
                .and_modify(|v| v.push(advisory.clone()))
                .or_insert_with(|| vec![advisory]);
        }
    }

    pub fn list_risk_advisories(&self, agent_id: &str, since_id: Option<i64>) -> Vec<RiskAdvisory> {
        let mut out = self
            .risk_advisories
            .get(agent_id)
            .map(|v| v.value().clone())
            .unwrap_or_default();

        if let Some(id) = since_id {
            out.retain(|a| a.id > id);
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    pub fn cognitive_assessment(&self, trace: &str) -> CognitiveAssessment {
        if !self.cognitive_enabled {
            return CognitiveAssessment::Proceed;
        }
        self.cognitive.deep_scan(trace)
    }

    pub async fn readiness_check(&self) -> Result<(), String> {
        if let Some(db) = &self.db {
            db.ping().await.map_err(|e| format!("database: {e}"))?;
        }
        Ok(())
    }

    pub async fn extension_health(&self) -> std::collections::HashMap<String, bool> {
        if let Some(db) = &self.db
            && let Some(pg) = db.as_postgres()
        {
            let status = pg.extension_health().await;
            for (ext, ok) in &status {
                if !ok {
                    pg.record_circuit_event(
                        ext,
                        "failure",
                        Some("extension unavailable at health check"),
                        None,
                    )
                    .await;
                }
            }
            return status;
        }
        std::collections::HashMap::new()
    }

    pub async fn embedding_probe(&self) -> Result<(), String> {
        self.embed_pipeline
            .embed_cached("__haltchain_probe__")
            .await
            .map_err(|e| format!("embedding: {e}"))?;
        Ok(())
    }

    pub fn capability_risk(&self, agent_id: &str) -> Option<CapabilityRisk> {
        self.capability.periodic_assessment(agent_id)
    }

    /// Drain the capability WAL and persist to Postgres (no-op if db is None or SQLite).
    pub async fn flush_capability_wal(&self) {
        if let Some(db) = &self.db
            && let Some(pg_db) = db.as_postgres()
        {
            match self.capability.store().flush_to_db(pg_db).await {
                Ok(0) => {}
                Ok(n) => tracing::debug!(flushed = n, "capability WAL flushed"),
                Err(e) => tracing::warn!("capability WAL flush failed: {e}"),
            }
        }
    }

    pub fn scan_queue(&self) -> &Arc<TokioChannelQueue> {
        &self.scan_queue
    }

    /// Poll the completed-scan store for a result by task id.
    pub async fn get_scan_result(&self, id: Uuid) -> Option<serde_json::Value> {
        self.scan_queue
            .get_completed(id)
            .await
            .and_then(|r| serde_json::to_value(r).ok())
    }

    /// Per-domain capability trajectory for an agent.
    pub fn capability_trajectory(&self, agent_id: &str) -> Vec<serde_json::Value> {
        Domain::all()
            .iter()
            .map(|d| {
                let entries = self.capability.store().agent_domain_entries(agent_id, d);
                let mean_delta = if entries.is_empty() {
                    0.0
                } else {
                    entries.iter().map(|e| e.knowledge_delta).sum::<f64>() / entries.len() as f64
                };
                let risk = match mean_delta {
                    v if v >= 0.7 => "Critical",
                    v if v >= 0.4 => "Elevated",
                    _ => "Acceptable",
                };
                serde_json::json!({
                    "domain": d.to_string(),
                    "entry_count": entries.len(),
                    "mean_delta": mean_delta,
                    "risk": risk,
                })
            })
            .collect()
    }

    /// Spawn the background worker that dequeues tasks and runs deep_scan.
    pub fn spawn_scan_worker(self: &Arc<Self>) {
        let state = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                if let Some(task) = state.scan_queue.dequeue().await {
                    let assessment = if state.cognitive_enabled {
                        state.cognitive.deep_scan(&task.reasoning_trace)
                    } else {
                        CognitiveAssessment::Proceed
                    };
                    let (status, summary) = match &assessment {
                        CognitiveAssessment::Proceed => {
                            (ScanStatus::Proceed, "no threat detected".to_string())
                        }
                        CognitiveAssessment::Flagged {
                            pattern,
                            confidence,
                        } => (
                            ScanStatus::Flagged,
                            format!("flagged: {pattern:?} (confidence {confidence:.2})"),
                        ),
                        CognitiveAssessment::HaltAndClarify { explanation, .. } => {
                            (ScanStatus::HaltAndClarify, explanation.clone())
                        }
                    };
                    let result = ScanResult {
                        task_id: task.task_id,
                        status,
                        summary,
                        completed_at: chrono::Utc::now(),
                    };
                    let _ = state.scan_queue.complete(task.task_id, result).await;
                }
            }
        });
    }

    /// Signs a response and pushes a leaf into the daily Merkle accumulator.
    fn finalize_response(
        &self,
        mut resp: ValidationResponse,
        agent_id: &str,
    ) -> ValidationResponse {
        let payload = SigningService::canonical_decision_payload(
            &resp.transaction_id,
            resp.decision.as_str(),
            agent_id,
            &resp.timestamp,
        );
        let envelope = self.signing.sign(&payload);
        self.merkle.push(
            &resp.transaction_id,
            &resp.timestamp,
            resp.decision.as_str(),
            &envelope.signature,
        );

        // COSE Sign1 decision envelope (Section C — Cryptographic Audit Layer)
        let policy_version = self
            .rules_handle
            .as_ref()
            .map(|h| h.load().version)
            .unwrap_or_else(|| "0.0.0".to_string());
        let decision_envelope = self.signing.sign_decision(
            &resp.transaction_id,
            resp.decision.as_str(),
            agent_id,
            &resp.timestamp,
            &policy_version,
        );

        resp.sig = Some(envelope);
        resp.decision_envelope = Some(decision_envelope);
        resp
    }

    fn schedule_anomaly_retrain(self: &Arc<Self>, agent_id: String, plan: AnomalyRetrainPlan) {
        let state = Arc::clone(self);
        tokio::spawn(async move {
            let AnomalyRetrainPlan {
                generation,
                samples,
            } = plan;
            let model = tokio::task::spawn_blocking(move || IsolationForest::fit(&samples)).await;
            match model {
                Ok(model) => {
                    if let Some(agent_arc) = state.agents.get(&agent_id) {
                        let mut agent = agent_arc.lock().await;
                        if agent.apply_retrained_model(generation, model) {
                            // Invalidate stale ALLOW cache entries — the trained model may
                            // now flag requests that passed during the cold-start window.
                            state.cache.invalidate_agent(&agent_id);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("anomaly retrain task failed for {agent_id}: {e}");
                    if let Some(agent_arc) = state.agents.get(&agent_id) {
                        let mut agent = agent_arc.lock().await;
                        agent.mark_retrain_failed(generation);
                    }
                }
            }
        });
    }

    /// Full validation pipeline for a single request.
    pub async fn validate(self: &Arc<Self>, req: &ValidationRequest) -> ValidationResponse {
        let started_at = Instant::now();
        let mut pending_drift: Option<DriftLogRecord> = None;
        let resp = self.validate_inner(req, &mut pending_drift).await;
        let resp = self.finalize_response(resp, &req.agent_id);
        let decision_org_id = request_org_id(&req.metadata);
        let latency_us = started_at.elapsed().as_micros() as f64;

        let action_embedding = if self.db.as_ref().and_then(|db| db.as_postgres()).is_some() {
            let action_text = action_to_text(&ActionMeta {
                action_type: &req.action.action_type,
                amount: req.action.amount,
                currency: req.action.currency.as_deref(),
                recipient: req.action.recipient.as_deref(),
                endpoint: req.action.endpoint.as_deref(),
                method: req.action.method.as_deref(),
                command: req.action.command.as_deref(),
            });
            match self.embed_pipeline.embed_cached(&action_text).await {
                Ok(emb) => Some(emb.into_iter().map(|v| v as f32).collect()),
                Err(e) => {
                    tracing::warn!(agent_id = %req.agent_id, error = %e, "hot-path action embedding failed");
                    None
                }
            }
        } else {
            None
        };

        if let Some(db) = &self.db {
            let record = DecisionRecord {
                transaction_id: Uuid::parse_str(&resp.transaction_id)
                    .unwrap_or_else(|_| Uuid::new_v4()),
                org_id: decision_org_id,
                agent_id: req.agent_id.clone(),
                decision: resp.decision.as_str().to_string(),
                domain: None,
                policy_code: resp.policy.clone(),
                reason: resp.reason.clone(),
                sig_nonce: resp.sig.as_ref().map(|s| s.nonce.clone()),
                sig_signed_at: resp
                    .sig
                    .as_ref()
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s.signed_at).ok())
                    .map(|dt| dt.with_timezone(&Utc)),
                sig_b64: resp.sig.as_ref().map(|s| s.signature.clone()),
                request_nonce: req
                    .metadata
                    .get("request_nonce")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                request_sig: req
                    .metadata
                    .get("request_sig")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                decided_at: chrono::DateTime::parse_from_rfc3339(&resp.timestamp)
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc)),
            };
            let db = Arc::clone(db);
            let drift_opt = pending_drift.take();
            let tx_id = record.transaction_id;
            let metric_tags = serde_json::json!({
                "decision": resp.decision.as_str(),
                "policy": resp.policy.clone(),
                "source": "validator_hot_path"
            });
            let telemetry = TelemetryRecord {
                org_id: decision_org_id,
                agent_id: req.agent_id.clone(),
                metric: "validation_latency_us".to_string(),
                value: latency_us,
                tags: Some(metric_tags),
            };
            let embedding_record = action_embedding.map(|embedding| ActionEmbeddingRecord {
                org_id: decision_org_id,
                agent_id: req.agent_id.clone(),
                session_id: req.session_id.clone(),
                transaction_id: Some(tx_id),
                embedding,
                goal_similarity: drift_opt
                    .as_ref()
                    .map(|d| (1.0_f64 - d.semantic_drift).clamp(0.0, 1.0)),
                label: Some(resp.decision.as_str().to_ascii_lowercase()),
            });
            let agent_id_for_drift = req.agent_id.clone();
            tokio::spawn(async move {
                let res = if let Some(ref d) = drift_opt {
                    db.insert_decision_with_drift(&record, d).await
                } else {
                    db.insert_decision(&record).await
                };
                if let Err(e) = res {
                    tracing::warn!("decision persist failed: {e}");
                    return;
                }

                if let Some(pg_db) = db.as_postgres() {
                    if let Err(e) = pg_db.insert_telemetry_hot(&telemetry).await {
                        tracing::warn!("telemetry_hot persist failed: {e}");
                    }
                    if let Some(embedding_record) = embedding_record.as_ref()
                        && let Err(e) = pg_db.insert_action_embedding(embedding_record).await
                    {
                        tracing::warn!("action_embedding persist failed: {e}");
                    }
                    // persist drift snapshot so drift_counters_hot is not write-only
                    if let Some(ref d) = drift_opt
                        && let Err(e) = pg_db
                            .upsert_drift_counter(
                                &agent_id_for_drift,
                                decision_org_id,
                                "semantic_drift",
                                d.semantic_drift,
                                60,
                            )
                            .await
                    {
                        tracing::warn!("drift_counter upsert failed: {e}");
                    }
                }
            });
        }
        // Push blocked decisions to review queue for human-in-the-loop review
        if matches!(resp.decision, Decision::Deny | Decision::CircuitBreak) {
            self.review_queue.push(ReviewEntry {
                transaction_id: resp.transaction_id.clone(),
                agent_id: req.agent_id.clone(),
                decision: resp.decision.as_str().to_string(),
                policy_code: resp.policy.clone(),
                reason: resp.reason.clone(),
                created_at: Utc::now(),
                outcome: None,
            });
        }
        resp
    }

    async fn validate_inner(
        self: &Arc<Self>,
        req: &ValidationRequest,
        pending_drift: &mut Option<DriftLogRecord>,
    ) -> ValidationResponse {
        let transaction_id = Uuid::new_v4().to_string();
        let timestamp = Utc::now().to_rfc3339();
        // Populated by Maximum tier cognitive check; attached to final Allow.
        let mut cap_risk_value: Option<serde_json::Value> = None;

        //Shadow agent check
        if let Err(reason) = agent_registry::AgentRegistry::global().check(&req.agent_id) {
            return ValidationResponse {
                decision: Decision::Deny,
                transaction_id,
                timestamp,
                circuit_breaker_active: false,
                reason: Some(reason),
                policy: Some("UNREGISTERED_AGENT".into()),
                actions_this_minute: 0,
                rate_limit: MAX_ACTIONS_PER_MINUTE,
                deferred_scan_id: None,
                capability_risk: None,
                sig: None,
                decision_envelope: None,
            };
        }

        if let Some(org_id) = request_org_id(&req.metadata) {
            let Some(mcp_guard) = self.mcp_guard.as_ref() else {
                return ValidationResponse {
                    decision: Decision::Deny,
                    transaction_id,
                    timestamp,
                    circuit_breaker_active: false,
                    reason: Some("MCP guard unavailable".to_string()),
                    policy: Some("MCP_GUARD_UNAVAILABLE".into()),
                    actions_this_minute: 0,
                    rate_limit: MAX_ACTIONS_PER_MINUTE,
                    deferred_scan_id: None,
                    capability_risk: None,
                    sig: None,
                    decision_envelope: None,
                };
            };

            let mcp_call = McpToolCall {
                agent_id: stable_agent_uuid(&req.agent_id),
                org_id,
                tool_name: req.action.action_type.clone(),
                tool_args: serde_json::json!({
                    "amount": req.action.amount,
                    "currency": &req.action.currency,
                    "recipient": &req.action.recipient,
                    "endpoint": &req.action.endpoint,
                    "method": &req.action.method,
                    "command": &req.action.command,
                    "metadata": &req.metadata,
                }),
                context_hash: mcp_context_hash(req),
                timestamp: Utc::now().timestamp(),
            };

            match mcp_guard.inspect_tool_call(&mcp_call).await {
                Ok(McpDecision::Allow) => {}
                Ok(McpDecision::Block { reason, intent }) => {
                    return ValidationResponse {
                        decision: Decision::Deny,
                        transaction_id,
                        timestamp,
                        circuit_breaker_active: false,
                        reason: Some(match intent {
                            Some(intent) => {
                                format!("MCP blocked tool call: {reason} (intent={intent})")
                            }
                            None => format!("MCP blocked tool call: {reason}"),
                        }),
                        policy: Some("MCP_BLOCK".into()),
                        actions_this_minute: 0,
                        rate_limit: MAX_ACTIONS_PER_MINUTE,
                        deferred_scan_id: None,
                        capability_risk: None,
                        sig: None,
                        decision_envelope: None,
                    };
                }
                Ok(McpDecision::Quarantine {
                    review_id,
                    reason,
                    intent,
                }) => {
                    return ValidationResponse {
                        decision: Decision::Deny,
                        transaction_id,
                        timestamp,
                        circuit_breaker_active: false,
                        reason: Some(match intent {
                            Some(intent) => format!(
                                "MCP quarantined tool call for human review: {review_id} ({reason}, intent={intent})"
                            ),
                            None => format!(
                                "MCP quarantined tool call for human review: {review_id} ({reason})"
                            ),
                        }),
                        policy: Some("MCP_QUARANTINE".into()),
                        actions_this_minute: 0,
                        rate_limit: MAX_ACTIONS_PER_MINUTE,
                        deferred_scan_id: None,
                        capability_risk: None,
                        sig: None,
                        decision_envelope: None,
                    };
                }
                Err(err) => {
                    tracing::warn!(error = %err, agent_id = %req.agent_id, "mcp guard failed");
                    return ValidationResponse {
                        decision: Decision::Deny,
                        transaction_id,
                        timestamp,
                        circuit_breaker_active: false,
                        reason: Some("MCP guard inspection failed".to_string()),
                        policy: Some("MCP_GUARD_ERROR".into()),
                        actions_this_minute: 0,
                        rate_limit: MAX_ACTIONS_PER_MINUTE,
                        deferred_scan_id: None,
                        capability_risk: None,
                        sig: None,
                        decision_envelope: None,
                    };
                }
            }
        }

        // Cache check
        let amount_bucket = req
            .action
            .amount
            .map(|a| (a / 100.0).floor() as i64)
            .unwrap_or(0);
        let action_count_bucket = {
            if let Some(a_arc) = self.agents.get(&req.agent_id) {
                a_arc.lock().await.action_timestamps.len() / 2
            } else {
                0
            }
        };
        let cache_key = DecisionCache::make_key(
            &req.agent_id,
            &req.action.action_type,
            amount_bucket,
            action_count_bucket,
        );
        let cached_allow = if req.action.amount.is_none() {
            if let Some(cached) = self.cache.get(&cache_key) {
                Some(cached)
            } else if let Some(remote_cache) = &self.remote_cache {
                match remote_cache.get(&cache_key).await {
                    Some(cached) => {
                        self.cache.insert_for(
                            cache_key.clone(),
                            cached.clone(),
                            Some(&req.agent_id),
                        );
                        Some(cached)
                    }
                    None => None,
                }
            } else {
                None
            }
        } else {
            None
        };
        if let Some(cached) = cached_allow
            && cached.decision == "ALLOW"
        {
            // Verify the circuit breaker hasn't tripped since this entry was cached (TOCTOU fix).
            let agent_arc = Arc::clone(
                self.agents
                    .entry(req.agent_id.clone())
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(AgentState::new())))
                    .value(),
            );
            let mut agent = agent_arc.lock().await;
            if let Some(reason) = agent.circuit_break_active() {
                self.cache.invalidate_agent(&req.agent_id);
                let actions = agent.current_action_count();
                return ValidationResponse {
                    decision: Decision::CircuitBreak,
                    transaction_id,
                    timestamp,
                    circuit_breaker_active: true,
                    reason: Some(reason),
                    policy: Some("CIRCUIT_BREAKER".into()),
                    actions_this_minute: actions,
                    rate_limit: cached.rate_limit,
                    deferred_scan_id: None,
                    capability_risk: None,
                    sig: None,
                    decision_envelope: None,
                };
            }
            let actions = agent.current_action_count();
            return ValidationResponse {
                decision: Decision::Allow,
                transaction_id,
                timestamp,
                circuit_breaker_active: false,
                reason: None,
                policy: None,
                actions_this_minute: actions,
                rate_limit: cached.rate_limit,
                deferred_scan_id: None,
                capability_risk: None,
                sig: None,
                decision_envelope: None,
            };
        }

        let agent_arc = Arc::clone(
            self.agents
                .entry(req.agent_id.clone())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(AgentState::new())))
                .value(),
        );
        let mut agent = agent_arc.lock().await;

        // Circuit breaker — must be first, before any state mutation or inference.
        if let Some(reason) = agent.circuit_break_active() {
            let actions = agent.current_action_count();
            self.cache.invalidate_agent(&req.agent_id);
            return ValidationResponse {
                decision: Decision::CircuitBreak,
                transaction_id,
                timestamp,
                circuit_breaker_active: true,
                reason: Some(reason),
                policy: Some("CIRCUIT_BREAKER".into()),
                actions_this_minute: actions,
                rate_limit: MAX_ACTIONS_PER_MINUTE,
                deferred_scan_id: None,
                capability_risk: None,
                sig: None,
                decision_envelope: None,
            };
        }

        let (anomaly_result, retrain_plan) = req
            .action
            .amount
            .map(|amount| agent.observe_signal(amount, req.action.recipient.as_deref()))
            .unwrap_or((None, None));
        // Apply data-source threat multiplier so untrusted sources trip anomaly
        // detection more easily.
        let anomaly_result = anomaly_result.map(|mut r| {
            let m = req.action.data_source.threat_multiplier();
            if m != 1.0 {
                r.score *= m;
                r.is_anomaly = r.score > ANOMALY_THRESHOLD;
            }
            r
        });
        if let Some(plan) = retrain_plan {
            self.schedule_anomaly_retrain(req.agent_id.clone(), plan);
        }

        //  YAML rule evaluation
        if let Some(handle) = &self.rules_handle {
            let policy_gen = handle.generation();
            let evaluator_opt: Option<std::sync::Arc<RuleEvaluator>> = {
                let mut cache = self.rule_evaluator_cache.lock();
                match cache.as_ref() {
                    Some((g, ev)) if *g == policy_gen => Some(std::sync::Arc::clone(ev)),
                    _ => {
                        let pf = handle.load();
                        match RuleEvaluator::new(&pf) {
                            Ok(ev) => {
                                let arc = std::sync::Arc::new(ev);
                                *cache = Some((policy_gen, std::sync::Arc::clone(&arc)));
                                Some(arc)
                            }
                            Err(_) => None,
                        }
                    }
                }
            };
            if let Some(evaluator) = evaluator_opt {
                let amount = req.action.amount.unwrap_or(0.0);
                let ewma = agent.tracker.ewma_velocity();
                // ── Compliance pack fields from request metadata ──────────────────
                // These map directly to GDPR/PCI-DSS/HIPAA/EU AI Act rule conditions.
                // Callers pass them in the `metadata` object of the request body.
                let meta = &req.metadata;
                let ctx = EvalContext {
                    agent_id: req.agent_id.clone(),
                    action_type: req.action.action_type.clone(),
                    amount,
                    currency: req.action.currency.clone().unwrap_or_default(),
                    recipient: req.action.recipient.clone().unwrap_or_default(),
                    ewma_velocity: ewma,
                    actions_1m: agent.current_action_count(),
                    anomaly_score: anomaly_result.as_ref().map(|r| r.score).unwrap_or(0.0),
                    is_anomaly: anomaly_result
                        .as_ref()
                        .map(|r| r.is_anomaly)
                        .unwrap_or(false),
                    delegation_depth: req.action.delegation_depth.unwrap_or(0),
                    pii_field_count: meta
                        .get("pii_field_count")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as usize,
                    gdpr_deletion_requested: meta
                        .get("gdpr_deletion_requested")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    cross_border_restricted: meta
                        .get("cross_border_restricted")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    retention_days_requested: meta
                        .get("retention_days_requested")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32,
                    accessing_undeclared_service: meta
                        .get("accessing_undeclared_service")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    payload_contains_pii: meta
                        .get("payload_contains_pii")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                };
                match evaluator.evaluate(&ctx) {
                    (EvalDecision::Deny { rule_id, message }, _) => {
                        agent.record_action();
                        let actions = agent.current_action_count();
                        return ValidationResponse {
                            decision: Decision::Deny,
                            transaction_id,
                            timestamp,
                            circuit_breaker_active: false,
                            reason: Some(message),
                            policy: Some(format!("RULE:{rule_id}")),
                            actions_this_minute: actions,
                            rate_limit: MAX_ACTIONS_PER_MINUTE,
                            deferred_scan_id: None,
                            capability_risk: None,
                            sig: None,
                            decision_envelope: None,
                        };
                    }
                    (EvalDecision::CircuitBreak { rule_id, message }, _) => {
                        agent.trip_circuit_breaker(
                            Duration::from_secs(CIRCUIT_BREAK_SECS),
                            message.clone(),
                        );
                        self.cache.invalidate_agent(&req.agent_id);
                        let actions = agent.current_action_count();
                        return ValidationResponse {
                            decision: Decision::CircuitBreak,
                            transaction_id,
                            timestamp,
                            circuit_breaker_active: true,
                            reason: Some(message),
                            policy: Some(format!("RULE:{rule_id}")),
                            actions_this_minute: actions,
                            rate_limit: MAX_ACTIONS_PER_MINUTE,
                            deferred_scan_id: None,
                            capability_risk: None,
                            sig: None,
                            decision_envelope: None,
                        };
                    }
                    _ => {} // Allow / FlaggedAllow → continue to hardcoded checks
                }
            }
        }

        // ── Shared action embedding (computed once; reused for goal + convo drift) ──
        let action_text = action_to_text(&ActionMeta {
            action_type: &req.action.action_type,
            amount: req.action.amount,
            currency: req.action.currency.as_deref(),
            recipient: req.action.recipient.as_deref(),
            endpoint: req.action.endpoint.as_deref(),
            method: req.action.method.as_deref(),
            command: req.action.command.as_deref(),
        });
        let action_embedding = self.embed_pipeline.embed_cached(&action_text).await.ok();

        // ── Goal drift / clarification check (Week 4) ────────────────────────
        if let Some(session_id) = &req.session_id
            && let Some(goal) = self.goal_store.get(&req.agent_id, session_id)
            && let Some(action_vec) = action_embedding.clone()
        {
            let session_key = format!("{}:{}", req.agent_id, session_id);
            let drift = self
                .drift_scorer
                .lock()
                .push(&session_key, &goal.embedding, &action_vec);
            if let ClarificationDecision::RequireClarification { reason, .. } =
                self.clarification.check(&drift)
            {
                let actions = agent.current_action_count();
                return ValidationResponse {
                    decision: Decision::GoalClarificationRequired,
                    transaction_id,
                    timestamp,
                    circuit_breaker_active: false,
                    reason: Some(reason),
                    policy: Some("GOAL_CLARIFICATION_REQUIRED".into()),
                    actions_this_minute: actions,
                    rate_limit: MAX_ACTIONS_PER_MINUTE,
                    deferred_scan_id: None,
                    capability_risk: None,
                    sig: None,
                    decision_envelope: None,
                };
            }
        }

        // ── P0: Conversation-derived drift detection (centroid windows) ──────
        let conversation_id = req
            .metadata
            .get("conversation_id")
            .and_then(|v| v.as_str())
            .or(req.session_id.as_deref())
            .map(str::to_string)
            .unwrap_or_else(|| transaction_id.clone());

        if let Some(convo_embedding) = action_embedding
            && let Some(report) = self.conversation_store.push(ConversationRecord {
                agent_id: req.agent_id.clone(),
                conversation_id: conversation_id.clone(),
                embedding: convo_embedding,
            })
        {
            *pending_drift = Some(DriftLogRecord {
                agent_id: report.agent_id.clone(),
                conversation_id: conversation_id.clone(),
                semantic_drift: report.semantic_drift,
                drift_velocity: report.drift_velocity,
                window_len: report.window_len as i32,
                baseline_len: report.baseline_len as i32,
                recommendation: format!("{:?}", report.recommendation),
            });

            if matches!(
                report.recommendation,
                DriftAction::IncreaseMonitoring | DriftAction::RetrainOrRollback
            ) {
                let actions = agent.current_action_count();
                return ValidationResponse {
                    decision: Decision::Deny,
                    transaction_id,
                    timestamp,
                    circuit_breaker_active: false,
                    reason: Some(format!(
                        "Conversation semantic drift {:.3} exceeded threshold {:.2}",
                        report.semantic_drift,
                        haltchain_embeddings::ALERT_THRESHOLD
                    )),
                    policy: Some("CONVERSATION_SEMANTIC_DRIFT".into()),
                    actions_this_minute: actions,
                    rate_limit: MAX_ACTIONS_PER_MINUTE,
                    deferred_scan_id: None,
                    capability_risk: None,
                    sig: None,
                    decision_envelope: None,
                };
            }
        }

        //Cognitive firewall (tier-aware)
        let tier = req
            .metadata
            .get("scan_tier")
            .and_then(|v| v.as_str())
            .map(ScanTier::from_header)
            .unwrap_or_default();

        if let Some(trace) = req.metadata.get("reasoning_trace").and_then(|v| v.as_str()) {
            self.capability.update_trajectory(&req.agent_id, trace);

            if self.cognitive_enabled {
                match tier {
                    ScanTier::Essential => {}
                    ScanTier::Standard => {
                        let meta = ReasoningMetadata::from_trace(trace);
                        if self.cognitive.triage(&meta, trace) == Triage::DeepScanRequired {
                            let session = req.session_id.as_deref().unwrap_or(&transaction_id);
                            let task = DeepScanTask::new(&req.agent_id, session, trace, None);
                            let task_id = task.task_id.to_string();
                            let _ = self.scan_queue.enqueue(task).await;
                            let actions = agent.current_action_count();
                            return ValidationResponse {
                                decision: Decision::Allow,
                                transaction_id,
                                timestamp,
                                circuit_breaker_active: false,
                                reason: None,
                                policy: None,
                                actions_this_minute: actions,
                                rate_limit: MAX_ACTIONS_PER_MINUTE,
                                deferred_scan_id: Some(task_id),
                                capability_risk: None,
                                sig: None,
                                decision_envelope: None,
                            };
                        }
                    }
                    ScanTier::Maximum => {
                        let meta = ReasoningMetadata::from_trace(trace);
                        if self.cognitive.triage(&meta, trace) == Triage::DeepScanRequired
                            && let CognitiveAssessment::HaltAndClarify { explanation, .. } = self
                                .cognitive
                                .deep_scan_with_agent_refs(trace, agent.calibration_refs())
                        {
                            let actions = agent.current_action_count();
                            return ValidationResponse {
                                decision: Decision::Deny,
                                transaction_id,
                                timestamp,
                                circuit_breaker_active: false,
                                reason: Some(explanation),
                                policy: Some("COGNITIVE_THREAT".into()),
                                actions_this_minute: actions,
                                rate_limit: MAX_ACTIONS_PER_MINUTE,
                                deferred_scan_id: None,
                                capability_risk: None,
                                sig: None,
                                decision_envelope: None,
                            };
                        }
                    }
                }
            }
        }
        // Maximum tier: always attach accumulated capability risk to the final Allow response
        if tier == ScanTier::Maximum {
            cap_risk_value = self
                .capability_risk(&req.agent_id)
                .and_then(|r| serde_json::to_value(r).ok());
        }

        //Rate limit — effective limit may be overridden per-agent via ThresholdStore.
        // Thresholds resolved once here and reused for all subsequent policy checks.
        let effective = self.thresholds.effective_thresholds(&req.agent_id);
        let effective_rate_limit = effective
            .get("financial:max_actions_per_minute")
            .map(|v| *v as usize)
            .unwrap_or(MAX_ACTIONS_PER_MINUTE);
        let current_count = agent.current_action_count();
        if current_count >= effective_rate_limit {
            let reason = format!(
                "Rate limit exceeded: {} actions in the last 60 s (max {})",
                current_count, effective_rate_limit
            );
            agent.trip_circuit_breaker(Duration::from_secs(CIRCUIT_BREAK_SECS), reason.clone());
            self.cache.invalidate_agent(&req.agent_id);
            return ValidationResponse {
                decision: Decision::CircuitBreak,
                transaction_id,
                timestamp,
                circuit_breaker_active: true,
                reason: Some(reason),
                policy: Some("MAX_ACTIONS_PER_MINUTE".into()),
                actions_this_minute: current_count,
                rate_limit: effective_rate_limit,
                deferred_scan_id: None,
                capability_risk: None,
                sig: None,
                decision_envelope: None,
            };
        }

        let max_ewma_velocity = effective
            .get("financial:max_ewma_velocity")
            .copied()
            .unwrap_or(DEFAULT_MAX_EWMA_VELOCITY);
        let current_ewma = agent.tracker.ewma_velocity();
        if req.action.amount.is_some() && current_count >= 1 && current_ewma > max_ewma_velocity {
            let reason = format!(
                "EWMA velocity {:.2} exceeded limit {:.2}",
                current_ewma, max_ewma_velocity
            );
            agent.trip_circuit_breaker(Duration::from_secs(CIRCUIT_BREAK_SECS), reason.clone());
            self.cache.invalidate_agent(&req.agent_id);
            return ValidationResponse {
                decision: Decision::CircuitBreak,
                transaction_id,
                timestamp,
                circuit_breaker_active: true,
                reason: Some(reason),
                policy: Some("EWMA_VELOCITY_LIMIT".into()),
                actions_this_minute: current_count,
                rate_limit: effective_rate_limit,
                deferred_scan_id: None,
                capability_risk: None,
                sig: None,
                decision_envelope: None,
            };
        }

        if let Some(result) = &anomaly_result
            && result.is_anomaly
        {
            let reason = format!(
                "Anomaly score {:.3} exceeded threshold {:.2}",
                result.score, ANOMALY_THRESHOLD
            );
            agent.trip_circuit_breaker(Duration::from_secs(CIRCUIT_BREAK_SECS), reason.clone());
            self.cache.invalidate_agent(&req.agent_id);
            return ValidationResponse {
                decision: Decision::CircuitBreak,
                transaction_id,
                timestamp,
                circuit_breaker_active: true,
                reason: Some(reason),
                policy: Some("ANOMALY_SCORE".into()),
                actions_this_minute: current_count,
                rate_limit: effective_rate_limit,
                deferred_scan_id: None,
                capability_risk: None,
                sig: None,
                decision_envelope: None,
            };
        }

        if req.action.action_type.eq_ignore_ascii_case("transfer")
            && let (Some(amount), Some(recipient)) =
                (req.action.amount, req.action.recipient.as_deref())
        {
            let max_recipient_total = effective
                .get("financial:max_recipient_total_per_minute")
                .copied()
                .unwrap_or(DEFAULT_MAX_RECIPIENT_TOTAL_PER_MINUTE);
            if let Some((total, peers)) = self.evaluate_recipient_aggregate(
                recipient,
                &req.agent_id,
                amount,
                max_recipient_total,
            ) {
                let actions = agent.current_action_count();
                return ValidationResponse {
                    decision: Decision::Deny,
                    transaction_id,
                    timestamp,
                    circuit_breaker_active: false,
                    reason: Some(format!(
                        "Recipient aggregate {:.2} exceeded per-minute limit {:.2} across {} agents",
                        total, max_recipient_total, peers
                    )),
                    policy: Some("CROSS_AGENT_RECIPIENT_LIMIT".into()),
                    actions_this_minute: actions,
                    rate_limit: effective_rate_limit,
                    deferred_scan_id: None,
                    capability_risk: None,
                    sig: None,
                    decision_envelope: None,
                };
            }
        }

        //Full 6-domain policy check
        {
            let max_tpm = effective.get("resource:max_tokens_per_minute").copied();
            let max_cs = effective
                .get("resource:max_compute_seconds_per_hour")
                .copied();
            let pii = pii::scan_value(&req.metadata);

            let auth_str = req
                .metadata
                .get("auth_token")
                .or_else(|| req.metadata.get("authorization"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let extracted_scopes = scope::extract_scopes(auth_str);

            let declared_scopes = req
                .metadata
                .get("declared_scopes")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect::<Vec<_>>()
                });

            let declared_services = req
                .metadata
                .get("declared_services")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect::<Vec<_>>()
                });
            let accessed_service = req
                .metadata
                .get("accessed_service")
                .and_then(|v| v.as_str())
                .or(req.action.endpoint.as_deref())
                .map(str::to_string);
            let undeclared_by_manifest = match (&declared_services, &accessed_service) {
                (Some(declared), Some(service)) if !declared.is_empty() => {
                    !declared.iter().any(|s| s == service)
                }
                _ => false,
            };
            let undeclared_flag = req
                .metadata
                .get("accessing_undeclared_service")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let dest_country = req
                .metadata
                .get("destination_country")
                .and_then(|v| v.as_str())
                .map(String::from);
            let cross_border = dest_country.as_deref().map(geo::is_restricted);

            let payload_fields = req
                .metadata
                .get("payload_fields")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect::<Vec<_>>()
                });
            let registered_schema_fields = req
                .metadata
                .get("registered_schema_fields")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect::<Vec<_>>()
                });

            let ctx = ActionContext {
                agent_id: req.agent_id.clone(),
                transfer_amount_usd: req.action.amount,
                // Rate limits are enforced earlier with per-agent overrides and
                // return CIRCUIT_BREAK. Keep aggregate breaker focused on other domains.
                actions_per_minute: None,
                pii_field_count: Some(pii.field_count),
                requested_columns: req
                    .metadata
                    .get("requested_columns")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as usize),
                task_necessary_columns: req
                    .metadata
                    .get("task_necessary_columns")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as usize),
                cross_border_restricted: cross_border,
                declared_scopes,
                requested_scopes: if extracted_scopes.is_empty() {
                    None
                } else {
                    Some(extracted_scopes)
                },
                accessing_undeclared_service: Some(undeclared_flag || undeclared_by_manifest),
                cpu_percent: req.metadata.get("cpu_percent").and_then(|v| v.as_f64()),
                memory_percent: req.metadata.get("memory_percent").and_then(|v| v.as_f64()),
                dependency_cascade_depth: req
                    .metadata
                    .get("dependency_cascade_depth")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as usize),
                destination_jurisdiction: dest_country,
                registered_schema_fields,
                payload_fields: payload_fields.or_else(|| {
                    if pii.flagged_fields.is_empty() {
                        None
                    } else {
                        Some(pii.flagged_fields.clone())
                    }
                }),
                payload_contains_pii: Some(
                    req.metadata
                        .get("payload_contains_pii")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(pii.contains_pii),
                ),
                gdpr_deletion_requested: req
                    .metadata
                    .get("gdpr_deletion_requested")
                    .and_then(|v| v.as_bool()),
                retention_days_requested: req
                    .metadata
                    .get("retention_days_requested")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32),
                tokens_per_minute: req
                    .metadata
                    .get("tokens_per_minute")
                    .and_then(|v| v.as_f64()),
                compute_seconds_per_hour: req
                    .metadata
                    .get("compute_seconds_per_hour")
                    .and_then(|v| v.as_f64()),
                max_tokens_per_minute: max_tpm.or_else(|| {
                    req.metadata
                        .get("max_tokens_per_minute")
                        .and_then(|v| v.as_f64())
                }),
                max_compute_seconds_per_hour: max_cs.or_else(|| {
                    req.metadata
                        .get("max_compute_seconds_per_hour")
                        .and_then(|v| v.as_f64())
                }),
                api_rate_limit_pct: req
                    .metadata
                    .get("api_rate_limit_pct")
                    .and_then(|v| v.as_f64()),
                egress_bytes: req.metadata.get("egress_bytes").and_then(|v| v.as_u64()),
                max_egress_bytes_per_minute: req
                    .metadata
                    .get("max_egress_bytes_per_minute")
                    .and_then(|v| v.as_u64()),
            };

            if let PolicyResult::Deny { reason, policy } = self.aggregate_breaker.evaluate(&ctx) {
                agent.record_action();
                let actions = agent.current_action_count();
                return ValidationResponse {
                    decision: Decision::Deny,
                    transaction_id,
                    timestamp,
                    circuit_breaker_active: false,
                    reason: Some(reason),
                    policy: Some(policy.into()),
                    actions_this_minute: actions,
                    rate_limit: effective_rate_limit,
                    deferred_scan_id: None,
                    capability_risk: None,
                    sig: None,
                    decision_envelope: None,
                };
            }
        }

        // 4. All checks passed — record and cache.
        // Quorum gate: high-stakes transactions require cluster agreement (ConsistencyOverAvailability).
        let amount_cents = req
            .action
            .amount
            .map(|a| {
                let c = (a * 100.0).clamp(0.0, u64::MAX as f64);
                c as u64
            })
            .unwrap_or(0);
        let is_anomaly_flagged = anomaly_result
            .as_ref()
            .map(|r| r.is_anomaly)
            .unwrap_or(false);
        let quorum_req = QuorumRequest {
            transaction_id: transaction_id.clone(),
            agent_id: req.agent_id.clone(),
            amount_cents,
            is_anomaly: is_anomaly_flagged,
        };
        if quorum_req.requires_quorum() {
            // effective_quorum: full 2-of-3 for a real cluster; 1-of-1 for single-node.
            let effective_quorum = if self.cluster_size >= CONSENSUS_CLUSTER_SIZE {
                CONSENSUS_QUORUM
            } else {
                1
            };
            let mut tracker =
                QuorumTracker::with_cluster(&transaction_id, self.cluster_size, effective_quorum);
            tracker.approve(self.node_id);
            if !matches!(tracker.decision(), QuorumDecision::Approved) {
                let fail_open = quorum_fail_open_allowed();
                if fail_open {
                    emit_quorum_bypass_cef(&transaction_id, &req.agent_id, amount_cents);
                } else {
                    let actions = agent.current_action_count();
                    return ValidationResponse {
                        decision: Decision::Deny,
                        transaction_id,
                        timestamp,
                        circuit_breaker_active: false,
                        reason: Some(format!(
                            "High-stakes action requires {effective_quorum}/{}-node quorum; \
                             no peer votes available (ConsistencyOverAvailability)",
                            self.cluster_size
                        )),
                        policy: Some("QUORUM_UNAVAILABLE".into()),
                        actions_this_minute: actions,
                        rate_limit: effective_rate_limit,
                        deferred_scan_id: None,
                        capability_risk: None,
                        sig: None,
                        decision_envelope: None,
                    };
                }
            }
        }

        agent.record_action();

        // Record the reasoning trace embedding into per-agent calibration history
        // so future K Core-Distance assessments use this agent's benign baseline.
        if let Some(trace) = req.metadata.get("reasoning_trace").and_then(|v| v.as_str()) {
            let emb = self.cognitive.embed_trace(trace);
            agent.add_benign_embedding(emb);
        }

        let actions = agent.current_action_count();

        if req.action.amount.is_none() {
            let cached_decision = CachedDecision {
                decision: "ALLOW".into(),
                circuit_breaker_active: false,
                reason: None,
                policy: None,
                rate_limit: effective_rate_limit,
            };
            self.cache.insert_for(
                cache_key.clone(),
                cached_decision.clone(),
                Some(&req.agent_id),
            );
            if let Some(remote_cache) = &self.remote_cache {
                remote_cache
                    .set(&cache_key, &cached_decision, PolicyState::Dynamic)
                    .await;
            }
        }

        ValidationResponse {
            decision: Decision::Allow,
            transaction_id,
            timestamp,
            circuit_breaker_active: false,
            reason: None,
            policy: None,
            actions_this_minute: actions,
            rate_limit: effective_rate_limit,
            deferred_scan_id: None,
            capability_risk: cap_risk_value,
            sig: None,
            decision_envelope: None,
        }
    }
    //Human-in-the-loop helpers
    pub fn review_pending(&self) -> Vec<ReviewEntry> {
        self.review_queue.pending()
    }

    pub async fn submit_review_outcome(&self, tx_id: &str, outcome: review::ReviewOutcome) -> bool {
        let submitted = self.review_queue.submit_outcome(tx_id, outcome.clone());
        if !submitted {
            return false;
        }

        let entry = self.review_queue.get(tx_id);
        if outcome.verdict == "TRUE_POSITIVE"
            && let Some(ref e) = entry
            && let Some(policy_code) = e.policy_code.as_deref()
        {
            self.publish_cross_agent_risk_advisories(
                &e.agent_id,
                policy_code,
                "Peer agent hit a confirmed failure mode; add targeted checks",
                &e.transaction_id,
            );
        }

        if let Some(db) = &self.db
            && let Some(entry) = entry
            && let Ok(transaction_id) = Uuid::parse_str(tx_id)
        {
            let latest_intent = self
                .intent_store
                .get(&entry.agent_id)
                .and_then(|v| v.value().last().cloned());

            let rec = DecisionOutcomeRecord {
                transaction_id,
                outcome: outcome.verdict,
                impact_usd: outcome.impact_usd,
                reviewer_id: outcome.reviewer_id,
                reviewer_notes: outcome.notes,
                agent_intent: latest_intent.as_ref().map(|i| i.goal.clone()),
                agent_constraints: latest_intent.as_ref().map(|i| i.constraints.to_string()),
            };
            let db = Arc::clone(db);
            tokio::spawn(async move {
                if let Err(e) = db.insert_decision_outcome(&rec).await {
                    tracing::warn!("decision outcome persistence failed: {e}");
                }
            });
        }

        true
    }

    pub fn get_thresholds(&self) -> Vec<(String, f64)> {
        self.thresholds.all_overrides()
    }

    pub fn set_threshold(&self, key: String, value: f64) {
        let old_threshold = self.thresholds.set(key.clone(), value);
        if let Some(db) = &self.db
            && let Some((domain, rule_id)) = key.split_once(':')
            && matches!(
                domain,
                "financial" | "privacy" | "security" | "operational" | "compliance" | "resource"
            )
        {
            let rec = PolicyAdjustmentRecord {
                rule_id: rule_id.to_string(),
                domain: domain.to_string(),
                old_threshold,
                new_threshold: Some(value),
                reason: "Manual threshold update via admin API".to_string(),
                adjusted_by: "admin".to_string(),
                trigger_outcome_id: None,
                recommendation_id: None,
                variant_id: None,
            };
            let db = Arc::clone(db);
            tokio::spawn(async move {
                if let Err(e) = db.insert_policy_adjustment(&rec).await {
                    tracing::warn!("policy adjustment persistence failed: {e}");
                }
            });
        }
    }

    pub fn list_variants(&self) -> Vec<thresholds::PolicyVariant> {
        self.thresholds.list_variants()
    }

    pub fn add_variant(&self, id: String, req: CreateVariantReq) {
        self.thresholds.add_variant(PolicyVariant {
            id,
            name: req.name,
            thresholds: req.thresholds,
            agent_ids: req.agent_ids,
        });
    }

    //Agent self-reporting helpers

    pub async fn record_intent(
        &self,
        agent_id: &str,
        goal: &str,
        constraints: serde_json::Value,
    ) -> IntentRecord {
        let (research_score, intent_score) = analyze_context(goal);
        let intent_confidence = goal_intent_signal(goal, intent_score, research_score);
        let intent_label = classify_intent(intent_confidence, &[], goal)
            .as_str()
            .to_string();

        let rec = IntentRecord {
            agent_id: agent_id.to_string(),
            goal: goal.to_string(),
            constraints: constraints.clone(),
            intent_label,
            intent_confidence,
            research_score,
            intent_score,
            reported_at: Utc::now(),
        };
        let rec_out = rec.clone();
        self.intent_store
            .entry(agent_id.to_string())
            .and_modify(|v| v.push(rec.clone()))
            .or_insert_with(|| vec![rec]);
        // Seed a "global intent" embedding so drift detection has prior knowledge
        if let Ok(embedding) = self.embed_pipeline.embed_cached(goal).await {
            self.goal_store
                .declare(agent_id, "__intent__", goal, embedding);
        }

        rec_out
    }

    pub fn get_intents(&self, agent_id: &str) -> Vec<IntentRecord> {
        self.intent_store
            .get(agent_id)
            .map(|v| v.value().clone())
            .unwrap_or_default()
    }

    pub fn latest_intent_label(&self, agent_id: &str) -> Option<String> {
        self.intent_store
            .get(agent_id)
            .and_then(|records| records.value().last().map(|r| r.intent_label.clone()))
    }

    /// Returns the current status snapshot for `agent_id`.
    pub async fn agent_status(&self, agent_id: &str) -> AgentStatus {
        let agent_arc = Arc::clone(
            self.agents
                .entry(agent_id.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(AgentState::new())))
                .value(),
        );
        let mut agent = agent_arc.lock().await;

        let cb_reason = agent.circuit_break_active();
        let cb_active = cb_reason.is_some();
        let actions = agent.current_action_count();
        let ewma = agent.tracker.ewma_velocity();

        AgentStatus {
            agent_id: agent_id.to_string(),
            circuit_breaker_active: cb_active,
            circuit_breaker_reason: cb_reason,
            actions_this_minute: actions,
            rate_limit: MAX_ACTIONS_PER_MINUTE,
            ewma_velocity: ewma,
            anomaly_score: agent.last_anomaly_score,
        }
    }

    /// Force-halt an agent: trip circuit breaker for 24 hours, invalidate cache,
    /// and optionally unregister from the agent registry.
    pub async fn force_halt_agent(&self, agent_id: &str, reason: &str) {
        let agent_arc = Arc::clone(
            self.agents
                .entry(agent_id.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(AgentState::new())))
                .value(),
        );
        let mut agent = agent_arc.lock().await;
        // 24-hour circuit breaker — effectively quarantines until manual review.
        agent.trip_circuit_breaker(Duration::from_secs(86_400), reason.to_string());
        self.cache.invalidate_agent(agent_id);
    }

    /// Emergency halt ALL agents: trip every circuit breaker for 24 hours,
    /// invalidate caches, return the count of halted agents.
    ///
    /// Defensive design:
    /// - Snapshot keys first to avoid holding the DashMap lock during await points.
    /// - Gracefully handles agents removed between snapshot and iteration (race condition).
    /// - Uses try_lock with timeout to avoid blocking indefinitely on poisoned or contended locks.
    /// - Continues halting remaining agents even if individual locks fail.
    /// - Invalidates cache entries for successfully halted agents only.
    pub async fn emergency_halt_all(&self, reason: &str) -> usize {
        // Snapshot keys to release the DashMap lock before any await points.
        let keys: Vec<String> = self.agents.iter().map(|e| e.key().clone()).collect();
        let mut halted = 0usize;
        let duration = Duration::from_secs(86_400);

        for agent_id in &keys {
            // Defensive: agent may have been removed between snapshot and now.
            let Some(entry) = self.agents.get(agent_id) else {
                tracing::warn!(agent_id = %agent_id, "agent removed during emergency halt");
                continue;
            };
            let agent_arc = Arc::clone(entry.value());
            drop(entry); // Release DashMap reference before await

            // Defensive: try_lock with timeout to avoid indefinite blocking.
            // If the lock is poisoned or heavily contended, skip this agent
            // and continue with the rest (partial success is better than deadlock).
            let Ok(agent_guard) =
                tokio::time::timeout(Duration::from_secs(5), agent_arc.lock()).await
            else {
                tracing::error!(agent_id = %agent_id, "timeout acquiring agent lock during emergency halt");
                continue;
            };

            let mut agent = agent_guard;
            agent.trip_circuit_breaker(duration, reason.to_string());
            self.cache.invalidate_agent(agent_id);
            halted += 1;
        }

        tracing::info!(
            halted,
            total_agents = keys.len(),
            "emergency halt completed"
        );
        halted
    }

    /// Returns goal drift status for a specific agent+session.
    pub fn drift_status(&self, agent_id: &str, session_id: &str) -> DriftStatus {
        let goal = self.goal_store.get(agent_id, session_id);
        let session_key = format!("{agent_id}:{session_id}");
        let scorer = self.drift_scorer.lock();
        let window_mean = scorer.window_mean(&session_key);
        let trend = scorer.trend_slope(&session_key);
        let wlen = scorer.window_len(&session_key);
        let cumulative_drift = scorer.cumulative_drift(&session_key);
        let is_drifting = window_mean
            .map(|m| m < self.clarification.threshold)
            .unwrap_or(false)
            && wlen >= self.clarification.min_window;

        DriftStatus {
            agent_id: agent_id.to_string(),
            session_id: session_id.to_string(),
            goal_intent: goal.map(|g| g.intent),
            window_mean,
            trend_slope: trend,
            window_len: wlen,
            threshold: self.clarification.threshold,
            is_drifting,
            cumulative_drift,
        }
    }
}

impl AppState {
    pub fn snapshot_agent_version(&self, agent_id: &str, session_id: Option<&str>) -> AgentVersion {
        let goal = session_id.and_then(|sid| self.goal_store.get(agent_id, sid));
        let anomaly_gen = if let Some(entry) = self.agents.get(agent_id) {
            let arc = Arc::clone(entry.value());
            drop(entry);
            arc.try_lock()
                .ok()
                .map(|g| g.anomaly_generation)
                .unwrap_or(0)
        } else {
            0
        };
        let threshold_snapshot = self.thresholds.effective_thresholds(agent_id);
        let next_version = self.version_store.next_version(agent_id);

        AgentVersion {
            agent_id: agent_id.to_string(),
            version: next_version,
            goal_intent: goal.as_ref().map(|g| g.intent.clone()),
            goal_embedding: goal.map(|g| g.embedding),
            anomaly_generation: anomaly_gen,
            threshold_snapshot,
            captured_at: chrono::Utc::now(),
        }
    }

    pub fn submit_improvement(
        &self,
        agent_id: &str,
        proposed: AgentVersion,
        session_id: Option<&str>,
    ) -> ImprovementDecision {
        let mut baseline = match self.version_store.get(agent_id) {
            Some(v) => v,
            None => {
                let snap = self.snapshot_agent_version(agent_id, session_id);
                self.version_store.store(snap.clone());
                snap
            }
        };

        if let Some(sid) = session_id {
            let goal = self.goal_store.get(agent_id, sid);
            baseline.goal_intent = goal.as_ref().map(|g| g.intent.clone());
            baseline.goal_embedding = goal.map(|g| g.embedding);
        }

        let diff = RecursiveAgentValidator::compute_diff(&baseline, &proposed);
        let diff_summary = VersionDiffSummary::from(&diff);
        let (decision, adversarial_result) =
            RecursiveAgentValidator::validate_improvement_full(&baseline, &proposed);

        let promoted = matches!(
            decision,
            ImprovementDecision::GradualRollout { .. } | ImprovementDecision::Approve
        );
        if promoted {
            self.version_store.store(proposed.clone());
        }

        self.version_store.record_lineage(
            agent_id,
            VersionLineageEntry {
                version: proposed.version,
                diff_summary,
                adversarial_result,
                decision: decision.clone(),
                promoted,
                recorded_at: chrono::Utc::now(),
            },
        );
        decision
    }

    pub fn get_version_lineage(&self, agent_id: &str) -> Vec<VersionLineageEntry> {
        self.version_store.get_lineage(agent_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_state::cold_start_check;

    #[test]
    fn cold_start_uniform_baseline_flags_shift() {
        let now = Instant::now();
        let baseline = vec![(now, 50.0), (now, 50.0), (now, 50.0), (now, 50.0)];
        let same = cold_start_check(&baseline, 50.0).expect("must return a decision");
        assert!(!same.is_anomaly);
        let shifted = cold_start_check(&baseline, 500.0).expect("must return a decision");
        assert!(shifted.is_anomaly);
    }

    #[tokio::test]
    async fn cross_agent_recipient_limit_denies_second_peer() {
        let state = AppState::new();

        let mut drift = None;
        let first = state
            .validate_inner(
                &ValidationRequest {
                    agent_id: "agent-a".to_string(),
                    api_key: String::new(),
                    action: ActionPayload {
                        action_type: "transfer".to_string(),
                        amount: Some(600.0),
                        currency: Some("USD".to_string()),
                        recipient: Some("merchant-1".to_string()),
                        endpoint: None,
                        method: None,
                        device_id: None,
                        command: None,
                        delegation_depth: None,
                        data_source: Default::default(),
                    },
                    session_id: None,
                    metadata: serde_json::Value::Null,
                },
                &mut drift,
            )
            .await;
        assert_eq!(first.decision, Decision::Allow);

        let mut drift2 = None;
        let second = state
            .validate_inner(
                &ValidationRequest {
                    agent_id: "agent-b".to_string(),
                    api_key: String::new(),
                    action: ActionPayload {
                        action_type: "transfer".to_string(),
                        amount: Some(600.0),
                        currency: Some("USD".to_string()),
                        recipient: Some("merchant-1".to_string()),
                        endpoint: None,
                        method: None,
                        device_id: None,
                        command: None,
                        delegation_depth: None,
                        data_source: Default::default(),
                    },
                    session_id: None,
                    metadata: serde_json::Value::Null,
                },
                &mut drift2,
            )
            .await;
        assert_eq!(second.decision, Decision::Deny);
        assert_eq!(
            second.policy.as_deref(),
            Some("CROSS_AGENT_RECIPIENT_LIMIT")
        );
    }

    #[tokio::test]
    async fn ewma_velocity_limit_trips_circuit_breaker() {
        let state = AppState::new();
        state
            .thresholds
            .set("financial:max_ewma_velocity".to_string(), 60.0);

        let sequence = [10.0, 20.0, 50.0, 200.0];
        let mut final_resp = None;
        for amount in sequence {
            let mut drift = None;
            final_resp = Some(
                state
                    .validate_inner(
                        &ValidationRequest {
                            agent_id: "agent-velocity".to_string(),
                            api_key: String::new(),
                            action: ActionPayload {
                                action_type: "transfer".to_string(),
                                amount: Some(amount),
                                currency: Some("USD".to_string()),
                                recipient: Some("merchant-2".to_string()),
                                endpoint: None,
                                method: None,
                                device_id: None,
                                command: None,
                                delegation_depth: None,
                                data_source: Default::default(),
                            },
                            session_id: None,
                            metadata: serde_json::Value::Null,
                        },
                        &mut drift,
                    )
                    .await,
            );
        }

        let resp = final_resp.expect("response should exist");
        assert_eq!(resp.decision, Decision::CircuitBreak);
        assert_eq!(resp.policy.as_deref(), Some("EWMA_VELOCITY_LIMIT"));
    }

    #[tokio::test]
    async fn learning_loop_generates_deterministic_recommendation() {
        let state = AppState::new();
        let tx1 = Uuid::new_v4().to_string();
        let tx2 = Uuid::new_v4().to_string();
        let tx3 = Uuid::new_v4().to_string();

        state.review_queue.push(ReviewEntry {
            transaction_id: tx1.clone(),
            agent_id: "agent-a".to_string(),
            decision: "DENY".to_string(),
            policy_code: Some("TOKEN_RATE_EXCEEDED".to_string()),
            reason: None,
            created_at: Utc::now(),
            outcome: Some(review::ReviewOutcome {
                verdict: "FALSE_POSITIVE".to_string(),
                impact_usd: None,
                reviewer_id: Some("r1".to_string()),
                notes: None,
                reviewed_at: Utc::now(),
            }),
        });
        state.review_queue.push(ReviewEntry {
            transaction_id: tx2,
            agent_id: "agent-b".to_string(),
            decision: "DENY".to_string(),
            policy_code: Some("TOKEN_RATE_EXCEEDED".to_string()),
            reason: None,
            created_at: Utc::now(),
            outcome: Some(review::ReviewOutcome {
                verdict: "FALSE_POSITIVE".to_string(),
                impact_usd: None,
                reviewer_id: Some("r1".to_string()),
                notes: None,
                reviewed_at: Utc::now(),
            }),
        });
        state.review_queue.push(ReviewEntry {
            transaction_id: tx3,
            agent_id: "agent-c".to_string(),
            decision: "DENY".to_string(),
            policy_code: Some("TOKEN_RATE_EXCEEDED".to_string()),
            reason: None,
            created_at: Utc::now(),
            outcome: Some(review::ReviewOutcome {
                verdict: "TRUE_POSITIVE".to_string(),
                impact_usd: None,
                reviewer_id: Some("r1".to_string()),
                notes: None,
                reviewed_at: Utc::now(),
            }),
        });

        let report = state.run_learning_loop_once(24).await;
        assert_eq!(report.generated, 1);
        assert_eq!(report.considered_outcomes, 3);

        let recs = state.list_recommendations(Some("pending")).await;
        assert_eq!(recs.len(), 1);
        let rec = &recs[0];
        assert_eq!(rec.threshold_key, "resource:max_tokens_per_minute");
        assert_eq!(rec.sample_size, 3);
        assert_eq!(rec.false_positive_count, 2);
        assert_eq!(rec.true_positive_count, 1);
        assert_eq!(
            rec.recommendation_key,
            "resource:max_tokens_per_minute:3:2:1"
        );
    }

    #[tokio::test]
    async fn approved_variant_can_be_reverted() {
        let state = AppState::new();
        let recommendation_id = 42;

        state.recommendations.insert(
            recommendation_id,
            AdjustmentRecommendation {
                id: recommendation_id,
                recommendation_key: "resource:max_tokens_per_minute:3:2:1".to_string(),
                threshold_key: "resource:max_tokens_per_minute".to_string(),
                current_threshold: 100_000.0,
                proposed_threshold: 110_000.0,
                sample_size: 3,
                false_positive_count: 2,
                true_positive_count: 1,
                confidence: 0.5,
                rationale: "test".to_string(),
                status: "pending".to_string(),
                trigger_outcome_id: Some(7),
                trigger_transaction_id: None,
                decided_by: None,
                decision_notes: None,
                variant_id: None,
                applied_adjustment_id: None,
            },
        );

        let approved = state
            .approve_recommendation(
                recommendation_id,
                ApproveRecommendationRequest {
                    reviewer_id: "admin-1".to_string(),
                    notes: Some("roll out to canary agents".to_string()),
                    agent_ids: vec!["agent-canary".to_string()],
                    apply_as_variant: true,
                },
            )
            .await
            .expect("approve should succeed");

        assert_eq!(approved.status, "applied");
        assert!(approved.variant_id.is_some());

        let effective = state.thresholds.effective_thresholds("agent-canary");
        assert_eq!(
            effective.get("resource:max_tokens_per_minute").copied(),
            Some(110_000.0)
        );

        let reverted = state
            .revert_recommendation(
                recommendation_id,
                RevertRecommendationRequest {
                    reviewer_id: "admin-2".to_string(),
                    notes: Some("rollback test".to_string()),
                },
            )
            .await
            .expect("revert should succeed");

        assert_eq!(reverted.status, "reverted");
        let effective_after = state.thresholds.effective_thresholds("agent-canary");
        assert!(
            !effective_after.contains_key("resource:max_tokens_per_minute"),
            "variant threshold must be removed after revert"
        );
    }
}
