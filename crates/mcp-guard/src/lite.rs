//! Standalone/lite MCP inspect path for demo and `--profile standalone`.
//! Pattern firewall + baseline inventory only (no Postgres policies/drift DB).

use std::collections::HashMap;

use aho_corasick::AhoCorasick;
use haltchain_merkle::MerkleAccumulator;
use haltchain_signing::{DecisionEnvelope, SigningService};
use serde::Serialize;
use uuid::Uuid;

use crate::types::{Decision, McpToolCall};

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
        let content = std::fs::read_to_string(&path).ok()?;
        let parsed: BaselineInventoryFile = serde_json::from_str(&content).ok()?;
        let mut baseline = Self {
            global_patterns: parsed.approved_tools,
            org_patterns: HashMap::new(),
            agent_patterns: HashMap::new(),
        };
        for (org, scope) in parsed.orgs {
            if let Ok(org_id) = Uuid::parse_str(&org) {
                baseline.org_patterns.insert(org_id, scope.approved_tools);
            }
        }
        for (agent, scope) in parsed.agents {
            if let Ok(agent_id) = Uuid::parse_str(&agent) {
                baseline.agent_patterns.insert(agent_id, scope.approved_tools);
            }
        }
        Some(baseline)
    }

    fn is_approved(&self, call: &McpToolCall) -> bool {
        if let Some(patterns) = self.agent_patterns.get(&call.agent_id) {
            return pattern_matches(patterns, &call.tool_name);
        }
        if let Some(patterns) = self.org_patterns.get(&call.org_id) {
            return pattern_matches(patterns, &call.tool_name);
        }
        if !self.global_patterns.is_empty() {
            return pattern_matches(&self.global_patterns, &call.tool_name);
        }
        true
    }
}

fn pattern_matches(patterns: &[String], tool_name: &str) -> bool {
    let name = tool_name.to_ascii_lowercase();
    patterns.iter().any(|p| {
        let pat = p.to_ascii_lowercase();
        if pat.contains('*') {
            wildcard_match(&name, &pat)
        } else {
            name == pat
        }
    })
}

fn wildcard_match(value: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return value.ends_with(suffix);
    }
    value == pattern
}

fn decision_text(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow => "ALLOW",
        Decision::Block { .. } => "BLOCK",
        Decision::Quarantine { .. } => "QUARANTINE",
    }
}

fn args_blob(args: &serde_json::Value) -> String {
    args.to_string().to_ascii_lowercase()
}

#[derive(Debug, Clone, Serialize)]
pub struct McpInspectProof {
    pub envelope: DecisionEnvelope,
    pub merkle_root: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LiteInspectResult {
    pub decision: Decision,
    pub latency_us: u64,
    pub proof: McpInspectProof,
}

pub struct LiteMcpGuard {
    pattern_firewall: AhoCorasick,
    baseline: Option<BaselineInventory>,
    signing: SigningService,
    merkle: MerkleAccumulator,
}

impl LiteMcpGuard {
    pub fn from_env() -> Self {
        let extra = std::env::var("HALTCHAIN_MCP_BLOCKED_TOOLS").unwrap_or_default();
        let mut patterns = vec![
            "exec", "shell", "sudo", "curl", "bash", "rm -rf", "drop database",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
        for p in extra.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            patterns.push(p.to_ascii_lowercase());
        }
        Self {
            pattern_firewall: AhoCorasick::new(patterns).expect("lite pattern set"),
            baseline: BaselineInventory::from_env(),
            signing: SigningService::generate(),
            merkle: MerkleAccumulator::new(),
        }
    }

    pub fn inspect(&mut self, call: &McpToolCall) -> LiteInspectResult {
        let t0 = std::time::Instant::now();
        let tool_lc = call.tool_name.to_ascii_lowercase();
        let args_lc = args_blob(&call.tool_args);

        let decision = if self.pattern_firewall.find(&tool_lc).is_some()
            || self.pattern_firewall.find(&args_lc).is_some()
        {
            Decision::Block {
                reason: "known-poisoned-tool".to_string(),
                intent: Some("malicious_execution".to_string()),
            }
        } else if let Some(bl) = &self.baseline {
            if !bl.is_approved(call) {
                Decision::Block {
                    reason: "unapproved-tool-inventory".to_string(),
                    intent: Some("unknown".to_string()),
                }
            } else {
                Decision::Allow
            }
        } else {
            Decision::Allow
        };

        let txn = Uuid::new_v4().to_string();
        let ts = chrono::Utc::now().to_rfc3339();
        let envelope = self.signing.sign_decision(
            &txn,
            decision_text(&decision),
            &call.agent_id.to_string(),
            &ts,
            "demo-lite",
        );
        self.merkle
            .push(&txn, &ts, decision_text(&decision), &envelope.content_hash);
        let merkle_root = self.merkle.status().root_hex;
        let latency_us = t0.elapsed().as_micros() as u64;

        LiteInspectResult {
            decision,
            latency_us,
            proof: McpInspectProof {
                envelope,
                merkle_root: merkle_root.unwrap_or_default(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_exec_shell_without_baseline() {
        let mut g = LiteMcpGuard::from_env();
        let call = McpToolCall {
            agent_id: Uuid::new_v4(),
            org_id: Uuid::new_v4(),
            tool_name: "exec_shell".to_string(),
            tool_args: serde_json::json!({"cmd": "rm -rf /"}),
            context_hash: "demo".to_string(),
            timestamp: 0,
        };
        let out = g.inspect(&call);
        assert!(matches!(out.decision, Decision::Block { .. }));
        assert!(!out.proof.merkle_root.is_empty());
    }
}
