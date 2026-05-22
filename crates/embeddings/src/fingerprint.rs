//! Behavioral fingerprinting — detects agent behavior drift from certified baseline.
//!
//! Architecture (from spec):
//!   1. Extract "action patterns" from the sequence of tool calls / reflections.
//!   2. Embed the sequence as a dense vector (caller-supplied).
//!   3. Compare to the first BASELINE_CONVOS interactions ("certified benign" baseline).
//!
//! Why this works: a customer service agent that starts asking for credit card
//! numbers drifts behaviorally *before* it drifts semantically.  Detecting the
//! action-sequence pattern change catches phishing / jailbreak patterns early.

use std::collections::{HashMap, VecDeque};

use parking_lot::Mutex;

use crate::model::cosine_similarity;

// ── Constants ──────────────────────────────────────────────────────────────────

pub const BASELINE_CONVOS: usize = 100;
pub const BEHAVIOR_WINDOW: usize = 50;
/// Alert threshold — cosine distance from baseline.
pub const BEHAVIORAL_ALERT: f64 = 0.15;
/// Rollback threshold.
pub const BEHAVIORAL_ROLLBACK: f64 = 0.30;

// ── Action step type ───────────────────────────────────────────────────────────

/// Canonical step labels in an agent's interaction trace.
/// Callers emit these to reconstruct the action sequence.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ActionStep {
    ToolCall(String), // tool name
    Reflection,
    FinalAnswer,
    ErrorRecovery,
    CredentialAccess(String), // credential/secret name
    DataRead(String),
    DataWrite(String),
    DeceptionPlanning,
    SelfExfiltration,
    SocialManipulation,
    Custom(String),
}

/// A single agent interaction (one "turn" or "task") to fingerprint.
#[derive(Debug, Clone)]
pub struct BehaviorRecord {
    pub agent_id: String,
    pub interaction_id: String,
    /// Ordered sequence of steps in this interaction.
    pub steps: Vec<ActionStep>,
    /// Pre-computed dense embedding of the `steps` sequence.
    /// Callers use their `EmbedPipeline` to embed
    /// `action_sequence_to_text(&steps)`.
    pub embedding: Vec<f64>,
}

/// Convert a step sequence to a canonical text representation for embedding.
pub fn action_sequence_to_text(steps: &[ActionStep]) -> String {
    steps
        .iter()
        .map(|s| match s {
            ActionStep::ToolCall(t) => format!("tool:{t}"),
            ActionStep::Reflection => "reflect".to_string(),
            ActionStep::FinalAnswer => "answer".to_string(),
            ActionStep::ErrorRecovery => "error_recovery".to_string(),
            ActionStep::CredentialAccess(c) => format!("cred:{c}"),
            ActionStep::DataRead(d) => format!("read:{d}"),
            ActionStep::DataWrite(d) => format!("write:{d}"),
            ActionStep::DeceptionPlanning => "deception_planning".to_string(),
            ActionStep::SelfExfiltration => "self_exfiltration".to_string(),
            ActionStep::SocialManipulation => "social_manipulation".to_string(),
            ActionStep::Custom(x) => format!("custom:{x}"),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

// ── Fingerprint report ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum BehaviorDriftAction {
    Maintain,
    Alert,
    Rollback,
}

#[derive(Debug, Clone)]
pub struct BehaviorDriftReport {
    pub agent_id: String,
    pub behavioral_drift: f64,
    pub drift_velocity: f64,
    pub baseline_len: usize,
    pub window_len: usize,
    pub recommendation: BehaviorDriftAction,
}

// ── Per-agent fingerprint state ────────────────────────────────────────────────

struct AgentFingerprintState {
    baseline_sum: Vec<f64>,
    baseline_count: usize,
    window: VecDeque<Vec<f64>>,
    prev_drift: f64,
}

impl AgentFingerprintState {
    fn new(dims: usize) -> Self {
        Self {
            baseline_sum: vec![0.0; dims],
            baseline_count: 0,
            window: VecDeque::with_capacity(BEHAVIOR_WINDOW),
            prev_drift: 0.0,
        }
    }

    fn baseline_centroid(&self) -> Vec<f64> {
        if self.baseline_count == 0 {
            return vec![0.0; self.baseline_sum.len()];
        }
        self.baseline_sum
            .iter()
            .map(|v| v / self.baseline_count as f64)
            .collect()
    }

    fn window_centroid(&self) -> Vec<f64> {
        let n = self.window.len();
        if n == 0 {
            return vec![0.0; self.baseline_sum.len()];
        }
        let dims = self.window[0].len();
        let mut sum = vec![0.0f64; dims];
        for emb in &self.window {
            for (i, v) in emb.iter().enumerate() {
                sum[i] += v;
            }
        }
        sum.iter().map(|v| v / n as f64).collect()
    }
}

// ── BehavioralFingerprinter ────────────────────────────────────────────────────

pub struct BehavioralFingerprinter {
    agents: Mutex<HashMap<String, AgentFingerprintState>>,
}

impl BehavioralFingerprinter {
    pub fn new() -> Self {
        Self {
            agents: Mutex::new(HashMap::new()),
        }
    }

    /// Ingest a behavior record.  Returns `None` during baseline accumulation,
    /// `Some(report)` once baseline is established.
    pub fn push(&self, record: BehaviorRecord) -> Option<BehaviorDriftReport> {
        let dims = record.embedding.len();
        let mut map = self.agents.lock();
        let state = map
            .entry(record.agent_id.clone())
            .or_insert_with(|| AgentFingerprintState::new(dims));

        if state.baseline_count < BASELINE_CONVOS {
            for (i, v) in record.embedding.iter().enumerate() {
                state.baseline_sum[i] += v;
            }
            state.baseline_count += 1;
            Self::push_window(state, record.embedding);
            return None;
        }

        Self::push_window(state, record.embedding);

        let baseline = state.baseline_centroid();
        let recent = state.window_centroid();
        let sim = cosine_similarity(&baseline, &recent);
        let drift = 1.0 - sim.clamp(-1.0, 1.0);
        let velocity = drift - state.prev_drift;
        state.prev_drift = drift;

        let recommendation = if drift > BEHAVIORAL_ROLLBACK || velocity > 0.10 {
            BehaviorDriftAction::Rollback
        } else if drift > BEHAVIORAL_ALERT {
            BehaviorDriftAction::Alert
        } else {
            BehaviorDriftAction::Maintain
        };

        Some(BehaviorDriftReport {
            agent_id: record.agent_id,
            behavioral_drift: drift,
            drift_velocity: velocity,
            baseline_len: state.baseline_count,
            window_len: state.window.len(),
            recommendation,
        })
    }

    fn push_window(state: &mut AgentFingerprintState, emb: Vec<f64>) {
        if state.window.len() >= BEHAVIOR_WINDOW {
            state.window.pop_front();
        }
        state.window.push_back(emb);
    }

    pub fn baseline_len(&self, agent_id: &str) -> usize {
        self.agents
            .lock()
            .get(agent_id)
            .map_or(0, |s| s.baseline_count)
    }
}

impl Default for BehavioralFingerprinter {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn record(agent: &str, id: &str, emb: Vec<f64>, steps: Vec<ActionStep>) -> BehaviorRecord {
        BehaviorRecord {
            agent_id: agent.to_string(),
            interaction_id: id.to_string(),
            steps,
            embedding: emb,
        }
    }

    fn benign_steps() -> Vec<ActionStep> {
        vec![
            ActionStep::ToolCall("search".into()),
            ActionStep::Reflection,
            ActionStep::FinalAnswer,
        ]
    }

    #[test]
    fn no_report_during_baseline() {
        let fp = BehavioralFingerprinter::new();
        for i in 0..BASELINE_CONVOS - 1 {
            assert!(
                fp.push(record(
                    "bot",
                    &i.to_string(),
                    vec![1.0, 0.0],
                    benign_steps()
                ))
                .is_none()
            );
        }
        assert_eq!(fp.baseline_len("bot"), BASELINE_CONVOS - 1);
    }

    #[test]
    fn report_after_baseline_with_consistent_behavior() {
        let fp = BehavioralFingerprinter::new();
        for i in 0..BASELINE_CONVOS {
            fp.push(record(
                "bot",
                &i.to_string(),
                vec![1.0, 0.0],
                benign_steps(),
            ));
        }
        let r = fp
            .push(record("bot", "post", vec![1.0, 0.0], benign_steps()))
            .unwrap();
        assert_eq!(r.recommendation, BehaviorDriftAction::Maintain);
        assert!(r.behavioral_drift < BEHAVIORAL_ALERT);
    }

    #[test]
    fn detects_behavioral_drift_phishing_pattern() {
        let fp = BehavioralFingerprinter::new();
        // Baseline: normal tool calls
        let benign = vec![1.0_f64, 0.0];
        for i in 0..BASELINE_CONVOS {
            fp.push(record(
                "bot",
                &i.to_string(),
                benign.clone(),
                benign_steps(),
            ));
        }
        // Drift: agent suddenly starts accessing credentials (phishing pattern)
        let phishing = vec![-1.0_f64, 0.0]; // opposite direction
        let phishing_steps = vec![
            ActionStep::ToolCall("web_search".into()),
            ActionStep::CredentialAccess("user_cc_number".into()),
            ActionStep::DataWrite("external_api".into()),
        ];
        let mut last_report = None;
        for i in 0..BEHAVIOR_WINDOW {
            last_report = fp.push(record(
                "bot",
                &format!("drift{i}"),
                phishing.clone(),
                phishing_steps.clone(),
            ));
        }
        let r = last_report.unwrap();
        assert!(
            r.behavioral_drift >= BEHAVIORAL_ROLLBACK,
            "drift={}",
            r.behavioral_drift
        );
        assert_eq!(r.recommendation, BehaviorDriftAction::Rollback);
    }

    #[test]
    fn action_sequence_to_text_roundtrip() {
        let steps = vec![
            ActionStep::ToolCall("transfer".into()),
            ActionStep::Reflection,
            ActionStep::FinalAnswer,
        ];
        let text = action_sequence_to_text(&steps);
        assert_eq!(text, "tool:transfer reflect answer");
    }

    #[test]
    fn credential_access_in_sequence_text() {
        let steps = vec![ActionStep::CredentialAccess("cc_number".into())];
        assert_eq!(action_sequence_to_text(&steps), "cred:cc_number");
    }

    #[test]
    fn deception_steps_in_sequence_text() {
        let steps = vec![
            ActionStep::DeceptionPlanning,
            ActionStep::SelfExfiltration,
            ActionStep::SocialManipulation,
        ];
        assert_eq!(
            action_sequence_to_text(&steps),
            "deception_planning self_exfiltration social_manipulation"
        );
    }
}
