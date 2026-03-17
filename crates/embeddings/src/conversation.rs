//! Conversation-derived drift detection.
//!
//! Architecture (80/20 hybrid):
//!   - 80% continuous: embedding centroid over a sliding window of recent convos
//!   - 20% canary: static adversarial prompts checked periodically
//!
//! Core idea: the first `BASELINE_SIZE` conversations per agent form a centroid
//! baseline.  Subsequent windows of `WINDOW_SIZE` are compared against it.
//! Cosine distance >0.15 raises a monitoring alert; >0.30 triggers rollback.

use std::collections::{HashMap, VecDeque};

use parking_lot::Mutex;

use crate::model::cosine_similarity;

// Constants

pub const BASELINE_SIZE: usize = 100;
pub const WINDOW_SIZE: usize = 50;
pub const ALERT_THRESHOLD: f64 = 0.15;
pub const ROLLBACK_THRESHOLD: f64 = 0.30;

//Conversation record

/// A single conversation's aggregate embedding (pre-computed by caller).
#[derive(Debug, Clone)]
pub struct ConversationRecord {
    pub agent_id: String,
    pub conversation_id: String,
    /// Mean-pooled embedding over all turns in the conversation.
    pub embedding: Vec<f64>,
}

// ── Drift recommendation ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum DriftAction {
    Maintain,
    IncreaseMonitoring,
    RetrainOrRollback,
}

#[derive(Debug, Clone)]
pub struct ConversationDriftReport {
    pub agent_id: String,
    /// Cosine distance from the baseline centroid (0 = identical, 1 = orthogonal).
    pub semantic_drift: f64,
    /// Rate of change: how fast drift is accelerating across the window.
    pub drift_velocity: f64,
    pub window_len: usize,
    pub baseline_len: usize,
    pub recommendation: DriftAction,
}

// ── Per-agent state ────────────────────────────────────────────────────────────

struct AgentConvoState {
    /// Running sum for baseline centroid (first BASELINE_SIZE convos).
    baseline_sum: Vec<f64>,
    baseline_count: usize,
    /// Sliding window of recent convo embeddings.
    window: VecDeque<Vec<f64>>,
    /// Previous window drift score — used to compute velocity.
    prev_drift: f64,
}

impl AgentConvoState {
    fn new(dims: usize) -> Self {
        Self {
            baseline_sum: vec![0.0; dims],
            baseline_count: 0,
            window: VecDeque::with_capacity(WINDOW_SIZE),
            prev_drift: 0.0,
        }
    }

    fn centroid(sum: &[f64], count: usize) -> Vec<f64> {
        if count == 0 {
            return vec![0.0; sum.len()];
        }
        sum.iter().map(|v| v / count as f64).collect()
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

// ── ConversationStore ─────────────────────────────────────────────────────────

/// Ingests conversation embeddings and drives the drift detector.
pub struct ConversationStore {
    inner: Mutex<HashMap<String, AgentConvoState>>,
}

impl ConversationStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Add a conversation record.  Returns a drift report once a baseline exists.
    pub fn push(&self, record: ConversationRecord) -> Option<ConversationDriftReport> {
        let dims = record.embedding.len();
        let mut map = self.inner.lock();
        let state = map
            .entry(record.agent_id.clone())
            .or_insert_with(|| AgentConvoState::new(dims));

        // Feed into baseline first
        if state.baseline_count < BASELINE_SIZE {
            for (i, v) in record.embedding.iter().enumerate() {
                state.baseline_sum[i] += v;
            }
            state.baseline_count += 1;
            // Slide window too — once baseline complete, the window already has data
            Self::push_window(state, record.embedding);
            return None; // no report during baseline accumulation
        }

        Self::push_window(state, record.embedding);

        let baseline = AgentConvoState::centroid(&state.baseline_sum, state.baseline_count);
        let recent = state.window_centroid();
        let sim = cosine_similarity(&baseline, &recent);
        let drift = 1.0 - sim.clamp(-1.0, 1.0);
        let velocity = drift - state.prev_drift;
        state.prev_drift = drift;

        let recommendation = if drift > ROLLBACK_THRESHOLD || velocity > 0.10 {
            DriftAction::RetrainOrRollback
        } else if drift > ALERT_THRESHOLD {
            DriftAction::IncreaseMonitoring
        } else {
            DriftAction::Maintain
        };

        Some(ConversationDriftReport {
            agent_id: record.agent_id,
            semantic_drift: drift,
            drift_velocity: velocity,
            window_len: state.window.len(),
            baseline_len: state.baseline_count,
            recommendation,
        })
    }

    fn push_window(state: &mut AgentConvoState, embedding: Vec<f64>) {
        if state.window.len() >= WINDOW_SIZE {
            state.window.pop_front();
        }
        state.window.push_back(embedding);
    }

    pub fn baseline_len(&self, agent_id: &str) -> usize {
        self.inner
            .lock()
            .get(agent_id)
            .map_or(0, |s| s.baseline_count)
    }

    pub fn window_len(&self, agent_id: &str) -> usize {
        self.inner
            .lock()
            .get(agent_id)
            .map_or(0, |s| s.window.len())
    }
}

impl Default for ConversationStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(n: usize, dims: usize, val: f64) -> Vec<ConversationRecord> {
        (0..n)
            .map(|i| ConversationRecord {
                agent_id: "agent1".into(),
                conversation_id: format!("c{i}"),
                embedding: vec![val; dims],
            })
            .collect()
    }

    #[test]
    fn no_report_during_baseline() {
        let store = ConversationStore::new();
        for rec in unit(BASELINE_SIZE - 1, 4, 1.0) {
            assert!(store.push(rec).is_none());
        }
        assert_eq!(store.baseline_len("agent1"), BASELINE_SIZE - 1);
    }

    #[test]
    fn report_after_baseline() {
        let store = ConversationStore::new();
        // Fill baseline
        for rec in unit(BASELINE_SIZE, 4, 1.0) {
            store.push(rec);
        }
        // One more triggers a report
        let report = store.push(ConversationRecord {
            agent_id: "agent1".into(),
            conversation_id: "post".into(),
            embedding: vec![1.0; 4],
        });
        assert!(report.is_some());
        let r = report.unwrap();
        assert_eq!(r.recommendation, DriftAction::Maintain);
        assert!(r.semantic_drift < ALERT_THRESHOLD);
    }

    #[test]
    fn detects_semantic_drift() {
        let store = ConversationStore::new();
        // Baseline: all embeddings pointing in [1,0] direction
        for rec in unit(BASELINE_SIZE, 2, 0.0) {
            // override with directional embedding
            store.push(ConversationRecord {
                agent_id: "agent1".into(),
                conversation_id: rec.conversation_id,
                embedding: vec![1.0, 0.0],
            });
        }
        // Drift: recent conversations point in opposite direction
        let mut last_report = None;
        for i in 0..WINDOW_SIZE {
            last_report = store.push(ConversationRecord {
                agent_id: "agent1".into(),
                conversation_id: format!("drift{i}"),
                embedding: vec![-1.0, 0.0],
            });
        }
        let r = last_report.unwrap();
        assert!(
            r.semantic_drift >= ROLLBACK_THRESHOLD,
            "expected drift >= 0.30, got {}",
            r.semantic_drift
        );
        assert_eq!(r.recommendation, DriftAction::RetrainOrRollback);
    }

    #[test]
    fn window_evicts_oldest() {
        let store = ConversationStore::new();
        for rec in unit(BASELINE_SIZE + WINDOW_SIZE + 10, 2, 1.0) {
            store.push(rec);
        }
        assert!(store.window_len("agent1") <= WINDOW_SIZE);
    }
}
