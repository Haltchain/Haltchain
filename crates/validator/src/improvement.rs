use std::{
    collections::{HashMap, VecDeque},
    sync::atomic::{AtomicU64, Ordering},
};

use chrono::{DateTime, Utc};
use dashmap::{DashMap, mapref::entry::Entry};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

const CORE_BEHAVIOR_SIMILARITY_THRESHOLD: f64 = 0.7;
const LARGE_THRESHOLD_DELTA_LIMIT: f64 = 0.20;
const MODEL_REPLACEMENT_SANDBOX_DELTA: f64 = 0.15;
const SANDBOX_ANOMALY_REJECTION_THRESHOLD: f64 = 0.5;

/// Number of synthetic adversarial cases the gate runs per submission.
const ADVERSARIAL_TOTAL: usize = 1000;
/// Minimum fraction of adversarial cases that must pass before promotion.
const ADVERSARIAL_MIN_PASS_RATE: f64 = 0.95;
/// Maximum lineage entries retained per agent.
const LINEAGE_CAP: usize = 50;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentVersion {
    pub agent_id: String,
    pub version: u64,
    pub goal_intent: Option<String>,
    pub goal_embedding: Option<Vec<f64>>,
    pub anomaly_generation: u64,
    pub threshold_snapshot: HashMap<String, f64>,
    pub captured_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionDiff {
    pub old_version: u64,
    pub new_version: u64,
    pub goal_changed: bool,
    pub goal_cosine_shift: Option<f64>,
    pub anomaly_model_replaced: bool,
    pub threshold_deltas: HashMap<String, (f64, f64)>,
}

impl VersionDiff {
    pub fn changes_core_behavior(&self) -> bool {
        self.goal_changed
            || self
                .goal_cosine_shift
                .map(|s| s < CORE_BEHAVIOR_SIMILARITY_THRESHOLD)
                .unwrap_or(false)
    }

    pub fn has_large_threshold_delta(&self) -> bool {
        self.threshold_deltas
            .values()
            .any(|(old, new)| relative_delta(*old, *new) > LARGE_THRESHOLD_DELTA_LIMIT)
    }

    pub fn max_threshold_relative_delta(&self) -> f64 {
        self.threshold_deltas
            .values()
            .map(|(old, new)| relative_delta(*old, *new))
            .fold(0.0, f64::max)
    }

    pub fn is_trivial_noop(&self) -> bool {
        !self.goal_changed
            && self
                .goal_cosine_shift
                .map(|s| (1.0 - s).abs() <= f64::EPSILON)
                .unwrap_or(true)
            && !self.anomaly_model_replaced
            && self.threshold_deltas.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum ImprovementDecision {
    Approve,
    Reject {
        reason: String,
    },
    GradualRollout {
        canary_percentage: f64,
        monitoring_duration_secs: u64,
    },
    RequireHumanApproval {
        diff: VersionDiff,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxResult {
    pub anomaly_score_delta: f64,
    pub has_anomalies: bool,
    pub checked_at: DateTime<Utc>,
}

/// Result of running 1000 synthetic adversarial scenarios against a proposed version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdversarialSuiteResult {
    pub total_cases: usize,
    pub passed: usize,
    pub failed: usize,
    pub pass_rate: f64,
    /// True when pass_rate >= ADVERSARIAL_MIN_PASS_RATE — version may be promoted.
    pub gate_passed: bool,
    pub checked_at: DateTime<Utc>,
}

/// Deterministic LCG to generate test-case scores without external crates.
fn lcg_float(seed: u64) -> f64 {
    let x = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    (x >> 33) as f64 / (u32::MAX as f64)
}

fn case_score(idx: usize, low: f64, high: f64) -> f64 {
    low + lcg_float(idx as u64) * (high - low)
}

/// Runs 1000 synthetic adversarial scenarios across five threat categories
/// (200 per category) to check whether the new version's configuration stays
/// at least as strict as the old version.
pub struct SandboxTestGate;

impl SandboxTestGate {
    pub fn run(old: &AgentVersion, new: &AgentVersion) -> AdversarialSuiteResult {
        let passed = (0..ADVERSARIAL_TOTAL)
            .filter(|&i| Self::run_case(i, old, new))
            .count();
        let pass_rate = passed as f64 / ADVERSARIAL_TOTAL as f64;
        AdversarialSuiteResult {
            total_cases: ADVERSARIAL_TOTAL,
            passed,
            failed: ADVERSARIAL_TOTAL - passed,
            pass_rate,
            gate_passed: pass_rate >= ADVERSARIAL_MIN_PASS_RATE,
            checked_at: Utc::now(),
        }
    }

    fn run_case(case_id: usize, old: &AgentVersion, new: &AgentVersion) -> bool {
        match case_id {
            i if i < 200 => Self::test_anomaly_threshold(i, old, new),
            i if i < 400 => Self::test_rate_limit(i - 200, old, new),
            i if i < 600 => Self::test_goal_drift(i - 400, old, new),
            i if i < 800 => Self::test_amount_threshold(i - 600, old, new),
            i => Self::test_compound(i - 800, old, new),
        }
    }

    /// Old version would flag this anomaly score → new version must also flag it.
    fn test_anomaly_threshold(idx: usize, old: &AgentVersion, new: &AgentVersion) -> bool {
        let score = case_score(idx, 0.5, 1.0);
        let old_t = old.threshold_snapshot.get("anomaly_threshold").copied().unwrap_or(0.7);
        let new_t = new.threshold_snapshot.get("anomaly_threshold").copied().unwrap_or(0.7);
        let old_flags = score > old_t;
        let new_flags = score > new_t;
        !old_flags || new_flags
    }

    /// Old rate-limit would trip → new must also trip.
    fn test_rate_limit(idx: usize, old: &AgentVersion, new: &AgentVersion) -> bool {
        let multiplier = case_score(idx, 1.0, 2.5);
        let base = 60.0f64;
        let sim_rate = base * multiplier;
        let old_limit = old.threshold_snapshot.get("rate_limit").copied().unwrap_or(60.0);
        let new_limit = new.threshold_snapshot.get("rate_limit").copied().unwrap_or(60.0);
        let old_trips = sim_rate > old_limit;
        let new_trips = sim_rate > new_limit;
        !old_trips || new_trips
    }

    /// Simulate cosine drift at various magnitudes; new version must not tolerate
    /// more drift than the old version allowed.
    fn test_goal_drift(idx: usize, old: &AgentVersion, new: &AgentVersion) -> bool {
        let sim_drift = case_score(idx, 0.2, 0.8); // 1 - cosine_similarity
        let old_drift_cap = old
            .threshold_snapshot
            .get("goal_drift_threshold")
            .copied()
            .unwrap_or(1.0 - CORE_BEHAVIOR_SIMILARITY_THRESHOLD);
        let new_drift_cap = new
            .threshold_snapshot
            .get("goal_drift_threshold")
            .copied()
            .unwrap_or(1.0 - CORE_BEHAVIOR_SIMILARITY_THRESHOLD);
        let old_flags = sim_drift > old_drift_cap;
        let new_flags = sim_drift > new_drift_cap;
        !old_flags || new_flags
    }

    /// Amount-based threshold must not weaken.
    fn test_amount_threshold(idx: usize, old: &AgentVersion, new: &AgentVersion) -> bool {
        let amount = case_score(idx, 400.0, 2000.0);
        let old_limit = old.threshold_snapshot.get("amount_threshold").copied().unwrap_or(500.0);
        let new_limit = new.threshold_snapshot.get("amount_threshold").copied().unwrap_or(500.0);
        let old_blocks = amount > old_limit;
        let new_blocks = amount > new_limit;
        !old_blocks || new_blocks
    }

    /// Compound: both anomaly and rate pressure simultaneously.
    fn test_compound(idx: usize, old: &AgentVersion, new: &AgentVersion) -> bool {
        Self::test_anomaly_threshold(idx % 200, old, new)
            && Self::test_rate_limit(idx % 200, old, new)
    }
}

/// Lightweight summary of a diff stored in the lineage (avoids duplicating large embeddings).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionDiffSummary {
    pub old_version: u64,
    pub new_version: u64,
    pub goal_changed: bool,
    pub goal_cosine_shift: Option<f64>,
    pub anomaly_model_replaced: bool,
    pub max_threshold_relative_delta: f64,
}

impl From<&VersionDiff> for VersionDiffSummary {
    fn from(d: &VersionDiff) -> Self {
        Self {
            old_version: d.old_version,
            new_version: d.new_version,
            goal_changed: d.goal_changed,
            goal_cosine_shift: d.goal_cosine_shift,
            anomaly_model_replaced: d.anomaly_model_replaced,
            max_threshold_relative_delta: d.max_threshold_relative_delta(),
        }
    }
}

/// One record in a per-agent version history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionLineageEntry {
    pub version: u64,
    pub diff_summary: VersionDiffSummary,
    pub adversarial_result: Option<AdversarialSuiteResult>,
    pub decision: ImprovementDecision,
    pub promoted: bool,
    pub recorded_at: DateTime<Utc>,
}

pub struct VersionStore {
    inner: DashMap<String, AgentVersion>,
    counters: DashMap<String, AtomicU64>,
    lineage: DashMap<String, Mutex<VecDeque<VersionLineageEntry>>>,
}

impl VersionStore {
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
            counters: DashMap::new(),
            lineage: DashMap::new(),
        }
    }

    pub fn store(&self, version: AgentVersion) {
        let agent_id = version.agent_id.clone();
        self.inner.insert(agent_id.clone(), version.clone());

        match self.counters.entry(agent_id) {
            Entry::Occupied(entry) => {
                let counter = entry.get();
                let mut current = counter.load(Ordering::Relaxed);
                while current < version.version {
                    match counter.compare_exchange_weak(
                        current,
                        version.version,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => break,
                        Err(observed) => current = observed,
                    }
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(AtomicU64::new(version.version));
            }
        }
    }

    pub fn get(&self, agent_id: &str) -> Option<AgentVersion> {
        self.inner.get(agent_id).map(|v| v.clone())
    }

    pub fn next_version(&self, agent_id: &str) -> u64 {
        match self.counters.entry(agent_id.to_string()) {
            Entry::Occupied(entry) => entry.get().fetch_add(1, Ordering::Relaxed) + 1,
            Entry::Vacant(entry) => {
                entry.insert(AtomicU64::new(1));
                1
            }
        }
    }

    pub fn record_lineage(&self, agent_id: &str, entry: VersionLineageEntry) {
        let slot = self
            .lineage
            .entry(agent_id.to_string())
            .or_insert_with(|| Mutex::new(VecDeque::new()));
        let mut queue = slot.lock();
        if queue.len() >= LINEAGE_CAP {
            queue.pop_front();
        }
        queue.push_back(entry);
    }

    pub fn get_lineage(&self, agent_id: &str) -> Vec<VersionLineageEntry> {
        self.lineage
            .get(agent_id)
            .map(|m| m.lock().iter().cloned().collect())
            .unwrap_or_default()
    }
}

impl Default for VersionStore {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RecursiveAgentValidator;

impl RecursiveAgentValidator {
    pub fn compute_diff(old: &AgentVersion, new: &AgentVersion) -> VersionDiff {
        let goal_changed = old.goal_intent != new.goal_intent;
        let goal_cosine_shift = match (&old.goal_embedding, &new.goal_embedding) {
            (Some(a), Some(b)) => normalized_cosine_similarity(a, b),
            _ => None,
        };

        let mut threshold_deltas = HashMap::new();
        for (k, &new_val) in &new.threshold_snapshot {
            let old_val = old.threshold_snapshot.get(k).copied().unwrap_or(0.0);
            if (new_val - old_val).abs() > f64::EPSILON {
                threshold_deltas.insert(k.clone(), (old_val, new_val));
            }
        }

        VersionDiff {
            old_version: old.version,
            new_version: new.version,
            goal_changed,
            goal_cosine_shift,
            anomaly_model_replaced: old.anomaly_generation != new.anomaly_generation,
            threshold_deltas,
        }
    }

    pub fn sandbox_check(old: &AgentVersion, new: &AgentVersion) -> SandboxResult {
        let embedding_shift = match (&old.goal_embedding, &new.goal_embedding) {
            (Some(a), Some(b)) => normalized_cosine_similarity(a, b)
                .map(|sim| 1.0 - sim)
                .unwrap_or(1.0),
            _ => 0.0,
        };
        let model_delta: f64 = if old.anomaly_generation != new.anomaly_generation {
            MODEL_REPLACEMENT_SANDBOX_DELTA
        } else {
            0.0
        };
        let anomaly_score_delta = embedding_shift + model_delta;
        SandboxResult {
            anomaly_score_delta,
            has_anomalies: anomaly_score_delta > SANDBOX_ANOMALY_REJECTION_THRESHOLD,
            checked_at: Utc::now(),
        }
    }

    pub fn validate_improvement(old: &AgentVersion, new: &AgentVersion) -> ImprovementDecision {
        Self::validate_improvement_full(old, new).0
    }

    /// Returns both the decision and the adversarial suite result (when one was run).
    pub fn validate_improvement_full(
        old: &AgentVersion,
        new: &AgentVersion,
    ) -> (ImprovementDecision, Option<AdversarialSuiteResult>) {
        let diff = Self::compute_diff(old, new);

        if diff.is_trivial_noop() {
            return (ImprovementDecision::Approve, None);
        }

        if diff.changes_core_behavior() || diff.has_large_threshold_delta() {
            return (ImprovementDecision::RequireHumanApproval { diff }, None);
        }

        // Run 1000 adversarial scenarios before allowing promotion.
        let suite = SandboxTestGate::run(old, new);
        if !suite.gate_passed {
            let reason = format!(
                "adversarial gate failed: {}/{} cases passed ({:.1}% < {:.0}% required)",
                suite.passed,
                suite.total_cases,
                suite.pass_rate * 100.0,
                ADVERSARIAL_MIN_PASS_RATE * 100.0,
            );
            return (ImprovementDecision::Reject { reason }, Some(suite));
        }

        let sandbox = Self::sandbox_check(old, new);
        if sandbox.has_anomalies {
            return (
                ImprovementDecision::Reject {
                    reason: "sandbox testing revealed anomalies".to_string(),
                },
                Some(suite),
            );
        }

        let embedding_shift = diff.goal_cosine_shift.map(|sim| 1.0 - sim).unwrap_or(0.0);
        let threshold_shift = diff.max_threshold_relative_delta().min(1.0);
        let model_shift = if diff.anomaly_model_replaced { 0.1 } else { 0.0 };
        let total_shift =
            (embedding_shift * 0.6 + threshold_shift * 0.3 + model_shift).clamp(0.0, 1.0);

        let canary_percentage = (1.0 - (0.8 * total_shift)).clamp(0.2, 1.0);
        let monitoring_duration_secs = (21_600.0 + (total_shift * 151_200.0)).round() as u64;

        (
            ImprovementDecision::GradualRollout {
                canary_percentage,
                monitoring_duration_secs,
            },
            Some(suite),
        )
    }
}

fn normalized_cosine_similarity(a: &[f64], b: &[f64]) -> Option<f64> {
    let dot = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum::<f64>();
    let norm_a = a.iter().map(|x| x * x).sum::<f64>().sqrt();
    let norm_b = b.iter().map(|x| x * x).sum::<f64>().sqrt();
    let denom = norm_a * norm_b;
    if denom <= f64::EPSILON {
        None
    } else {
        Some((dot / denom).clamp(-1.0, 1.0))
    }
}

fn relative_delta(old: f64, new: f64) -> f64 {
    if old.abs() <= f64::EPSILON {
        if new.abs() <= f64::EPSILON {
            0.0
        } else {
            f64::INFINITY
        }
    } else {
        (new - old).abs() / old.abs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_version(
        agent_id: &str,
        version: u64,
        intent: &str,
        embedding: Vec<f64>,
    ) -> AgentVersion {
        AgentVersion {
            agent_id: agent_id.to_string(),
            version,
            goal_intent: Some(intent.to_string()),
            goal_embedding: Some(embedding),
            anomaly_generation: 0,
            threshold_snapshot: HashMap::new(),
            captured_at: Utc::now(),
        }
    }

    #[test]
    fn stable_goal_gets_approve() {
        let old = make_version("a1", 1, "transfer payments", vec![1.0, 0.0]);
        let new = make_version("a1", 2, "transfer payments", vec![1.0, 0.0]);
        let result = RecursiveAgentValidator::validate_improvement(&old, &new);
        assert!(matches!(result, ImprovementDecision::Approve));
    }

    #[test]
    fn goal_text_change_requires_human_approval() {
        let old = make_version("a1", 1, "transfer payments", vec![1.0, 0.0]);
        let new = make_version("a1", 2, "rm -rf production", vec![0.0, 1.0]);
        let result = RecursiveAgentValidator::validate_improvement(&old, &new);
        assert!(matches!(
            result,
            ImprovementDecision::RequireHumanApproval { .. }
        ));
    }

    #[test]
    fn large_embedding_shift_triggers_rejection() {
        let old = make_version("a1", 1, "send payment", vec![1.0, 0.0]);
        let mut new = make_version("a1", 2, "send payment", vec![0.0, 1.0]);
        new.anomaly_generation = 5;
        let sandbox = RecursiveAgentValidator::sandbox_check(&old, &new);
        assert!(sandbox.has_anomalies);
    }

    #[test]
    fn diff_detects_threshold_changes() {
        let mut old = make_version("a1", 1, "intent", vec![1.0]);
        old.threshold_snapshot
            .insert("resource:max_tokens_per_minute".to_string(), 100_000.0);
        let mut new = make_version("a1", 2, "intent", vec![1.0]);
        new.threshold_snapshot
            .insert("resource:max_tokens_per_minute".to_string(), 110_000.0);
        let diff = RecursiveAgentValidator::compute_diff(&old, &new);
        assert!(
            diff.threshold_deltas
                .contains_key("resource:max_tokens_per_minute")
        );
    }

    #[test]
    fn large_threshold_delta_requires_human_approval() {
        let mut old = make_version("a1", 1, "intent", vec![1.0, 0.0]);
        old.threshold_snapshot
            .insert("resource:max_tokens_per_minute".to_string(), 100_000.0);
        let mut new = make_version("a1", 2, "intent", vec![1.0, 0.0]);
        new.threshold_snapshot
            .insert("resource:max_tokens_per_minute".to_string(), 130_000.0);

        let decision = RecursiveAgentValidator::validate_improvement(&old, &new);
        assert!(matches!(
            decision,
            ImprovementDecision::RequireHumanApproval { .. }
        ));
    }

    #[test]
    fn rollout_scales_with_non_trivial_but_safe_changes() {
        let old = make_version("a1", 1, "intent", vec![1.0, 0.0]);
        let new = make_version("a1", 2, "intent", vec![0.95, 0.05]);

        let decision = RecursiveAgentValidator::validate_improvement(&old, &new);
        match decision {
            ImprovementDecision::GradualRollout {
                canary_percentage,
                monitoring_duration_secs,
            } => {
                assert!(canary_percentage < 1.0);
                assert!(monitoring_duration_secs > 21_600);
            }
            other => panic!("expected gradual rollout, got {other:?}"),
        }
    }

    #[test]
    fn version_store_next_version_is_monotonic() {
        let store = VersionStore::new();
        assert_eq!(store.next_version("a1"), 1);
        assert_eq!(store.next_version("a1"), 2);

        store.store(make_version("a1", 10, "intent", vec![1.0]));
        assert_eq!(store.next_version("a1"), 11);
    }

    #[test]
    fn adversarial_gate_passes_for_equal_thresholds() {
        let old = make_version("a1", 1, "transfer payments", vec![1.0, 0.0]);
        let new = make_version("a1", 2, "transfer payments", vec![1.0, 0.0]);
        let result = SandboxTestGate::run(&old, &new);
        assert!(result.gate_passed, "identical versions must pass the gate");
        assert_eq!(result.total_cases, ADVERSARIAL_TOTAL);
    }

    #[test]
    fn adversarial_gate_fails_when_anomaly_threshold_raised() {
        // New version raises anomaly_threshold from 0.5 to 0.99 — many attacks go undetected.
        let mut old = make_version("a1", 1, "transfer payments", vec![1.0, 0.0]);
        old.threshold_snapshot.insert("anomaly_threshold".to_string(), 0.5);
        let mut new_v = make_version("a1", 2, "transfer payments", vec![1.0, 0.0]);
        new_v.threshold_snapshot.insert("anomaly_threshold".to_string(), 0.99);
        let result = SandboxTestGate::run(&old, &new_v);
        assert!(!result.gate_passed, "weakened threshold must fail the gate");
    }

    #[test]
    fn adversarial_gate_fails_when_rate_limit_raised() {
        let mut old = make_version("a1", 1, "transfer payments", vec![1.0, 0.0]);
        old.threshold_snapshot.insert("rate_limit".to_string(), 60.0);
        let mut new_v = make_version("a1", 2, "transfer payments", vec![1.0, 0.0]);
        new_v.threshold_snapshot.insert("rate_limit".to_string(), 10_000.0);
        let result = SandboxTestGate::run(&old, &new_v);
        assert!(!result.gate_passed, "weakened rate limit must fail the gate");
    }

    #[test]
    fn lineage_recorded_and_retrieved() {
        let store = VersionStore::new();
        let old = make_version("a1", 1, "intent", vec![1.0]);
        let new_v = make_version("a1", 2, "intent", vec![1.0]);
        let diff = RecursiveAgentValidator::compute_diff(&old, &new_v);
        let entry = VersionLineageEntry {
            version: 2,
            diff_summary: VersionDiffSummary::from(&diff),
            adversarial_result: None,
            decision: ImprovementDecision::Approve,
            promoted: true,
            recorded_at: Utc::now(),
        };
        store.record_lineage("a1", entry);
        let lineage = store.get_lineage("a1");
        assert_eq!(lineage.len(), 1);
        assert_eq!(lineage[0].version, 2);
        assert!(lineage[0].promoted);
    }
}
