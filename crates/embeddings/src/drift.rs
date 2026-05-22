//! Thursday: Drift scoring.
//!
//! Measures whether an agent's actions are drifting away from its declared goal
//! by tracking a rolling window of cosine similarities between the goal vector
//! and each action vector.  A negative trend slope indicates drift.
//!
//! **Cumulative drift** (added for "boiling frog" resistance): tracks a frozen
//! baseline centroid from the first `BASELINE_ACTIONS` actions, then reports
//! the distance from that baseline on every subsequent action.  This prevents
//! an adversary from making small (<threshold) changes per step that accumulate
//! into a large overall drift.

use std::collections::{HashMap, VecDeque};

use crate::model::cosine_similarity;

pub const DEFAULT_WINDOW: usize = 20;

/// Number of initial actions used to establish the baseline centroid.
pub const BASELINE_ACTIONS: usize = 5;

// ─── Rolling window of similarity scores ─────────────────────────────────────

pub struct DriftWindow {
    scores: VecDeque<f64>,
    capacity: usize,
    // Running centroid of action embeddings for consistency checking
    action_sum: Vec<f64>,
    action_count: usize,
    // ── Cumulative baseline tracking ──
    // Sum of the first `baseline_size` action embeddings (frozen after baseline_size reached)
    baseline_sum: Vec<f64>,
    baseline_count: usize,
    baseline_size: usize,
    baseline_frozen: bool,
    // Normalized baseline centroid (computed once when baseline_frozen becomes true)
    baseline_centroid: Vec<f64>,
}

impl DriftWindow {
    pub fn new(capacity: usize) -> Self {
        Self::with_baseline(capacity, BASELINE_ACTIONS)
    }

    pub fn with_baseline(capacity: usize, baseline_size: usize) -> Self {
        Self {
            scores: VecDeque::with_capacity(capacity),
            capacity,
            action_sum: Vec::new(),
            action_count: 0,
            baseline_sum: Vec::new(),
            baseline_count: 0,
            baseline_size,
            baseline_frozen: false,
            baseline_centroid: Vec::new(),
        }
    }

    pub fn push(&mut self, score: f64) {
        if self.scores.len() >= self.capacity {
            self.scores.pop_front();
        }
        self.scores.push_back(score);
    }

    /// Track action embedding for centroid consistency and baseline accumulation
    pub fn track_action(&mut self, action: &[f64]) {
        if self.action_sum.is_empty() {
            self.action_sum = vec![0.0; action.len()];
        }
        for (s, a) in self.action_sum.iter_mut().zip(action.iter()) {
            *s += a;
        }
        self.action_count += 1;

        // Accumulate baseline centroid from early actions
        if !self.baseline_frozen {
            if self.baseline_sum.is_empty() {
                self.baseline_sum = vec![0.0; action.len()];
            }
            for (s, a) in self.baseline_sum.iter_mut().zip(action.iter()) {
                *s += a;
            }
            self.baseline_count += 1;
            if self.baseline_count >= self.baseline_size {
                // Freeze the baseline and compute the centroid
                let n = self.baseline_count as f64;
                self.baseline_centroid = self.baseline_sum.iter().map(|s| s / n).collect();
                self.baseline_frozen = true;
            }
        }
    }

    /// Cosine similarity between the current action and the frozen baseline centroid.
    /// Returns `None` if baseline hasn't been established yet.
    pub fn baseline_similarity(&self, action: &[f64]) -> Option<f64> {
        if !self.baseline_frozen || self.baseline_centroid.is_empty() {
            return None;
        }
        Some(cosine_similarity(&self.baseline_centroid, action))
    }

    /// Cosine similarity between an action and the session's running centroid.
    /// Returns 0.5 (uncertain) if no centroid available yet — avoids false
    /// "perfect alignment" on the first action.
    pub fn centroid_similarity(&self, action: &[f64]) -> f64 {
        if self.action_count == 0 || self.action_sum.is_empty() {
            return 0.5;
        }
        let n = self.action_count as f64;
        let centroid: Vec<f64> = self.action_sum.iter().map(|s| s / n).collect();
        cosine_similarity(&centroid, action)
    }

    pub fn len(&self) -> usize {
        self.scores.len()
    }

    pub fn is_empty(&self) -> bool {
        self.scores.is_empty()
    }

    pub fn mean(&self) -> f64 {
        if self.scores.is_empty() {
            return 1.0;
        }
        self.scores.iter().sum::<f64>() / self.scores.len() as f64
    }

    /// Linear regression slope over the window (negative = drifting away).
    pub fn trend_slope(&self) -> f64 {
        let n = self.scores.len();
        if n < 2 {
            return 0.0;
        }
        let nf = n as f64;
        let x_mean = (nf - 1.0) / 2.0;
        let y_mean = self.mean();
        let mut num = 0.0f64;
        let mut den = 0.0f64;
        for (i, &y) in self.scores.iter().enumerate() {
            let dx = i as f64 - x_mean;
            num += dx * (y - y_mean);
            den += dx * dx;
        }
        if den.abs() < 1e-12 { 0.0 } else { num / den }
    }
}

// Drift result

#[derive(Debug, Clone)]
pub struct DriftResult {
    /// Cosine similarity between goal and this specific action.
    pub similarity: f64,
    /// Rolling mean over the window.
    pub window_mean: f64,
    /// Trend slope (negative = declining similarity).
    pub trend_slope: f64,
    /// Number of scores in the window.
    pub window_len: usize,
    /// Cumulative drift: `1.0 - cosine_similarity(action, baseline_centroid)`.
    /// `None` until the baseline is established (first `BASELINE_ACTIONS` actions).
    /// Values near 0.0 = on-baseline, values near 1.0 = far from baseline.
    pub cumulative_drift: Option<f64>,
}

// ─── Scorer ───────────────────────────────────────────────────────────────────

pub struct DriftScorer {
    windows: HashMap<String, DriftWindow>,
    window_size: usize,
    baseline_size: usize,
}

impl DriftScorer {
    pub fn new(window_size: usize) -> Self {
        Self {
            windows: HashMap::new(),
            window_size,
            baseline_size: BASELINE_ACTIONS,
        }
    }

    pub fn with_baseline(window_size: usize, baseline_size: usize) -> Self {
        Self {
            windows: HashMap::new(),
            window_size,
            baseline_size,
        }
    }

    /// Score an action against a goal and update the window.
    /// `session_key` is typically `"{agent_id}:{session_id}"`.
    ///
    /// The score blends goal-alignment (cosine similarity to goal) with
    /// a consistency factor from the session's intra-action centroid.
    /// This penalizes actions that are topically close to the goal
    /// but intent-divergent (e.g., warehouse theft vs warehouse management).
    pub fn push(&mut self, session_key: &str, goal: &[f64], action: &[f64]) -> DriftResult {
        let goal_sim = cosine_similarity(goal, action);
        let w = self
            .windows
            .entry(session_key.to_string())
            .or_insert_with(|| DriftWindow::with_baseline(self.window_size, self.baseline_size));

        // Blend goal similarity with action-centroid consistency
        // This catches topic-adjacent but intent-divergent actions
        let centroid_sim = w.centroid_similarity(action);
        let sim = if w.action_count >= 2 {
            // After enough actions, weight by consistency
            goal_sim * 0.6 + centroid_sim * 0.4
        } else {
            goal_sim
        };

        // Compute cumulative drift BEFORE tracking (so we compare against frozen baseline)
        let cumulative_drift = w.baseline_similarity(action).map(|s| 1.0 - s);

        w.track_action(action);
        w.push(sim);
        DriftResult {
            similarity: sim,
            window_mean: w.mean(),
            trend_slope: w.trend_slope(),
            window_len: w.len(),
            cumulative_drift,
        }
    }

    /// Reset the window for a session (e.g., after clarification).
    pub fn clear(&mut self, session_key: &str) {
        self.windows.remove(session_key);
    }

    /// Latest window mean, or `None` if no data.
    pub fn window_mean(&self, session_key: &str) -> Option<f64> {
        self.windows.get(session_key).map(|w| w.mean())
    }

    pub fn trend_slope(&self, session_key: &str) -> Option<f64> {
        self.windows.get(session_key).map(|w| w.trend_slope())
    }

    pub fn window_len(&self, session_key: &str) -> usize {
        self.windows.get(session_key).map(|w| w.len()).unwrap_or(0)
    }

    /// Latest cumulative drift from frozen baseline, or `None` if baseline not yet established.
    pub fn cumulative_drift(&self, session_key: &str) -> Option<f64> {
        // Return the most recent cumulative_drift if baseline is frozen;
        // callers should use the value from the DriftResult returned by push() for per-action data.
        self.windows.get(session_key).and_then(|w| {
            if w.baseline_frozen {
                // Approximate: compute distance from baseline centroid to current running centroid
                if w.action_count > 0 && !w.action_sum.is_empty() && !w.baseline_centroid.is_empty()
                {
                    let n = w.action_count as f64;
                    let current_centroid: Vec<f64> = w.action_sum.iter().map(|s| s / n).collect();
                    Some(1.0 - cosine_similarity(&current_centroid, &w.baseline_centroid))
                } else {
                    None
                }
            } else {
                None
            }
        })
    }
}

impl Default for DriftScorer {
    fn default() -> Self {
        Self::new(DEFAULT_WINDOW)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(v: Vec<f64>) -> Vec<f64> {
        let norm: f64 = v.iter().map(|x| x * x).sum::<f64>().sqrt();
        v.into_iter().map(|x| x / norm).collect()
    }

    #[test]
    fn window_mean_correct() {
        let mut w = DriftWindow::new(5);
        w.push(0.8);
        w.push(0.6);
        w.push(0.4);
        let mean = w.mean();
        assert!((mean - (0.8 + 0.6 + 0.4) / 3.0).abs() < 1e-9);
    }

    #[test]
    fn trend_slope_negative_on_decline() {
        let mut w = DriftWindow::new(10);
        for i in 0..5 {
            w.push(1.0 - i as f64 * 0.1);
        }
        assert!(
            w.trend_slope() < 0.0,
            "slope should be negative for declining scores"
        );
    }

    #[test]
    fn trend_slope_positive_on_growth() {
        let mut w = DriftWindow::new(10);
        for i in 0..5 {
            w.push(0.5 + i as f64 * 0.1);
        }
        assert!(w.trend_slope() > 0.0);
    }

    #[test]
    fn no_drift_stable_scores() {
        let mut s = DriftScorer::new(10);
        let goal = unit(vec![1.0, 0.0]);
        let action = unit(vec![0.9, 0.1]);
        for _ in 0..5 {
            s.push("a1:s1", &goal, &action);
        }
        let mean = s.window_mean("a1:s1").unwrap();
        assert!(mean > 0.5, "stable actions should not show drift");
    }

    #[test]
    fn drift_detected_after_direction_change() {
        let mut s = DriftScorer::new(10);
        let goal = unit(vec![1.0, 0.0]);
        let on_goal = unit(vec![1.0, 0.0]);
        let off_goal = unit(vec![0.0, 1.0]); // orthogonal → sim ≈ 0
        // First half: on-goal
        for _ in 0..5 {
            s.push("a1:s1", &goal, &on_goal);
        }
        // Second half: off-goal
        for _ in 0..5 {
            s.push("a1:s1", &goal, &off_goal);
        }
        let dr = s.push("a1:s1", &goal, &off_goal);
        assert!(
            dr.window_mean < 0.6,
            "mean should drop after off-goal actions"
        );
        assert!(dr.trend_slope < 0.0, "slope should be negative");
    }

    #[test]
    fn clear_resets_window() {
        let mut s = DriftScorer::new(5);
        let v = unit(vec![1.0, 0.0]);
        s.push("k", &v, &v);
        s.clear("k");
        assert!(s.window_mean("k").is_none());
    }

    #[test]
    fn cumulative_drift_none_during_baseline() {
        let mut s = DriftScorer::with_baseline(10, 5);
        let goal = unit(vec![1.0, 0.0]);
        let action = unit(vec![0.9, 0.1]);
        // First 4 actions: baseline not yet frozen
        for _ in 0..4 {
            let dr = s.push("sess", &goal, &action);
            assert!(
                dr.cumulative_drift.is_none(),
                "no cumulative_drift before baseline freezes"
            );
        }
    }

    #[test]
    fn cumulative_drift_detects_boiling_frog() {
        // Baseline actions use a consistent on-goal direction.
        // Subsequent actions gradually rotate away — each step is small
        // but cumulative drift from baseline should grow.
        let mut s = DriftScorer::with_baseline(20, 3);
        let goal = unit(vec![1.0, 0.0, 0.0]);
        let on_goal = unit(vec![1.0, 0.0, 0.0]);

        // Establish baseline with 3 on-goal actions
        for _ in 0..3 {
            s.push("boil", &goal, &on_goal);
        }

        // Now gradually rotate toward orthogonal
        let steps = 10;
        let mut last_drift = 0.0_f64;
        for i in 1..=steps {
            let angle = (i as f64 / steps as f64) * std::f64::consts::FRAC_PI_2;
            let drifted = unit(vec![angle.cos(), angle.sin(), 0.0]);
            let dr = s.push("boil", &goal, &drifted);
            if let Some(cd) = dr.cumulative_drift {
                assert!(
                    cd >= last_drift - 0.01,
                    "cumulative_drift should grow monotonically (step {i}): {cd:.4} < {last_drift:.4}"
                );
                last_drift = cd;
            }
        }
        // After rotating 90°, cumulative drift should be substantial
        assert!(
            last_drift > 0.3,
            "cumulative_drift after 90° rotation should be > 0.3, got {last_drift:.4}"
        );
    }
}
