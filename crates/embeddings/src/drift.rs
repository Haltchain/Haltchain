//! Thursday: Drift scoring.
//!
//! Measures whether an agent's actions are drifting away from its declared goal
//! by tracking a rolling window of cosine similarities between the goal vector
//! and each action vector.  A negative trend slope indicates drift.

use std::collections::{HashMap, VecDeque};

use crate::model::cosine_similarity;

pub const DEFAULT_WINDOW: usize = 20;

// ─── Rolling window of similarity scores ─────────────────────────────────────

pub struct DriftWindow {
    scores: VecDeque<f64>,
    capacity: usize,
}

impl DriftWindow {
    pub fn new(capacity: usize) -> Self {
        Self {
            scores: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    pub fn push(&mut self, score: f64) {
        if self.scores.len() >= self.capacity {
            self.scores.pop_front();
        }
        self.scores.push_back(score);
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

// ─── Drift result ─────────────────────────────────────────────────────────────

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
}

// ─── Scorer ───────────────────────────────────────────────────────────────────

pub struct DriftScorer {
    windows: HashMap<String, DriftWindow>,
    window_size: usize,
}

impl DriftScorer {
    pub fn new(window_size: usize) -> Self {
        Self {
            windows: HashMap::new(),
            window_size,
        }
    }

    /// Score an action against a goal and update the window.
    /// `session_key` is typically `"{agent_id}:{session_id}"`.
    pub fn push(&mut self, session_key: &str, goal: &[f64], action: &[f64]) -> DriftResult {
        let sim = cosine_similarity(goal, action);
        let w = self
            .windows
            .entry(session_key.to_string())
            .or_insert_with(|| DriftWindow::new(self.window_size));
        w.push(sim);
        DriftResult {
            similarity: sim,
            window_mean: w.mean(),
            trend_slope: w.trend_slope(),
            window_len: w.len(),
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
}
