//! Friday: Goal clarification protocol.
//!
//! If an agent's action window mean similarity drops below [`DRIFT_THRESHOLD`],
//! the validator returns `GOAL_CLARIFICATION_REQUIRED` and the agent must call
//! `POST /goals` to confirm or update its intent before proceeding.

use crate::drift::DriftResult;

/// Mean cosine similarity below this value triggers clarification.
pub const DRIFT_THRESHOLD: f64 = 0.30;

/// Minimum data points in the drift window before issuing clarification.
pub const MIN_WINDOW_FOR_CLARIFICATION: usize = 3;

// ─── Decision ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ClarificationDecision {
    Continue,
    RequireClarification {
        reason: String,
        current_mean: f64,
        threshold: f64,
    },
}

impl ClarificationDecision {
    pub fn is_required(&self) -> bool {
        matches!(self, ClarificationDecision::RequireClarification { .. })
    }
}

// ─── Protocol ────────────────────────────────────────────────────────────────

pub struct ClarificationProtocol {
    pub threshold: f64,
    pub min_window: usize,
}

impl Default for ClarificationProtocol {
    fn default() -> Self {
        Self {
            threshold: DRIFT_THRESHOLD,
            min_window: MIN_WINDOW_FOR_CLARIFICATION,
        }
    }
}

impl ClarificationProtocol {
    pub fn new(threshold: f64, min_window: usize) -> Self {
        Self {
            threshold,
            min_window,
        }
    }

    pub fn check(&self, drift: &DriftResult) -> ClarificationDecision {
        if drift.window_len < self.min_window {
            return ClarificationDecision::Continue;
        }
        if drift.window_mean < self.threshold {
            ClarificationDecision::RequireClarification {
                reason: format!(
                    "Goal drift detected: mean similarity {:.3} is below threshold {:.3}. \
                     Re-declare intent via POST /goals.",
                    drift.window_mean, self.threshold
                ),
                current_mean: drift.window_mean,
                threshold: self.threshold,
            }
        } else {
            ClarificationDecision::Continue
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drift::DriftResult;

    fn result(mean: f64, len: usize) -> DriftResult {
        DriftResult {
            similarity: mean,
            window_mean: mean,
            trend_slope: 0.0,
            window_len: len,
        }
    }

    #[test]
    fn continue_above_threshold() {
        let p = ClarificationProtocol::default();
        assert_eq!(p.check(&result(0.8, 5)), ClarificationDecision::Continue);
    }

    #[test]
    fn require_clarification_below_threshold() {
        let p = ClarificationProtocol::default();
        assert!(p.check(&result(0.1, 5)).is_required());
    }

    #[test]
    fn skip_small_window() {
        let p = ClarificationProtocol::default();
        // Only 2 data points — too few to be confident.
        assert_eq!(p.check(&result(0.05, 2)), ClarificationDecision::Continue);
    }

    #[test]
    fn exactly_at_threshold_continues() {
        let p = ClarificationProtocol::default();
        assert_eq!(
            p.check(&result(DRIFT_THRESHOLD, 5)),
            ClarificationDecision::Continue
        );
    }

    #[test]
    fn custom_threshold_respected() {
        let p = ClarificationProtocol::new(0.70, 3);
        assert!(p.check(&result(0.65, 4)).is_required());
        assert_eq!(p.check(&result(0.75, 4)), ClarificationDecision::Continue);
    }
}
