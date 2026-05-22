//! Section 8.1.2 / 8.1.3: Alert severity policy and false-positive optimization.
//!
//! Implements:
//! - 5-tier alert classification with explicit response actions
//! - Cost-sensitive threshold tuning under an FPR constraint
//! - Temporal correlation helper for sustained-alert filtering

use serde::{Deserialize, Serialize};

/// Section 8.1.2 5-tier severity model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertTier {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

/// Operational response action for an alert tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertAction {
    LoggingOnly,
    BatchReview,
    PromptInvestigation,
    AutomatedContainment,
    FullSystemIsolation,
}

/// Explicit policy bundle used by downstream workflows/SIEM connectors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertDirective {
    pub tier: AlertTier,
    pub response_time_seconds: u64,
    pub action: AlertAction,
    pub escalation_path: &'static str,
}

impl AlertDirective {
    /// Create a directive from the severity table in Project Architecture §8.1.2.
    pub fn from_tier(tier: AlertTier) -> Self {
        match tier {
            AlertTier::Informational => Self {
                tier,
                response_time_seconds: 24 * 60 * 60,
                action: AlertAction::LoggingOnly,
                escalation_path: "None",
            },
            AlertTier::Low => Self {
                tier,
                response_time_seconds: 24 * 60 * 60,
                action: AlertAction::BatchReview,
                escalation_path: "Analyst queue",
            },
            AlertTier::Medium => Self {
                tier,
                response_time_seconds: 4 * 60 * 60,
                action: AlertAction::PromptInvestigation,
                escalation_path: "Senior analyst",
            },
            AlertTier::High => Self {
                tier,
                response_time_seconds: 0,
                action: AlertAction::AutomatedContainment,
                escalation_path: "Security operations",
            },
            AlertTier::Critical => Self {
                tier,
                response_time_seconds: 0,
                action: AlertAction::FullSystemIsolation,
                escalation_path: "Executive + legal",
            },
        }
    }
}

/// Signals used for operational tier classification.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AlertSignals {
    /// Combined model risk score in [0, 1].
    pub risk_score: f64,
    /// Ensemble consensus confidence in [0, 1].
    pub consensus: f64,
    /// Number of temporally-correlated hits in the current window.
    pub sustained_hits: u32,
}

impl AlertSignals {
    pub fn normalized(self) -> Self {
        Self {
            risk_score: self.risk_score.clamp(0.0, 1.0),
            consensus: self.consensus.clamp(0.0, 1.0),
            sustained_hits: self.sustained_hits,
        }
    }
}

/// Classify alert tier with conservative escalation under uncertainty.
///
/// - High risk + high consensus or sustained multi-hit patterns escalate rapidly
/// - Low consensus prevents over-escalation unless sustained evidence is present
pub fn classify_alert_tier(signals: AlertSignals) -> AlertTier {
    let s = signals.normalized();

    if s.risk_score >= 0.95 && (s.consensus >= 0.80 || s.sustained_hits >= 3) {
        return AlertTier::Critical;
    }
    if s.risk_score >= 0.80 && (s.consensus >= 0.70 || s.sustained_hits >= 3) {
        return AlertTier::High;
    }
    if s.risk_score >= 0.60 && (s.consensus >= 0.55 || s.sustained_hits >= 2) {
        return AlertTier::Medium;
    }
    if s.risk_score >= 0.35 {
        return AlertTier::Low;
    }
    AlertTier::Informational
}

/// A threshold selected by cost-sensitive optimization under an FPR cap.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ThresholdSelection {
    pub threshold: f64,
    pub precision: f64,
    pub recall: f64,
    pub fpr: f64,
}

/// Optimizer for Section 8.1.3 false-positive control.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FalsePositiveOptimizer {
    pub target_fpr: f64,
    pub false_positive_cost: f64,
    pub false_negative_cost: f64,
}

impl Default for FalsePositiveOptimizer {
    fn default() -> Self {
        Self {
            target_fpr: 0.10,
            false_positive_cost: 1.0,
            false_negative_cost: 2.0,
        }
    }
}

impl FalsePositiveOptimizer {
    /// Choose threshold minimizing cost while respecting the FPR target.
    ///
    /// `labeled_scores`: (score, is_true_anomaly)
    pub fn select_threshold(&self, labeled_scores: &[(f64, bool)]) -> Option<ThresholdSelection> {
        if labeled_scores.is_empty() {
            return None;
        }

        let mut candidates: Vec<f64> = labeled_scores.iter().map(|(s, _)| *s).collect();
        candidates.sort_by(|a, b| a.total_cmp(b));
        candidates.dedup_by(|a, b| (*a - *b).abs() < 1e-12);

        let mut best: Option<(ThresholdSelection, f64)> = None;

        for threshold in candidates {
            let mut tp = 0_u64;
            let mut fp = 0_u64;
            let mut tn = 0_u64;
            let mut fn_ = 0_u64;

            for (score, is_true_anomaly) in labeled_scores {
                let pred_positive = *score >= threshold;
                match (pred_positive, *is_true_anomaly) {
                    (true, true) => tp += 1,
                    (true, false) => fp += 1,
                    (false, false) => tn += 1,
                    (false, true) => fn_ += 1,
                }
            }

            let precision = if tp + fp == 0 {
                0.0
            } else {
                tp as f64 / (tp + fp) as f64
            };
            let recall = if tp + fn_ == 0 {
                0.0
            } else {
                tp as f64 / (tp + fn_) as f64
            };
            let fpr = if fp + tn == 0 {
                0.0
            } else {
                fp as f64 / (fp + tn) as f64
            };

            if fpr > self.target_fpr {
                continue;
            }

            let cost = self.false_positive_cost * fp as f64 + self.false_negative_cost * fn_ as f64;
            let selection = ThresholdSelection {
                threshold,
                precision,
                recall,
                fpr,
            };

            match best {
                Some((current, current_cost)) => {
                    let better_cost = cost < current_cost;
                    let tie_better_recall =
                        (cost - current_cost).abs() < 1e-12 && selection.recall > current.recall;
                    if better_cost || tie_better_recall {
                        best = Some((selection, cost));
                    }
                }
                None => {
                    best = Some((selection, cost));
                }
            }
        }

        best.map(|(selection, _)| selection)
    }

    /// Temporal correlation filter (Section 8.1.3) for sustained alerts.
    pub fn has_sustained_alerts(
        &self,
        alert_timestamps_secs: &[u64],
        window_secs: u64,
        min_hits: usize,
    ) -> bool {
        if min_hits == 0 {
            return true;
        }
        if alert_timestamps_secs.len() < min_hits {
            return false;
        }

        let mut sorted = alert_timestamps_secs.to_vec();
        sorted.sort_unstable();

        for i in 0..=sorted.len() - min_hits {
            let start = sorted[i];
            let end = sorted[i + min_hits - 1];
            if end.saturating_sub(start) <= window_secs {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directive_matches_section_8_table() {
        let medium = AlertDirective::from_tier(AlertTier::Medium);
        assert_eq!(medium.response_time_seconds, 4 * 60 * 60);
        assert_eq!(medium.action, AlertAction::PromptInvestigation);

        let critical = AlertDirective::from_tier(AlertTier::Critical);
        assert_eq!(critical.response_time_seconds, 0);
        assert_eq!(critical.action, AlertAction::FullSystemIsolation);
    }

    #[test]
    fn classify_alert_tier_escalates_with_consensus_and_hits() {
        let low = classify_alert_tier(AlertSignals {
            risk_score: 0.40,
            consensus: 0.20,
            sustained_hits: 0,
        });
        assert_eq!(low, AlertTier::Low);

        let high = classify_alert_tier(AlertSignals {
            risk_score: 0.84,
            consensus: 0.72,
            sustained_hits: 1,
        });
        assert_eq!(high, AlertTier::High);

        let critical_by_sustained = classify_alert_tier(AlertSignals {
            risk_score: 0.96,
            consensus: 0.40,
            sustained_hits: 3,
        });
        assert_eq!(critical_by_sustained, AlertTier::Critical);
    }

    #[test]
    fn threshold_optimizer_respects_fpr_cap() {
        // Scores are intentionally interleaved so threshold choice matters.
        let labeled_scores = vec![
            (0.95, true),
            (0.90, true),
            (0.88, false),
            (0.80, true),
            (0.70, false),
            (0.60, false),
            (0.55, true),
            (0.40, false),
            (0.30, false),
        ];

        let optimizer = FalsePositiveOptimizer {
            target_fpr: 0.25,
            false_positive_cost: 1.0,
            false_negative_cost: 3.0,
        };

        let selected = optimizer
            .select_threshold(&labeled_scores)
            .expect("threshold should be selected");

        assert!(selected.fpr <= 0.25 + 1e-9);
        assert!(selected.recall >= 0.50);
    }

    #[test]
    fn temporal_filter_requires_sustained_hits() {
        let optimizer = FalsePositiveOptimizer::default();

        let sparse = vec![10_u64, 120, 240, 360];
        assert!(!optimizer.has_sustained_alerts(&sparse, 60, 3));

        let burst = vec![100_u64, 115, 140, 300];
        assert!(optimizer.has_sustained_alerts(&burst, 60, 3));
    }
}
