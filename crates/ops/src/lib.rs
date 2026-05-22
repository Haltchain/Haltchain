//! Section 8: Implementation & Deployment
//!
//! Implements:
//! - 8.1 Sampling & Alerting (Stratified sampling, Multi-armed bandit)
//! - 8.2 Performance SLAs (MTTD, MTTR, Precision@Recall)

pub mod alerting;
pub mod sampling;
pub mod sla;

pub use sampling::{
    BanditArm, EpsilonGreedyBandit, Interaction, RiskLevel, SamplingStratum, StratifiedSampler,
};

#[cfg(feature = "experimental")]
pub use sampling::{ThompsonArm, ThompsonSamplingBandit};

pub use sla::{
    AlertSeverity, ConfusionMatrix, DetectionRecord, ResponseRecord, RollingSlaTracker, SlaMetrics,
    SlaTracker,
};

pub use alerting::{
    AlertAction, AlertDirective, AlertSignals, AlertTier, FalsePositiveOptimizer,
    ThresholdSelection, classify_alert_tier,
};
