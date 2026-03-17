//! Section 8: Implementation & Deployment
//!
//! Implements:
//! - 8.1 Sampling & Alerting (Stratified sampling, Multi-armed bandit)
//! - 8.2 Performance SLAs (MTTD, MTTR, Precision@Recall)

pub mod sampling;
pub mod sla;

pub use sampling::{
    StratifiedSampler, SamplingStratum, RiskLevel, Interaction,
    EpsilonGreedyBandit, ThompsonSamplingBandit, BanditArm, ThompsonArm,
};

pub use sla::{
    SlaTracker, RollingSlaTracker, SlaMetrics,
    DetectionRecord, ResponseRecord, ConfusionMatrix,
    AlertSeverity,
};
