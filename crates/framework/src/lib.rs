//! Section 7: Integrated Operational Frameworks
//!
//! Implements:
//! - 7.1 SCAB Protocol (Strength, Corruption, Alignment, Bonus/Penalty, Intelligence, Utility)

pub mod scab;

pub use scab::{
    ScabEvaluator, ScabReport, ScabDimension,
    StrengthScore, CorruptionScore, AlignmentScore,
    IncentiveScore, IntelligenceScore, UtilityScore,
    RiskLevel, Agent, SessionRecord, Action, Outcome,
    AgentState, DimensionEvaluator, AttestationVerifier,
    AttestationResult, BehavioralFingerprint, ActivationCheck,
    ActivationProbe, ActivationProbeSet, ProbeResult,
};
