pub mod ai_threats;
pub mod calibration;
pub mod context;
pub mod drift;
pub mod ensemble_divergence;
pub mod intent;
pub mod learning;
pub mod math;
pub mod monitor;
pub mod onnx_detector;
pub mod patterns;
pub mod robust_detector;
pub mod semantic_monitoring;
pub mod structural_invariants;
pub mod types;

// Re-export commonly used math functions for convenience
pub use math::{
    cosine_similarity_normalized, euclidean_distance, jensen_shannon_divergence, kl_divergence,
    l2_normalize,
};

// Re-export canonical AlertTier (AC-05 FIX: unified type)
pub use types::{AlertTier, DecisionRegion};

// Section 6: AI Threat Detection
pub use ai_threats::{
    AlertType, BehavioralMarker, BehavioralMarkerEngine, CommandContainmentBridge,
    ContainmentBridge, ContainmentExecutorMode, ContainmentLevel, Context, DetectionMethod,
    DeterministicContainmentBridge, DynamicPlaybook, InjectionResult, InversionRisk,
    MockContainmentBridge, MockSiem, PromptInjectionDetector, QueryRecord, ResponseResult,
    RiskLevel, SecurityAlert, Severity, SiemInterface, WebhookSiem,
    build_containment_bridge_from_env,
};

pub use calibration::{CalibratedScore, CalibrationDB, TieredDecision, default_calibration};
pub use context::{adjust_confidence, analyze_context, classify_context};
pub use drift::{MultiScaleAnalyzer, core_distance, robust_similarity, zedd_drift_score};
pub use ensemble_divergence::{DriftScore, KCoreDistanceDetector};
pub use intent::{IntentLabel, classify_intent};
pub use learning::{
    fp_count, record_false_positive, record_true_positive, suggested_benign_refresh_count, tp_count,
};
pub use monitor::{CognitiveAssessment, CognitiveMonitor, ReasoningMetadata, Triage};
pub use onnx_detector::{CalibrationPipeline, MultiScaleResult, OnnxDetectionResult, OnnxDetector};
pub use patterns::{
    COVERT_COMMUNICATION_PATTERNS, POWER_SEEKING_PATTERNS, REWARD_HACKING_PATTERNS,
    ReasoningPattern,
};
pub use robust_detector::{
    CalibrationStats, ContextAwareDetector, ContextClassifier, ContextType, ContextualResult,
    CoreDistanceDetector, DetectionResult, FakingResult,
};
pub use structural_invariants::{
    ActionDescriptor, InvariantClass, StructuralVerdict, evaluate as evaluate_structural_invariants,
};

// Section 5: Semantic Monitoring
pub use semantic_monitoring::{
    CoherenceReport, ConsistencyScore, CrossModalMonitor, HierarchicalMonitor, HierarchyViolation,
    HnswIndex, LayerEmbedding, SemanticDriftDetector, ZeddResult,
};
