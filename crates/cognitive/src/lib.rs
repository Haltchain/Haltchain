pub mod ai_threats;
pub mod calibration;
pub mod context;
pub mod drift;
pub mod ensemble_divergence;
pub mod goal_drift;
pub mod guardian;
pub mod latent_markers;
pub mod math;
pub mod monitor;
pub mod neural_probes;
pub mod onnx_detector;
pub mod patterns;
pub mod robust_detector;
pub mod semantic_monitoring;
pub mod types;
pub mod zedd_monitor;

// Re-export commonly used math functions for convenience
pub use math::{jensen_shannon_divergence, kl_divergence, l2_normalize, euclidean_distance, cosine_similarity_normalized};

// Re-export canonical AlertTier (AC-05 FIX: unified type)
pub use types::{AlertTier, DecisionRegion};

// Section 6: AI Threat Detection
pub use ai_threats::{
    PromptInjectionDetector, InjectionResult, DetectionMethod,
    BehavioralMarker, BehavioralMarkerEngine, InversionRisk, RiskLevel,
    SecurityAlert, Severity, AlertType, DynamicPlaybook, ResponseResult,
    ContainmentLevel, SiemInterface, MockSiem, QueryRecord, Context,
};

pub use calibration::{CalibrationDB, CalibratedScore, TieredDecision, default_calibration};
pub use context::{analyze_context, adjust_confidence, classify_context};
pub use drift::{MultiScaleAnalyzer, core_distance, zedd_drift_score, robust_similarity};
pub use ensemble_divergence::{KCoreDistanceDetector, DriftScore};
pub use goal_drift::{
    GoalDriftMonitor, CoTMonitor, IntegratedGoalMonitor,
    DriftReport, DriftRecommendation, DivergenceClass,
    CoTAssessment, CoTClassification, IntegratedReport,
};
pub use guardian::{MonitorGuardian, AgentObservation, SafetyAssessment, RoguePattern, ContainmentAction};
pub use monitor::{CognitiveAssessment, CognitiveMonitor, ReasoningMetadata, Triage};
pub use latent_markers::{
    LatentPatternDetector, LatentThreatAssessment, LatentDetails,
    POWER_SEEKING_PATTERNS, REWARD_HACKING_PATTERNS, COVERT_COMMUNICATION_PATTERNS,
    SEMANTIC_CLUSTERS,
};
pub use onnx_detector::{OnnxDetector, OnnxDetectionResult, MultiScaleResult, CalibrationPipeline};
pub use patterns::ReasoningPattern;
pub use robust_detector::{
    CalibrationStats, AlignmentFakingDetector, ContextAwareDetector,
    ContextClassifier, ContextType, CoreDistanceDetector, DetectionResult,
    ContextualResult, FakingResult,
};

// Section 5: Semantic Monitoring
pub use semantic_monitoring::{
    SemanticDriftDetector, ZeddResult, HnswIndex, CrossModalMonitor,
    ConsistencyScore, HierarchicalMonitor, LayerEmbedding, CoherenceReport,
    HierarchyViolation, PersistentHomologyAnalyzer, TopologicalFeatures,
};

pub use zedd_monitor::{ZeddMonitor, ZeddAssessment};
