//! `haltchain-embeddings` — semantic goal tracking for AI agents.
//!
//! Modules:
//!   * [`model`]         — `EmbeddingModel` trait, `LocalModel`, `RemoteModel`, `ModelKind`
//!   * [`cache`]         — `EmbeddingCache` with LRU eviction (Weekend perf)
//!   * [`goal`]          — goal declaration store (Tuesday)
//!   * [`pipeline`]      — action-to-embedding pipeline + batch support (Wednesday)
//!   * [`drift`]         — rolling-window drift scorer (Thursday)
//!   * [`clarification`] — goal clarification protocol (Friday)
//!   * [`conversation`]  — conversation-derived drift detector (P0)

pub mod cache;
pub mod clarification;
pub mod conversation;
pub mod drift;
pub mod fingerprint;
pub mod goal;
pub mod model;
pub mod onnx_model;
pub mod pipeline;

pub use cache::EmbeddingCache;
pub use clarification::{ClarificationDecision, ClarificationProtocol, DRIFT_THRESHOLD};
pub use conversation::{
    ALERT_THRESHOLD, BASELINE_SIZE, ConversationDriftReport, ConversationRecord, ConversationStore,
    DriftAction, ROLLBACK_THRESHOLD, WINDOW_SIZE,
};
pub use drift::{DEFAULT_WINDOW, DriftResult, DriftScorer};
pub use fingerprint::{
    ActionStep, BASELINE_CONVOS, BEHAVIOR_WINDOW, BEHAVIORAL_ALERT, BEHAVIORAL_ROLLBACK,
    BehaviorDriftAction, BehaviorDriftReport, BehaviorRecord, BehavioralFingerprinter,
    action_sequence_to_text,
};
pub use goal::{GoalDeclaration, GoalStore};
pub use model::{
    EmbedError, EmbeddingModel, LOCAL_DIMS, LocalModel, ModelKind, RemoteModel, cosine_similarity,
    model_output_hash, verify_model_checksum,
};
pub use pipeline::{ActionMeta, EmbedPipeline, action_to_text};
