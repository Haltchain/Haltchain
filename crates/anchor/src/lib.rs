use async_trait::async_trait;
use chrono::{DateTime, Utc};
use thiserror::Error;

pub mod postgres;
pub mod s3;

#[cfg(feature = "l2")]
pub mod l2;

pub use postgres::PostgresAnchor;
pub use s3::{S3Anchor, S3AnchorConfig};

#[cfg(feature = "l2")]
pub use l2::{BaseL2Anchor, BaseL2AnchorConfig};

#[derive(Debug, Error)]
pub enum AnchorError {
    #[error("database error: {0}")]
    Database(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("network error: {0}")]
    Network(String),
}

/// Minimal view of a validated decision passed to an anchor.
#[derive(Debug, Clone)]
pub struct AnchorDecision<'a> {
    pub transaction_id: &'a str,
    pub agent_id: &'a str,
    /// One of: ALLOW, DENY, CIRCUIT_BREAK, GOAL_CLARIFICATION_REQUIRED
    pub decision: &'a str,
    /// ISO-8601 UTC timestamp from the validation response.
    pub timestamp: &'a str,
    pub policy_code: Option<&'a str>,
    pub merkle_root: Option<&'a str>,
}

/// Opaque proof returned after a decision has been committed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnchorProof {
    pub anchor_type: &'static str,
    /// Stable identifier for this committed record (DB row ID, S3 object key, tx hash, …).
    pub proof_id: String,
    /// Human-readable location: S3 URL, Base chain explorer link, etc.
    pub location: String,
    pub committed_at: DateTime<Utc>,
}

/// Core abstraction.  All implementations must be `Send + Sync`.
#[async_trait]
pub trait Anchor: Send + Sync {
    async fn commit(&self, decision: &AnchorDecision<'_>) -> Result<AnchorProof, AnchorError>;
}
