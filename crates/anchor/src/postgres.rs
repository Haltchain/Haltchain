use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use haltchain_db::{DbStore, DecisionRecord};
use uuid::Uuid;

use crate::{Anchor, AnchorDecision, AnchorError, AnchorProof};

pub struct PostgresAnchor {
    db: Arc<DbStore>,
}

impl PostgresAnchor {
    pub fn new(db: Arc<DbStore>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl Anchor for PostgresAnchor {
    async fn commit(&self, d: &AnchorDecision<'_>) -> Result<AnchorProof, AnchorError> {
        let tx_id = Uuid::parse_str(d.transaction_id).unwrap_or_else(|_| Uuid::new_v4());
        let record = DecisionRecord {
            transaction_id: tx_id,
            org_id: None,
            agent_id: d.agent_id.to_string(),
            decision: d.decision.to_string(),
            domain: None,
            policy_code: d.policy_code.map(str::to_string),
            reason: None,
            sig_nonce: None,
            sig_signed_at: None,
            sig_b64: None,
            request_nonce: None,
            request_sig: None,
            decided_at: chrono::DateTime::parse_from_rfc3339(d.timestamp)
                .ok()
                .map(|dt| dt.with_timezone(&chrono::Utc)),
        };
        let row_id = self
            .db
            .insert_decision(&record)
            .await
            .map_err(|e| AnchorError::Database(e.to_string()))?;
        Ok(AnchorProof {
            anchor_type: "postgres",
            proof_id: row_id.to_string(),
            location: format!("decisions_hot.id={row_id}"),
            committed_at: Utc::now(),
        })
    }
}
