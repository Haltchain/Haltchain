/// Integration tests for haltchain-anchor Postgres path.
///
/// Requires DATABASE_URL pointing to a Postgres instance with the HaltChain schema.
use haltchain_anchor::{Anchor, AnchorDecision, PostgresAnchor};
use haltchain_db::DbStore;
use std::sync::Arc;

async fn connect_or_skip() -> Option<Arc<DbStore>> {
    let url = match std::env::var("DATABASE_URL") {
        Ok(u) if !u.is_empty() => u,
        _ => {
            eprintln!("DATABASE_URL not set — skipping integration test");
            return None;
        }
    };
    Some(Arc::new(
        DbStore::connect(&url)
            .await
            .expect("failed to connect to test DB"),
    ))
}

#[tokio::test]
async fn test_postgres_anchor_commit() {
    let Some(db) = connect_or_skip().await else {
        return;
    };

    let anchor = PostgresAnchor::new(db);
    let txn_id = uuid::Uuid::new_v4().to_string();

    let decision = AnchorDecision {
        transaction_id: &txn_id,
        agent_id: "anchor-test-agent",
        decision: "DENY",
        timestamp: &chrono::Utc::now().to_rfc3339(),
        policy_code: Some("MAX_TRANSFER_USD"),
        merkle_root: None,
    };

    let proof = anchor
        .commit(&decision)
        .await
        .expect("postgres anchor commit failed");

    assert_eq!(proof.anchor_type, "postgres");
    assert!(
        !proof.proof_id.is_empty(),
        "proof_id should be the DB row id"
    );
    assert!(
        proof.location.starts_with("decisions_hot.id="),
        "location format unexpected: {}",
        proof.location
    );
}
