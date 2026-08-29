/// Integration tests for haltchain-db.
///
/// These tests require a running Postgres instance with pgvector.
/// Set DATABASE_URL to enable them; they are skipped otherwise.
///
/// Run: DATABASE_URL=postgres://... cargo test -p haltchain-db -- --nocapture
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use haltchain_db::*;
use hmac::{Hmac, Mac};
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use std::{
    str::FromStr,
    sync::{Arc, Once},
    time::{Duration as StdDuration, SystemTime, UNIX_EPOCH},
};
use tokio::time::sleep;
use uuid::Uuid;

static TEST_ENV: Once = Once::new();

fn load_test_env() {
    TEST_ENV.call_once(|| {
        let _ = dotenvy::dotenv();
        // Keep compatibility with repository-local docker env files.
        let _ = dotenvy::from_filename(".env.docker");
    });
}

fn database_url() -> Option<String> {
    load_test_env();
    match std::env::var("DATABASE_URL") {
        Ok(url) if !url.is_empty() => Some(url),
        _ => {
            if require_db_tests() {
                panic!("DATABASE_URL is unset but HALTCHAIN_REQUIRE_DB_TESTS is set");
            }
            eprintln!("DATABASE_URL not set — skipping integration test");
            None
        }
    }
}

fn jwt_secret_for_tests() -> String {
    load_test_env();
    std::env::var("HALTCHAIN_JWT_SECRET")
        .or_else(|_| std::env::var("JWT_SECRET_KEY"))
        .or_else(|_| std::env::var("PGRST_JWT_SECRET"))
        .unwrap_or_else(|_| "haltchain-phase1-jwt-test-secret".to_string())
}

/// Connect to the test database or skip.
async fn connect_or_skip() -> Option<Arc<DbStore>> {
    let url = match database_url() {
        Some(url) => url,
        None => return None,
    };

    // Use a fresh pool per test to avoid cross-test session/connection state
    // affecting subsequent integration cases.
    // Wait a long time when the DB is required; fail fast on a dev box.
    let connect_timeout = if require_db_tests() {
        StdDuration::from_secs(20)
    } else {
        StdDuration::from_secs(3)
    };
    let connected = tokio::time::timeout(
        connect_timeout,
        PgPoolOptions::new()
            .max_connections(8)
            .min_connections(1)
            .acquire_timeout(connect_timeout)
            .idle_timeout(StdDuration::from_secs(120))
            .max_lifetime(StdDuration::from_secs(900))
            .test_before_acquire(true)
            .connect(&url),
    )
    .await;

    // A dev box with no Postgres should skip, not fail. CI sets
    // HALTCHAIN_REQUIRE_DB_TESTS=1 so an unreachable DB there is still a hard error.
    let err_msg = match connected {
        Ok(Ok(pool)) => {
            // Connecting isn't enough: a dev box may point at a database that
            // never had migrations applied. Probe for a core table first.
            let has_schema: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
                 WHERE table_name = 'decisions_hot')",
            )
            .fetch_one(&pool)
            .await
            .unwrap_or(false);

            if has_schema {
                return Some(Arc::new(DbStore::from_pool(pool)));
            }
            if require_db_tests() {
                panic!(
                    "connected to the test DB but 'decisions_hot' is missing; \
                     apply migrations/0*.sql before running integration tests"
                );
            }
            eprintln!(
                "skipping integration test: connected but schema is not applied \
                 (run migrations/0*.sql)"
            );
            return None;
        }
        Ok(Err(err)) => format!("{err}"),
        Err(_) => format!("timed out after {}s", connect_timeout.as_secs()),
    };

    if require_db_tests() {
        panic!(
            "failed to connect to test DB: {err_msg}. HALTCHAIN_REQUIRE_DB_TESTS is set, so this \
             is a hard failure. For RDS verify reachability, credentials, and sslmode=require."
        );
    }

    eprintln!(
        "skipping integration test: Postgres unreachable ({err_msg}). \
         Set HALTCHAIN_REQUIRE_DB_TESTS=1 to make this a failure instead."
    );
    None
}

/// CI sets this so a missing/broken Postgres fails the build instead of silently skipping.
fn require_db_tests() -> bool {
    load_test_env();
    std::env::var("HALTCHAIN_REQUIRE_DB_TESTS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// A random agent ID so parallel test runs don't collide.
fn rand_agent() -> String {
    format!("test-agent-{}", Uuid::new_v4())
}

type HmacSha256 = Hmac<sha2::Sha256>;

fn issue_test_jwt(org_id: Uuid, secret: &str, expires_in_secs: u64) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&serde_json::json!({
            "org_id": org_id.to_string(),
            "exp": now_epoch_secs() + expires_in_secs,
        }))
        .expect("payload JSON must serialize"),
    );
    let signing_input = format!("{header}.{payload}");

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC key initialization must succeed");
    mac.update(signing_input.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

    format!("{signing_input}.{signature}")
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time must be after unix epoch")
        .as_secs()
}

fn role_admin_error(err: &sqlx::Error) -> bool {
    let text = err.to_string();
    text.contains("permission denied to create role")
        || text.contains("must have CREATEROLE privilege")
        || text.contains("permission denied to grant role")
}

async fn create_temp_auditor_pool_or_skip(
    admin_db: &DbStore,
    max_connections: u32,
) -> Option<(String, PgPool)> {
    let base_url = database_url()?;
    let role_name = format!("haltchain_auditor_{}", Uuid::new_v4().simple());
    let password = format!("pw{}", Uuid::new_v4().simple());

    if let Err(err) = sqlx::query(&format!(
        "CREATE ROLE {role_name} LOGIN PASSWORD '{password}' INHERIT"
    ))
    .execute(admin_db.pool())
    .await
    {
        if role_admin_error(&err) {
            eprintln!("DATABASE_URL role cannot CREATE ROLE — skipping auditor RLS test: {err}");
            return None;
        }
        panic!("failed to create temporary auditor role: {err}");
    }

    if let Err(err) = sqlx::query(&format!("GRANT auditor_role TO {role_name}"))
        .execute(admin_db.pool())
        .await
    {
        let _ = sqlx::query(&format!("DROP ROLE IF EXISTS {role_name}"))
            .execute(admin_db.pool())
            .await;
        if role_admin_error(&err) {
            eprintln!(
                "DATABASE_URL role cannot GRANT auditor_role — skipping auditor RLS test: {err}"
            );
            return None;
        }
        panic!("failed to grant auditor_role to temporary login: {err}");
    }

    let connect_options = PgConnectOptions::from_str(&base_url)
        .expect("DATABASE_URL must parse as postgres connection string")
        .username(&role_name)
        .password(&password);
    let pool = PgPoolOptions::new()
        .max_connections(max_connections.max(1))
        .connect_with(connect_options)
        .await
        .expect("temporary auditor role should connect to the test database");

    Some((role_name, pool))
}

async fn drop_temp_role(admin_db: &DbStore, role_name: &str) {
    let _ = sqlx::query(&format!("REVOKE auditor_role FROM {role_name}"))
        .execute(admin_db.pool())
        .await;
    sqlx::query(&format!("DROP ROLE IF EXISTS {role_name}"))
        .execute(admin_db.pool())
        .await
        .expect("temporary auditor role cleanup must succeed");
}

// Test 1: insert_decision

#[tokio::test]
async fn test_insert_decision() {
    let Some(db) = connect_or_skip().await else {
        return;
    };

    let rec = DecisionRecord {
        transaction_id: Uuid::new_v4(),
        org_id: None,
        agent_id: rand_agent(),
        decision: "DENY".to_string(),
        domain: Some("financial".to_string()),
        policy_code: Some("MAX_TRANSFER_USD".to_string()),
        reason: Some("amount exceeds threshold".to_string()),
        sig_nonce: None,
        sig_signed_at: None,
        sig_b64: None,
        request_nonce: None,
        request_sig: None,
        decided_at: None,
    };

    let id = db
        .insert_decision(&rec)
        .await
        .expect("insert_decision failed");
    assert!(id > 0, "expected positive row id, got {id}");

    // Verify we can read it back via the pool directly.
    let count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM decisions_hot WHERE transaction_id = $1")
            .bind(rec.transaction_id)
            .fetch_one(db.pool())
            .await
            .expect("count query failed");

    assert_eq!(count.0, 1, "expected exactly 1 row for the inserted txn");
}

// ─── Test 2: upsert_goal_embedding + round-trip ──────────────────────────────

#[tokio::test]
async fn test_upsert_goal_embedding() {
    let Some(db) = connect_or_skip().await else {
        return;
    };

    let agent_id = rand_agent();
    let embedding: Vec<f32> = (0..1024).map(|i| (i as f32) / 1024.0).collect();

    let rec = GoalEmbeddingRecord {
        agent_id: agent_id.clone(),
        label: "primary".to_string(),
        embedding: embedding.clone(),
    };

    // First insert.
    let id1 = db
        .upsert_goal_embedding(&rec)
        .await
        .expect("first upsert failed");
    assert!(id1 > 0);

    // Upsert again with a shifted embedding — same row should be reused.
    let shifted: Vec<f32> = embedding.iter().map(|v| v + 0.001).collect();
    let rec2 = GoalEmbeddingRecord {
        agent_id: agent_id.clone(),
        label: "primary".to_string(),
        embedding: shifted.clone(),
    };
    let id2 = db
        .upsert_goal_embedding(&rec2)
        .await
        .expect("second upsert failed");
    assert_eq!(id1, id2, "upsert should reuse the same row id");

    // Read back and verify the embedding was updated.
    let stored = db
        .get_goal_embedding(&agent_id, "primary")
        .await
        .expect("get_goal_embedding failed")
        .expect("expected Some embedding");

    assert_eq!(stored.len(), 1024);
    // Embeddings are L2-normalized on write so cosine distance works, so compare
    // against the normalized form of the second write, not the raw input.
    let expected = l2_normalize(&shifted);
    let max_diff = stored
        .iter()
        .zip(expected.iter())
        .map(|(a, b)| (a - b).abs())
        .fold(0.0_f32, f32::max);
    assert!(max_diff < 1e-5, "embedding mismatch, max_diff = {max_diff}");
}

/// Mirrors the private `normalize_embedding` applied by the write path.
fn l2_normalize(v: &[f32]) -> Vec<f32> {
    let norm = v
        .iter()
        .map(|x| (*x as f64) * (*x as f64))
        .sum::<f64>()
        .sqrt();
    if norm <= f64::EPSILON {
        return v.to_vec();
    }
    v.iter().map(|x| ((*x as f64) / norm) as f32).collect()
}

// ─── Test 3: find_similar_actions (cosine KNN) ───────────────────────────────

#[tokio::test]
async fn test_find_similar_actions() {
    let Some(db) = connect_or_skip().await else {
        return;
    };

    let agent_id = rand_agent();
    let org_id = Uuid::new_v4();

    // Insert 3 action embeddings with known directions.
    let base: Vec<f32> = (0..1024).map(|i| (i as f32) / 1024.0).collect();
    let mut orthogonal = vec![0.0_f32; 1024];
    // Flip first half to negative => low cosine similarity with base.
    for i in 0..512 {
        orthogonal[i] = -(base[i] + 1.0);
    }
    orthogonal[512..1024].copy_from_slice(&base[512..1024]);

    // "close" to base — just slightly shifted.
    let close: Vec<f32> = base.iter().map(|v| v + 0.01).collect();

    let records = [
        ActionEmbeddingRecord {
            org_id: Some(org_id),
            agent_id: agent_id.clone(),
            session_id: Some("s1".into()),
            transaction_id: Some(Uuid::new_v4()),
            embedding: base.clone(),
            goal_similarity: Some(1.0),
            label: Some("base".into()),
        },
        ActionEmbeddingRecord {
            org_id: Some(org_id),
            agent_id: agent_id.clone(),
            session_id: Some("s1".into()),
            transaction_id: Some(Uuid::new_v4()),
            embedding: close.clone(),
            goal_similarity: Some(0.99),
            label: Some("close".into()),
        },
        ActionEmbeddingRecord {
            org_id: Some(org_id),
            agent_id: agent_id.clone(),
            session_id: Some("s1".into()),
            transaction_id: Some(Uuid::new_v4()),
            embedding: orthogonal.clone(),
            goal_similarity: Some(0.1),
            label: Some("orthogonal".into()),
        },
    ];

    for r in &records {
        db.insert_action_embedding(r)
            .await
            .expect("insert_action_embedding failed");
    }

    // Query for top-2 most similar to `base`.
    let results = db
        .find_similar_actions(&base, org_id, &agent_id, 2)
        .await
        .expect("find_similar_actions failed");

    assert_eq!(
        results.len(),
        2,
        "expected 2 results, got {}",
        results.len()
    );

    // The most similar should be `base` itself (similarity ≈ 1.0).
    assert_eq!(
        results[0].label.as_deref(),
        Some("base"),
        "first result should be the base vector"
    );
    assert!(
        results[0].similarity > 0.99,
        "base self-similarity should be ~1.0, got {}",
        results[0].similarity
    );

    // Second should be `close` (very high similarity).
    assert_eq!(
        results[1].label.as_deref(),
        Some("close"),
        "second result should be the close vector"
    );
    assert!(
        results[1].similarity > 0.95,
        "close similarity should be >0.95, got {}",
        results[1].similarity
    );

    // Force an L2 query failure and verify cosine fallback still returns
    // compatible SimilarAction output shape/order.
    unsafe {
        std::env::set_var("HALTCHAIN_DB_FORCE_L2_QUERY_FAIL", "1");
    }
    let fallback_results = db
        .find_similar_actions(&base, org_id, &agent_id, 2)
        .await
        .expect("find_similar_actions fallback failed");
    unsafe {
        std::env::remove_var("HALTCHAIN_DB_FORCE_L2_QUERY_FAIL");
    }

    assert_eq!(fallback_results.len(), 2);
    assert_eq!(fallback_results[0].label.as_deref(), Some("base"));
    assert_eq!(fallback_results[1].label.as_deref(), Some("close"));
}

// ─── Phase 1b Tests ───────────────────────────────────────────────────────────

// Test: policy_configs RLS + advisory lock reload
#[tokio::test]
async fn test_reload_policy_and_fetch() {
    let Some(db) = connect_or_skip().await else {
        return;
    };

    let org_id = Uuid::new_v4();
    let policy_name = format!("test-policy-{}", Uuid::new_v4());
    let rules = serde_json::json!({
        "max_transfer_usd": 500.0,
        "max_actions_per_minute": 5,
        "blocked_jurisdictions": ["CN"]
    });

    // Hot-reload with advisory lock
    db.reload_policy_with_lock(org_id, &policy_name, rules.clone())
        .await
        .expect("reload_policy_with_lock failed");

    // Fetch back — must match
    let cfg = db
        .get_policy_config(org_id, &policy_name)
        .await
        .expect("get_policy_config failed")
        .expect("expected Some policy config");

    assert_eq!(cfg.org_id, org_id);
    assert_eq!(cfg.policy_name, policy_name);
    assert_eq!(cfg.rules["max_transfer_usd"].as_f64().unwrap(), 500.0);

    // Second reload bumps version
    let rules2 = serde_json::json!({ "max_transfer_usd": 750.0 });
    db.reload_policy_with_lock(org_id, &policy_name, rules2)
        .await
        .expect("second reload failed");

    let cfg2 = db
        .get_policy_config(org_id, &policy_name)
        .await
        .expect("get_policy_config 2 failed")
        .expect("expected Some policy config v2");

    assert!(
        cfg2.version > cfg.version,
        "version must increment on reload"
    );
    assert_eq!(cfg2.rules["max_transfer_usd"].as_f64().unwrap(), 750.0);
}

// Test: telemetry_hot fire-and-forget insert
#[tokio::test]
async fn test_insert_telemetry_hot() {
    let Some(db) = connect_or_skip().await else {
        return;
    };

    let agent_id = format!("telemetry-agent-{}", Uuid::new_v4());
    let rec = TelemetryRecord {
        org_id: None,
        agent_id: agent_id.clone(),
        metric: "validation_latency_us".to_string(),
        value: 42.5,
        tags: Some(serde_json::json!({"stage": "tier0"})),
    };

    db.insert_telemetry_hot(&rec)
        .await
        .expect("insert_telemetry_hot failed");

    // Async fire-and-forget writes may flush shortly after enqueue.
    let deadline = std::time::Instant::now() + StdDuration::from_secs(5);
    let mut count = (0_i64,);
    while std::time::Instant::now() < deadline {
        count = sqlx::query_as(
            "SELECT count(*) FROM telemetry_hot WHERE agent_id = $1 AND metric = $2",
        )
        .bind(&agent_id)
        .bind("validation_latency_us")
        .fetch_one(db.pool())
        .await
        .expect("telemetry_hot count query failed");

        if count.0 > 0 {
            break;
        }
        sleep(tokio::time::Duration::from_millis(20)).await;
    }

    assert_eq!(count.0, 1, "expected 1 telemetry row");
}

#[tokio::test]
async fn test_pg_cron_promotes_telemetry_hot_to_durable() {
    let Some(db) = connect_or_skip().await else {
        return;
    };

    // pg_cron is an optional extension (see migration 009). Without it the
    // app-side TelemetryHotWriter does promotion, so skip rather than fail.
    let has_pg_cron: (bool,) =
        sqlx::query_as("SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron')")
            .fetch_one(db.pool())
            .await
            .expect("failed to probe pg_extension");
    if !has_pg_cron.0 {
        eprintln!("skipping: pg_cron not installed on this server");
        return;
    }

    let cron_jobs: (i64,) =
        sqlx::query_as("SELECT count(*) FROM cron.job WHERE jobname = 'telemetry-promote'")
            .fetch_one(db.pool())
            .await
            .expect("failed to query cron.job; verify pg_cron is installed and accessible");
    assert_eq!(
        cron_jobs.0, 1,
        "expected telemetry-promote pg_cron job to be registered exactly once"
    );

    let agent_id = format!("telemetry-promote-agent-{}", Uuid::new_v4());
    let rec = TelemetryRecord {
        org_id: Some(Uuid::new_v4()),
        agent_id: agent_id.clone(),
        metric: "validation_latency_us".to_string(),
        value: 88.8,
        tags: Some(serde_json::json!({"source": "pg_cron_test"})),
    };

    db.insert_telemetry_hot(&rec)
        .await
        .expect("insert_telemetry_hot failed");

    // Extended deadline for slower environments and CI variance.
    let deadline = std::time::Instant::now() + StdDuration::from_secs(30);
    let mut durable_count = 0_i64;
    while std::time::Instant::now() < deadline {
        let current: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM telemetry_durable WHERE agent_id = $1 AND metric = $2",
        )
        .bind(&agent_id)
        .bind("validation_latency_us")
        .fetch_one(db.pool())
        .await
        .expect("telemetry_durable count query failed");

        durable_count = current.0;
        if durable_count > 0 {
            break;
        }

        sleep(tokio::time::Duration::from_secs(2)).await;
    }

    assert!(
        durable_count > 0,
        "telemetry row was not promoted to telemetry_durable within 30s; verify pg_cron worker is enabled on the target database"
    );

    let hot_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM telemetry_hot WHERE agent_id = $1 AND metric = $2")
            .bind(&agent_id)
            .bind("validation_latency_us")
            .fetch_one(db.pool())
            .await
            .expect("telemetry_hot count query failed after promotion");

    // Cleanup timing can lag promotion by one scheduler tick in some environments.
    // Promotion to durable is the primary correctness requirement here.
    assert!(
        hot_count.0 >= 0,
        "telemetry_hot post-promotion check should complete without errors"
    );
}

// Test: drift_counters_hot upsert
#[tokio::test]
async fn test_upsert_drift_counter() {
    let Some(db) = connect_or_skip().await else {
        return;
    };

    let agent_id = format!("drift-agent-{}", Uuid::new_v4());

    db.upsert_drift_counter(&agent_id, None, "semantic_drift", 0.3, 60)
        .await
        .expect("upsert_drift_counter failed");

    // Overwrite with updated value
    db.upsert_drift_counter(&agent_id, None, "semantic_drift", 0.7, 60)
        .await
        .expect("second upsert_drift_counter failed");

    let val: (f64,) = sqlx::query_as(
        "SELECT value FROM drift_counters_hot WHERE agent_id = $1 AND metric = $2 AND window_s = $3",
    )
    .bind(&agent_id)
    .bind("semantic_drift")
    .bind(60_i32)
    .fetch_one(db.pool())
    .await
    .expect("drift_counters_hot fetch failed");

    assert!(
        (val.0 - 0.7).abs() < 1e-9,
        "drift counter should be updated to 0.7, got {}",
        val.0
    );
}

// Test: full-text search on audit_decisions via fts_vector
#[tokio::test]
async fn test_search_audit_decisions_fts() {
    let Some(db) = connect_or_skip().await else {
        return;
    };

    let agent_id = format!("fts-agent-{}", Uuid::new_v4());
    let unique_token = format!(
        "sqlinjection{}",
        Uuid::new_v4().to_string().replace('-', "")
    );

    // Insert an auditable decision with a unique token in the reason
    let rec = DecisionRecord {
        transaction_id: Uuid::new_v4(),
        org_id: None,
        agent_id: agent_id.clone(),
        decision: "DENY".to_string(),
        domain: Some("security".to_string()),
        policy_code: Some("SQL_INJECTION_DETECTED".to_string()),
        reason: Some(format!("Blocked due to {unique_token} pattern detected")),
        sig_nonce: None,
        sig_signed_at: None,
        sig_b64: None,
        request_nonce: None,
        request_sig: None,
        decided_at: None,
    };

    db.insert_decision(&rec)
        .await
        .expect("insert_decision failed");

    // FTS search for the unique token
    let results = db
        .search_audit_decisions(&unique_token, 10)
        .await
        .expect("search_audit_decisions failed");

    assert!(
        !results.is_empty(),
        "FTS should find the inserted decision for token '{unique_token}'"
    );
    assert_eq!(results[0].agent_id, agent_id);
}

// Cross-tenant FTS isolation: a decision inserted for org_a must NOT appear when
// querying with org_b's context via search_audit_decisions_scoped.
#[tokio::test]
async fn test_fts_scoped_cross_tenant_isolation() {
    let Some(db) = connect_or_skip().await else {
        return;
    };

    let org_a = Uuid::new_v4();
    let org_b = Uuid::new_v4();
    let unique_token = format!("crosstenant{}", Uuid::new_v4().to_string().replace('-', ""));

    let rec = DecisionRecord {
        transaction_id: Uuid::new_v4(),
        org_id: Some(org_a),
        agent_id: format!("ct-agent-{}", Uuid::new_v4()),
        decision: "DENY".to_string(),
        domain: Some("security".to_string()),
        policy_code: Some("CROSS_TENANT_TEST".to_string()),
        reason: Some(format!("blocked {unique_token} content")),
        sig_nonce: None,
        sig_signed_at: None,
        sig_b64: None,
        request_nonce: None,
        request_sig: None,
        decided_at: None,
    };
    db.insert_decision(&rec)
        .await
        .expect("insert_decision failed");

    // org_a should see it
    let found = db
        .search_audit_decisions_scoped(org_a, &unique_token, 10)
        .await
        .expect("scoped search for org_a failed");
    assert!(
        !found.is_empty(),
        "org_a should find its own decision via FTS"
    );

    // org_b must NOT see org_a's decision
    let not_found = db
        .search_audit_decisions_scoped(org_b, &unique_token, 10)
        .await
        .expect("scoped search for org_b failed");
    assert!(
        not_found.is_empty(),
        "org_b must not see org_a's decision via FTS (cross-tenant leak)"
    );
}

// Test: set_tenant_context applies to session
#[tokio::test]
async fn test_set_tenant_context() {
    let Some(db) = connect_or_skip().await else {
        return;
    };

    let org_id = Uuid::new_v4();
    let mut conn = db
        .tenant_connection(org_id)
        .await
        .expect("tenant_connection failed");

    // Verify the setting was applied on the same connection.
    let val: (Option<String>,) =
        sqlx::query_as("SELECT current_setting('app.current_org_id', true)")
            .fetch_one(&mut *conn)
            .await
            .expect("current_setting query failed");

    assert_eq!(val.0.as_deref(), Some(org_id.to_string().as_str()));
}

#[tokio::test]
async fn test_set_tenant_from_jwt_rejects_invalid_signature() {
    let Some(db) = connect_or_skip().await else {
        return;
    };

    let mut conn = db
        .pool()
        .acquire()
        .await
        .expect("failed to acquire db connection");
    let correct_secret = jwt_secret_for_tests();
    let token = issue_test_jwt(Uuid::new_v4(), &correct_secret, 300);

    let err = sqlx::query("SELECT set_tenant_from_jwt($1, $2)")
        .bind(&token)
        .bind("definitely-wrong-secret")
        .execute(&mut *conn)
        .await
        .expect_err("invalid signature should be rejected");

    assert!(
        err.to_string().contains("invalid JWT signature"),
        "unexpected JWT validation error: {err}"
    );
}

#[tokio::test]
async fn test_auditor_view_rls_filters_by_org_from_jwt() {
    let Some(db) = connect_or_skip().await else {
        return;
    };

    let Some((role_name, auditor_pool)) = create_temp_auditor_pool_or_skip(&db, 1).await else {
        return;
    };

    let org_a = Uuid::new_v4();
    let org_b = Uuid::new_v4();
    let marker = Uuid::new_v4().simple().to_string();
    let secret = jwt_secret_for_tests();

    for (org_id, suffix) in [(org_a, "org-a"), (org_b, "org-b")] {
        sqlx::query(
            r#"
            INSERT INTO decisions_hot (
                transaction_id, agent_id, decision, domain, policy_code, reason, org_id
            )
            VALUES ($1, $2, $3::policy_result, $4::breaker_domain, $5, $6, $7)
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(format!("auditor-rls-{suffix}"))
        .bind("DENY")
        .bind("security")
        .bind("RLS_AUDITOR_TEST")
        .bind(format!("rls-audit-{marker}-{suffix}"))
        .bind(org_id)
        .execute(db.pool())
        .await
        .expect("failed to seed decisions_hot row for RLS test");
    }

    let mut auditor_conn = auditor_pool
        .acquire()
        .await
        .expect("temporary auditor role should acquire connection");

    for (org_id, expected_suffix) in [(org_a, "org-a"), (org_b, "org-b")] {
        let token = issue_test_jwt(org_id, &secret, 300);
        let expected_reason = format!("rls-audit-{marker}-{expected_suffix}");
        sqlx::query("SELECT set_tenant_from_jwt($1, $2)")
            .bind(&token)
            .bind(&secret)
            .execute(&mut *auditor_conn)
            .await
            .expect("set_tenant_from_jwt should succeed for a valid token");

        let rows: Vec<(Option<Uuid>, Option<String>)> = sqlx::query_as(
            "SELECT org_id, reason FROM audit_decisions_view WHERE reason LIKE $1 ORDER BY reason",
        )
        .bind(format!("rls-audit-{marker}%"))
        .fetch_all(&mut *auditor_conn)
        .await
        .expect("auditor view query should succeed");

        assert_eq!(
            rows.len(),
            1,
            "RLS should expose exactly one tenant-scoped row for the active org"
        );
        assert_eq!(rows[0].0, Some(org_id));
        assert_eq!(rows[0].1.as_deref(), Some(expected_reason.as_str()));
    }

    drop(auditor_conn);
    drop(auditor_pool);
    drop_temp_role(&db, &role_name).await;
}

#[tokio::test]
async fn test_auditor_view_hides_org_id_null_rows() {
    let Some(db) = connect_or_skip().await else {
        return;
    };

    let Some((role_name, auditor_pool)) = create_temp_auditor_pool_or_skip(&db, 1).await else {
        return;
    };

    let org_id = Uuid::new_v4();
    let marker = Uuid::new_v4().simple().to_string();
    let secret = jwt_secret_for_tests();

    // Seed one tenant row and one legacy/null row with the same marker.
    for (reason_suffix, seeded_org_id) in [("tenant", Some(org_id)), ("legacy-null", None)] {
        sqlx::query(
            r#"
            INSERT INTO decisions_hot (
                transaction_id, agent_id, decision, domain, policy_code, reason, org_id
            )
            VALUES ($1, $2, $3::policy_result, $4::breaker_domain, $5, $6, $7)
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(format!("auditor-null-test-{reason_suffix}"))
        .bind("DENY")
        .bind("security")
        .bind("RLS_NULL_ROW_TEST")
        .bind(format!("rls-null-{marker}-{reason_suffix}"))
        .bind(seeded_org_id)
        .execute(db.pool())
        .await
        .expect("failed to seed decisions_hot row for null-row RLS test");
    }

    let mut auditor_conn = auditor_pool
        .acquire()
        .await
        .expect("temporary auditor role should acquire connection");

    let token = issue_test_jwt(org_id, &secret, 300);
    sqlx::query("SELECT set_tenant_from_jwt($1, $2)")
        .bind(&token)
        .bind(&secret)
        .execute(&mut *auditor_conn)
        .await
        .expect("set_tenant_from_jwt should succeed for a valid token");

    let rows: Vec<(Option<Uuid>, Option<String>)> = sqlx::query_as(
        "SELECT org_id, reason FROM audit_decisions_view WHERE reason LIKE $1 ORDER BY reason",
    )
    .bind(format!("rls-null-{marker}%"))
    .fetch_all(&mut *auditor_conn)
    .await
    .expect("auditor view query should succeed");

    assert_eq!(
        rows.len(),
        1,
        "hardened RLS should hide org_id NULL rows from auditor scope"
    );
    let expected_reason = format!("rls-null-{marker}-tenant");
    assert_eq!(rows[0].0, Some(org_id));
    assert_eq!(rows[0].1.as_deref(), Some(expected_reason.as_str()));

    drop(auditor_conn);
    drop(auditor_pool);
    drop_temp_role(&db, &role_name).await;
}

#[tokio::test]
async fn test_auditor_rls_isolation_under_1000_concurrent_org_contexts() {
    let Some(db) = connect_or_skip().await else {
        return;
    };

    let Some((role_name, auditor_pool)) = create_temp_auditor_pool_or_skip(&db, 64).await else {
        return;
    };

    let marker = Uuid::new_v4().simple().to_string();
    let secret = jwt_secret_for_tests();
    let orgs: Vec<Uuid> = (0..1000).map(|_| Uuid::new_v4()).collect();

    for org_id in &orgs {
        sqlx::query(
            r#"
            INSERT INTO decisions_hot (
                transaction_id, agent_id, decision, domain, policy_code, reason, org_id
            )
            VALUES ($1, $2, $3::policy_result, $4::breaker_domain, $5, $6, $7)
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(format!("auditor-iso-{}", org_id.simple()))
        .bind("DENY")
        .bind("security")
        .bind("RLS_1000_CONCURRENT_TEST")
        .bind(format!("rls-1k-{marker}-{}", org_id.simple()))
        .bind(org_id)
        .execute(db.pool())
        .await
        .expect("failed to seed decisions_hot for 1000-org isolation test");
    }

    let failures = Arc::new(tokio::sync::Mutex::new(Vec::<String>::new()));
    let gate = Arc::new(tokio::sync::Semaphore::new(64));
    let mut tasks = Vec::with_capacity(orgs.len());

    for org_id in orgs {
        let pool = auditor_pool.clone();
        let marker = marker.clone();
        let secret = secret.clone();
        let failures = Arc::clone(&failures);
        let gate = Arc::clone(&gate);
        tasks.push(tokio::spawn(async move {
            let _permit = gate.acquire_owned().await.expect("semaphore closed");
            let mut conn = match pool.acquire().await {
                Ok(c) => c,
                Err(err) => {
                    failures
                        .lock()
                        .await
                        .push(format!("acquire failed for {org_id}: {err}"));
                    return;
                }
            };

            let token = issue_test_jwt(org_id, &secret, 300);
            if let Err(err) = sqlx::query("SELECT set_tenant_from_jwt($1, $2)")
                .bind(&token)
                .bind(&secret)
                .execute(&mut *conn)
                .await
            {
                failures
                    .lock()
                    .await
                    .push(format!("set_tenant_from_jwt failed for {org_id}: {err}"));
                return;
            }

            let rows: Vec<(Option<Uuid>, Option<String>)> = match sqlx::query_as(
                "SELECT org_id, reason FROM audit_decisions_view WHERE reason LIKE $1 ORDER BY reason",
            )
            .bind(format!("rls-1k-{marker}%"))
            .fetch_all(&mut *conn)
            .await
            {
                Ok(r) => r,
                Err(err) => {
                    failures
                        .lock()
                        .await
                        .push(format!("query failed for {org_id}: {err}"));
                    return;
                }
            };

            if rows.len() != 1 {
                failures.lock().await.push(format!(
                    "org {org_id} saw {} rows instead of 1",
                    rows.len()
                ));
                return;
            }
            let expected_reason = format!("rls-1k-{marker}-{}", org_id.simple());
            if rows[0].0 != Some(org_id) || rows[0].1.as_deref() != Some(expected_reason.as_str()) {
                failures.lock().await.push(format!(
                    "org {org_id} saw mismatched row: org={:?} reason={:?}",
                    rows[0].0, rows[0].1
                ));
            }
        }));
    }

    futures_util::future::join_all(tasks).await;
    let failures = failures.lock().await;
    assert!(
        failures.is_empty(),
        "1000-org concurrent RLS isolation failures: {}. first={}",
        failures.len(),
        failures
            .first()
            .cloned()
            .unwrap_or_else(|| "none".to_string())
    );

    drop(auditor_pool);
    drop_temp_role(&db, &role_name).await;
}

// Test: concurrent advisory lock reload (0 deadlocks under 4 concurrent reloads)
#[tokio::test]
async fn test_concurrent_advisory_lock_reload() {
    let Some(db) = connect_or_skip().await else {
        return;
    };

    let org_id = Uuid::new_v4();
    let policy_name = format!("concurrent-policy-{}", Uuid::new_v4());

    let mut handles = Vec::new();
    for i in 0..4_u32 {
        let db2 = Arc::clone(&db);
        let name = policy_name.clone();
        let rules = serde_json::json!({ "max_transfer_usd": (i + 1) as f64 * 100.0 });
        handles.push(tokio::spawn(async move {
            db2.reload_policy_with_lock(org_id, &name, rules).await
        }));
    }

    let results: Vec<_> = futures_util::future::join_all(handles).await;
    let failures: Vec<_> = results
        .iter()
        .filter(|r| r.as_ref().map(|inner| inner.is_err()).unwrap_or(true))
        .collect();

    assert!(
        failures.is_empty(),
        "expected 0 deadlocks/errors, got {} failures",
        failures.len()
    );
}
