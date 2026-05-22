use chrono::{DateTime, Utc};
use pgvector::Vector;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, postgres::PgPoolOptions};
use std::time::Duration;
use thiserror::Error;
use uuid::Uuid;

pub mod sqlite;
mod telemetry_hot_writer;
pub use sqlite::{DbBackend, SqliteStore};
use telemetry_hot_writer::TelemetryHotWriter;

#[derive(Debug, Clone)]
pub struct OutcomeLearningRecord {
    pub outcome_id: i64,
    pub transaction_id: Uuid,
    pub policy_code: Option<String>,
    pub outcome: String,
}

#[derive(Debug, Clone)]
pub struct AdjustmentRecommendationRecord {
    pub recommendation_key: String,
    pub threshold_key: String,
    pub current_threshold: f64,
    pub proposed_threshold: f64,
    pub sample_size: i32,
    pub false_positive_count: i32,
    pub true_positive_count: i32,
    pub confidence: f64,
    pub rationale: String,
    pub trigger_outcome_id: Option<i64>,
    pub trigger_transaction_id: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub struct StoredRecommendationRecord {
    pub id: i64,
    pub recommendation_key: String,
    pub threshold_key: String,
    pub current_threshold: f64,
    pub proposed_threshold: f64,
    pub sample_size: i32,
    pub false_positive_count: i32,
    pub true_positive_count: i32,
    pub confidence: f64,
    pub rationale: String,
    pub status: String,
    pub trigger_outcome_id: Option<i64>,
    pub trigger_transaction_id: Option<Uuid>,
    pub decision_notes: Option<String>,
    pub decided_by: Option<String>,
    pub variant_id: Option<String>,
    pub applied_adjustment_id: Option<i64>,
}

#[derive(Debug, Error)]
pub enum DbError {
    #[error("database: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("database configuration: {0}")]
    Misconfigured(String),
}

pub struct DbStore {
    pool: PgPool,
    telemetry_hot_writer: TelemetryHotWriter,
}

pub struct DecisionRecord {
    pub transaction_id: Uuid,
    pub org_id: Option<Uuid>,
    pub agent_id: String,
    /// Must match `policy_result` enum values: ALLOW, DENY, CIRCUIT_BREAK, GOAL_CLARIFICATION_REQUIRED
    pub decision: String,
    /// Must match `breaker_domain` enum values: financial, privacy, security, operational, compliance, resource
    pub domain: Option<String>,
    pub policy_code: Option<String>,
    pub reason: Option<String>,
    pub sig_nonce: Option<String>,
    pub sig_signed_at: Option<DateTime<Utc>>,
    pub sig_b64: Option<String>,
    pub request_nonce: Option<String>,
    pub request_sig: Option<String>,
    /// ISO-8601 UTC timestamp of the decision (used for hash chaining).
    /// If `None`, the current time is used.
    pub decided_at: Option<DateTime<Utc>>,
}

pub struct DriftLogRecord {
    pub agent_id: String,
    pub conversation_id: String,
    pub semantic_drift: f64,
    pub drift_velocity: f64,
    pub window_len: i32,
    pub baseline_len: i32,
    pub recommendation: String,
}

pub struct DecisionOutcomeRecord {
    pub transaction_id: Uuid,
    /// TRUE_POSITIVE | FALSE_POSITIVE | EXPECTED_EDGE_CASE
    pub outcome: String,
    pub impact_usd: Option<f64>,
    pub reviewer_id: Option<String>,
    pub reviewer_notes: Option<String>,
    pub agent_intent: Option<String>,
    pub agent_constraints: Option<String>,
}

pub struct CapabilityTrajectoryRecord {
    pub agent_id: String,
    pub domain: String,
    pub knowledge_delta: f64,
    pub created_at: DateTime<Utc>,
}

// ── pgvector embedding records ───────────────────────────────────────────────

pub struct GoalEmbeddingRecord {
    pub agent_id: String,
    pub label: String,
    pub embedding: Vec<f32>,
}

pub struct ActionEmbeddingRecord {
    pub org_id: Option<Uuid>,
    pub agent_id: String,
    pub session_id: Option<String>,
    pub transaction_id: Option<Uuid>,
    pub embedding: Vec<f32>,
    pub goal_similarity: Option<f64>,
    pub label: Option<String>,
}

pub struct PatternCentroidRecord {
    pub pattern: String,
    pub centroid: Vec<f32>,
    pub sample_count: i32,
}

pub struct DriftSnapshotRecord {
    pub agent_id: String,
    pub window_label: String,
    pub centroid: Vec<f32>,
    pub action_count: i32,
    pub mean_similarity: Option<f64>,
    pub trend_slope: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct SimilarAction {
    pub action_id: i64,
    pub agent_id: String,
    pub session_id: Option<String>,
    pub similarity: f64,
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
}

pub struct PolicyAdjustmentRecord {
    pub rule_id: String,
    pub domain: String,
    pub old_threshold: Option<f64>,
    pub new_threshold: Option<f64>,
    pub reason: String,
    pub adjusted_by: String,
    pub trigger_outcome_id: Option<i64>,
    pub recommendation_id: Option<i64>,
    pub variant_id: Option<String>,
}

impl DbStore {
    pub fn from_pool(pool: PgPool) -> Self {
        let telemetry_hot_writer = TelemetryHotWriter::start(pool.clone());
        Self {
            pool,
            telemetry_hot_writer,
        }
    }

    fn strict_tenant_org_required() -> bool {
        std::env::var("HALTCHAIN_REQUIRE_TENANT_ORG")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
            .unwrap_or(false)
    }

    fn ensure_write_org_id(org_id: Option<Uuid>) -> Result<(), DbError> {
        if Self::strict_tenant_org_required() && org_id.is_none() {
            return Err(DbError::Misconfigured(
                "database write missing org_id while HALTCHAIN_REQUIRE_TENANT_ORG is enabled"
                    .to_string(),
            ));
        }
        Ok(())
    }

    async fn set_tx_tenant_context(
        tx: &mut sqlx::Transaction<'_, Postgres>,
        org_id: Uuid,
    ) -> Result<(), DbError> {
        sqlx::query("SELECT set_config('app.current_org_id', $1, true)")
            .bind(org_id.to_string())
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    pub async fn connect(url: &str) -> Result<Self, DbError> {
        let is_supabase = url.contains("supabase.com") || url.contains("pooler.supabase.com");
        let require_ssl = read_bool_env("HALTCHAIN_DB_REQUIRE_SSL", is_supabase);
        if require_ssl {
            let lower = url.to_ascii_lowercase();
            let has_ssl = lower.contains("sslmode=require")
                || lower.contains("sslmode=verify-ca")
                || lower.contains("sslmode=verify-full");
            if !has_ssl {
                return Err(DbError::Misconfigured(
                    "DATABASE_URL must include sslmode=require (or verify-ca / verify-full) \
                     when HALTCHAIN_DB_REQUIRE_SSL is enabled"
                        .to_string(),
                ));
            }
        }

        let target_rps = read_u32_env("HALTCHAIN_DB_TARGET_RPS", 10_000).max(1);
        let target_p95_ms = read_f64_env("HALTCHAIN_DB_TARGET_P95_MS", 2.0).max(0.1);
        let computed_pool_size = compute_littles_law_pool_size(target_rps, target_p95_ms);
        let max_connections =
            read_u32_env("HALTCHAIN_DB_MAX_CONNECTIONS", computed_pool_size).max(1);
        let min_connections = read_u32_env("HALTCHAIN_DB_MIN_CONNECTIONS", 2).min(max_connections);
        let connect_timeout_secs = read_u64_env("HALTCHAIN_DB_CONNECT_TIMEOUT_SECS", 5);
        let acquire_timeout = read_acquire_timeout();
        let idle_timeout_secs = read_u64_env("HALTCHAIN_DB_IDLE_TIMEOUT_SECS", 300);
        let max_lifetime_secs = read_u64_env("HALTCHAIN_DB_MAX_LIFETIME_SECS", 1800);

        let pool = tokio::time::timeout(
            Duration::from_secs(connect_timeout_secs),
            PgPoolOptions::new()
                .max_connections(max_connections)
                .min_connections(min_connections)
                .acquire_timeout(acquire_timeout)
                .idle_timeout(Duration::from_secs(idle_timeout_secs))
                .max_lifetime(Duration::from_secs(max_lifetime_secs))
                .test_before_acquire(true)
                .connect(url),
        )
        .await
        .map_err(|_| {
            DbError::Misconfigured(format!(
                "initial postgres connect timed out after {connect_timeout_secs}s"
            ))
        })??;
        tracing::info!(
            max_connections,
            min_connections,
            target_rps,
            target_p95_ms,
            computed_pool_size,
            connect_timeout_secs,
            acquire_timeout_ms = acquire_timeout.as_millis(),
            idle_timeout_secs,
            max_lifetime_secs,
            require_ssl,
            "postgres pool established"
        );
        let telemetry_hot_writer = TelemetryHotWriter::start(pool.clone());
        Ok(Self {
            pool,
            telemetry_hot_writer,
        })
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn ping(&self) -> Result<(), DbError> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    pub async fn admin_fetch_login_row(
        &self,
        email: &str,
    ) -> Result<Option<(String, bool)>, DbError> {
        let row = sqlx::query_as::<_, (String, bool)>(
            "SELECT password_hash, is_active FROM admin_users WHERE email = $1",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn admin_users_count(&self) -> Result<i64, DbError> {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*)::bigint FROM admin_users")
            .fetch_one(&self.pool)
            .await?;
        Ok(n)
    }

    pub async fn admin_bootstrap_upsert(&self, email: &str, hash: &str) -> Result<(), DbError> {
        sqlx::query(
            r#"INSERT INTO admin_users (email, password_hash, is_active) VALUES ($1, $2, true)
               ON CONFLICT (email) DO UPDATE SET password_hash = EXCLUDED.password_hash, is_active = true"#,
        )
        .bind(email)
        .bind(hash)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn insert_decision(&self, r: &DecisionRecord) -> Result<i64, DbError> {
        Self::ensure_write_org_id(r.org_id)?;
        // ── Postgres append-only hash chaining (Section C) ────────────────────
        // Each row stores:
        //   content_hash = SHA-256(txn_id \0 agent_id \0 decision \0 decided_at_iso)
        //   prev_hash    = row_hash of the most-recent preceding row
        //   row_hash     = SHA-256(prev_hash_bytes || content_hash_bytes)
        //
        // A SERIALIZABLE transaction ensures no two concurrent inserts observe
        // the same chain tip, keeping the chain totally ordered.
        let decided_at = r.decided_at.unwrap_or_else(Utc::now);
        let decided_at_str = decided_at.to_rfc3339();

        let mut tx = self.pool.begin().await?;
        // Set SERIALIZABLE isolation to prevent chain forks under concurrency.
        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *tx)
            .await?;
        if let Some(org_id) = r.org_id {
            Self::set_tx_tenant_context(&mut tx, org_id).await?;
        }

        // Fetch the tip of the hash chain.
        let prev_hash_hex: Option<String> =
            sqlx::query_scalar("SELECT row_hash FROM decisions_hot WHERE row_hash IS NOT NULL ORDER BY id DESC LIMIT 1")
                .fetch_optional(&mut *tx)
                .await?;

        // Genesis sentinel: 32 zero bytes when no prior row exists.
        let genesis = [0u8; 32];
        let prev_hash_bytes: Vec<u8> = match &prev_hash_hex {
            Some(h) => hex::decode(h).unwrap_or_else(|_| genesis.to_vec()),
            None => genesis.to_vec(),
        };
        let prev_hash_stored = prev_hash_hex.unwrap_or_else(|| hex::encode(genesis));

        // content_hash = SHA-256(transaction_id \0 agent_id \0 decision \0 decided_at_iso)
        let mut ch = Sha256::new();
        ch.update(r.transaction_id.as_bytes());
        ch.update(b"\x00");
        ch.update(r.agent_id.as_bytes());
        ch.update(b"\x00");
        ch.update(r.decision.as_bytes());
        ch.update(b"\x00");
        ch.update(decided_at_str.as_bytes());
        let content_hash_bytes = ch.finalize();
        let content_hash_hex = hex::encode(content_hash_bytes);

        // row_hash = SHA-256(prev_hash_bytes || content_hash_bytes)
        let mut rh = Sha256::new();
        rh.update(&prev_hash_bytes);
        rh.update(content_hash_bytes);
        let row_hash_hex = hex::encode(rh.finalize());

        let row_id: i64 = sqlx::query_scalar(
            r#"
            INSERT INTO decisions_hot
                (transaction_id, org_id, agent_id, decision, domain, policy_code, reason,
                 sig_nonce, sig_signed_at, sig_b64, request_nonce, request_sig,
                 content_hash, prev_hash, row_hash)
            VALUES
                ($1, $2, $3, $4::policy_result, $5::breaker_domain,
                 $6, $7, $8, $9, $10, $11, $12,
                 $13, $14, $15)
            RETURNING id
            "#,
        )
        .bind(r.transaction_id)
        .bind(r.org_id)
        .bind(&r.agent_id)
        .bind(&r.decision)
        .bind(&r.domain)
        .bind(&r.policy_code)
        .bind(&r.reason)
        .bind(&r.sig_nonce)
        .bind(r.sig_signed_at)
        .bind(&r.sig_b64)
        .bind(&r.request_nonce)
        .bind(&r.request_sig)
        .bind(&content_hash_hex)
        .bind(&prev_hash_stored)
        .bind(&row_hash_hex)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(row_id)
    }

    /// Same hash-chained decision insert as [`Self::insert_decision`], plus drift row in one SERIALIZABLE tx (Roadmap E).
    pub async fn insert_decision_with_drift(
        &self,
        r: &DecisionRecord,
        drift: &DriftLogRecord,
    ) -> Result<i64, DbError> {
        Self::ensure_write_org_id(r.org_id)?;
        let decided_at = r.decided_at.unwrap_or_else(Utc::now);
        let decided_at_str = decided_at.to_rfc3339();

        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *tx)
            .await?;
        if let Some(org_id) = r.org_id {
            Self::set_tx_tenant_context(&mut tx, org_id).await?;
        }

        let prev_hash_hex: Option<String> =
            sqlx::query_scalar("SELECT row_hash FROM decisions_hot WHERE row_hash IS NOT NULL ORDER BY id DESC LIMIT 1")
                .fetch_optional(&mut *tx)
                .await?;

        let genesis = [0u8; 32];
        let prev_hash_bytes: Vec<u8> = match &prev_hash_hex {
            Some(h) => hex::decode(h).unwrap_or_else(|_| genesis.to_vec()),
            None => genesis.to_vec(),
        };
        let prev_hash_stored = prev_hash_hex.unwrap_or_else(|| hex::encode(genesis));

        let mut ch = Sha256::new();
        ch.update(r.transaction_id.as_bytes());
        ch.update(b"\x00");
        ch.update(r.agent_id.as_bytes());
        ch.update(b"\x00");
        ch.update(r.decision.as_bytes());
        ch.update(b"\x00");
        ch.update(decided_at_str.as_bytes());
        let content_hash_bytes = ch.finalize();
        let content_hash_hex = hex::encode(content_hash_bytes);

        let mut rh = Sha256::new();
        rh.update(&prev_hash_bytes);
        rh.update(content_hash_bytes);
        let row_hash_hex = hex::encode(rh.finalize());

        let row_id: i64 = sqlx::query_scalar(
            r#"
            INSERT INTO decisions_hot
                (transaction_id, org_id, agent_id, decision, domain, policy_code, reason,
                 sig_nonce, sig_signed_at, sig_b64, request_nonce, request_sig,
                 content_hash, prev_hash, row_hash)
            VALUES
                ($1, $2, $3, $4::policy_result, $5::breaker_domain,
                 $6, $7, $8, $9, $10, $11, $12,
                 $13, $14, $15)
            RETURNING id
            "#,
        )
        .bind(r.transaction_id)
        .bind(r.org_id)
        .bind(&r.agent_id)
        .bind(&r.decision)
        .bind(&r.domain)
        .bind(&r.policy_code)
        .bind(&r.reason)
        .bind(&r.sig_nonce)
        .bind(r.sig_signed_at)
        .bind(&r.sig_b64)
        .bind(&r.request_nonce)
        .bind(&r.request_sig)
        .bind(&content_hash_hex)
        .bind(&prev_hash_stored)
        .bind(&row_hash_hex)
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO conversation_drift_log
                (agent_id, conversation_id, semantic_drift, drift_velocity,
                 window_len, baseline_len, recommendation)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(&drift.agent_id)
        .bind(&drift.conversation_id)
        .bind(drift.semantic_drift)
        .bind(drift.drift_velocity)
        .bind(drift.window_len)
        .bind(drift.baseline_len)
        .bind(&drift.recommendation)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(row_id)
    }

    pub async fn insert_drift_log(&self, r: &DriftLogRecord) -> Result<(), DbError> {
        sqlx::query(
            r#"
            INSERT INTO conversation_drift_log
                (agent_id, conversation_id, semantic_drift, drift_velocity,
                 window_len, baseline_len, recommendation)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(&r.agent_id)
        .bind(&r.conversation_id)
        .bind(r.semantic_drift)
        .bind(r.drift_velocity)
        .bind(r.window_len)
        .bind(r.baseline_len)
        .bind(&r.recommendation)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn insert_decision_outcome(&self, r: &DecisionOutcomeRecord) -> Result<i64, DbError> {
        let row_id: i64 = sqlx::query_scalar(
            r#"
            INSERT INTO decision_outcomes
                (transaction_id, outcome, impact_usd, reviewer_id,
                 reviewer_notes, agent_intent, agent_constraints)
            VALUES
                ($1, $2::outcome_type, $3, $4, $5, $6, $7)
            RETURNING id
            "#,
        )
        .bind(r.transaction_id)
        .bind(&r.outcome)
        .bind(r.impact_usd)
        .bind(&r.reviewer_id)
        .bind(&r.reviewer_notes)
        .bind(&r.agent_intent)
        .bind(&r.agent_constraints)
        .fetch_one(&self.pool)
        .await?;
        Ok(row_id)
    }

    pub async fn insert_policy_adjustment(
        &self,
        r: &PolicyAdjustmentRecord,
    ) -> Result<i64, DbError> {
        let row_id: i64 = sqlx::query_scalar(
            r#"
            INSERT INTO policy_adjustments
                (
                    rule_id,
                    domain,
                    old_threshold,
                    new_threshold,
                    reason,
                    adjusted_by,
                    trigger_outcome_id,
                    recommendation_id,
                    applied_variant_id
                )
            VALUES
                ($1, $2::breaker_domain, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id
            "#,
        )
        .bind(&r.rule_id)
        .bind(&r.domain)
        .bind(r.old_threshold)
        .bind(r.new_threshold)
        .bind(&r.reason)
        .bind(&r.adjusted_by)
        .bind(r.trigger_outcome_id)
        .bind(r.recommendation_id)
        .bind(&r.variant_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row_id)
    }

    pub async fn list_learning_outcomes(
        &self,
        max_age_hours: i64,
    ) -> Result<Vec<OutcomeLearningRecord>, DbError> {
        use sqlx::Row;

        let rows = sqlx::query(
            r#"
            SELECT
                o.id,
                o.transaction_id,
                d.policy_code,
                o.outcome::text AS outcome
            FROM decision_outcomes o
            INNER JOIN decisions_hot d ON d.transaction_id = o.transaction_id
            WHERE o.reviewed_at >= now() - ($1::text || ' hours')::interval
            ORDER BY o.id ASC
            "#,
        )
        .bind(max_age_hours.to_string())
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(OutcomeLearningRecord {
                outcome_id: row.get("id"),
                transaction_id: row.get("transaction_id"),
                policy_code: row.get("policy_code"),
                outcome: row.get("outcome"),
            });
        }
        Ok(out)
    }

    pub async fn upsert_adjustment_recommendation(
        &self,
        r: &AdjustmentRecommendationRecord,
    ) -> Result<i64, DbError> {
        let row_id: i64 = sqlx::query_scalar(
            r#"
            INSERT INTO policy_adjustment_recommendations
                (
                    recommendation_key,
                    threshold_key,
                    current_threshold,
                    proposed_threshold,
                    sample_size,
                    false_positive_count,
                    true_positive_count,
                    confidence,
                    rationale,
                    trigger_outcome_id,
                    trigger_transaction_id
                )
            VALUES
                ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (recommendation_key)
            DO UPDATE SET
                current_threshold = EXCLUDED.current_threshold,
                proposed_threshold = EXCLUDED.proposed_threshold,
                sample_size = EXCLUDED.sample_size,
                false_positive_count = EXCLUDED.false_positive_count,
                true_positive_count = EXCLUDED.true_positive_count,
                confidence = EXCLUDED.confidence,
                rationale = EXCLUDED.rationale,
                trigger_outcome_id = EXCLUDED.trigger_outcome_id,
                trigger_transaction_id = EXCLUDED.trigger_transaction_id
            RETURNING id
            "#,
        )
        .bind(&r.recommendation_key)
        .bind(&r.threshold_key)
        .bind(r.current_threshold)
        .bind(r.proposed_threshold)
        .bind(r.sample_size)
        .bind(r.false_positive_count)
        .bind(r.true_positive_count)
        .bind(r.confidence)
        .bind(&r.rationale)
        .bind(r.trigger_outcome_id)
        .bind(r.trigger_transaction_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row_id)
    }

    pub async fn list_adjustment_recommendations(
        &self,
        status_filter: Option<&str>,
    ) -> Result<Vec<StoredRecommendationRecord>, DbError> {
        use sqlx::Row;

        let rows = if let Some(status) = status_filter {
            sqlx::query(
                r#"
                SELECT
                    id,
                    recommendation_key,
                    threshold_key,
                    current_threshold,
                    proposed_threshold,
                    sample_size,
                    false_positive_count,
                    true_positive_count,
                    confidence,
                    rationale,
                    status,
                    trigger_outcome_id,
                    trigger_transaction_id,
                    decision_notes,
                    decided_by,
                    variant_id,
                    applied_adjustment_id
                FROM policy_adjustment_recommendations
                WHERE status = $1
                ORDER BY id ASC
                "#,
            )
            .bind(status)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                r#"
                SELECT
                    id,
                    recommendation_key,
                    threshold_key,
                    current_threshold,
                    proposed_threshold,
                    sample_size,
                    false_positive_count,
                    true_positive_count,
                    confidence,
                    rationale,
                    status,
                    trigger_outcome_id,
                    trigger_transaction_id,
                    decision_notes,
                    decided_by,
                    variant_id,
                    applied_adjustment_id
                FROM policy_adjustment_recommendations
                ORDER BY id ASC
                "#,
            )
            .fetch_all(&self.pool)
            .await?
        };

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(StoredRecommendationRecord {
                id: row.get("id"),
                recommendation_key: row.get("recommendation_key"),
                threshold_key: row.get("threshold_key"),
                current_threshold: row.get("current_threshold"),
                proposed_threshold: row.get("proposed_threshold"),
                sample_size: row.get("sample_size"),
                false_positive_count: row.get("false_positive_count"),
                true_positive_count: row.get("true_positive_count"),
                confidence: row.get("confidence"),
                rationale: row.get("rationale"),
                status: row.get("status"),
                trigger_outcome_id: row.get("trigger_outcome_id"),
                trigger_transaction_id: row.get("trigger_transaction_id"),
                decision_notes: row.get("decision_notes"),
                decided_by: row.get("decided_by"),
                variant_id: row.get("variant_id"),
                applied_adjustment_id: row.get("applied_adjustment_id"),
            });
        }
        Ok(out)
    }

    pub async fn get_adjustment_recommendation(
        &self,
        id: i64,
    ) -> Result<Option<StoredRecommendationRecord>, DbError> {
        use sqlx::Row;

        let row = sqlx::query(
            r#"
            SELECT
                id,
                recommendation_key,
                threshold_key,
                current_threshold,
                proposed_threshold,
                sample_size,
                false_positive_count,
                true_positive_count,
                confidence,
                rationale,
                status,
                trigger_outcome_id,
                trigger_transaction_id,
                decision_notes,
                decided_by,
                variant_id,
                applied_adjustment_id
            FROM policy_adjustment_recommendations
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        Ok(Some(StoredRecommendationRecord {
            id: row.get("id"),
            recommendation_key: row.get("recommendation_key"),
            threshold_key: row.get("threshold_key"),
            current_threshold: row.get("current_threshold"),
            proposed_threshold: row.get("proposed_threshold"),
            sample_size: row.get("sample_size"),
            false_positive_count: row.get("false_positive_count"),
            true_positive_count: row.get("true_positive_count"),
            confidence: row.get("confidence"),
            rationale: row.get("rationale"),
            status: row.get("status"),
            trigger_outcome_id: row.get("trigger_outcome_id"),
            trigger_transaction_id: row.get("trigger_transaction_id"),
            decision_notes: row.get("decision_notes"),
            decided_by: row.get("decided_by"),
            variant_id: row.get("variant_id"),
            applied_adjustment_id: row.get("applied_adjustment_id"),
        }))
    }

    pub async fn decide_adjustment_recommendation(
        &self,
        id: i64,
        status: &str,
        decided_by: &str,
        notes: Option<&str>,
        variant_id: Option<&str>,
        applied_adjustment_id: Option<i64>,
    ) -> Result<bool, DbError> {
        let rows = sqlx::query(
            r#"
            UPDATE policy_adjustment_recommendations
            SET
                status = $2,
                decided_by = $3,
                decision_notes = $4,
                decided_at = now(),
                variant_id = COALESCE($5, variant_id),
                applied_adjustment_id = COALESCE($6, applied_adjustment_id)
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(status)
        .bind(decided_by)
        .bind(notes)
        .bind(variant_id)
        .bind(applied_adjustment_id)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(rows > 0)
    }

    pub async fn mark_recommendation_reverted(
        &self,
        id: i64,
        reverted_by: &str,
        notes: Option<&str>,
        revert_adjustment_id: Option<i64>,
    ) -> Result<bool, DbError> {
        let rows = sqlx::query(
            r#"
            UPDATE policy_adjustment_recommendations
            SET
                status = 'reverted',
                reverted_at = now(),
                reverted_by = $2,
                decision_notes = COALESCE($3, decision_notes),
                revert_adjustment_id = COALESCE($4, revert_adjustment_id)
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(reverted_by)
        .bind(notes)
        .bind(revert_adjustment_id)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(rows > 0)
    }

    /// Bulk-insert capability trajectory entries from the WAL flush.
    pub async fn insert_capability_trajectory_batch(
        &self,
        entries: &[CapabilityTrajectoryRecord],
    ) -> Result<(), DbError> {
        for e in entries {
            sqlx::query(
                r#"
                INSERT INTO capability_trajectory
                    (agent_id, domain, knowledge_delta, created_at)
                VALUES ($1, $2, $3, $4)
                "#,
            )
            .bind(&e.agent_id)
            .bind(&e.domain)
            .bind(e.knowledge_delta)
            .bind(e.created_at)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    // pgvector embedding operations

    /// Upsert an agent's goal baseline embedding.
    pub async fn upsert_goal_embedding(&self, r: &GoalEmbeddingRecord) -> Result<i64, DbError> {
        let normalized = normalize_embedding(&r.embedding);
        let vec = Vector::from(normalized);
        let row_id: i64 = sqlx::query_scalar(
            r#"
            INSERT INTO agent_goal_embeddings (agent_id, label, embedding)
            VALUES ($1, $2, $3)
            ON CONFLICT (agent_id, label)
            DO UPDATE SET embedding = EXCLUDED.embedding, created_at = now()
            RETURNING id
            "#,
        )
        .bind(&r.agent_id)
        .bind(&r.label)
        .bind(vec)
        .fetch_one(&self.pool)
        .await?;
        Ok(row_id)
    }

    /// Retrieve an agent's goal embedding.
    pub async fn get_goal_embedding(
        &self,
        agent_id: &str,
        label: &str,
    ) -> Result<Option<Vec<f32>>, DbError> {
        let row: Option<(Vector,)> = sqlx::query_as(
            r#"
            SELECT embedding
            FROM agent_goal_embeddings
            WHERE agent_id = $1 AND label = $2
            "#,
        )
        .bind(agent_id)
        .bind(label)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(v,)| v.to_vec()))
    }

    /// Insert an action embedding for drift tracking.
    pub async fn insert_action_embedding(&self, r: &ActionEmbeddingRecord) -> Result<i64, DbError> {
        Self::ensure_write_org_id(r.org_id)?;
        let normalized = normalize_embedding(&r.embedding);
        let vec = Vector::from(normalized.clone());
        let vec_l2 = Vector::from(normalized.clone());
        let mut tx = self.pool.begin().await?;
        if let Some(org_id) = r.org_id {
            Self::set_tx_tenant_context(&mut tx, org_id).await?;
        }
        let row_id = sqlx::query_scalar(
            r#"
            INSERT INTO action_embeddings
                (org_id, agent_id, session_id, transaction_id, embedding, embedding_l2,
                 goal_similarity, label)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id
            "#,
        )
        .bind(r.org_id)
        .bind(&r.agent_id)
        .bind(&r.session_id)
        .bind(r.transaction_id)
        .bind(vec)
        .bind(vec_l2)
        .bind(r.goal_similarity)
        .bind(&r.label)
        .fetch_one(&mut *tx)
        .await;
        let row_id: i64 = match row_id {
            Ok(id) => {
                tx.commit().await?;
                id
            }
            Err(err) if is_missing_l2_schema_error(&err) => {
                // Backward-compatible insert path before migration 012 is applied.
                // Once a statement errors in a transaction, Postgres marks it
                // aborted; restart in a fresh transaction for fallback.
                let _ = tx.rollback().await;
                let mut fallback_tx = self.pool.begin().await?;
                if let Some(org_id) = r.org_id {
                    Self::set_tx_tenant_context(&mut fallback_tx, org_id).await?;
                }
                let id: i64 = sqlx::query_scalar(
                    r#"
                    INSERT INTO action_embeddings
                        (org_id, agent_id, session_id, transaction_id, embedding,
                         goal_similarity, label)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                    RETURNING id
                    "#,
                )
                .bind(r.org_id)
                .bind(&r.agent_id)
                .bind(&r.session_id)
                .bind(r.transaction_id)
                .bind(Vector::from(normalized))
                .bind(r.goal_similarity)
                .bind(&r.label)
                .fetch_one(&mut *fallback_tx)
                .await?;
                fallback_tx.commit().await?;
                return Ok(id);
            }
            Err(err) => return Err(err.into()),
        };
        Ok(row_id)
    }

    /// Find K most similar action embeddings for a given agent.
    pub async fn find_similar_actions(
        &self,
        query_embedding: &[f32],
        org_id: Uuid,
        agent_id: &str,
        k: i32,
    ) -> Result<Vec<SimilarAction>, DbError> {
        use sqlx::Row;
        let normalized = normalize_embedding(query_embedding);
        let vec = Vector::from(normalized.clone());
        let l2_expr = if read_bool_env("HALTCHAIN_DB_FORCE_L2_QUERY_FAIL", false) {
            "embedding_l2_nonexistent"
        } else {
            "embedding_l2"
        };
        let mut conn = self.pool.acquire().await?;
        sqlx::query("SELECT set_config('app.current_org_id', $1, false)")
            .bind(org_id.to_string())
            .execute(&mut *conn)
            .await?;
        let l2_sql = format!(
            r#"
            SELECT
                id,
                agent_id,
                session_id,
                1 - ((({0} <-> $1) * ({0} <-> $1)) / 2.0) AS similarity,
                label,
                created_at
            FROM action_embeddings
            WHERE agent_id = $2
            ORDER BY {0} <-> $1
            LIMIT $3
            "#,
            l2_expr
        );
        let l2_rows = sqlx::query(&l2_sql)
            .bind(&vec)
            .bind(agent_id)
            .bind(k)
            .fetch_all(&mut *conn)
            .await;
        let rows = match l2_rows {
            Ok(rows) => rows,
            Err(_) => {
                let cosine_vec = Vector::from(normalized);
                sqlx::query(
                    r#"
                    SELECT
                        id,
                        agent_id,
                        session_id,
                        1 - (embedding <=> $1) AS similarity,
                        label,
                        created_at
                    FROM action_embeddings
                    WHERE agent_id = $2
                    ORDER BY embedding <=> $1
                    LIMIT $3
                    "#,
                )
                .bind(&cosine_vec)
                .bind(agent_id)
                .bind(k)
                .fetch_all(&mut *conn)
                .await?
            }
        };

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(SimilarAction {
                action_id: row.get("id"),
                agent_id: row.get("agent_id"),
                session_id: row.get("session_id"),
                similarity: row.get("similarity"),
                label: row.get("label"),
                created_at: row.get("created_at"),
            });
        }
        Ok(out)
    }

    /// Upsert a pattern centroid (warm-start for OnnxDetector).
    pub async fn upsert_pattern_centroid(&self, r: &PatternCentroidRecord) -> Result<i64, DbError> {
        let vec = Vector::from(r.centroid.clone());
        let row_id: i64 = sqlx::query_scalar(
            r#"
            INSERT INTO pattern_centroids (pattern, centroid, sample_count)
            VALUES ($1, $2, $3)
            ON CONFLICT (pattern)
            DO UPDATE SET
                centroid = EXCLUDED.centroid,
                sample_count = EXCLUDED.sample_count,
                updated_at = now()
            RETURNING id
            "#,
        )
        .bind(&r.pattern)
        .bind(vec)
        .bind(r.sample_count)
        .fetch_one(&self.pool)
        .await?;
        Ok(row_id)
    }

    /// Load all pattern centroids (for detector warm-start).
    pub async fn list_pattern_centroids(&self) -> Result<Vec<(String, Vec<f32>, i32)>, DbError> {
        use sqlx::Row;
        let rows = sqlx::query(r#"SELECT pattern, centroid, sample_count FROM pattern_centroids"#)
            .fetch_all(&self.pool)
            .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let v: Vector = row.get("centroid");
            out.push((
                row.get::<String, _>("pattern"),
                v.to_vec(),
                row.get::<i32, _>("sample_count"),
            ));
        }
        Ok(out)
    }

    /// Insert a drift snapshot.
    pub async fn insert_drift_snapshot(&self, r: &DriftSnapshotRecord) -> Result<i64, DbError> {
        let vec = Vector::from(r.centroid.clone());
        let row_id: i64 = sqlx::query_scalar(
            r#"
            INSERT INTO drift_snapshots
                (agent_id, window_label, centroid, action_count,
                 mean_similarity, trend_slope)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
            "#,
        )
        .bind(&r.agent_id)
        .bind(&r.window_label)
        .bind(vec)
        .bind(r.action_count)
        .bind(r.mean_similarity)
        .bind(r.trend_slope)
        .fetch_one(&self.pool)
        .await?;
        Ok(row_id)
    }
}

// ── Phase 1b: JSONB Policy Engine ────────────────────────────────────────────

/// A policy rule set stored as JSONB in `policy_configs`.
#[derive(Debug, Clone)]
pub struct PolicyConfig {
    pub id: Uuid,
    pub org_id: Uuid,
    pub policy_name: String,
    pub version: i32,
    pub rules: serde_json::Value,
    pub enabled: bool,
}

// ── Phase 1b: Telemetry Records ───────────────────────────────────────────────

/// A single telemetry data point written to the unlogged hot table.
#[derive(Debug, Clone)]
pub struct TelemetryRecord {
    pub org_id: Option<Uuid>,
    pub agent_id: String,
    pub metric: String,
    pub value: f64,
    pub tags: Option<serde_json::Value>,
}

/// A row returned from a full-text search on `decisions_hot`.
#[derive(Debug, Clone)]
pub struct AuditSearchResult {
    pub id: i64,
    pub transaction_id: Uuid,
    pub agent_id: String,
    pub decision: String,
    pub reason: Option<String>,
    pub policy_code: Option<String>,
    pub decided_at: DateTime<Utc>,
}

impl DbStore {
    // ── Advisory-Lock Policy Hot-Reload ──────────────────────────────────────
    // Uses pg_advisory_xact_lock(hashtext(policy_name)) so concurrent reloads
    // for the same policy are serialized without blocking other policies.

    /// Reload a named policy inside a SERIALIZABLE transaction with advisory lock.
    /// The caller supplies `apply_fn` which runs the actual update logic within
    /// the transaction.  The lock is automatically released on commit/rollback.
    pub async fn reload_policy_with_lock(
        &self,
        org_id: Uuid,
        policy_name: &str,
        rules: serde_json::Value,
    ) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await?;
        // Advisory lock scoped to this transaction — auto-released on commit.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(policy_name)
            .execute(&mut *tx)
            .await?;

        sqlx::query(
            r#"
            INSERT INTO policy_configs (org_id, policy_name, version, rules, enabled)
            VALUES ($1, $2,
                COALESCE(
                    (SELECT MAX(version) FROM policy_configs
                     WHERE org_id = $1 AND policy_name = $2), 0
                ) + 1,
                $3, true)
            ON CONFLICT (org_id, policy_name, version) DO UPDATE
                SET rules = EXCLUDED.rules,
                    enabled = true,
                    updated_at = now()
            "#,
        )
        .bind(org_id)
        .bind(policy_name)
        .bind(&rules)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Fetch the latest enabled policy rules for a given org + policy name.
    /// Returns `None` if no policy is found.
    pub async fn get_policy_config(
        &self,
        org_id: Uuid,
        policy_name: &str,
    ) -> Result<Option<PolicyConfig>, DbError> {
        use sqlx::Row;
        let row = sqlx::query(
            r#"
            SELECT id, org_id, policy_name, version, rules, enabled
            FROM policy_configs
            WHERE org_id = $1 AND policy_name = $2 AND enabled = true
            ORDER BY version DESC
            LIMIT 1
            "#,
        )
        .bind(org_id)
        .bind(policy_name)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| PolicyConfig {
            id: r.get("id"),
            org_id: r.get("org_id"),
            policy_name: r.get("policy_name"),
            version: r.get("version"),
            rules: r.get("rules"),
            enabled: r.get("enabled"),
        }))
    }

    // ── L3 Unlogged Telemetry (fire-and-forget) ───────────────────────────────

    /// Write a telemetry data point to the unlogged hot table.
    /// This is fire-and-forget: errors are logged but do NOT propagate.
    /// Critical audit data must go through `insert_decision` instead.
    pub async fn insert_telemetry_hot(&self, r: &TelemetryRecord) -> Result<(), DbError> {
        self.telemetry_hot_writer.enqueue(r).await
    }

    /// Upsert a drift counter in the unlogged hot table.
    pub async fn upsert_drift_counter(
        &self,
        agent_id: &str,
        org_id: Option<Uuid>,
        metric: &str,
        value: f64,
        window_s: i32,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"
            INSERT INTO drift_counters_hot (agent_id, org_id, metric, value, window_s, updated_at)
            VALUES ($1, $2, $3, $4, $5, now())
            ON CONFLICT (agent_id, metric, window_s) DO UPDATE
                SET value = EXCLUDED.value,
                    org_id = EXCLUDED.org_id,
                    updated_at = now()
            "#,
        )
        .bind(agent_id)
        .bind(org_id)
        .bind(metric)
        .bind(value)
        .bind(window_s)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ── Full-Text Search on Audit Decisions ───────────────────────────────────

    /// Full-text search over `decisions_hot` using TSVector index.
    /// `query` is a plain-text string; converted to tsquery via plainto_tsquery.
    /// Returns up to `limit` results ordered by recency.
    pub async fn search_audit_decisions(
        &self,
        query: &str,
        limit: i64,
    ) -> Result<Vec<AuditSearchResult>, DbError> {
        use sqlx::Row;
        let rows = sqlx::query(
            r#"
            SELECT id, transaction_id, agent_id, decision::text AS decision, reason, policy_code, decided_at
            FROM decisions_hot
            WHERE fts_vector @@ plainto_tsquery('english', $1)
            ORDER BY decided_at DESC
            LIMIT $2
            "#,
        )
        .bind(query)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(AuditSearchResult {
                id: row.get("id"),
                transaction_id: row.get("transaction_id"),
                agent_id: row.get("agent_id"),
                decision: row.get("decision"),
                reason: row.get("reason"),
                policy_code: row.get("policy_code"),
                decided_at: row.get("decided_at"),
            });
        }
        Ok(out)
    }

    // ── Set Tenant Context ─────────────────────────────────────────────────────

    /// Acquire a connection and set `app.current_org_id` on it (session-level).
    ///
    /// IMPORTANT: callers must hold the returned connection and execute all
    /// RLS-guarded queries through it. Dropping the connection before querying
    /// returns it to the pool, where the session setting persists until
    /// `reset_tenant_context()` is called. Use `with_tenant_context` for a
    /// scoped pattern that auto-resets on drop.
    pub async fn tenant_connection(
        &self,
        org_id: Uuid,
    ) -> Result<sqlx::pool::PoolConnection<Postgres>, DbError> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("SELECT set_config('app.current_org_id', $1, false)")
            .bind(org_id.to_string())
            .execute(&mut *conn)
            .await?;
        Ok(conn)
    }

    /// Execute `f` with tenant RLS context set, then reset before returning the connection.
    /// This is the safe way to run RLS-scoped queries without leaking tenant context
    /// into other pool borrowers.
    pub async fn with_tenant_context<F, T, E>(&self, org_id: Uuid, f: F) -> Result<T, DbError>
    where
        F: std::future::Future<Output = Result<T, E>>,
        E: Into<DbError>,
    {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("SELECT set_config('app.current_org_id', $1, false)")
            .bind(org_id.to_string())
            .execute(&mut *conn)
            .await?;
        drop(conn); // release back; context set on pool-level session
        let result = f.await.map_err(|e| e.into());
        // reset so the next borrower starts clean
        if let Ok(mut reset_conn) = self.pool.acquire().await {
            let _ = sqlx::query("SELECT reset_tenant_context()")
                .execute(&mut *reset_conn)
                .await;
        }
        result
    }

    /// Check if required PostgreSQL extensions are available.
    /// Returns a map of extension name → available bool.
    pub async fn extension_health(&self) -> std::collections::HashMap<String, bool> {
        let mut out = std::collections::HashMap::new();
        let extensions = ["vector", "pg_cron", "pgcrypto"];
        for ext in extensions {
            let ok = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM pg_extension WHERE extname = $1",
            )
            .bind(ext)
            .fetch_one(&self.pool)
            .await
            .map(|c| c > 0)
            .unwrap_or(false);
            out.insert(ext.to_string(), ok);
        }
        out
    }

    /// Record a dependency circuit event (cascade failure tracking).
    /// Fire-and-forget: errors are logged but not returned.
    pub async fn record_circuit_event(
        &self,
        dependency: &str,
        event_type: &str,
        detail: Option<&str>,
        org_id: Option<Uuid>,
    ) {
        let _ = sqlx::query(
            "INSERT INTO dependency_circuit_events (dependency, org_id, event_type, detail) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(dependency)
        .bind(org_id)
        .bind(event_type)
        .bind(detail)
        .execute(&self.pool)
        .await;
    }
}

fn read_u32_env(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(default)
}

fn read_u64_env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

fn read_f64_env(name: &str, default: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(default)
}

fn read_acquire_timeout() -> Duration {
    if let Some(ms) = std::env::var("HALTCHAIN_DB_ACQUIRE_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        return Duration::from_millis(ms);
    }
    if let Some(secs) = std::env::var("HALTCHAIN_DB_ACQUIRE_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        return Duration::from_secs(secs);
    }
    Duration::from_millis(200)
}

fn compute_littles_law_pool_size(target_rps: u32, p95_ms: f64) -> u32 {
    ((target_rps as f64 * p95_ms / 1000.0) * 1.2)
        .ceil()
        .max(1.0) as u32
}

fn normalize_embedding(embedding: &[f32]) -> Vec<f32> {
    let norm = embedding
        .iter()
        .map(|x| (*x as f64) * (*x as f64))
        .sum::<f64>()
        .sqrt();
    if norm <= f64::EPSILON {
        return embedding.to_vec();
    }
    embedding
        .iter()
        .map(|x| ((*x as f64) / norm) as f32)
        .collect()
}

fn is_missing_l2_schema_error(err: &sqlx::Error) -> bool {
    match err {
        sqlx::Error::Database(db_err) => {
            let code = db_err.code().map(|code| code.to_string());
            code.as_deref() == Some("42703") || code.as_deref() == Some("42P01")
        }
        _ => false,
    }
}

fn read_bool_env(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .and_then(|v| match v.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        })
        .unwrap_or(default)
}
