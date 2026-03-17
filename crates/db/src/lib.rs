use chrono::{DateTime, Utc};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::time::Duration;
use thiserror::Error;
use uuid::Uuid;

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
}

pub struct DecisionRecord {
    pub transaction_id: Uuid,
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
    pub async fn connect(url: &str) -> Result<Self, DbError> {
        let is_supabase = url.contains("supabase.com") || url.contains("pooler.supabase.com");
        let require_ssl = read_bool_env("HALTCHAIN_DB_REQUIRE_SSL", is_supabase);
        if require_ssl && !url.to_ascii_lowercase().contains("sslmode=require") {
            return Err(DbError::Misconfigured(
                "DATABASE_URL must include sslmode=require when HALTCHAIN_DB_REQUIRE_SSL is enabled"
                    .to_string(),
            ));
        }

        let max_connections = read_u32_env("HALTCHAIN_DB_MAX_CONNECTIONS", 10).max(1);
        let min_connections = read_u32_env("HALTCHAIN_DB_MIN_CONNECTIONS", 2).min(max_connections);
        let connect_timeout_secs = read_u64_env("HALTCHAIN_DB_CONNECT_TIMEOUT_SECS", 5);
        let acquire_timeout_secs = read_u64_env("HALTCHAIN_DB_ACQUIRE_TIMEOUT_SECS", 5);
        let idle_timeout_secs = read_u64_env("HALTCHAIN_DB_IDLE_TIMEOUT_SECS", 300);
        let max_lifetime_secs = read_u64_env("HALTCHAIN_DB_MAX_LIFETIME_SECS", 1800);

        let pool = tokio::time::timeout(
            Duration::from_secs(connect_timeout_secs),
            PgPoolOptions::new()
                .max_connections(max_connections)
                .min_connections(min_connections)
                .acquire_timeout(Duration::from_secs(acquire_timeout_secs))
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
            connect_timeout_secs,
            acquire_timeout_secs,
            idle_timeout_secs,
            max_lifetime_secs,
            require_ssl,
            "postgres pool established"
        );
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn insert_decision(&self, r: &DecisionRecord) -> Result<i64, DbError> {
        let row_id: i64 = sqlx::query_scalar(
            r#"
            INSERT INTO decisions_hot
                (transaction_id, agent_id, decision, domain, policy_code, reason,
                 sig_nonce, sig_signed_at, sig_b64, request_nonce, request_sig)
            VALUES
                ($1, $2, $3::policy_result, $4::breaker_domain,
                 $5, $6, $7, $8, $9, $10, $11)
            RETURNING id
            "#,
        )
        .bind(r.transaction_id)
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
        .fetch_one(&self.pool)
        .await?;
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
