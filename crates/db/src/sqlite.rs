//! SQLite backend for standalone (`--profile standalone`) deployments.
//!
//! Provides an audit-log-only persistence layer with zero external dependencies.
//! Vector-similarity operations (pgvector), policy adjustment analytics, and
//! capability trajectory batching are no-ops; their data remains in memory.
//!
//! Schema is created automatically on first connect via `CREATE TABLE IF NOT EXISTS`.

use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use std::time::Duration;
use uuid::Uuid;

use crate::{
    AdjustmentRecommendationRecord, DbError, DecisionOutcomeRecord, DecisionRecord, DriftLogRecord,
    OutcomeLearningRecord, PolicyAdjustmentRecord, StoredRecommendationRecord,
};

/// SQLite-backed store for standalone deployments.
///
/// Only `decisions` and `drift_logs` tables are persisted; all other methods
/// return empty / zero results so the rest of the validator pipeline is unaffected.
pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    /// Connect to (or create) a SQLite database at `path`.
    ///
    /// Pass `":memory:"` for an ephemeral in-process database.
    /// Pass a file path (e.g. `"haltchain.db"`) for durable storage.
    pub async fn connect(path: &str) -> Result<Self, DbError> {
        let url = if path == ":memory:" {
            "sqlite::memory:".to_string()
        } else {
            format!("sqlite:{path}?mode=rwc")
        };

        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&url)
            .await?;

        Self::migrate(&pool).await?;
        Ok(Self { pool })
    }

    async fn migrate(pool: &SqlitePool) -> Result<(), DbError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS decisions (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_id  TEXT    NOT NULL,
                agent_id        TEXT    NOT NULL,
                decision        TEXT    NOT NULL,
                policy_code     TEXT,
                reason          TEXT,
                sig_nonce       TEXT,
                sig_b64         TEXT,
                request_nonce   TEXT,
                created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_decisions_agent ON decisions(agent_id);
            CREATE INDEX IF NOT EXISTS idx_decisions_created ON decisions(created_at);
            "#,
        )
        .execute(pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS drift_logs (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id        TEXT      NOT NULL,
                conversation_id TEXT      NOT NULL,
                semantic_drift  REAL      NOT NULL,
                drift_velocity  REAL      NOT NULL,
                window_len      INTEGER   NOT NULL,
                baseline_len    INTEGER   NOT NULL,
                recommendation  TEXT      NOT NULL,
                created_at      TEXT      NOT NULL DEFAULT (datetime('now'))
            );
            "#,
        )
        .execute(pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS admin_users (
                id              TEXT PRIMARY KEY,
                email           TEXT NOT NULL UNIQUE,
                password_hash   TEXT NOT NULL,
                is_active       INTEGER NOT NULL DEFAULT 1,
                created_at      TEXT NOT NULL DEFAULT (datetime('now'))
            );
            "#,
        )
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn admin_fetch_login_row(
        &self,
        email: &str,
    ) -> Result<Option<(String, bool)>, DbError> {
        let row = sqlx::query_as::<_, (String, i64)>(
            "SELECT password_hash, is_active FROM admin_users WHERE email = ?",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(h, a)| (h, a != 0)))
    }

    pub async fn admin_users_count(&self) -> Result<i64, DbError> {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM admin_users")
            .fetch_one(&self.pool)
            .await?;
        Ok(n)
    }

    pub async fn admin_bootstrap_upsert(&self, email: &str, hash: &str) -> Result<(), DbError> {
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO admin_users (id, email, password_hash, is_active) VALUES (?, ?, ?, 1)
             ON CONFLICT(email) DO UPDATE SET password_hash = excluded.password_hash, is_active = 1",
        )
        .bind(&id)
        .bind(email)
        .bind(hash)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn ping(&self) -> Result<(), DbError> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    // ── Core audit methods ───────────────────────────────────────────────────

    pub async fn insert_decision(&self, r: &DecisionRecord) -> Result<i64, DbError> {
        let tx_id = r.transaction_id.to_string();
        let result = sqlx::query(
            r#"INSERT INTO decisions
               (transaction_id, agent_id, decision, policy_code, reason,
                sig_nonce, sig_b64, request_nonce)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(&tx_id)
        .bind(&r.agent_id)
        .bind(&r.decision)
        .bind(&r.policy_code)
        .bind(&r.reason)
        .bind(&r.sig_nonce)
        .bind(&r.sig_b64)
        .bind(&r.request_nonce)
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    pub async fn insert_drift_log(&self, r: &DriftLogRecord) -> Result<(), DbError> {
        sqlx::query(
            r#"INSERT INTO drift_logs
               (agent_id, conversation_id, semantic_drift, drift_velocity,
                window_len, baseline_len, recommendation)
               VALUES (?, ?, ?, ?, ?, ?, ?)"#,
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

    pub async fn insert_decision_with_drift(
        &self,
        r: &DecisionRecord,
        drift: &DriftLogRecord,
    ) -> Result<i64, DbError> {
        let mut tx = self.pool.begin().await?;
        let tx_id = r.transaction_id.to_string();
        let result = sqlx::query(
            r#"INSERT INTO decisions
               (transaction_id, agent_id, decision, policy_code, reason,
                sig_nonce, sig_b64, request_nonce)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(&tx_id)
        .bind(&r.agent_id)
        .bind(&r.decision)
        .bind(&r.policy_code)
        .bind(&r.reason)
        .bind(&r.sig_nonce)
        .bind(&r.sig_b64)
        .bind(&r.request_nonce)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r#"INSERT INTO drift_logs
               (agent_id, conversation_id, semantic_drift, drift_velocity,
                window_len, baseline_len, recommendation)
               VALUES (?, ?, ?, ?, ?, ?, ?)"#,
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
        Ok(result.last_insert_rowid())
    }

    // ── No-op stubs for Postgres-only features ───────────────────────────────
    // These allow the validator to call `db.*` uniformly without branching.

    pub async fn insert_decision_outcome(
        &self,
        _r: &DecisionOutcomeRecord,
    ) -> Result<i64, DbError> {
        Ok(0)
    }

    pub async fn insert_policy_adjustment(
        &self,
        _r: &PolicyAdjustmentRecord,
    ) -> Result<i64, DbError> {
        Ok(0)
    }

    pub async fn list_learning_outcomes(
        &self,
        _max_age_hours: i64,
    ) -> Result<Vec<OutcomeLearningRecord>, DbError> {
        Ok(vec![])
    }

    pub async fn upsert_adjustment_recommendation(
        &self,
        _r: &AdjustmentRecommendationRecord,
    ) -> Result<i64, DbError> {
        Ok(0)
    }

    pub async fn list_adjustment_recommendations(
        &self,
        _status_filter: Option<&str>,
    ) -> Result<Vec<StoredRecommendationRecord>, DbError> {
        Ok(vec![])
    }

    pub async fn get_adjustment_recommendation(
        &self,
        _id: i64,
    ) -> Result<Option<StoredRecommendationRecord>, DbError> {
        Ok(None)
    }

    pub async fn decide_adjustment_recommendation(
        &self,
        _id: i64,
        _status: &str,
        _decided_by: &str,
        _notes: Option<&str>,
        _variant_id: Option<&str>,
        _applied_adjustment_id: Option<i64>,
    ) -> Result<bool, DbError> {
        Ok(false)
    }

    pub async fn mark_recommendation_reverted(
        &self,
        _id: i64,
        _reverted_by: &str,
        _notes: Option<&str>,
        _revert_adjustment_id: Option<i64>,
    ) -> Result<bool, DbError> {
        Ok(false)
    }
}

// ── DbBackend: unified enum used by AppState ─────────────────────────────────

/// Wraps either a Postgres or SQLite backend, providing a uniform interface
/// to all call sites in the validator.  New backends are added here.
pub enum DbBackend {
    Postgres(crate::DbStore),
    Sqlite(SqliteStore),
}

impl DbBackend {
    pub async fn insert_decision(&self, r: &DecisionRecord) -> Result<i64, DbError> {
        match self {
            Self::Postgres(db) => db.insert_decision(r).await,
            Self::Sqlite(db) => db.insert_decision(r).await,
        }
    }

    pub async fn insert_drift_log(&self, r: &DriftLogRecord) -> Result<(), DbError> {
        match self {
            Self::Postgres(db) => db.insert_drift_log(r).await,
            Self::Sqlite(db) => db.insert_drift_log(r).await,
        }
    }

    pub async fn insert_decision_with_drift(
        &self,
        r: &DecisionRecord,
        drift: &DriftLogRecord,
    ) -> Result<i64, DbError> {
        match self {
            Self::Postgres(db) => db.insert_decision_with_drift(r, drift).await,
            Self::Sqlite(db) => db.insert_decision_with_drift(r, drift).await,
        }
    }

    pub async fn insert_decision_outcome(&self, r: &DecisionOutcomeRecord) -> Result<i64, DbError> {
        match self {
            Self::Postgres(db) => db.insert_decision_outcome(r).await,
            Self::Sqlite(db) => db.insert_decision_outcome(r).await,
        }
    }

    pub async fn insert_policy_adjustment(
        &self,
        r: &PolicyAdjustmentRecord,
    ) -> Result<i64, DbError> {
        match self {
            Self::Postgres(db) => db.insert_policy_adjustment(r).await,
            Self::Sqlite(db) => db.insert_policy_adjustment(r).await,
        }
    }

    pub async fn list_learning_outcomes(
        &self,
        max_age_hours: i64,
    ) -> Result<Vec<OutcomeLearningRecord>, DbError> {
        match self {
            Self::Postgres(db) => db.list_learning_outcomes(max_age_hours).await,
            Self::Sqlite(db) => db.list_learning_outcomes(max_age_hours).await,
        }
    }

    pub async fn upsert_adjustment_recommendation(
        &self,
        r: &AdjustmentRecommendationRecord,
    ) -> Result<i64, DbError> {
        match self {
            Self::Postgres(db) => db.upsert_adjustment_recommendation(r).await,
            Self::Sqlite(db) => db.upsert_adjustment_recommendation(r).await,
        }
    }

    pub async fn list_adjustment_recommendations(
        &self,
        status_filter: Option<&str>,
    ) -> Result<Vec<StoredRecommendationRecord>, DbError> {
        match self {
            Self::Postgres(db) => db.list_adjustment_recommendations(status_filter).await,
            Self::Sqlite(db) => db.list_adjustment_recommendations(status_filter).await,
        }
    }

    pub async fn get_adjustment_recommendation(
        &self,
        id: i64,
    ) -> Result<Option<StoredRecommendationRecord>, DbError> {
        match self {
            Self::Postgres(db) => db.get_adjustment_recommendation(id).await,
            Self::Sqlite(db) => db.get_adjustment_recommendation(id).await,
        }
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
        match self {
            Self::Postgres(db) => {
                db.decide_adjustment_recommendation(
                    id,
                    status,
                    decided_by,
                    notes,
                    variant_id,
                    applied_adjustment_id,
                )
                .await
            }
            Self::Sqlite(db) => {
                db.decide_adjustment_recommendation(
                    id,
                    status,
                    decided_by,
                    notes,
                    variant_id,
                    applied_adjustment_id,
                )
                .await
            }
        }
    }

    pub async fn mark_recommendation_reverted(
        &self,
        id: i64,
        reverted_by: &str,
        notes: Option<&str>,
        revert_adjustment_id: Option<i64>,
    ) -> Result<bool, DbError> {
        match self {
            Self::Postgres(db) => {
                db.mark_recommendation_reverted(id, reverted_by, notes, revert_adjustment_id)
                    .await
            }
            Self::Sqlite(db) => {
                db.mark_recommendation_reverted(id, reverted_by, notes, revert_adjustment_id)
                    .await
            }
        }
    }

    /// Returns the inner `DbStore` if this is a Postgres backend.
    /// Used by `flush_capability_wal` which requires direct Postgres access.
    pub fn as_postgres(&self) -> Option<&crate::DbStore> {
        match self {
            Self::Postgres(db) => Some(db),
            Self::Sqlite(_) => None,
        }
    }

    /// Returns the Postgres connection pool, or `None` for SQLite backends.
    /// Admin-user bootstrapping and other Postgres-only paths use this.
    pub fn pool(&self) -> Option<&sqlx::PgPool> {
        match self {
            Self::Postgres(db) => Some(db.pool()),
            Self::Sqlite(_) => None,
        }
    }

    pub async fn ping(&self) -> Result<(), DbError> {
        match self {
            Self::Postgres(db) => db.ping().await,
            Self::Sqlite(db) => db.ping().await,
        }
    }

    pub async fn admin_fetch_login_row(
        &self,
        email: &str,
    ) -> Result<Option<(String, bool)>, DbError> {
        match self {
            Self::Postgres(db) => db.admin_fetch_login_row(email).await,
            Self::Sqlite(db) => db.admin_fetch_login_row(email).await,
        }
    }

    pub async fn admin_bootstrap_upsert(&self, email: &str, hash: &str) -> Result<(), DbError> {
        match self {
            Self::Postgres(db) => db.admin_bootstrap_upsert(email, hash).await,
            Self::Sqlite(db) => db.admin_bootstrap_upsert(email, hash).await,
        }
    }

    pub async fn admin_users_count(&self) -> Result<i64, DbError> {
        match self {
            Self::Postgres(db) => db.admin_users_count().await,
            Self::Sqlite(db) => db.admin_users_count().await,
        }
    }
}
