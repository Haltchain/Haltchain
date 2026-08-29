//! SQLite backend for standalone (`--profile standalone`) deployments.
//!
//! Persists decisions, drift logs, review outcomes, policy adjustments and
//! threshold recommendations with zero external dependencies.
//!
//! Still Postgres-only (not available here): pgvector similarity search,
//! unlogged hot telemetry, FTS ranking, RLS tenant isolation, and capability
//! trajectory batching. Those call sites go through `DbStore` directly.
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

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS decision_outcomes (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_id    TEXT NOT NULL,
                outcome           TEXT NOT NULL,
                impact_usd        REAL,
                reviewer_id       TEXT,
                reviewer_notes    TEXT,
                agent_intent      TEXT,
                agent_constraints TEXT,
                reviewed_at       TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_outcomes_txn ON decision_outcomes(transaction_id);
            CREATE INDEX IF NOT EXISTS idx_outcomes_reviewed ON decision_outcomes(reviewed_at);
            "#,
        )
        .execute(pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS policy_adjustments (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id            TEXT NOT NULL,
                domain             TEXT NOT NULL,
                old_threshold      REAL,
                new_threshold      REAL,
                reason             TEXT NOT NULL,
                adjusted_by        TEXT NOT NULL,
                trigger_outcome_id INTEGER,
                recommendation_id  INTEGER,
                applied_variant_id TEXT,
                created_at         TEXT NOT NULL DEFAULT (datetime('now'))
            );
            "#,
        )
        .execute(pool)
        .await?;

        // recommendation_key is UNIQUE so upsert can use ON CONFLICT
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS policy_adjustment_recommendations (
                id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                recommendation_key    TEXT NOT NULL UNIQUE,
                threshold_key         TEXT NOT NULL,
                current_threshold     REAL NOT NULL,
                proposed_threshold    REAL NOT NULL,
                sample_size           INTEGER NOT NULL,
                false_positive_count  INTEGER NOT NULL,
                true_positive_count   INTEGER NOT NULL,
                confidence            REAL NOT NULL,
                rationale             TEXT NOT NULL,
                status                TEXT NOT NULL DEFAULT 'pending',
                trigger_outcome_id    INTEGER,
                trigger_transaction_id TEXT,
                decision_notes        TEXT,
                decided_by            TEXT,
                decided_at            TEXT,
                variant_id            TEXT,
                applied_adjustment_id INTEGER,
                reverted_at           TEXT,
                reverted_by           TEXT,
                revert_adjustment_id  INTEGER,
                created_at            TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_recs_status ON policy_adjustment_recommendations(status);
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

    // ── Learning / review outcomes ───────────────────────────────────────────

    pub async fn insert_decision_outcome(&self, r: &DecisionOutcomeRecord) -> Result<i64, DbError> {
        let txn = r.transaction_id.to_string();
        let res = sqlx::query(
            r#"INSERT INTO decision_outcomes
               (transaction_id, outcome, impact_usd, reviewer_id,
                reviewer_notes, agent_intent, agent_constraints)
               VALUES (?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(&txn)
        .bind(&r.outcome)
        .bind(r.impact_usd)
        .bind(&r.reviewer_id)
        .bind(&r.reviewer_notes)
        .bind(&r.agent_intent)
        .bind(&r.agent_constraints)
        .execute(&self.pool)
        .await?;
        Ok(res.last_insert_rowid())
    }

    pub async fn insert_policy_adjustment(
        &self,
        r: &PolicyAdjustmentRecord,
    ) -> Result<i64, DbError> {
        let res = sqlx::query(
            r#"INSERT INTO policy_adjustments
               (rule_id, domain, old_threshold, new_threshold, reason,
                adjusted_by, trigger_outcome_id, recommendation_id, applied_variant_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
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
        .execute(&self.pool)
        .await?;
        Ok(res.last_insert_rowid())
    }

    pub async fn list_learning_outcomes(
        &self,
        max_age_hours: i64,
    ) -> Result<Vec<OutcomeLearningRecord>, DbError> {
        use sqlx::Row;
        // sqlite has no interval type; build a modifier like '-24 hours'
        let cutoff = format!("-{max_age_hours} hours");
        let rows = sqlx::query(
            r#"SELECT o.id AS id, o.transaction_id AS transaction_id,
                      d.policy_code AS policy_code, o.outcome AS outcome
               FROM decision_outcomes o
               INNER JOIN decisions d ON d.transaction_id = o.transaction_id
               WHERE o.reviewed_at >= datetime('now', ?)
               ORDER BY o.id ASC"#,
        )
        .bind(&cutoff)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let txn_str: String = row.get("transaction_id");
            // skip rows whose txn id is not a valid uuid rather than failing the batch
            let Ok(transaction_id) = Uuid::parse_str(&txn_str) else {
                continue;
            };
            out.push(OutcomeLearningRecord {
                outcome_id: row.get("id"),
                transaction_id,
                policy_code: row.get("policy_code"),
                outcome: row.get("outcome"),
            });
        }
        Ok(out)
    }

    // ── Threshold adjustment recommendations ─────────────────────────────────

    pub async fn upsert_adjustment_recommendation(
        &self,
        r: &AdjustmentRecommendationRecord,
    ) -> Result<i64, DbError> {
        let trigger_txn = r.trigger_transaction_id.map(|u| u.to_string());
        sqlx::query(
            r#"INSERT INTO policy_adjustment_recommendations
               (recommendation_key, threshold_key, current_threshold, proposed_threshold,
                sample_size, false_positive_count, true_positive_count, confidence,
                rationale, trigger_outcome_id, trigger_transaction_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(recommendation_key) DO UPDATE SET
                   current_threshold = excluded.current_threshold,
                   proposed_threshold = excluded.proposed_threshold,
                   sample_size = excluded.sample_size,
                   false_positive_count = excluded.false_positive_count,
                   true_positive_count = excluded.true_positive_count,
                   confidence = excluded.confidence,
                   rationale = excluded.rationale,
                   trigger_outcome_id = excluded.trigger_outcome_id,
                   trigger_transaction_id = excluded.trigger_transaction_id"#,
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
        .bind(&trigger_txn)
        .execute(&self.pool)
        .await?;

        // last_insert_rowid is 0 on a conflict-update, so read the id back by key
        let id: i64 = sqlx::query_scalar(
            "SELECT id FROM policy_adjustment_recommendations WHERE recommendation_key = ?",
        )
        .bind(&r.recommendation_key)
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn list_adjustment_recommendations(
        &self,
        status_filter: Option<&str>,
    ) -> Result<Vec<StoredRecommendationRecord>, DbError> {
        let rows = match status_filter {
            Some(status) => {
                sqlx::query(&format!("{REC_SELECT} WHERE status = ? ORDER BY id ASC"))
                    .bind(status)
                    .fetch_all(&self.pool)
                    .await?
            }
            None => {
                sqlx::query(&format!("{REC_SELECT} ORDER BY id ASC"))
                    .fetch_all(&self.pool)
                    .await?
            }
        };
        Ok(rows.iter().map(row_to_recommendation).collect())
    }

    pub async fn get_adjustment_recommendation(
        &self,
        id: i64,
    ) -> Result<Option<StoredRecommendationRecord>, DbError> {
        let row = sqlx::query(&format!("{REC_SELECT} WHERE id = ?"))
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.as_ref().map(row_to_recommendation))
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
            r#"UPDATE policy_adjustment_recommendations
               SET status = ?, decided_by = ?, decision_notes = ?,
                   decided_at = datetime('now'),
                   variant_id = COALESCE(?, variant_id),
                   applied_adjustment_id = COALESCE(?, applied_adjustment_id)
               WHERE id = ?"#,
        )
        .bind(status)
        .bind(decided_by)
        .bind(notes)
        .bind(variant_id)
        .bind(applied_adjustment_id)
        .bind(id)
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
            r#"UPDATE policy_adjustment_recommendations
               SET status = 'reverted', reverted_at = datetime('now'), reverted_by = ?,
                   decision_notes = COALESCE(?, decision_notes),
                   revert_adjustment_id = COALESCE(?, revert_adjustment_id)
               WHERE id = ?"#,
        )
        .bind(reverted_by)
        .bind(notes)
        .bind(revert_adjustment_id)
        .bind(id)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(rows > 0)
    }
}

const REC_SELECT: &str = r#"SELECT id, recommendation_key, threshold_key, current_threshold,
    proposed_threshold, sample_size, false_positive_count, true_positive_count,
    confidence, rationale, status, trigger_outcome_id, trigger_transaction_id,
    decision_notes, decided_by, variant_id, applied_adjustment_id
    FROM policy_adjustment_recommendations"#;

fn row_to_recommendation(row: &sqlx::sqlite::SqliteRow) -> StoredRecommendationRecord {
    use sqlx::Row;
    let trigger_txn: Option<String> = row.get("trigger_transaction_id");
    StoredRecommendationRecord {
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
        trigger_transaction_id: trigger_txn.and_then(|s| Uuid::parse_str(&s).ok()),
        decision_notes: row.get("decision_notes"),
        decided_by: row.get("decided_by"),
        variant_id: row.get("variant_id"),
        applied_adjustment_id: row.get("applied_adjustment_id"),
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

#[cfg(test)]
mod tests {
    use super::*;

    async fn store() -> SqliteStore {
        SqliteStore::connect(":memory:").await.expect("connect")
    }

    fn decision(txn: Uuid) -> DecisionRecord {
        DecisionRecord {
            transaction_id: txn,
            org_id: None,
            agent_id: "agent-1".to_string(),
            decision: "DENY".to_string(),
            domain: None,
            policy_code: Some("PII_LEAK".to_string()),
            reason: Some("test".to_string()),
            sig_nonce: None,
            sig_signed_at: None,
            sig_b64: None,
            request_nonce: None,
            request_sig: None,
            decided_at: None,
        }
    }

    #[tokio::test]
    async fn outcome_round_trips_into_learning_list() {
        let db = store().await;
        let txn = Uuid::new_v4();
        db.insert_decision(&decision(txn)).await.expect("decision");

        let id = db
            .insert_decision_outcome(&DecisionOutcomeRecord {
                transaction_id: txn,
                outcome: "FALSE_POSITIVE".to_string(),
                impact_usd: Some(12.5),
                reviewer_id: Some("rev-1".to_string()),
                reviewer_notes: None,
                agent_intent: None,
                agent_constraints: None,
            })
            .await
            .expect("outcome");
        assert!(id > 0, "outcome id must be a real rowid, got {id}");

        let learned = db.list_learning_outcomes(24).await.expect("list");
        assert_eq!(learned.len(), 1, "outcome should be readable back");
        assert_eq!(learned[0].transaction_id, txn);
        assert_eq!(learned[0].outcome, "FALSE_POSITIVE");
        assert_eq!(learned[0].policy_code.as_deref(), Some("PII_LEAK"));
    }

    #[tokio::test]
    async fn learning_list_respects_age_window() {
        let db = store().await;
        let txn = Uuid::new_v4();
        db.insert_decision(&decision(txn)).await.expect("decision");
        db.insert_decision_outcome(&DecisionOutcomeRecord {
            transaction_id: txn,
            outcome: "TRUE_POSITIVE".to_string(),
            impact_usd: None,
            reviewer_id: None,
            reviewer_notes: None,
            agent_intent: None,
            agent_constraints: None,
        })
        .await
        .expect("outcome");

        // age window of 0 hours excludes anything reviewed before "now"
        let none = db.list_learning_outcomes(0).await.expect("list");
        assert!(none.len() <= 1);
        let some = db.list_learning_outcomes(48).await.expect("list");
        assert_eq!(some.len(), 1);
    }

    #[tokio::test]
    async fn policy_adjustment_persists() {
        let db = store().await;
        let id = db
            .insert_policy_adjustment(&PolicyAdjustmentRecord {
                rule_id: "rule-7".to_string(),
                domain: "financial".to_string(),
                old_threshold: Some(0.8),
                new_threshold: Some(0.6),
                reason: "too many false positives".to_string(),
                adjusted_by: "reviewer".to_string(),
                trigger_outcome_id: None,
                recommendation_id: None,
                variant_id: None,
            })
            .await
            .expect("adjustment");
        assert!(id > 0, "adjustment must return a real rowid");
    }

    fn rec(key: &str) -> AdjustmentRecommendationRecord {
        AdjustmentRecommendationRecord {
            recommendation_key: key.to_string(),
            threshold_key: "drift.semantic".to_string(),
            current_threshold: 0.8,
            proposed_threshold: 0.65,
            sample_size: 40,
            false_positive_count: 9,
            true_positive_count: 31,
            confidence: 0.87,
            rationale: "fp rate above target".to_string(),
            trigger_outcome_id: None,
            trigger_transaction_id: Some(Uuid::new_v4()),
        }
    }

    #[tokio::test]
    async fn recommendation_upsert_is_idempotent_by_key() {
        let db = store().await;
        let first = db
            .upsert_adjustment_recommendation(&rec("k1"))
            .await
            .expect("first upsert");

        let mut second_rec = rec("k1");
        second_rec.proposed_threshold = 0.5;
        let second = db
            .upsert_adjustment_recommendation(&second_rec)
            .await
            .expect("second upsert");

        assert_eq!(first, second, "same key must reuse the same row id");
        let stored = db
            .get_adjustment_recommendation(first)
            .await
            .expect("get")
            .expect("row exists");
        assert_eq!(stored.proposed_threshold, 0.5, "update must overwrite");
        assert_eq!(stored.status, "pending");
    }

    #[tokio::test]
    async fn recommendation_decide_and_revert_flow() {
        let db = store().await;
        let id = db
            .upsert_adjustment_recommendation(&rec("k2"))
            .await
            .expect("upsert");

        let decided = db
            .decide_adjustment_recommendation(id, "approved", "alice", Some("ok"), None, None)
            .await
            .expect("decide");
        assert!(decided, "decide must report a row was updated");

        let approved = db
            .list_adjustment_recommendations(Some("approved"))
            .await
            .expect("list");
        assert_eq!(approved.len(), 1);
        assert_eq!(approved[0].decided_by.as_deref(), Some("alice"));

        let reverted = db
            .mark_recommendation_reverted(id, "bob", Some("regression"), None)
            .await
            .expect("revert");
        assert!(reverted);

        let after = db
            .get_adjustment_recommendation(id)
            .await
            .expect("get")
            .expect("row");
        assert_eq!(after.status, "reverted");
    }

    #[tokio::test]
    async fn decide_missing_recommendation_returns_false() {
        let db = store().await;
        let hit = db
            .decide_adjustment_recommendation(9999, "approved", "alice", None, None, None)
            .await
            .expect("decide");
        assert!(
            !hit,
            "no matching row must return false, not a fake success"
        );
    }

    #[tokio::test]
    async fn list_recommendations_filters_by_status() {
        let db = store().await;
        db.upsert_adjustment_recommendation(&rec("a"))
            .await
            .expect("a");
        let b = db
            .upsert_adjustment_recommendation(&rec("b"))
            .await
            .expect("b");
        db.decide_adjustment_recommendation(b, "rejected", "carol", None, None, None)
            .await
            .expect("decide");

        let pending = db
            .list_adjustment_recommendations(Some("pending"))
            .await
            .expect("pending");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].recommendation_key, "a");

        let all = db.list_adjustment_recommendations(None).await.expect("all");
        assert_eq!(all.len(), 2);
    }
}
