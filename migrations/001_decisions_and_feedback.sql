-- HaltChain PostgreSQL schema — decisions + feedback loop
-- Run order: 001 (this file) before any application migration.
--
-- Retention strategy:
--   decisions_hot   → 90 days   (operational queries, dispute resolution)
--   decisions_cold  → 7 years   (compliance, legal discovery)
--   decision_outcomes / policy_adjustments → indefinite (learning loop)
--
-- Partitioning: decisions_hot is range-partitioned by month.
-- Archival: a pg_cron job (or external scheduler) moves rows older than
--   90 days from decisions_hot into decisions_cold and drops old partitions.

-- ── Enums (idempotent)

DO $$ BEGIN CREATE TYPE policy_result AS ENUM (
    'ALLOW', 'DENY', 'CIRCUIT_BREAK', 'GOAL_CLARIFICATION_REQUIRED'
); EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN CREATE TYPE outcome_type AS ENUM (
    'TRUE_POSITIVE', 'FALSE_POSITIVE', 'EXPECTED_EDGE_CASE'
); EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN CREATE TYPE breaker_domain AS ENUM (
    'financial', 'privacy', 'security', 'operational'
); EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ── Hot decisions (90-day rolling window) ─────────────────────────────────────
-- Partitioned by decided_at month; partition management handled externally.

CREATE TABLE IF NOT EXISTS decisions_hot (
    id              BIGSERIAL,
    transaction_id  UUID        NOT NULL,
    agent_id        TEXT        NOT NULL,
    decision        policy_result NOT NULL,
    domain          breaker_domain,           -- which breaker fired (NULL = ALLOW)
    policy_code     TEXT,                     -- e.g. "MAX_TRANSFER_USD"
    reason          TEXT,
    -- Ed25519 response envelope (64-byte sig stored as base64)
    sig_nonce       TEXT,
    sig_signed_at   TIMESTAMPTZ,
    sig_b64         TEXT,
    -- Outbound request HMAC (for audit trail)
    request_nonce   TEXT,
    request_sig     TEXT,
    decided_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id, decided_at)
) PARTITION BY RANGE (decided_at);

-- Create current + next month partition on deploy; add future partitions via cron.
CREATE TABLE IF NOT EXISTS decisions_hot_default PARTITION OF decisions_hot DEFAULT;

CREATE INDEX ON decisions_hot (agent_id, decided_at DESC);
CREATE INDEX ON decisions_hot (transaction_id);
CREATE INDEX ON decisions_hot (decision, decided_at DESC);

-- ── Cold decisions (7-year compliance archive) ────────────────────────────────
-- One row per day per agent: Merkle root over that day's decisions_hot rows.

CREATE TABLE IF NOT EXISTS decisions_cold (
    id              BIGSERIAL PRIMARY KEY,
    agent_id        TEXT        NOT NULL,
    period_date     DATE        NOT NULL,
    decision_count  INTEGER     NOT NULL DEFAULT 0,
    allow_count     INTEGER     NOT NULL DEFAULT 0,
    deny_count      INTEGER     NOT NULL DEFAULT 0,
    circuit_break_count INTEGER NOT NULL DEFAULT 0,
    -- SHA-256 Merkle root over sorted transaction_ids for the day
    merkle_root     TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (agent_id, period_date)
);

CREATE INDEX ON decisions_cold (agent_id, period_date DESC);

-- ── Decision outcomes (human feedback) ───────────────────────────────────────
-- Every circuit break or deny can receive a reviewer outcome.
-- This is the raw signal for the feedback learning loop.

CREATE TABLE IF NOT EXISTS decision_outcomes (
    id              BIGSERIAL PRIMARY KEY,
    -- Soft reference to decisions_hot; no FK because decisions_hot is a partitioned
    -- table whose PK includes decided_at, so transaction_id alone cannot be unique.
    transaction_id  UUID        NOT NULL,
    outcome         outcome_type NOT NULL,
    -- Monetary or business estimate of impact (positive = damage prevented,
    -- negative = false positive business cost).
    impact_usd      NUMERIC(14,2),
    reviewer_id     TEXT,                     -- human reviewer or 'auto'
    reviewer_notes  TEXT,
    -- Agent's self-reported context at time of block
    agent_intent    TEXT,
    agent_constraints TEXT,
    -- Set when a new policy variant was derived from this outcome
    derived_variant_id BIGINT,
    reviewed_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ON decision_outcomes (transaction_id);
CREATE INDEX ON decision_outcomes (outcome, reviewed_at DESC);

-- ── Policy adjustments (learning loop audit trail) ────────────────────────────
-- Every threshold change is logged here; enables rollback and A/B analysis.

CREATE TABLE IF NOT EXISTS policy_adjustments (
    id              BIGSERIAL PRIMARY KEY,
    rule_id         TEXT        NOT NULL,     -- e.g. "MAX_TRANSFER_USD"
    domain          breaker_domain NOT NULL,
    old_threshold   NUMERIC(14,4),
    new_threshold   NUMERIC(14,4),
    -- Aggregated stats that motivated the change
    fp_rate_before  NUMERIC(5,4),
    tp_rate_before  NUMERIC(5,4),
    sample_window   INTEGER,                  -- number of decisions sampled
    reason          TEXT        NOT NULL,
    -- Source: 'auto' (Bayesian optimizer) or reviewer_id
    adjusted_by     TEXT        NOT NULL DEFAULT 'auto',
    -- If this adjustment is under A/B test, record the cohort
    ab_cohort_id    TEXT,
    -- Link back to the outcome that triggered this (optional)
    trigger_outcome_id BIGINT REFERENCES decision_outcomes(id),
    adjusted_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ON policy_adjustments (rule_id, adjusted_at DESC);

-- ── Conversation drift log ────────────────────────────────────────────────────
-- Records from ConversationStore::push() once baseline is established.

CREATE TABLE IF NOT EXISTS conversation_drift_log (
    id              BIGSERIAL PRIMARY KEY,
    agent_id        TEXT        NOT NULL,
    conversation_id TEXT        NOT NULL,
    semantic_drift  NUMERIC(6,4) NOT NULL,
    drift_velocity  NUMERIC(6,4) NOT NULL,
    window_len      INTEGER     NOT NULL,
    baseline_len    INTEGER     NOT NULL,
    recommendation  TEXT        NOT NULL,     -- 'Maintain' | 'IncreaseMonitoring' | 'RetrainOrRollback'
    logged_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ON conversation_drift_log (agent_id, logged_at DESC);
CREATE INDEX ON conversation_drift_log (recommendation, logged_at DESC)
    WHERE recommendation != 'Maintain';
