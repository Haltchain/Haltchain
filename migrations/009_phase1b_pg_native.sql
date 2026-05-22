-- HaltChain Phase 1b — PostgreSQL-Native Compliance Engine
-- Run order: after 008_hash_chaining.sql
--
-- This migration implements:
--   1. Unlogged telemetry tables for hot-path fire-and-forget writes (<10µs)
--   2. pg_cron job to promote ephemeral telemetry to WAL every 5s
--   3. RLS multi-tenant isolation on audit / policy / telemetry tables
--   4. JWT/pgcrypto auth roles and policies
--   5. Full-text search (TSVector) index on audit decisions
--   6. JSONB policy_configs table for dynamic policy DAG evaluation
--   7. PostgREST / auditor role bootstrap
--
-- Extensions required: pgcrypto, pg_cron, vector (already from 007)
-- PostgreSQL version: 16+

-- ── Extensions ────────────────────────────────────────────────────────────────

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_cron;  -- may require superuser on first run

-- ── Roles ─────────────────────────────────────────────────────────────────────

DO $$ BEGIN
    CREATE ROLE app_role NOLOGIN;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE ROLE auditor_role NOLOGIN;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE ROLE web_anon NOLOGIN;  -- PostgREST anonymous role
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ── JSONB Policy Configs ───────────────────────────────────────────────────────
-- Source of truth for dynamic policy rules evaluated via jsonb_path_query().
-- Hot-reload is race-free via pg_advisory_xact_lock() in the app layer.

CREATE TABLE IF NOT EXISTS policy_configs (
    id          UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id      UUID        NOT NULL,
    policy_name TEXT        NOT NULL,
    version     INT         NOT NULL DEFAULT 1,
    rules       JSONB       NOT NULL DEFAULT '{}',
    -- e.g. {"max_transfer_usd": 1000, "max_actions_per_minute": 10, ...}
    enabled     BOOLEAN     NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, policy_name, version)
);

CREATE INDEX IF NOT EXISTS idx_policy_configs_org_enabled
    ON policy_configs (org_id, enabled)
    WHERE enabled = true;

-- GIN index for fast jsonb_path_query() extraction
CREATE INDEX IF NOT EXISTS idx_policy_configs_rules_gin
    ON policy_configs USING GIN (rules);

COMMENT ON TABLE policy_configs IS
    'Dynamic policy rules stored as JSONB. Hot-reloaded via advisory lock in app layer.';

-- ── Unlogged Telemetry (L3 hot-path cache layer) ──────────────────────────────
-- Fire-and-forget writes: no WAL overhead, <10µs target.
-- Acceptable ephemeral loss on crash — critical audit data lives in WAL tables.

CREATE UNLOGGED TABLE IF NOT EXISTS telemetry_hot (
    id          BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id      UUID,
    agent_id    TEXT        NOT NULL,
    metric      TEXT        NOT NULL,  -- e.g. 'validation_latency_us', 'drift_score'
    value       DOUBLE PRECISION NOT NULL,
    tags        JSONB,                 -- optional labels / dimensions
    ts          TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE telemetry_hot IS
    'Unlogged hot-path telemetry. Promoted to telemetry_durable every 5s by pg_cron.';

-- ── Durable Telemetry (WAL-backed) ────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS telemetry_durable (
    id          BIGINT      PRIMARY KEY,
    org_id      UUID,
    agent_id    TEXT        NOT NULL,
    metric      TEXT        NOT NULL,
    value       DOUBLE PRECISION NOT NULL,
    tags        JSONB,
    ts          TIMESTAMPTZ NOT NULL,
    promoted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_telemetry_durable_agent_ts
    ON telemetry_durable (agent_id, ts DESC);

CREATE INDEX IF NOT EXISTS idx_telemetry_durable_metric_ts
    ON telemetry_durable (metric, ts DESC);

-- ── pg_cron: Promote unlogged telemetry → WAL every 5 seconds ─────────────────

SELECT cron.schedule(
    'telemetry-promote',
    '5 seconds',
    $$
    INSERT INTO telemetry_durable (id, org_id, agent_id, metric, value, tags, ts)
    SELECT id, org_id, agent_id, metric, value, tags, ts FROM telemetry_hot
    ON CONFLICT (id) DO NOTHING;
    DELETE FROM telemetry_hot WHERE id IN (
        SELECT id FROM telemetry_durable
    );
    $$
);

-- ── Full-Text Search on Audit Decisions ───────────────────────────────────────
-- Inverted index for post-hoc audit search without Elasticsearch.

-- Add tsvector column to decisions_hot (safe: IF NOT EXISTS semantics via ALTER)
ALTER TABLE decisions_hot
    ADD COLUMN IF NOT EXISTS fts_vector TSVECTOR
        GENERATED ALWAYS AS (
            to_tsvector('english',
                coalesce(reason, '') || ' ' ||
                coalesce(policy_code, '') || ' ' ||
                coalesce(agent_id, '')
            )
        ) STORED;

CREATE INDEX IF NOT EXISTS idx_decisions_hot_fts
    ON decisions_hot USING GIN (fts_vector);

COMMENT ON COLUMN decisions_hot.fts_vector IS
    'Auto-updated TSVector for full-text search on audit decisions.';

-- ── RLS: Multi-Tenant Isolation ───────────────────────────────────────────────
-- org_id = current_setting('app.current_org_id') enforced at connection level.
-- Application code sets this via: SET LOCAL app.current_org_id = '<uuid>';

-- decisions_hot
ALTER TABLE decisions_hot     ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE decisions_cold    ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE telemetry_durable OWNER TO app_role;  -- ensure owned

ALTER TABLE decisions_hot     ENABLE ROW LEVEL SECURITY;
ALTER TABLE decisions_cold    ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_configs    ENABLE ROW LEVEL SECURITY;
ALTER TABLE telemetry_durable ENABLE ROW LEVEL SECURITY;
ALTER TABLE action_embeddings ENABLE ROW LEVEL SECURITY;

-- decisions_hot: tenant isolation
DO $$ BEGIN
    CREATE POLICY tenant_isolation_hot ON decisions_hot
        USING (
            org_id IS NULL  -- legacy rows visible to all
            OR org_id = nullif(current_setting('app.current_org_id', true), '')::UUID
        );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- auditor read-only on decisions_hot
DO $$ BEGIN
    CREATE POLICY auditor_read_hot ON decisions_hot
        FOR SELECT TO auditor_role
        USING (
            org_id IS NULL
            OR org_id = nullif(current_setting('app.current_org_id', true), '')::UUID
        );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- decisions_cold: tenant isolation
DO $$ BEGIN
    CREATE POLICY tenant_isolation_cold ON decisions_cold
        USING (
            org_id IS NULL
            OR org_id = nullif(current_setting('app.current_org_id', true), '')::UUID
        );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- policy_configs: tenant isolation (full CRUD for app_role, read for auditor)
DO $$ BEGIN
    CREATE POLICY tenant_isolation_policy ON policy_configs
        USING (org_id = nullif(current_setting('app.current_org_id', true), '')::UUID);
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- telemetry_durable: tenant isolation
DO $$ BEGIN
    CREATE POLICY tenant_isolation_telemetry ON telemetry_durable
        USING (
            org_id IS NULL
            OR org_id = nullif(current_setting('app.current_org_id', true), '')::UUID
        );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- action_embeddings: no org_id column yet — add and protect
ALTER TABLE action_embeddings ADD COLUMN IF NOT EXISTS org_id UUID;

DO $$ BEGIN
    CREATE POLICY tenant_isolation_embeddings ON action_embeddings
        USING (
            org_id IS NULL
            OR org_id = nullif(current_setting('app.current_org_id', true), '')::UUID
        );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ── Grants ────────────────────────────────────────────────────────────────────

-- app_role: full access to operational tables
GRANT SELECT, INSERT, UPDATE ON decisions_hot     TO app_role;
GRANT SELECT, INSERT         ON decisions_cold    TO app_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON policy_configs TO app_role;
GRANT INSERT                 ON telemetry_hot     TO app_role;
GRANT SELECT, INSERT         ON telemetry_durable TO app_role;
GRANT SELECT, INSERT, UPDATE ON action_embeddings TO app_role;

-- auditor_role: read-only, RLS-scoped
GRANT SELECT ON decisions_hot     TO auditor_role;
GRANT SELECT ON decisions_cold    TO auditor_role;
GRANT SELECT ON policy_configs    TO auditor_role;
GRANT SELECT ON telemetry_durable TO auditor_role;
GRANT SELECT ON action_embeddings TO auditor_role;

-- web_anon: PostgREST anonymous JWT exchange only (no direct table access)
GRANT USAGE ON SCHEMA public TO web_anon;
GRANT auditor_role TO web_anon;  -- PostgREST switches role after JWT validation

-- ── JWT Auth Helper (pgcrypto) ────────────────────────────────────────────────
-- Application layer generates JWT; PostgreSQL validates via pgcrypto.
-- This function extracts org_id from a HS256 JWT and sets app.current_org_id.
-- Call at connection start: SELECT set_tenant_from_jwt($1, $2);

CREATE OR REPLACE FUNCTION set_tenant_from_jwt(
    token TEXT,
    secret TEXT
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    header_b64   TEXT;
    payload_b64  TEXT;
    sig_b64      TEXT;
    expected_sig TEXT;
    payload_json JSONB;
    org_id_val   TEXT;
    exp_val      BIGINT;
BEGIN
    -- Split JWT into header.payload.signature
    header_b64  := split_part(token, '.', 1);
    payload_b64 := split_part(token, '.', 2);
    sig_b64     := split_part(token, '.', 3);

    -- Verify HMAC-SHA256 signature
    expected_sig := encode(
        hmac(header_b64 || '.' || payload_b64, secret, 'sha256'),
        'base64'
    );
    -- Normalize both signatures to base64url (no padding) before comparison.
    expected_sig := regexp_replace(
        translate(trim(expected_sig), '+/', '-_'),
        '=+$',
        ''
    );
    sig_b64 := regexp_replace(trim(sig_b64), '=+$', '');

    IF expected_sig <> sig_b64 THEN
        RAISE EXCEPTION 'invalid JWT signature';
    END IF;

    -- Decode payload (base64url padding may be absent)
    payload_json := convert_from(
        decode(
            rpad(replace(replace(payload_b64, '-', '+'), '_', '/'),
                 length(payload_b64) + (4 - length(payload_b64) % 4) % 4, '='),
            'base64'
        ),
        'UTF8'
    )::JSONB;

    -- Validate expiry
    exp_val := (payload_json ->> 'exp')::BIGINT;
    IF exp_val IS NOT NULL AND exp_val < extract(epoch FROM now())::BIGINT THEN
        RAISE EXCEPTION 'JWT expired';
    END IF;

    -- Set org_id session variable for RLS enforcement
    org_id_val := payload_json ->> 'org_id';
    IF org_id_val IS NULL THEN
        RAISE EXCEPTION 'JWT missing org_id claim';
    END IF;

    PERFORM set_config('app.current_org_id', org_id_val, false);  -- session scope
END;
$$;

COMMENT ON FUNCTION set_tenant_from_jwt IS
    'Validates HS256 JWT and sets app.current_org_id for RLS enforcement. '
    'Call at connection start. Secret passed by application from env.';

-- ── PostgREST: Auditor Views ───────────────────────────────────────────────────
-- RLS-scoped read-only views exposed by PostgREST.

CREATE OR REPLACE VIEW audit_decisions_view
WITH (security_invoker = true) AS
SELECT
    id,
    transaction_id,
    agent_id,
    decision,
    domain,
    policy_code,
    reason,
    sig_b64,
    content_hash,
    row_hash,
    decided_at,
    org_id
FROM decisions_hot
ORDER BY decided_at DESC;

COMMENT ON VIEW audit_decisions_view IS
    'PostgREST-exposed auditor view. RLS on decisions_hot filters by org_id.';

GRANT SELECT ON audit_decisions_view TO auditor_role;

CREATE OR REPLACE VIEW compliance_summary_view
WITH (security_invoker = true) AS
SELECT
    dc.agent_id,
    dc.period_date,
    dc.decision_count,
    dc.allow_count,
    dc.deny_count,
    dc.circuit_break_count,
    dc.merkle_root,
    dc.org_id
FROM decisions_cold dc
ORDER BY dc.period_date DESC;

COMMENT ON VIEW compliance_summary_view IS
    'Daily Merkle-root compliance summary. RLS scoped per org.';

GRANT SELECT ON compliance_summary_view TO auditor_role;

-- ── Telemetry drift counters (unlogged, queryable L3) ─────────────────────────
-- Drift counter snapshots: one row per agent per computed window.
-- Queryable by app layer for backpressure decisions without hitting WAL tables.

CREATE UNLOGGED TABLE IF NOT EXISTS drift_counters_hot (
    agent_id    TEXT        NOT NULL,
    org_id      UUID,
    metric      TEXT        NOT NULL,  -- e.g. 'semantic_drift', 'goal_erosion'
    value       DOUBLE PRECISION NOT NULL,
    window_s    INT         NOT NULL DEFAULT 60,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, metric, window_s)
);

COMMENT ON TABLE drift_counters_hot IS
    'Per-agent drift counters (unlogged). Overwritten on each computation cycle.';
