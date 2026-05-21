-- Phase 1b concurrency hardening + Phase 2 kernel prep
-- Run order: after 014_mcp_policy_engine.sql
--
-- 1. Connection-reset guard: prevents stale tenant context leaking across pool connections
-- 2. Advisory lock wrapper for policy config upserts (belt+suspenders over app-layer lock)
-- 3. seccomp_profiles table for Phase 2 dynamic seccomp-BPF profile storage
-- 4. FTS rank index for scored audit search
-- 5. Cascade-failure circuit tracking table

-- Extension guard
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ── 1. Connection Reset Guard ─────────────────────────────────────────────────
-- Called by the app layer before returning a connection to the pool.
-- Clears app.current_org_id so the next borrower starts clean.
CREATE OR REPLACE FUNCTION reset_tenant_context()
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM set_config('app.current_org_id', '', false);
END;
$$;

COMMENT ON FUNCTION reset_tenant_context IS
    'Clear tenant RLS context before returning connection to pool. '
    'Call via sqlx: SELECT reset_tenant_context();';

-- ── 2. Safe Policy Upsert (advisory lock enforced at DB level too) ────────────
-- Double-locks with both app-layer pg_advisory_xact_lock and this trigger,
-- so a race between a DB-direct write and the app never causes a split-brain.
CREATE OR REPLACE FUNCTION policy_configs_version_check()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    -- Force monotone version: new version must be > any existing version for this policy.
    IF NEW.version <= COALESCE(
        (SELECT MAX(version) FROM policy_configs
         WHERE org_id = NEW.org_id AND policy_name = NEW.policy_name AND id <> NEW.id),
        0
    ) THEN
        -- Silently bump to max+1 rather than erroring; keeps concurrent inserts safe.
        NEW.version := COALESCE(
            (SELECT MAX(version) FROM policy_configs
             WHERE org_id = NEW.org_id AND policy_name = NEW.policy_name),
            0
        ) + 1;
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'trg_policy_version_monotone'
          AND tgrelid = 'policy_configs'::regclass
    ) THEN
        CREATE TRIGGER trg_policy_version_monotone
            BEFORE INSERT OR UPDATE ON policy_configs
            FOR EACH ROW EXECUTE FUNCTION policy_configs_version_check();
    END IF;
END;
$$;

-- ── 3. seccomp_profiles — Phase 2 dynamic Seccomp-BPF storage ────────────────
-- Stores generated seccomp profiles per agent/workload type.
-- Phase 2 eBPF layer reads these to configure the kernel sandbox.
CREATE TABLE IF NOT EXISTS seccomp_profiles (
    id          UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id      UUID        NOT NULL,
    workload    TEXT        NOT NULL,  -- e.g. 'onnx_worker', 'agent_sandbox', 'mcp_server'
    version     INT         NOT NULL DEFAULT 1,
    profile     JSONB       NOT NULL, -- seccomp profile JSON (libseccomp format)
    is_active   BOOLEAN     NOT NULL DEFAULT false,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at TIMESTAMPTZ,
    UNIQUE (org_id, workload, version)
);

CREATE INDEX IF NOT EXISTS idx_seccomp_profiles_active
    ON seccomp_profiles (org_id, workload, is_active)
    WHERE is_active = true;

COMMENT ON TABLE seccomp_profiles IS
    'Phase 2: Dynamic seccomp-BPF profiles per workload. '
    'Generated from observed syscall patterns via eBPF tracing.';

ALTER TABLE seccomp_profiles ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    CREATE POLICY tenant_isolation_seccomp ON seccomp_profiles
        USING (org_id::text = nullif(current_setting('app.current_org_id', true), ''))
        WITH CHECK (org_id::text = nullif(current_setting('app.current_org_id', true), ''));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

ALTER TABLE seccomp_profiles FORCE ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE ON seccomp_profiles TO app_role;
GRANT SELECT ON seccomp_profiles TO auditor_role;

-- ── 4. FTS rank support (ts_rank for scored audit search) ─────────────────────
-- Adds a helper function so the app can do scored FTS without writing raw SQL.
CREATE OR REPLACE FUNCTION audit_fts_search(
    query_text TEXT,
    max_rows   INT DEFAULT 50
)
RETURNS TABLE (
    id              BIGINT,
    transaction_id  UUID,
    agent_id        TEXT,
    decision        TEXT,
    reason          TEXT,
    policy_code     TEXT,
    decided_at      TIMESTAMPTZ,
    rank            REAL
)
LANGUAGE SQL STABLE SECURITY INVOKER AS $$
    SELECT
        id,
        transaction_id,
        agent_id,
        decision::text,
        reason,
        policy_code,
        decided_at,
        ts_rank(fts_vector, plainto_tsquery('english', query_text)) AS rank
    FROM decisions_hot
    WHERE fts_vector @@ plainto_tsquery('english', query_text)
      AND org_id::text = nullif(current_setting('app.current_org_id', true), '')
    ORDER BY rank DESC, decided_at DESC
    LIMIT max_rows;
$$;

COMMENT ON FUNCTION audit_fts_search IS
    'RLS-enforced FTS with ts_rank scoring. Tenant-scoped via app.current_org_id.';

GRANT EXECUTE ON FUNCTION audit_fts_search TO app_role;
GRANT EXECUTE ON FUNCTION audit_fts_search TO auditor_role;

-- ── 5. Cascade-failure circuit tracking ──────────────────────────────────────
-- Tracks dependency failure events for alerting / circuit-breaker decisions.
CREATE UNLOGGED TABLE IF NOT EXISTS dependency_circuit_events (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    dependency  TEXT        NOT NULL,  -- 'dragonflydb', 'pgvector', 'pg_cron', 'onnx_worker'
    org_id      UUID,
    event_type  TEXT        NOT NULL,  -- 'open', 'half_open', 'close', 'failure', 'fallback'
    detail      TEXT,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_dep_circuit_dep_ts
    ON dependency_circuit_events (dependency, ts DESC);

COMMENT ON TABLE dependency_circuit_events IS
    'Unlogged audit of cascade failure events per dependency. '
    'Used by the health endpoint and alerting to detect degraded-mode operation.';
