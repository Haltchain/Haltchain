-- HaltChain Phase 1b runtime reliability fixes
-- Run order: after 009_phase1b_pg_native.sql
--
-- This migration repairs two runtime issues discovered during local proof runs:
--   1) JWT HS256 signature comparison now normalizes base64url correctly
--      (fixes false negatives for valid tokens without '=' padding)
--   2) telemetry-promote pg_cron cadence is forced to true 5-second scheduling
--      on existing databases (instead of minute-granularity interpretation)

-- Ensure pg_cron is present for schedule operations.
CREATE EXTENSION IF NOT EXISTS pg_cron;

-- Recreate telemetry-promote with an explicit 5-second interval.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'telemetry-promote') THEN
        PERFORM cron.unschedule('telemetry-promote');
    END IF;

    PERFORM cron.schedule(
        'telemetry-promote',
        '5 seconds',
        $job$
        INSERT INTO telemetry_durable (id, org_id, agent_id, metric, value, tags, ts)
        SELECT id, org_id, agent_id, metric, value, tags, ts FROM telemetry_hot
        ON CONFLICT (id) DO NOTHING;
        DELETE FROM telemetry_hot WHERE id IN (
            SELECT id FROM telemetry_durable
        );
        $job$
    );
END;
$$;

-- Normalize JWT signatures as base64url without padding before compare.
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
    header_b64  := split_part(token, '.', 1);
    payload_b64 := split_part(token, '.', 2);
    sig_b64     := split_part(token, '.', 3);

    expected_sig := encode(
        hmac(header_b64 || '.' || payload_b64, secret, 'sha256'),
        'base64'
    );

    expected_sig := regexp_replace(
        translate(trim(expected_sig), '+/', '-_'),
        '=+$',
        ''
    );
    sig_b64 := regexp_replace(trim(sig_b64), '=+$', '');

    IF expected_sig <> sig_b64 THEN
        RAISE EXCEPTION 'invalid JWT signature';
    END IF;

    payload_json := convert_from(
        decode(
            rpad(replace(replace(payload_b64, '-', '+'), '_', '/'),
                 length(payload_b64) + (4 - length(payload_b64) % 4) % 4, '='),
            'base64'
        ),
        'UTF8'
    )::JSONB;

    exp_val := (payload_json ->> 'exp')::BIGINT;
    IF exp_val IS NOT NULL AND exp_val < extract(epoch FROM now())::BIGINT THEN
        RAISE EXCEPTION 'JWT expired';
    END IF;

    org_id_val := payload_json ->> 'org_id';
    IF org_id_val IS NULL THEN
        RAISE EXCEPTION 'JWT missing org_id claim';
    END IF;

    PERFORM set_config('app.current_org_id', org_id_val, false);
END;
$$;

-- Ensure RLS is evaluated in caller context for auditor-facing views.
ALTER VIEW IF EXISTS audit_decisions_view
    SET (security_invoker = true);

ALTER VIEW IF EXISTS compliance_summary_view
    SET (security_invoker = true);

-- Harden RLS policies against empty tenant settings and keep UUID casts safe.
DROP POLICY IF EXISTS tenant_isolation_hot ON decisions_hot;
CREATE POLICY tenant_isolation_hot ON decisions_hot
    USING (
        org_id IS NULL
        OR org_id = nullif(current_setting('app.current_org_id', true), '')::UUID
    );

DROP POLICY IF EXISTS auditor_read_hot ON decisions_hot;
CREATE POLICY auditor_read_hot ON decisions_hot
    FOR SELECT TO auditor_role
    USING (
        org_id IS NULL
        OR org_id = nullif(current_setting('app.current_org_id', true), '')::UUID
    );

DROP POLICY IF EXISTS tenant_isolation_cold ON decisions_cold;
CREATE POLICY tenant_isolation_cold ON decisions_cold
    USING (
        org_id IS NULL
        OR org_id = nullif(current_setting('app.current_org_id', true), '')::UUID
    );

DROP POLICY IF EXISTS tenant_isolation_policy ON policy_configs;
CREATE POLICY tenant_isolation_policy ON policy_configs
    USING (org_id = nullif(current_setting('app.current_org_id', true), '')::UUID);

DROP POLICY IF EXISTS tenant_isolation_telemetry ON telemetry_durable;
CREATE POLICY tenant_isolation_telemetry ON telemetry_durable
    USING (
        org_id IS NULL
        OR org_id = nullif(current_setting('app.current_org_id', true), '')::UUID
    );

DROP POLICY IF EXISTS tenant_isolation_embeddings ON action_embeddings;
CREATE POLICY tenant_isolation_embeddings ON action_embeddings
    USING (
        org_id IS NULL
        OR org_id = nullif(current_setting('app.current_org_id', true), '')::UUID
    );
