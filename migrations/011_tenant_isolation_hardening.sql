-- HaltChain Phase 1b tenant isolation hardening
-- Run order: after 010_phase1b_runtime_reliability_fixes.sql
--
-- Goals:
--   1) Remove permissive org_id IS NULL access paths in RLS policies.
--   2) Add WITH CHECK constraints so writes must carry tenant org_id.
--   3) Force RLS so table owners do not silently bypass tenant filters.
--
-- Note: existing legacy rows with org_id IS NULL remain in-place but become
-- inaccessible through tenant-scoped roles until explicitly backfilled.

-- Ensure all tenant-sensitive tables enforce RLS for every role, including owner.
ALTER TABLE decisions_hot FORCE ROW LEVEL SECURITY;
ALTER TABLE decisions_cold FORCE ROW LEVEL SECURITY;
ALTER TABLE policy_configs FORCE ROW LEVEL SECURITY;
ALTER TABLE telemetry_durable FORCE ROW LEVEL SECURITY;
ALTER TABLE action_embeddings FORCE ROW LEVEL SECURITY;

-- decisions_hot: strict tenant read/write isolation
DROP POLICY IF EXISTS tenant_isolation_hot ON decisions_hot;
CREATE POLICY tenant_isolation_hot ON decisions_hot
    USING (org_id::text = nullif(current_setting('app.current_org_id', true), ''))
    WITH CHECK (org_id::text = nullif(current_setting('app.current_org_id', true), ''));

-- decisions_hot: auditor read-only, tenant-scoped
DROP POLICY IF EXISTS auditor_read_hot ON decisions_hot;
CREATE POLICY auditor_read_hot ON decisions_hot
    FOR SELECT TO auditor_role
    USING (org_id::text = nullif(current_setting('app.current_org_id', true), ''));

-- decisions_cold: strict tenant read/write isolation
DROP POLICY IF EXISTS tenant_isolation_cold ON decisions_cold;
CREATE POLICY tenant_isolation_cold ON decisions_cold
    USING (org_id::text = nullif(current_setting('app.current_org_id', true), ''))
    WITH CHECK (org_id::text = nullif(current_setting('app.current_org_id', true), ''));

-- policy_configs: strict tenant read/write isolation
DROP POLICY IF EXISTS tenant_isolation_policy ON policy_configs;
CREATE POLICY tenant_isolation_policy ON policy_configs
    USING (org_id::text = nullif(current_setting('app.current_org_id', true), ''))
    WITH CHECK (org_id::text = nullif(current_setting('app.current_org_id', true), ''));

-- telemetry_durable: strict tenant read/write isolation
DROP POLICY IF EXISTS tenant_isolation_telemetry ON telemetry_durable;
CREATE POLICY tenant_isolation_telemetry ON telemetry_durable
    USING (org_id::text = nullif(current_setting('app.current_org_id', true), ''))
    WITH CHECK (org_id::text = nullif(current_setting('app.current_org_id', true), ''));

-- action_embeddings: strict tenant read/write isolation
DROP POLICY IF EXISTS tenant_isolation_embeddings ON action_embeddings;
CREATE POLICY tenant_isolation_embeddings ON action_embeddings
    USING (org_id::text = nullif(current_setting('app.current_org_id', true), ''))
    WITH CHECK (org_id::text = nullif(current_setting('app.current_org_id', true), ''));
