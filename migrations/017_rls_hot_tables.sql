-- Close RLS gaps on hot/ephemeral tables that hold tenant data but had no policies.
-- telemetry_hot, drift_counters_hot, dependency_circuit_events were created without
-- ENABLE ROW LEVEL SECURITY, creating a cross-tenant read gap.

ALTER TABLE telemetry_hot ENABLE ROW LEVEL SECURITY;
ALTER TABLE telemetry_hot FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS telemetry_hot_tenant_isolation ON telemetry_hot;
CREATE POLICY telemetry_hot_tenant_isolation ON telemetry_hot
    USING (
        org_id::text = nullif(current_setting('app.current_org_id', true), '')
        OR org_id = '00000000-0000-0000-0000-000000000001'::uuid
    );

GRANT SELECT, INSERT ON telemetry_hot TO app_role;
GRANT SELECT ON telemetry_hot TO auditor_role;

ALTER TABLE drift_counters_hot ENABLE ROW LEVEL SECURITY;
ALTER TABLE drift_counters_hot FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS drift_counters_hot_tenant_isolation ON drift_counters_hot;
CREATE POLICY drift_counters_hot_tenant_isolation ON drift_counters_hot
    USING (
        org_id::text = nullif(current_setting('app.current_org_id', true), '')
        OR org_id = '00000000-0000-0000-0000-000000000001'::uuid
    );

GRANT SELECT, INSERT, UPDATE ON drift_counters_hot TO app_role;

ALTER TABLE dependency_circuit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE dependency_circuit_events FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS dep_circuit_events_tenant_isolation ON dependency_circuit_events;
CREATE POLICY dep_circuit_events_tenant_isolation ON dependency_circuit_events
    USING (
        org_id IS NULL
        OR org_id::text = nullif(current_setting('app.current_org_id', true), '')
        OR org_id = '00000000-0000-0000-0000-000000000001'::uuid
    );

GRANT SELECT, INSERT ON dependency_circuit_events TO app_role;
