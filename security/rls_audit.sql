-- Phase 1b RLS audit checks

-- 1) Null-org rows must be blocked at source for tenant-sensitive decisions.
SELECT count(*) AS null_org_rows
FROM decision_records
WHERE org_id IS NULL;

-- 2) Tenant tables must have row security enabled.
SELECT schemaname, tablename AS relname, rowsecurity
FROM pg_tables
WHERE schemaname = 'public'
  AND tablename IN (
    'decisions_hot',
    'decisions_cold',
    'action_embeddings',
    'telemetry_durable',
    'policy_configs'
  )
ORDER BY tablename;

-- 3) Verify policy presence for strict tenant isolation.
SELECT schemaname, tablename, policyname, cmd
FROM pg_policies
WHERE schemaname='public'
  AND tablename IN (
    'decisions_hot',
    'decisions_cold',
    'action_embeddings',
    'telemetry_durable',
    'policy_configs'
  )
ORDER BY tablename, policyname;
