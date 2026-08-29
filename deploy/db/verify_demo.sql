-- Post-demo checks (run as DB owner / app_role with tenant context set).

\set demo_org '11111111-1111-1111-1111-111111111111'

SELECT 'null_org_rows' AS check, count(*)::bigint AS value
FROM decisions_hot WHERE org_id IS NULL
UNION ALL
SELECT 'mcp_history_rows', count(*)::bigint
FROM mcp_tool_history WHERE org_id = :'demo_org'::uuid;

SELECT tool_name, decision, reason, merkle_root IS NOT NULL AS has_merkle, timestamp
FROM mcp_tool_history
WHERE org_id = :'demo_org'::uuid
ORDER BY timestamp DESC
LIMIT 20;

SELECT schemaname, tablename, rowsecurity
FROM pg_tables
WHERE schemaname = 'public'
  AND tablename IN ('mcp_tool_history', 'mcp_tool_policies', 'decisions_hot')
ORDER BY tablename;
