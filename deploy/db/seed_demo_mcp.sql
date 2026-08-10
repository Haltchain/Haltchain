-- Demo org/agent for Kill Switch + Postgres MCP path (dev/staging only).
-- Matches demo/haltchain/demo/rogue_agent.py defaults.

\set demo_org '11111111-1111-1111-1111-111111111111'
\set demo_agent '22222222-2222-2222-2222-222222222222'

-- Block shell/exec tools via JSONB policy (runs after baseline check in guard).
DELETE FROM mcp_tool_policies
WHERE org_id = :'demo_org'::uuid
  AND policy_name IN ('deny-exec-tools', 'quarantine-curl');

INSERT INTO mcp_tool_policies (org_id, agent_id, policy_name, enabled, priority, policy)
VALUES (
  :'demo_org'::uuid,
  NULL,
  'deny-exec-tools',
  TRUE,
  200,
  '{"tool_name_pattern":"exec*","decision":"block","reason":"mcp-policy:deny-exec-tools"}'::jsonb
);

-- Quarantine curl/wget style exfil (optional second scenario).
INSERT INTO mcp_tool_policies (org_id, agent_id, policy_name, enabled, priority, policy)
VALUES (
  :'demo_org'::uuid,
  :'demo_agent'::uuid,
  'quarantine-curl',
  TRUE,
  150,
  '{"tool_name_pattern":"curl","denied_arg_patterns":["http"],"decision":"quarantine","reason":"mcp-policy:quarantine-curl"}'::jsonb
);
