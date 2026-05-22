-- HaltChain Phase 1b MCP Guard policy engine schema
-- JSONB-backed runtime policies with tenant isolation.

CREATE TABLE IF NOT EXISTS mcp_tool_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL,
    agent_id UUID,
    policy_name TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    priority INTEGER NOT NULL DEFAULT 100,
    policy JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mcp_tool_policies_org_enabled_priority
    ON mcp_tool_policies (org_id, enabled, priority DESC, created_at ASC);

CREATE INDEX IF NOT EXISTS idx_mcp_tool_policies_org_agent
    ON mcp_tool_policies (org_id, agent_id)
    WHERE agent_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_mcp_tool_policies_policy_gin
    ON mcp_tool_policies USING GIN (policy jsonb_path_ops);

ALTER TABLE mcp_tool_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_tool_policies FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_mcp_tool_policies ON mcp_tool_policies;
CREATE POLICY tenant_isolation_mcp_tool_policies ON mcp_tool_policies
    USING (org_id::text = nullif(current_setting('app.current_org_id', true), ''))
    WITH CHECK (org_id::text = nullif(current_setting('app.current_org_id', true), ''));

DROP POLICY IF EXISTS auditor_read_mcp_tool_policies ON mcp_tool_policies;
CREATE POLICY auditor_read_mcp_tool_policies ON mcp_tool_policies
    FOR SELECT TO auditor_role
    USING (org_id::text = nullif(current_setting('app.current_org_id', true), ''));

GRANT SELECT, INSERT, UPDATE, DELETE ON mcp_tool_policies TO app_role;
GRANT SELECT ON mcp_tool_policies TO auditor_role;
