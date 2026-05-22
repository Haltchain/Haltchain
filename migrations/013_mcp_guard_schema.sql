-- HaltChain Phase 1b MCP Guard schema
-- Mirrors crates/mcp-guard/migrations/001_mcp_schema.sql for root migration flows.

CREATE TABLE IF NOT EXISTS mcp_tool_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    tool_name TEXT NOT NULL,
    tool_args JSONB NOT NULL,
    args_hash BYTEA NOT NULL,
    args_embedding VECTOR,
    decision TEXT NOT NULL,
    reason TEXT,
    context_hash TEXT NOT NULL,
    review_id UUID,
    envelope JSONB,
    merkle_root TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mcp_history_agent_time
    ON mcp_tool_history (agent_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_mcp_history_org_agent_time
    ON mcp_tool_history (org_id, agent_id, timestamp DESC);

CREATE TABLE IF NOT EXISTS mcp_review_queue (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    tool_call JSONB NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    reviewed_at TIMESTAMPTZ,
    reviewer_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mcp_review_queue_org_status_created
    ON mcp_review_queue (org_id, status, created_at DESC);

ALTER TABLE mcp_tool_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_tool_history FORCE ROW LEVEL SECURITY;
ALTER TABLE mcp_review_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_review_queue FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_mcp_tool_history ON mcp_tool_history;
CREATE POLICY tenant_isolation_mcp_tool_history ON mcp_tool_history
    USING (org_id::text = nullif(current_setting('app.current_org_id', true), ''))
    WITH CHECK (org_id::text = nullif(current_setting('app.current_org_id', true), ''));

DROP POLICY IF EXISTS tenant_isolation_mcp_review_queue ON mcp_review_queue;
CREATE POLICY tenant_isolation_mcp_review_queue ON mcp_review_queue
    USING (org_id::text = nullif(current_setting('app.current_org_id', true), ''))
    WITH CHECK (org_id::text = nullif(current_setting('app.current_org_id', true), ''));

DROP POLICY IF EXISTS auditor_read_mcp_tool_history ON mcp_tool_history;
CREATE POLICY auditor_read_mcp_tool_history ON mcp_tool_history
    FOR SELECT TO auditor_role
    USING (org_id::text = nullif(current_setting('app.current_org_id', true), ''));

DROP POLICY IF EXISTS auditor_read_mcp_review_queue ON mcp_review_queue;
CREATE POLICY auditor_read_mcp_review_queue ON mcp_review_queue
    FOR SELECT TO auditor_role
    USING (org_id::text = nullif(current_setting('app.current_org_id', true), ''));

GRANT SELECT, INSERT ON mcp_tool_history TO app_role;
GRANT SELECT, INSERT, UPDATE ON mcp_review_queue TO app_role;
GRANT SELECT ON mcp_tool_history TO auditor_role;
GRANT SELECT ON mcp_review_queue TO auditor_role;

CREATE OR REPLACE VIEW auditor_mcp_review_queue AS
SELECT id, org_id, agent_id, tool_call, reason, status, reviewed_at, reviewer_id, created_at
FROM mcp_review_queue;

GRANT SELECT ON auditor_mcp_review_queue TO auditor_role;
