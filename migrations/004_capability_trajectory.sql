CREATE TABLE IF NOT EXISTS capability_trajectory (
    id             BIGSERIAL PRIMARY KEY,
    agent_id       TEXT NOT NULL,
    domain         TEXT NOT NULL,
    knowledge_delta DOUBLE PRECISION NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS capability_trajectory_agent_domain_idx
    ON capability_trajectory (agent_id, domain, created_at DESC);
