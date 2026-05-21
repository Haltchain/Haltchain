-- HaltChain pgvector migration — semantic embedding storage
-- Requires: Supabase (pgvector pre-installed) or `CREATE EXTENSION vector`
-- Run order: after 006_create_partitions.sql
--
-- This migration enables:
--   1. Persistent storage of agent action embeddings for drift analysis
--   2. Goal/objective baseline vectors per agent
--   3. Nearest-neighbour similarity search (cosine) for anomaly detection
--   4. Cognitive pattern centroid storage for ONNX detector warm-start
--
-- Embedding model: Snowflake Arctic Embed 2.0 Large — 1024 dimensions, f32

-- ── Enable pgvector extension 
-- Supabase projects have pgvector pre-installed; this is idempotent.
CREATE EXTENSION IF NOT EXISTS vector;

-- ── Agent goal baselines ──────────────────────────────────────────────────────
-- One row per agent: the declared-objective embedding that drift is measured
-- against. Updated when an agent re-registers or its objective changes.

CREATE TABLE IF NOT EXISTS agent_goal_embeddings (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    TEXT        NOT NULL,
    label       TEXT        NOT NULL DEFAULT 'primary',
    embedding   vector(1024) NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (agent_id, label)
);

COMMENT ON TABLE agent_goal_embeddings IS
    'Declared-objective embedding baselines for drift detection. One per agent per label.';

-- ── Action embeddings (rolling window) ────────────────────────────────────────
-- Each action or reasoning trace processed by the validator produces an
-- embedding. Stored here for:
--   • Persistent drift scoring across restarts
--   • Post-hoc forensic similarity search ("find all actions near this vector")
--   • Calibration data for ReferenceDistribution

CREATE TABLE IF NOT EXISTS action_embeddings (
    id              BIGSERIAL PRIMARY KEY,
    agent_id        TEXT        NOT NULL,
    session_id      TEXT,
    transaction_id  UUID,
    embedding       vector(1024) NOT NULL,
    -- Pre-computed similarity to the agent's goal baseline (avoids re-query)
    goal_similarity DOUBLE PRECISION,
    label           TEXT,          -- optional tag: 'benign', 'flagged', 'halted'
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_action_emb_agent_time
    ON action_embeddings (agent_id, created_at DESC);

-- HNSW index for fast cosine nearest-neighbour search.
-- ef_construction=128 and m=16 balance recall vs insert speed.
CREATE INDEX IF NOT EXISTS idx_action_emb_hnsw
    ON action_embeddings
    USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 128);

-- ── Cognitive pattern centroids ───────────────────────────────────────────────
-- Warm-start data for OnnxDetector: pre-computed centroids per reasoning
-- pattern (DeceptionPlanning, SelfPreservation, etc.)
-- Updated by the calibration pipeline; read at startup.

CREATE TABLE IF NOT EXISTS pattern_centroids (
    id          BIGSERIAL PRIMARY KEY,
    pattern     TEXT        NOT NULL UNIQUE,
    centroid    vector(1024) NOT NULL,
    sample_count INTEGER    NOT NULL DEFAULT 0,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE pattern_centroids IS
    'Pre-computed centroids per ReasoningPattern for OnnxDetector warm-start.';

-- ── Drift snapshots ───────────────────────────────────────────────────────────
-- Periodic snapshots of an agent's embedding centroid for long-term trend
-- analysis. One snapshot per agent per window (e.g. hourly).

CREATE TABLE IF NOT EXISTS drift_snapshots (
    id              BIGSERIAL PRIMARY KEY,
    agent_id        TEXT        NOT NULL,
    window_label    TEXT        NOT NULL DEFAULT '1h',
    centroid        vector(1024) NOT NULL,
    action_count    INTEGER     NOT NULL DEFAULT 0,
    mean_similarity DOUBLE PRECISION,
    trend_slope     DOUBLE PRECISION,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_drift_snap_agent_time
    ON drift_snapshots (agent_id, created_at DESC);

--  Similarity search helper function 
-- Find the K nearest action embeddings to a query vector for a given agent.

CREATE OR REPLACE FUNCTION find_similar_actions(
    query_embedding vector(1024),
    target_agent_id TEXT,
    k INT DEFAULT 10
)
RETURNS TABLE (
    action_id   BIGINT,
    agent_id    TEXT,
    session_id  TEXT,
    similarity  DOUBLE PRECISION,
    label       TEXT,
    created_at  TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        ae.id AS action_id,
        ae.agent_id,
        ae.session_id,
        1 - (ae.embedding <=> query_embedding) AS similarity,
        ae.label,
        ae.created_at
    FROM action_embeddings ae
    WHERE ae.agent_id = target_agent_id
    ORDER BY ae.embedding <=> query_embedding
    LIMIT k;
END;
$$ LANGUAGE plpgsql STABLE;

-- ── Anomaly detection helper ──────────────────────────────────────────────────
-- Find action embeddings that are furthest from their agent's goal baseline.

CREATE OR REPLACE FUNCTION find_anomalous_actions(
    target_agent_id TEXT,
    similarity_threshold DOUBLE PRECISION DEFAULT 0.5,
    max_results INT DEFAULT 50
)
RETURNS TABLE (
    action_id       BIGINT,
    session_id      TEXT,
    goal_similarity DOUBLE PRECISION,
    label           TEXT,
    created_at      TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        ae.id AS action_id,
        ae.session_id,
        ae.goal_similarity,
        ae.label,
        ae.created_at
    FROM action_embeddings ae
    WHERE ae.agent_id = target_agent_id
      AND ae.goal_similarity IS NOT NULL
      AND ae.goal_similarity < similarity_threshold
    ORDER BY ae.goal_similarity ASC
    LIMIT max_results;
END;
$$ LANGUAGE plpgsql STABLE;
