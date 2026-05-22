-- HaltChain Phase 1b vector optimization
-- Run order: after 011_tenant_isolation_hardening.sql
--
-- Adds L2-ready embedding storage/index while preserving cosine compatibility.

CREATE EXTENSION IF NOT EXISTS vector;

ALTER TABLE action_embeddings
    ADD COLUMN IF NOT EXISTS embedding_l2 vector(1024);

-- Backfill existing rows for compatibility. New writes will use normalized vectors.
UPDATE action_embeddings
SET embedding_l2 = embedding
WHERE embedding_l2 IS NULL;

CREATE INDEX IF NOT EXISTS idx_action_emb_l2_hnsw
    ON action_embeddings
    USING hnsw (embedding_l2 vector_l2_ops)
    WITH (m = 12, ef_construction = 48);
