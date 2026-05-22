-- HaltChain: Cryptographic hash-chain columns for decisions_hot
-- Implements Section C requirement: "Postgres Append-Only Tables with
-- cryptographic hash chaining (each row includes hash of previous row)"
--
-- Each row's `row_hash` = SHA-256(prev_hash || content_hash) where:
--   content_hash = SHA-256(transaction_id || agent_id || decision || decided_at)
--   prev_hash    = row_hash of the immediately-preceding row (or genesis_hash for row 1)
--
-- Verifiers can replay the chain by walking rows in ascending `id` order
-- and recomputing row_hash.  Any tampered row will break the chain.

ALTER TABLE decisions_hot
    ADD COLUMN IF NOT EXISTS content_hash TEXT,
    ADD COLUMN IF NOT EXISTS prev_hash    TEXT,
    ADD COLUMN IF NOT EXISTS row_hash     TEXT;

-- Partial index to efficiently find the latest chain tip (non-NULL row_hash)
CREATE INDEX IF NOT EXISTS idx_decisions_hot_row_hash
    ON decisions_hot (id DESC)
    WHERE row_hash IS NOT NULL;

COMMENT ON COLUMN decisions_hot.content_hash IS
    'SHA-256 hex of (transaction_id || agent_id || decision || decided_at ISO-8601)';
COMMENT ON COLUMN decisions_hot.prev_hash IS
    'row_hash of the previous row, or the genesis marker for the first row';
COMMENT ON COLUMN decisions_hot.row_hash IS
    'SHA-256 hex of (prev_hash || content_hash); forms the immutable audit chain';
