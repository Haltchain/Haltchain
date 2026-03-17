-- Milestone 4: Automated learning loop recommendation and approval workflow.

ALTER TABLE policy_adjustments
    ADD COLUMN IF NOT EXISTS recommendation_id BIGINT,
    ADD COLUMN IF NOT EXISTS applied_variant_id TEXT;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.table_constraints
        WHERE table_name = 'policy_adjustments'
          AND constraint_name = 'policy_adjustments_recommendation_id_fkey'
    ) THEN
        ALTER TABLE policy_adjustments
            ADD CONSTRAINT policy_adjustments_recommendation_id_fkey
            FOREIGN KEY (recommendation_id)
            REFERENCES policy_adjustment_recommendations(id)
            DEFERRABLE INITIALLY DEFERRED;
    END IF;
EXCEPTION
    WHEN undefined_table THEN
        -- recommendation table may not exist yet during first pass; deferred below
        NULL;
END $$;

CREATE TABLE IF NOT EXISTS policy_adjustment_recommendations (
    id BIGSERIAL PRIMARY KEY,
    recommendation_key TEXT NOT NULL UNIQUE,
    threshold_key TEXT NOT NULL,
    current_threshold NUMERIC(14,4) NOT NULL,
    proposed_threshold NUMERIC(14,4) NOT NULL,
    sample_size INTEGER NOT NULL,
    false_positive_count INTEGER NOT NULL DEFAULT 0,
    true_positive_count INTEGER NOT NULL DEFAULT 0,
    confidence NUMERIC(5,4) NOT NULL,
    rationale TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected', 'applied', 'reverted')),
    trigger_outcome_id BIGINT REFERENCES decision_outcomes(id),
    trigger_transaction_id UUID,
    decided_by TEXT,
    decision_notes TEXT,
    decided_at TIMESTAMPTZ,
    variant_id TEXT,
    applied_adjustment_id BIGINT REFERENCES policy_adjustments(id),
    reverted_by TEXT,
    reverted_at TIMESTAMPTZ,
    revert_adjustment_id BIGINT REFERENCES policy_adjustments(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_par_status_created
    ON policy_adjustment_recommendations(status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_par_threshold_status
    ON policy_adjustment_recommendations(threshold_key, status, created_at DESC);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.table_constraints
        WHERE table_name = 'policy_adjustments'
          AND constraint_name = 'policy_adjustments_recommendation_id_fkey'
    ) THEN
        ALTER TABLE policy_adjustments
            ADD CONSTRAINT policy_adjustments_recommendation_id_fkey
            FOREIGN KEY (recommendation_id)
            REFERENCES policy_adjustment_recommendations(id)
            DEFERRABLE INITIALLY DEFERRED;
    END IF;
END $$;
