-- Seed test data for local development
-- This file is optional and should NOT be run in production
--
-- Admin users are NOT seeded here. Set HALTCHAIN_BOOTSTRAP_ADMIN_EMAIL and
-- HALTCHAIN_BOOTSTRAP_ADMIN_PASSWORD in your environment instead. The API
-- will create the first account on startup if admin_users is empty.

-- Insert sample decisions for testing dashboard
INSERT INTO decisions_hot (transaction_id, agent_id, decision, domain, policy_code, reason, decided_at)
SELECT 
    gen_random_uuid(),
    'agent-' || (random() * 5)::int,
    (ARRAY['ALLOW', 'DENY', 'CIRCUIT_BREAK', 'GOAL_CLARIFICATION_REQUIRED'])[1 + (random() * 3)::int],
    (ARRAY['financial', 'privacy', 'security', 'operational'])[1 + (random() * 3)::int],
    (ARRAY['MAX_TRANSFER_USD', 'RATE_LIMIT', 'SENSITIVE_DATA'])[1 + (random() * 2)::int],
    'Test decision reason',
    now() - (random() * interval '30 days')
FROM generate_series(1, 100);

-- Insert sample decision outcomes
INSERT INTO decision_outcomes (transaction_id, outcome, impact_usd, reviewer_id, reviewer_notes)
SELECT 
    d.transaction_id,
    (ARRAY['TRUE_POSITIVE', 'FALSE_POSITIVE', 'EXPECTED_EDGE_CASE'])[1 + (random() * 2)::int],
    (random() * 10000 - 1000)::numeric(14,2),
    'reviewer-' || (random() * 3)::int,
    'Sample review notes'
FROM decisions_hot d
LIMIT 20;
