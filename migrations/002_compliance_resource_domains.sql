-- Add compliance and resource domains added in P1.
-- Safe to run multiple times (IF NOT EXISTS).

ALTER TYPE breaker_domain ADD VALUE IF NOT EXISTS 'compliance';
ALTER TYPE breaker_domain ADD VALUE IF NOT EXISTS 'resource';
