#!/usr/bin/env bash
# Apply all haltchain SQL migrations in order.
# Usage: DATABASE_URL=postgres://user:pass@host:5432/dbname ./deploy/db/apply_migrations.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

if [[ -z "${DATABASE_URL:-}" ]]; then
  echo "DATABASE_URL is required" >&2
  exit 1
fi

for f in \
  migrations/001_decisions_and_feedback.sql \
  migrations/002_compliance_resource_domains.sql \
  migrations/003_adjustment_recommendations.sql \
  migrations/004_capability_trajectory.sql \
  migrations/005_admin_users.sql \
  migrations/006_create_partitions.sql \
  migrations/007_pgvector_embeddings.sql \
  migrations/008_hash_chaining.sql \
  migrations/009_phase1b_pg_native.sql \
  migrations/010_phase1b_runtime_reliability_fixes.sql \
  migrations/011_tenant_isolation_hardening.sql \
  migrations/012_vector_optimization.sql \
  migrations/013_mcp_guard_schema.sql \
  migrations/014_mcp_policy_engine.sql \
  migrations/015_concurrency_hardening_and_phase2_prep.sql \
  migrations/016_backfill_null_org_rows.sql \
  migrations/017_rls_hot_tables.sql
do
  echo "==> $f"
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$f"
done

echo "migrations ok"
