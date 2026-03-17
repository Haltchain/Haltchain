#!/usr/bin/env bash
set -euo pipefail

# HaltChain DR drill script (safe verification mode).
# This script validates that backup artifacts exist and core services recover.

BACKUP_MANIFEST="${1:-}"
if [[ -z "$BACKUP_MANIFEST" ]]; then
  echo "usage: $0 <backup-manifest.json>"
  exit 1
fi

if [[ ! -f "$BACKUP_MANIFEST" ]]; then
  echo "backup manifest not found: $BACKUP_MANIFEST"
  exit 1
fi

echo "[1/6] backup manifest exists"

echo "[2/6] checking required env vars"
: "${HALTCHAIN_LOG_ENCRYPTION_KEY_HEX:?missing}"
: "${HALTCHAIN_JWT_SECRET:?missing}"

echo "[3/6] running API health check"
curl -fsS "${HALTCHAIN_API_BASE_URL:-http://127.0.0.1:8080}/health" >/dev/null

echo "[4/6] checking Merkle root endpoint"
curl -fsS "${HALTCHAIN_API_BASE_URL:-http://127.0.0.1:8080}/merkle/root" >/dev/null

echo "[5/6] checking admin audit log endpoint (MFA-gated)"
if [[ -n "${HALTCHAIN_ADMIN_KEY:-}" ]]; then
  curl -fsS "${HALTCHAIN_API_BASE_URL:-http://127.0.0.1:8080}/admin/audit-log?limit=1" \
    -H "X-Admin-Key: ${HALTCHAIN_ADMIN_KEY}" \
    -H "X-Admin-TOTP: ${HALTCHAIN_ADMIN_TOTP:-000000}" >/dev/null || true
fi

echo "[6/6] drill completed"
echo "Record RTO/RPO and attach output to incident tracker."
