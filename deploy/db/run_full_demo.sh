#!/usr/bin/env bash
# Full Postgres demo: migrate, seed, start API, rogue agent, verify history.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

: "${DATABASE_URL:?set DATABASE_URL to your postgres DSN}"

export HALTCHAIN_MCP_BASELINE_PATH="$ROOT/demo/baseline.json"
export HALTCHAIN_API_KEYS="${HALTCHAIN_API_KEYS:-dev-key}"
export PORT="${PORT:-8787}"
export RUST_LOG="${RUST_LOG:-info}"

echo "1) migrations"
bash deploy/db/apply_migrations.sh

echo "2) demo seed"
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f deploy/db/seed_demo_mcp.sql

echo "3) build api"
cargo build -p haltchain-api --release --bin haltchain-api
TARGET_DIR="$(cargo metadata --format-version=1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
BIN="$TARGET_DIR/release/haltchain-api"

echo "4) start full profile (postgres mcp guard)"
"$BIN" --profile full &
PID=$!
trap 'kill "$PID" 2>/dev/null || true' EXIT

for _ in $(seq 1 60); do
  curl -sf "http://127.0.0.1:${PORT}/health/live" >/dev/null 2>&1 && break
  sleep 0.5
done

echo "5) rogue block"
PYTHONPATH="$ROOT/demo" python3 -m haltchain.demo.rogue_agent --base-url "http://127.0.0.1:${PORT}"

echo "6) approved tool allow"
curl -sf "http://127.0.0.1:${PORT}/mcp/inspect" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $HALTCHAIN_API_KEYS" \
  -H "x-haltchain-org: 11111111-1111-1111-1111-111111111111" \
  -d '{"agent_id":"22222222-2222-2222-2222-222222222222","org_id":"11111111-1111-1111-1111-111111111111","tool_name":"read_file","tool_args":{"path":"/tmp/readme.txt"},"context_hash":"demo-allow","timestamp":0}' \
  | python3 -c 'import json,sys; o=json.load(sys.stdin); assert o["decision"]=="allow", o; print("allow ok")'

echo "7) db verify"
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f deploy/db/verify_demo.sql

echo "full postgres demo ok"
