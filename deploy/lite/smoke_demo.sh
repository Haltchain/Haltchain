#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

export HALTCHAIN_MCP_BASELINE_PATH="$ROOT/demo/baseline.json"
export HALTCHAIN_API_KEYS=dev-key
export HALTCHAIN_SQLITE_PATH=/tmp/haltchain-smoke.db
export PORT=8787
export RUST_LOG=info

echo "building haltchain-api..."
cargo build -p haltchain-api --release --bin haltchain-api
TARGET_DIR="$(cargo metadata --format-version=1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
BIN="$TARGET_DIR/release/haltchain-api"

rm -f "$HALTCHAIN_SQLITE_PATH"

"$BIN" --profile standalone &
PID=$!
trap 'kill "$PID" 2>/dev/null || true' EXIT

for i in $(seq 1 50); do
  if curl -sf "http://127.0.0.1:${PORT}/health/live" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

ORG=11111111-1111-1111-1111-111111111111
AGENT=22222222-2222-2222-2222-222222222222

echo "curl block..."
curl -sf "http://127.0.0.1:${PORT}/mcp/inspect" \
  -H "Content-Type: application/json" \
  -H "x-api-key: dev-key" \
  -H "x-haltchain-org: $ORG" \
  -d "{\"agent_id\":\"$AGENT\",\"org_id\":\"$ORG\",\"tool_name\":\"exec_shell\",\"tool_args\":{\"cmd\":\"rm -rf /\"},\"context_hash\":\"smoke\",\"timestamp\":0}" \
  | python3 -c 'import json,sys; o=json.load(sys.stdin); assert o["decision"]=="block", o; assert o.get("intent")=="malicious_execution", o; assert o.get("latency_ms") is not None, o; assert o.get("proof",{}).get("merkle_root"), o; print(json.dumps(o, indent=2))'

echo "rogue agent..."
PYTHONPATH="$ROOT/demo" python3 -m haltchain.demo.rogue_agent --base-url "http://127.0.0.1:${PORT}"

echo "smoke ok"
