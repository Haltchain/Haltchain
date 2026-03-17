#!/bin/bash
# Phase 1 mixed baseline: signed backend load + frontend smoke E2E in parallel.
set -euo pipefail

API_BASE_URL="${HALTCHAIN_API_BASE_URL:-http://127.0.0.1:8080}"
FRONTEND_DIR="${HALTCHAIN_FRONTEND_DIR:-./frontend}"
API_KEY="${PHASE1_API_KEY:-dev-key}"
LOAD_REQUESTS="${MIXED_LOAD_REQUESTS:-300}"
LOAD_CONCURRENCY="${MIXED_LOAD_CONCURRENCY:-50}"

if ! [[ "$LOAD_REQUESTS" =~ ^[0-9]+$ ]] || ! [[ "$LOAD_CONCURRENCY" =~ ^[0-9]+$ ]]; then
  echo "Error: MIXED_LOAD_REQUESTS and MIXED_LOAD_CONCURRENCY must be integers"
  exit 1
fi

if [[ "$LOAD_REQUESTS" -lt 1 ]] || [[ "$LOAD_CONCURRENCY" -lt 1 ]]; then
  echo "Error: MIXED_LOAD_REQUESTS and MIXED_LOAD_CONCURRENCY must be >= 1"
  exit 1
fi

if [[ ! -d "$FRONTEND_DIR" ]]; then
  echo "Error: frontend directory not found at $FRONTEND_DIR"
  exit 1
fi

echo "== HaltChain Phase 1 Mixed Baseline =="
echo "Backend:  $API_BASE_URL"
echo "Load:     $LOAD_REQUESTS requests @ concurrency $LOAD_CONCURRENCY"
echo "Frontend: $FRONTEND_DIR (smoke:e2e:loop)"

if ! curl -fsS "$API_BASE_URL/health" >/dev/null 2>&1; then
  echo "Error: backend health check failed at $API_BASE_URL/health"
  exit 1
fi

sign_request() {
  local agent_id="$1"
  local nonce="$2"
  local timestamp="$3"
  printf '%s\0%s\0%s' "$agent_id" "$nonce" "$timestamp" \
    | openssl dgst -sha256 -hmac "$API_KEY" -binary \
    | xxd -p -c 256
}

run_burst_request() {
  local agent_id="$1"
  local nonce timestamp sig payload
  nonce="$(uuidgen | tr '[:upper:]' '[:lower:]')"
  timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  sig="$(sign_request "$agent_id" "$nonce" "$timestamp")"
  payload="$(printf '{\"agent_id\":\"%s\",\"action\":{\"type\":\"generic\"},\"metadata\":{},\"request_nonce\":\"%s\",\"request_timestamp\":\"%s\",\"request_sig\":\"%s\"}' "$agent_id" "$nonce" "$timestamp" "$sig")"

  curl -sS -o /dev/null -w "%{http_code}\n" \
    -X POST "$API_BASE_URL/validate" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $API_KEY" \
    -d "$payload" || echo 000
}

RESULTS_FILE="$(mktemp)"
for i in $(seq 1 "$LOAD_REQUESTS"); do
  run_burst_request "mixed-agent-$i" >> "$RESULTS_FILE" &
  while [[ "$(jobs -rp | wc -l | tr -d ' ')" -ge "$LOAD_CONCURRENCY" ]]; do
    sleep 0.05
  done
done

set +e
(
  cd "$FRONTEND_DIR"
  npm run smoke:e2e:loop
)
SMOKE_EXIT=$?
set -e

wait

RESULTS="$(cat "$RESULTS_FILE")"
rm -f "$RESULTS_FILE"
TOTAL=$(echo "$RESULTS" | wc -l | tr -d ' ')
OK=$(echo "$RESULTS" | grep -c '^200$' || true)
RATE_LIMITED=$(echo "$RESULTS" | grep -c '^429$' || true)
OTHER_FAIL=$((TOTAL - OK - RATE_LIMITED))

printf "Mixed load summary -> Total: %s  Success(200): %s  RateLimited(429): %s  OtherFail: %s\n" \
  "$TOTAL" "$OK" "$RATE_LIMITED" "$OTHER_FAIL"

if [[ "$SMOKE_EXIT" -ne 0 ]]; then
  echo "Error: frontend smoke loop failed while backend load was active"
  exit 1
fi

if [[ "$OTHER_FAIL" -gt 0 ]]; then
  echo "Error: backend returned non-rate-limit failures under mixed load"
  exit 1
fi

echo "Mixed baseline complete"

# ── Section 2: Latency benchmark ─────────────────────────────────────────────
echo ""
echo "== Latency Benchmark =="
LATENCY_CONCURRENCY="${BENCH_CONCURRENCY:-100}"
LATENCY_REQUESTS="${BENCH_REQUESTS:-1000}"
LATENCY_RESULTS_FILE="$(mktemp)"

for i in $(seq 1 "$LATENCY_REQUESTS"); do
  {
    nonce="$(uuidgen | tr '[:upper:]' '[:lower:]')"
    timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    sig="$(sign_request "bench-agent" "$nonce" "$timestamp")"
    payload="$(printf '{"agent_id":"bench-agent","action":{"type":"transfer","amount":100},"metadata":{},"request_nonce":"%s","request_timestamp":"%s","request_sig":"%s"}' "$nonce" "$timestamp" "$sig")"
    start_ns="$(date +%s%N 2>/dev/null || gdate +%s%N)"
    http_code="$(curl -sS -o /dev/null -w "%{http_code}" \
      -X POST "$API_BASE_URL/validate" \
      -H "Content-Type: application/json" \
      -H "X-API-Key: $API_KEY" \
      -d "$payload" || echo 000)"
    end_ns="$(date +%s%N 2>/dev/null || gdate +%s%N)"
    elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))
    echo "$http_code $elapsed_ms"
  } >> "$LATENCY_RESULTS_FILE" &
  while [[ "$(jobs -rp | wc -l | tr -d ' ')" -ge "$LATENCY_CONCURRENCY" ]]; do
    sleep 0.02
  done
done
wait

LATENCY_DATA="$(cat "$LATENCY_RESULTS_FILE")"
rm -f "$LATENCY_RESULTS_FILE"
LATENCY_TOTAL=$(echo "$LATENCY_DATA" | wc -l | tr -d ' ')
LATENCY_OK=$(echo "$LATENCY_DATA" | awk '$1 == "200"' | wc -l | tr -d ' ')

# Compute p50 and p99 from latency values (milliseconds).
if command -v awk >/dev/null 2>&1 && [[ "$LATENCY_OK" -gt 0 ]]; then
  P50_MS=$(echo "$LATENCY_DATA" | awk '$1 == "200" {print $2}' \
    | sort -n | awk 'BEGIN{c=0; a[0]=0} {a[c++]=$1} END{print a[int(c*0.50)]}')
  P99_MS=$(echo "$LATENCY_DATA" | awk '$1 == "200" {print $2}' \
    | sort -n | awk 'BEGIN{c=0; a[0]=0} {a[c++]=$1} END{print a[int(c*0.99)]}')
  printf "Latency -> p50: %sms  p99: %sms  successes: %s/%s\n" \
    "$P50_MS" "$P99_MS" "$LATENCY_OK" "$LATENCY_TOTAL"

  P99_TARGET_MS="${BENCH_P99_TARGET_MS:-10}"
  if [[ "$P99_MS" -gt "$P99_TARGET_MS" ]]; then
    echo "Warning: p99 ${P99_MS}ms exceeds target ${P99_TARGET_MS}ms — consider scaling pods"
  fi
fi

# ── Section 3: Circuit-breaker reaction test ──────────────────────────────────
echo ""
echo "== Circuit Breaker Reaction Test =="
CB_AGENT="cb_test_$(uuidgen | tr '[:upper:]' '[:lower:]' | head -c 8)"

for i in $(seq 1 50); do
  nonce="$(uuidgen | tr '[:upper:]' '[:lower:]')"
  timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  sig="$(sign_request "$CB_AGENT" "$nonce" "$timestamp")"
  payload="$(printf '{"agent_id":"%s","action":{"type":"transfer","amount":999999},"metadata":{},"request_nonce":"%s","request_timestamp":"%s","request_sig":"%s"}' \
    "$CB_AGENT" "$nonce" "$timestamp" "$sig")"
  curl -sS -o /dev/null \
    -X POST "$API_BASE_URL/validate" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $API_KEY" \
    -d "$payload" &
done
wait

CB_STATUS_CODE=$(curl -sS -o /dev/null -w "%{http_code}" "$API_BASE_URL/status/$CB_AGENT" 2>/dev/null || echo 000)
if [[ "$CB_STATUS_CODE" == "200" ]]; then
  CB_DECISION=$(curl -sS "$API_BASE_URL/status/$CB_AGENT" \
    -H "X-API-Key: $API_KEY" 2>/dev/null | grep -o '"decision":"[^"]*"' | head -1 || true)
  echo "Circuit breaker state after flood: $CB_DECISION"
else
  echo "Status endpoint returned $CB_STATUS_CODE (agent may not exist yet)"
fi

# ── Section 4: Consensus overhead test ────────────────────────────────────────
echo ""
echo "== Consensus Overhead Test =="
QUORUM_AGENT="quorum_test_$(uuidgen | tr '[:upper:]' '[:lower:]' | head -c 8)"
nonce="$(uuidgen | tr '[:upper:]' '[:lower:]')"
timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
sig="$(sign_request "$QUORUM_AGENT" "$nonce" "$timestamp")"
quorum_payload="$(printf '{"agent_id":"%s","action":{"type":"transfer","amount":1000000},"metadata":{"tokens_per_minute":800,"compute_seconds_per_hour":10,"cpu_percent":15,"memory_percent":20,"payload_contains_pii":false,"destination_country":"US","dependency_cascade_depth":1},"request_nonce":"%s","request_timestamp":"%s","request_sig":"%s"}' \
  "$QUORUM_AGENT" "$nonce" "$timestamp" "$sig")"

QUORUM_START_NS="$(date +%s%N 2>/dev/null || gdate +%s%N)"
QUORUM_HTTP=$(curl -sS -o /dev/null -w "%{http_code}" \
  -X POST "$API_BASE_URL/validate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d "$quorum_payload" || echo 000)
QUORUM_END_NS="$(date +%s%N 2>/dev/null || gdate +%s%N)"
QUORUM_MS=$(( (QUORUM_END_NS - QUORUM_START_NS) / 1000000 ))

printf "High-stakes quorum request -> HTTP %s  elapsed: %dms\n" "$QUORUM_HTTP" "$QUORUM_MS"

echo ""
echo "Phase 1 performance suite complete."

