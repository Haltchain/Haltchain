#!/bin/bash
# Phase 1: Supabase session-pool baseline (security + speed)
set -euo pipefail

API_BASE_URL="${HALTCHAIN_API_BASE_URL:-http://localhost:8080}"
REQUESTS="${PHASE1_REQUESTS:-80}"
CONCURRENCY="${PHASE1_CONCURRENCY:-20}"
API_KEY="${PHASE1_API_KEY:-dev-key}"

printf "\n== HaltChain Phase 1 (Supabase) ==\n"
printf "API base URL: %s\n" "$API_BASE_URL"
printf "Load test: %s requests @ concurrency %s\n\n" "$REQUESTS" "$CONCURRENCY"

if ! [[ "$REQUESTS" =~ ^[0-9]+$ ]] || ! [[ "$CONCURRENCY" =~ ^[0-9]+$ ]]; then
  echo "Error: PHASE1_REQUESTS and PHASE1_CONCURRENCY must be integers"
  exit 1
fi

if [[ "$REQUESTS" -lt 1 ]] || [[ "$CONCURRENCY" -lt 1 ]]; then
  echo "Error: PHASE1_REQUESTS and PHASE1_CONCURRENCY must be >= 1"
  exit 1
fi

if [[ -n "${DATABASE_URL:-}" ]]; then
  if [[ "$DATABASE_URL" == *"supabase"* ]] || [[ "$DATABASE_URL" == *"pooler"* ]]; then
    if [[ "$DATABASE_URL" != *"sslmode=require"* ]]; then
      echo "Error: Supabase DATABASE_URL must include sslmode=require"
      exit 1
    fi
  fi
else
  if [[ ! -f ".env.docker" ]]; then
    echo "Error: DATABASE_URL is not set and .env.docker is missing"
    exit 1
  fi
  echo "DATABASE_URL will be loaded by docker-compose/run-migrations from .env.docker"
fi

if [[ ! -x "./run-migrations.sh" ]]; then
  chmod +x ./run-migrations.sh
fi

sign_request() {
  local agent_id="$1"
  local nonce="$2"
  local timestamp="$3"
  printf '%s\0%s\0%s' "$agent_id" "$nonce" "$timestamp" \
    | openssl dgst -sha256 -hmac "$API_KEY" -binary \
    | xxd -p -c 256
}

send_validate_request() {
  local agent_id="$1"
  local nonce timestamp sig payload
  nonce="$(uuidgen | tr '[:upper:]' '[:lower:]')"
  timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  sig="$(sign_request "$agent_id" "$nonce" "$timestamp")"
  payload="$(printf '{\"agent_id\":\"%s\",\"action\":{\"type\":\"generic\"},\"metadata\":{},\"request_nonce\":\"%s\",\"request_timestamp\":\"%s\",\"request_sig\":\"%s\"}' "$agent_id" "$nonce" "$timestamp" "$sig")"

  curl -sS -o /tmp/haltchain_phase1_validate.json -w "%{http_code}" \
    -X POST "$API_BASE_URL/validate" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $API_KEY" \
    -d "$payload"
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

printf "\n1) Running DB migrations...\n"
./run-migrations.sh

printf "\n2) Starting Supabase-backed API stack...\n"
docker-compose -f docker-compose.supabase.yml up -d api redis frontend

printf "\n3) Waiting for API health...\n"
for i in $(seq 1 30); do
  if curl -fsS "$API_BASE_URL/health" >/dev/null 2>&1; then
    echo "API healthy"
    break
  fi
  if [[ "$i" == "30" ]]; then
    echo "Error: API did not become healthy"
    docker-compose -f docker-compose.supabase.yml logs --tail=120 api || true
    exit 1
  fi
  sleep 2
done

printf "\n4) Security smoke check (validate endpoint)...\n"
HTTP_CODE=$(send_validate_request \
  "phase1-agent")
if [[ "$HTTP_CODE" != "200" ]]; then
  echo "Error: /validate smoke check failed with HTTP $HTTP_CODE"
  cat /tmp/haltchain_phase1_validate.json || true
  exit 1
fi
echo "Validate smoke check passed"

printf "\n5) API burst test (HTTP-level)...\n"
RESULTS_FILE="$(mktemp)"
for i in $(seq 1 "$REQUESTS"); do
  run_burst_request "phase1-agent-$i" >> "$RESULTS_FILE" &
  while [[ "$(jobs -rp | wc -l | tr -d ' ')" -ge "$CONCURRENCY" ]]; do
    sleep 0.1
  done
done
wait
RESULTS="$(cat "$RESULTS_FILE")"
rm -f "$RESULTS_FILE"
TOTAL=$(echo "$RESULTS" | wc -l | tr -d ' ')
OK=$(echo "$RESULTS" | grep -c '^200$' || true)
RATE_LIMITED=$(echo "$RESULTS" | grep -c '^429$' || true)
OTHER_FAIL=$((TOTAL - OK - RATE_LIMITED))

printf "Total: %s  Success(200): %s  RateLimited(429): %s  OtherFail: %s\n" \
  "$TOTAL" "$OK" "$RATE_LIMITED" "$OTHER_FAIL"

if [[ "$RATE_LIMITED" -gt 0 ]] && [[ "$OTHER_FAIL" -eq 0 ]]; then
  echo "Rate limiter engaged as designed; continuing because no backend faults were observed"
fi

if [[ "$OTHER_FAIL" -gt 0 ]]; then
  echo "Error: burst test observed non-rate-limit failures"
  exit 1
fi

printf "\n6) Running internal latency bench (optional but recommended)...\n"
if command -v cargo >/dev/null 2>&1; then
  HALTCHAIN_BENCH_P99_TARGET_US="${HALTCHAIN_BENCH_P99_TARGET_US:-5000}" cargo run -p haltchain-bench --release
else
  echo "Skipping: cargo not found"
fi

printf "\nPhase 1 baseline complete.\n"
