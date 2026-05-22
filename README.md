# HaltChain

Circuit breaker protocol for autonomous AI economies. Prevents goal drift, velocity attacks, and agent conflicts in real-time through a high-performance Rust validator service and a Python SDK.

## Status: Experimental

Reference implementation — not production ready.

---

## Architecture

```
┌─────────────────────────────────────┐
│          AI Agent (Python)          │
│  haltchain.HaltChainClient / @validate decorator  │
└────────────────┬────────────────────┘
                 │ POST /validate
┌────────────────▼────────────────────┐
│     HaltChain Validator (Rust)      │
│  Policy · Circuit Breaker · Drift   │
│  Goal Store · Embeddings · Raft     │
└─────────────────────────────────────┘
```

**Crates** (`crates/`):

| Crate | Role |
|---|---|
| `api` | Axum HTTP server — all routes |
| `validator` | Core safety engine, `AppState` |
| `policy` | Hard policy rules |
| `rules` | Dynamic rule loader |
| `embeddings` | Intent embedding pipeline |
| `consensus` | Raft cluster coordination |
| `tendermint` | Tendermint bridge (`CheckTx` / `DeliverTx` request mapping) |
| `cache` | Internal caching primitives |
| `analytics` | Usage metrics |
| `bench` | Performance benchmarking harness |

---

## Tendermint Integration

HaltChain now includes a Tendermint bridge crate for deterministic transaction validation flow:

- Crate: `haltchain-tendermint`
- Entry point: `crates/tendermint/src/lib.rs`
- Mapping: Tendermint transaction bytes (JSON `ValidationRequest`) -> validator pipeline -> `CheckTx`/`DeliverTx` style responses

This keeps the existing Raft path intact while enabling BFT-oriented integration work.

Environment:

```bash
export HALTCHAIN_TM_CHAIN_ID="haltchain-local"
export HALTCHAIN_TM_APP_VERSION="0.1.0"
export HALTCHAIN_TM_VALIDATORS="node1@10.0.0.1:26656#us-east-1,node2@10.0.1.1:26656#us-west-2,node3@10.0.2.1:26656#us-east-1"
```

Run crate tests:

```bash
cargo test -p haltchain-tendermint
```

BFT readiness gate (admin endpoint):

```bash
curl -s http://localhost:8080/admin/tendermint/readiness \
  -H 'X-Admin-Key: dev-admin-key' \
  -H 'X-Admin-TOTP: 123456'
```

---

## Distributed Merkle Verification

Configure witness public keys and threshold:

```bash
export HALTCHAIN_MERKLE_WITNESS_KEYS="w1:<base64-pubkey>,w2:<base64-pubkey>,w3:<base64-pubkey>"
export HALTCHAIN_MERKLE_WITNESS_THRESHOLD="2"
```

Verify witness attestations for current root:

```bash
curl -s -X POST http://localhost:8080/admin/merkle/verify-distributed \
  -H 'Content-Type: application/json' \
  -H 'X-Admin-Key: dev-admin-key' \
  -H 'X-Admin-TOTP: 123456' \
  -d '{"attestations":[{"witness_id":"w1","signature_b64":"..."}]}'
```

---

## Audit Log Security

Encrypted audit logs + redaction are enabled with:

```bash
export HALTCHAIN_LOG_ENCRYPTION_KEY_HEX="$(openssl rand -hex 32)"
export HALTCHAIN_AUDIT_LOG_PATH="/var/log/haltchain/audit.log.enc"
export HALTCHAIN_AUDIT_RETENTION_DAYS="30"
export HALTCHAIN_AUDIT_PRUNE_INTERVAL_SECS="3600"
```

`HALTCHAIN_AUDIT_RETENTION_DAYS` controls event TTL; a background prune worker
runs every `HALTCHAIN_AUDIT_PRUNE_INTERVAL_SECS` seconds and removes expired
encrypted entries.

Read recent audit entries (admin MFA required):

```bash
curl -s "http://localhost:8080/admin/audit-log?limit=50" \
  -H 'X-Admin-Key: dev-admin-key' \
  -H 'X-Admin-TOTP: 123456'
```

---

## Disaster Recovery

- Runbook: `DISASTER_RECOVERY_RUNBOOK.md`
- Drill helper: `drills/disaster_recovery_drill.sh`

---

## Running the Validator API (local)

The server reads the `PORT` environment variable and defaults to **`8080`**.

```bash
cargo run -p haltchain-api
```

Health probe:

```bash
curl http://localhost:8080/health
```

Validate an action (allowed):

```bash
curl -s -X POST http://localhost:8080/validate \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"trader_bot_01","api_key":"dev-key","action":{"type":"transfer","amount":500,"currency":"USD","recipient":"acct_abc"}}'
```

Validate an action that violates the hard-coded policy (denied):

```bash
curl -s -X POST http://localhost:8080/validate \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"trader_bot_01","api_key":"dev-key","action":{"type":"transfer","amount":1500,"currency":"USD","recipient":"acct_abc"}}'
```

Trip the rate-limit circuit breaker (10 actions/min) with 11 rapid requests:

```bash
for i in $(seq 1 11); do
  curl -s -X POST http://localhost:8080/validate \
    -H 'Content-Type: application/json' \
    -d '{"agent_id":"rater","api_key":"dev","action":{"type":"generic"}}'
  echo
done
```

Check agent status (circuit-breaker state + rate usage):

```bash
curl http://localhost:8080/status/rater
```

Goal declaration (drift detection):

```bash
# Declare intent at session start
curl -s -X POST http://localhost:8080/goals \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"bot","session_id":"s1","intent":"transfer funds within approved limits"}'

# Check drift score mid-session
curl http://localhost:8080/drift/bot/s1

# Revoke goal on session end
curl -X DELETE http://localhost:8080/goals/bot/s1
```

---

## API Reference

| Method | Path | Description |
|---|---|---|
| `POST` | `/validate` | Validate an agent action |
| `GET` | `/health` | Liveness / health check |
| `GET` | `/status/:agent_id` | Circuit-breaker state + rate usage |
| `POST` | `/goals` | Declare agent session intent |
| `DELETE` | `/goals/:agent_id/:session_id` | Revoke a goal declaration |
| `GET` | `/drift/:agent_id/:session_id` | Current drift window snapshot |

---

## API Standard (Advanced)

HaltChain is now REST-first and versioned by URI.

### Core Style Decision

- Primary style: REST over HTTP/JSON
- Stable namespace: `/v1/*`
- Backward-compatibility: unversioned routes currently mirror `/v1/*` routes

### Why REST is the default here

- The product exposes policy and validator resources with clear CRUD and command semantics.
- Existing SDK and operational tooling are already HTTP/JSON-centric.
- Security controls (API key + signature + nonce + timestamp) are already integrated into REST handlers.

### When to choose GraphQL or gRPC

- Choose GraphQL only if clients consistently suffer from over-fetching or need deeply nested, client-specific query shapes from multiple domains.
- Choose gRPC only for internal low-latency service-to-service paths where strict contracts, streaming, and strong typed clients provide measurable performance wins.
- Keep external/public API contract on REST unless there is a proven product-level incompatibility.

### Advanced REST conventions used

- Versioning: URI versioning with `/v1`.
- Pagination: offset-based pagination using `limit` and `offset` query params.
- Pagination metadata: `total_records`, `has_next_page`, and `next_offset` in response payloads.
- Error responses: JSON payloads with explicit error messages and correct HTTP status codes.

Example (admin recommendations):

```bash
curl -s "http://localhost:8080/v1/admin/recommendations?status=pending&limit=20&offset=0" \
  -H 'x-admin-key: dev-admin-key'
```


## Building

```bash
cargo build --workspace
```

## Testing

End-to-end testing story (frontend BFF → API → cognitive/embeddings/rules) and CI gates are documented in **[Documents/TestingFlow.md](Documents/TestingFlow.md)**.

```bash
cargo test --workspace
```

SDK/API contract tests (need a running API + Postgres): see `sdk-contract` in [`.github/workflows/ci.yml`](.github/workflows/ci.yml). Corpus replay against `POST /validate`: [scripts/replay_validate_corpus.py](scripts/replay_validate_corpus.py) and [fixtures/validate_corpus.jsonl](fixtures/validate_corpus.jsonl).

---

## Python SDK

Install:

```bash
pip install ./sdk/python
pip install "./sdk/python[http2]"   # optional HTTP/2 transport
pip install "./sdk/python[crypto]"  # optional signature verification
```

Quick example:

```python
import haltchain

agent = haltchain.HaltChainClient(agent_id="trader_bot_01", api_key="dev-key")

@agent.validate
def execute_trade(order: dict) -> None:
    # Runs only when HaltChain returns ALLOW
    print("executing", order)

execute_trade({"type": "transfer", "amount": 100, "currency": "USD"})
```

See [`sdk/python/README.md`](sdk/python/README.md) for full SDK documentation.

The default SDK install stays lightweight (`pip install ./sdk/python`) and production safety checks run server-side by default, so teams do not need extra setup for baseline protection.

---

## Deployment

Use the maintained container paths for local and testnet environments.

```bash
docker compose up -d
```

For the multi-node local testnet profile:

```bash
docker compose -f docker-compose.testnet.yml up -d
```

The server binds to `PORT` when provided and defaults to `8080`.

---

## Credits

- Tendermint Core/ABCI design inspiration for BFT state-machine replication.
- Anthropic alignment research themes (alignment faking, sabotage, reward maximization) that informed cognitive detector coverage.
