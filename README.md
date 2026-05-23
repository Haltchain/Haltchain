# HaltChain

The kill switch for AI agents. <2ms runtime defense with cryptographic audit trails.

Circuit breaker protocol for autonomous AI economies. Prevents goal drift, velocity attacks, MCP tool poisoning, and agent conflicts in real-time through a high-performance Rust validator pipeline and Python/TypeScript SDKs.

**What we do that nobody else can:**
- **<2ms validation** — Python guardrails add 200ms. We add 2ms. Rust-native, zero GC.
- **Runtime MCP enforcement** — not a scanner. A circuit breaker that intercepts in-flight tool calls and kills anomalous behavior before it executes.
- **Cryptographic audit** — Merkle trees, Ed25519 signing, hash chaining. When the SEC asks what happened, we provide mathematical proof, not logs.
- **Hardware attestation** — PKCS#11, SoftHSM2, YubiHSM key backends. FIPS 140-2 ready.
- **Byzantine consensus** — Raft with fsync WAL. 2-of-3 quorum for high-stakes decisions.

---

## Quick Start

### Install the MCP scanner

```bash
cargo install haltchain-mcp
haltchain-mcp scan --config ~/.cursor/mcp.json
```

### Production readiness (May 2026)

| Surface | Status |
|---------|--------|
| Core validator + MCP library | Works via `haltchain-api` |
| `haltchain-mcp serve` | HTTP sidecar with `/health` and `/check` (reduced semantics vs full API path) |
| K8s operator hot-reload | Wired to `/admin/webhook/policy-sync` on sidecar port 8787 |
| eBPF enforcement | Skeleton; BPF crate build gated separately |
| Performance gates | See [`Documents/Project_Status.md`](Documents/Project_Status.md) and [`BENCHMARK_RESULTS.json`](BENCHMARK_RESULTS.json) |

### Run the validator API

```bash
cargo run -p haltchain-api
curl http://localhost:8080/health
```

### Python SDK

```bash
pip install ./sdk/python
```

```python
import haltchain

agent = haltchain.HaltChainClient(agent_id="trader_bot_01", api_key="dev-key")

@agent.validate
def execute_trade(order: dict) -> None:
    print("executing", order)

execute_trade({"type": "transfer", "amount": 100, "currency": "USD"})
```

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                 AI Agent / MCP Server                │
│  Python SDK / TypeScript SDK / haltchain-mcp CLI     │
└────────────────────┬─────────────────────────────────┘
                     │ POST /validate (or localhost:8787 sidecar)
┌────────────────────▼─────────────────────────────────┐
│           HaltChain Validator Pipeline (Rust)         │
│                                                       │
│  ┌─────────┐  ┌──────────┐  ┌─────────┐  ┌────────┐ │
│  │ Registry │→│ L1/L2    │→│ Circuit │→│ Rules  │ │
│  │ Gate     │  │ Cache    │  │ Breaker │  │ Engine │ │
│  └─────────┘  └──────────┘  └─────────┘  └────────┘ │
│       ↓                                              │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────┐   │
│  │ Goal     │→│ Cognitive │→│ Aggregate Policy  │   │
│  │ Drift    │  │ Triage   │  │ (7 domains)      │   │
│  └──────────┘  └──────────┘  └───────────────────┘   │
│       ↓                                              │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────┐   │
│  │ Quorum   │→│ Ed25519  │→│ Merkle + Postgres │   │
│  │ Gate     │  │ Sign     │  │ Audit Trail       │   │
│  └──────────┘  └──────────┘  └───────────────────┘   │
└──────────────────────────────────────────────────────┘
                     │
┌────────────────────▼─────────────────────────────────┐
│  PostgreSQL + pgvector + pg_cron + RLS               │
│  Telemetry (unlogged → WAL) · Embeddings · Policies  │
└──────────────────────────────────────────────────────┘
```

---

## Crates

| Crate | Role | Status |
|---|---|---|
| `api` | Axum HTTP server — all routes, auth, TLS, SIEM | Production |
| `validator` | 14-stage validation pipeline, `AppState` orchestration | Production |
| `mcp-guard` | MCP runtime enforcement — pattern firewall, ZEDD drift, baseline inventory | Production |
| `cognitive` | ZEDD drift detection, pattern firewall, ONNX detector, calibration | Production |
| `policy` | 7-domain circuit breakers + JSONB policy engine | Production |
| `rules` | Dynamic YAML rule loader with hot-reload | Production |
| `embeddings` | ONNX pipeline, conversation drift, behavioral fingerprinting | Production |
| `consensus` | Raft leader election, log replication, quorum gate | Production |
| `signing` | Ed25519, HSM abstraction, A2A delegation, COSE envelope | Production |
| `merkle` | Merkle accumulator, inclusion proofs, distributed witness verify | Production |
| `db` | Postgres + SQLite, pgvector, telemetry hot-writer | Production |
| `cache` | DecisionCache + DragonflyDB async client | Production |
| `analytics` | Isolation Forest, SPC, auth anomaly detection | Production |
| `capability` | Agent capability trajectory, domain/risk classification | Production |
| `ebpf` | eBPF syscall interception (Phase 2 — skeleton, `aya-ebpf`) | Phase 2 |
| `bench` | Latency/saturation benchmark harnesses | Production |
| `tendermint` | BFT bridge — CheckTx/DeliverTx mapping | Production |
| `anchor` | Postgres/S3/L2 anchoring for compliance retention | Production |

---

## MCP Guard — The Competitive Differentiator

HaltChain's `mcp-guard` crate is a **runtime enforcement engine** for MCP tool calls, not a post-config scanner.

**What it does on every tool call:**
1. **Pattern firewall** — Aho-Corasick 200+ patterns, O(n) guaranteed. Instant lexical triage.
2. **Baseline inventory** — Per-org, per-agent approved tool patterns from `baseline.json`.
3. **JSONB policy evaluation** — Reads `mcp_tool_policies` from DB. Allow/block/quarantine.
4. **ZEDD drift detection** — Embeds tool descriptions, checks drift against baseline via K Core-Distance.
5. **Cross-agent correlation** — Detects Agent A delegating to Agent B with capability escalation.
6. **Containment bridge** — terminate/revoke/snapshot/SOC notify when anomaly exceeds threshold.
7. **Cryptographic audit** — Ed25519 signed envelopes + Merkle tree accumulation.

```bash
# Scan MCP configs (static/local checks)
haltchain-mcp scan --config ~/.cursor/mcp.json

# Lightweight HTTP sidecar (pattern + baseline checks; full enforcement via haltchain-api)
haltchain-mcp serve --port 8787 --baseline ./baseline.json

# Full runtime enforcement (DB policies, drift, containment, audit)
cargo run -p haltchain-api
# POST /mcp/inspect
```

---

## 14-Stage Validation Pipeline

Every agent action passes through these stages (measured latency targets):

| Stage | Target | What it does |
|-------|--------|-------------|
| 1. Registry gate | <1µs | Is this agent registered? |
| 2. L1 cache lookup | <1µs | SHA-256 keyed LRU hit? |
| 3. L2 Dragonfly lookup | <500µs | Distributed cache hit? |
| 4. Circuit breaker | <10µs | Rate limit / velocity check |
| 5. Rules engine | <500µs | Dynamic YAML policy DAG eval |
| 6. Goal drift check | <1ms | Semantic drift from declared intent |
| 7. Conversation drift | <1ms | Centroid drift over conversation window |
| 8. Cognitive triage | <5ms | Pattern firewall + optional deep scan |
| 9. Capability check | <1ms | Domain/risk classification |
| 10. Aggregate policy | <500µs | 7-domain circuit breaker evaluation |
| 11. Quorum gate | <3ms | 2-of-3 Raft for high-stakes |
| 12. Ed25519 sign | <100µs | COSE decision envelope |
| 13. Merkle push | <50µs | Hash chain accumulation |
| 14. Async persist | non-blocking | Postgres + telemetry fire-and-forget |

**Measured**: cache-hit p99 38µs, mixed-path concurrent p99 311µs, full pipeline <2ms p50.

---

## Compliance & Audit

| Feature | Implementation |
|---------|---------------|
| **Hash chaining** | Each `decisions_hot` row includes SHA-256 of previous row — tamper-evident chain |
| **Merkle trees** | Real-time accumulation, inclusion proofs, distributed witness verification |
| **Ed25519 signing** | Every decision signed with COSE envelope — client-verifiable |
| **RLS isolation** | `org_id` enforced at connection level, `FORCE ROW LEVEL SECURITY` |
| **Full-text search** | TSVector inverted indexes on audit content — no Elasticsearch needed |
| **PostgREST views** | `audit_decisions_view` + `compliance_summary_view` — RLS-enforced API |
| **S3 Object Lock** | WORM storage for 7-year compliance retention |

### Regulatory Rule Packs

| Pack | Scope |
|------|-------|
| GDPR | Article 35 DPIA automation, data minimization, cross-border transfer blocks |
| PCI-DSS | CDE segmentation, PAN access velocity limits |
| HIPAA | PHI concentration thresholds, minimum necessary access |
| EU AI Act | High-risk documentation, human oversight checkpoints |

---

## Deployment

### Docker Compose

```bash
docker compose up -d
```

### Kubernetes (Operator)

```bash
# Install CRDs
kubectl apply -f deploy/operator/crds/haltchain-crds.yaml

# Deploy operator
kubectl apply -f deploy/operator/manifests/operator.yaml

# Sidecar injection — add annotation to your agent pod
#   haltchain.haltchain.dev/inject: "true"
```

### Sidecar Mode (Zero-Code Integration)

```yaml
# Inject into any agent pod — no code changes needed
containers:
  - name: haltchain-guard
    image: haltchain-sidecar:latest
    ports:
      - containerPort: 8787
```

### Standalone Mode (No Dependencies)

```bash
# SQLite + in-memory cache — single binary
cargo run -p haltchain-api --features standalone
```

---

## Testing

```bash
cargo test --workspace --all-targets --no-run   # must compile all targets including operator
cargo test --workspace                          # 440+ tests across 40 suites (see Project_Status for gate caveats)
```

### CI Gates

| Gate | What it checks |
|------|---------------|
| `ci.yml` | Build, lint, test, SDK contract, frontend smoke, benchmark, security audit |
| `garak.yml` | Nightly adversarial probes (workflow exists; REST adapter + PR gate still maturing) |
| `canary.yml` | Daily multi-domain adversarial suite, auto-issues on regression |
| `python-sdk-ci.yml` | Python 3.9–3.13 matrix |

### Benchmarks

```bash
cargo run -p haltchain-bench --bin cache_hit_gate           # enqueue L1 path
cargo run -p haltchain-bench --bin unlogged_write_gate      # enqueue-only (<10µs)
cargo run -p haltchain-bench --bin unlogged_insert_gate     # synchronous INSERT p95
cargo run -p haltchain-bench --bin pgvector_search_gate     # <2ms target
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
| `POST` | `/audit/fts` | Full-text search on audit decisions |
| `POST` | `/mcp/inspect` | Runtime MCP tool call inspection |
| `GET` | `/admin/recommendations` | Policy adjustment recommendations |
| `POST` | `/admin/policy-db/reload` | Hot-reload JSONB policy configs |

---

## Environment Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | API listen port |
| `DATABASE_URL` | — | PostgreSQL DSN |
| `HALTCHAIN_API_KEYS` | — | Comma-separated API keys |
| `HALTCHAIN_ADMIN_KEYS` | — | Comma-separated admin keys |
| `JWT_SECRET` | — | HMAC JWT signing secret |
| `HALTCHAIN_EMBEDDING_MODE` | `hybrid` | `local` / `hybrid` / `api_only` |
| `HALTCHAIN_MODEL_DIR` | — | ONNX model directory |
| `HALTCHAIN_MCP_BASELINE_PATH` | — | MCP baseline inventory JSON |
| `HALTCHAIN_COGNITIVE_DISABLED` | — | Set `1` to skip cognitive scan |
| `HALTCHAIN_QUORUM_FAIL_OPEN` | — | Set `1` to allow without quorum |

---

## License

Proprietary — see LICENSE file.
