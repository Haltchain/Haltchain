# HaltChain Python SDK

The safety layer between your AI agents and the real world.
Every action an agent tries to take is validated against HaltChain policy before it executes — including a 60-second offline grace window and full LangChain integration.

Supported Python versions: 3.9 through 3.13.
Python 3.14 is intentionally unsupported for now because the current LangChain compatibility path still depends on Pydantic v1 behavior.

```bash
pip install haltchain
pip install "haltchain[http2]"       # optional HTTP/2 transport stack
pip install "haltchain[crypto]"      # optional Ed25519 signature verification
pip install "haltchain[langchain]"   # optional LangChain callback integration
pip install "haltchain[redis]"       # optional Redis cache backend
```

**Hosted validator:** `https://haltchain-consensus.fly.dev`
(3-node Raft cluster, US-East region, Fly.io)

Default usage is intentionally simple: install `haltchain`, set `agent_id` and `api_key`, and call `check` or `@validate`. Advanced features stay opt-in through extras.

---

## Quick Start

```python
from haltchain import HaltChainClient
from haltchain.exceptions import PolicyViolationError, ValidatorUnavailableError

agent = HaltChainClient(
    agent_id = "trader_bot_01",
    api_key  = "your-api-key",
)

# Option 1: decorator — function only runs on ALLOW
@agent.validate
def execute_trade(order: dict) -> None:
    do_the_trade(order)

# Option 2: explicit check
try:
    result = agent.check({"type": "transfer", "amount": 500, "currency": "USD"})
    print(result["decision"])  # "ALLOW"
except PolicyViolationError as e:
    print("Blocked:", e)
except ValidatorUnavailableError:
    print("Validator unreachable — action denied (fail-secure)")

# Option 3: direct flow with auto metadata convenience wrapper
result = agent.check_with_context(
    {"type": "data_export", "endpoint": "user-db"},
    conversation_id="conv-123",
    declared_services=["user-db", "audit"],
    requested_columns=10,
    task_necessary_columns=3,
    retention_days_requested=30,
)
```

---

## Async Client

```python
from haltchain import AsyncHaltChainClient

async with AsyncHaltChainClient(agent_id="bot", api_key="key") as ac:
    result = await ac.check({"type": "transfer", "amount": 200})

@ac.validate
async def async_trade(order: dict) -> None: ...
```

The async client uses a 50-connection pool with 20 keepalive connections.
Use `await ac.astatus()` and `await ac.ahealth()` for async status/health checks.

---

## Fail-Secure Contract

| Validator state | Cache state | Outcome |
|---|---|---|
| Reachable | — | Live decision; result cached |
| Unreachable | Hit (within TTL) | Cached decision returned |
| Unreachable | Miss or expired | **DENY** → `ValidatorUnavailableError` |

The SDK **never** allows blindly when the validator is down.

---

## Custom Action Builder

Map function arguments to a structured action dict:

```python
@agent.validate(action_builder=lambda o: {
    "type":     "transfer",
    "amount":   o["price"] * o["quantity"],
    "currency": "USD",
})
def buy(order: dict) -> None: ...
```

---

## LangChain Integration

```python
from haltchain.langchain_handler import HaltChainCallbackHandler

handler = HaltChainCallbackHandler(
    client=agent,
    tool_action_map={
        "transfer_money": lambda inp: {"type": "transfer", "amount": inp["amount"]},
    },
)

agent_executor = AgentExecutor(agent=lc_agent, tools=tools, callbacks=[handler])
```

Every `on_tool_start` and `on_agent_action` event is validated before the tool executes.
A `PolicyViolationError` halts the chain immediately.

The handler now auto-builds and forwards validator metadata from run context,
including `conversation_id`, `accessed_service`, and schema/retention hints
when present in tool input.

```python
from haltchain import build_metadata_from_langchain
from haltchain.langchain_handler import HaltChainCallbackHandler

handler = HaltChainCallbackHandler(
    client=agent,
    # Optional: override metadata generation.
    metadata_builder=lambda action, ctx: build_metadata_from_langchain(
        action=action,
        tool_name=ctx["tool_name"],
        parsed_input=ctx["parsed_input"],
        run_id=ctx["run_id"],
        parent_run_id=ctx["parent_run_id"],
    ),
)
```

---

## Multimodal Drift Metadata

`check_with_context` and `AsyncHaltChainClient.check_with_context` accept optional multimodal summaries through `multimodal_summary`.
This is backward-compatible: if omitted, existing metadata behavior is unchanged.

Supported fields:

- `text_summary`
- `code_summary`
- `tool_summary`
- `vision_summary`

```python
from haltchain import build_multimodal_drift_payload

result = agent.check_with_context(
    {"type": "tool_call", "endpoint": "code-index"},
    multimodal_summary=build_multimodal_drift_payload(
        text_summary="goal drift in user conversation",
        code_summary="unsafe file access pattern",
        tool_summary="repeated privileged tool invocation",
        vision_summary="ocr mismatch on screenshot",
    ),
)
```

---

## Cross-Agent Risk Advisories

When one agent confirms a failure mode (for example, a reviewed `TRUE_POSITIVE`), the server can emit advisories for peer agents.
The SDK exposes typed accessors to fetch or poll these advisories.

```python
# Sync
advisories = agent.poll_risk_advisories()
advisories_since = agent.get_risk_advisories(agent_id="agent-b", since_id=42)

# Async
advisories_async = await ac.apoll_risk_advisories()
advisories_async_since = await ac.aget_risk_advisories(agent_id="agent-b", since_id=42)
```

Each advisory item includes:

- `id`
- `source_agent_id`
- `target_agent_id`
- `policy_code`
- `reason`
- `trigger_transaction_id`
- `created_at`

---

## Cache Backends

### In-Memory (default)

LRU cache with configurable TTL and capacity. Thread-safe. Used automatically unless Redis is configured.

```python
agent = HaltChainClient(
    agent_id="bot",
    api_key="key",
    cache_ttl=60,          # seconds; set 0 to disable cache
    cache_max_size=2000,   # max entries before LRU eviction
)

# Inspect or pre-warm:
print(agent.cache.size())
agent.cache.put("bot", {"type": "transfer", "amount": 100},
                decision="ALLOW", reason="within limits", policy="MAX_TRANSFER")
```

### Redis Backend

Shares cache across multiple SDK instances or processes. TTL is enforced by Redis `SETEX` natively.

```python
agent = HaltChainClient(
    agent_id="bot",
    api_key="key",
    redis_url="redis://localhost:6379",
    redis_prefix="haltchain:policy",   # optional namespace
    cache_ttl=60,
)
```

Requires `pip install "haltchain[redis]"`.

---

## Client Configuration

| Parameter | Default | Description |
|---|---|---|
| `agent_id` | *(required)* | Unique agent identifier |
| `api_key` | *(required)* | API authentication key |
| `base_url` | `https://haltchain-consensus.fly.dev` | Validator base URL |
| `cache_ttl` | `60.0` | Cache TTL in seconds; `0` disables cache |
| `cache_max_size` | `2000` | Max in-memory LRU entries |
| `redis_url` | `None` | Enable Redis cache backend |
| `redis_prefix` | `haltchain:policy` | Redis key namespace |
| `timeout` | `10.0` | HTTP request timeout in seconds |
| `max_connections` | `20` (sync) / `50` (async) | HTTP connection pool size |
| `max_keepalive` | `10` (sync) / `20` (async) | Keepalive connections |

---

## Error Reference

| Exception | When raised |
|---|---|
| `PolicyViolationError` | Action blocked by policy (`DENY` / `GOAL_CLARIFICATION_REQUIRED`) |
| `CircuitBreakerError` | Agent circuit breaker tripped (too many violations) |
| `ValidatorUnavailableError` | Validator unreachable, no valid cache entry — action **denied** |
| `ValidationError` | HTTP 4xx/5xx from the validator, or malformed request |

All inherit from `HaltChainError`.

---

## Development

```bash
cd sdk/python
. .venv/bin/activate  # or create it first: python3 -m venv .venv
python -m pip install -e ".[dev]"
pytest tests/ -v
```

If `.venv` does not exist yet:

```bash
cd sdk/python
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
pytest tests/ -v
```

**Test coverage**: sync client, async client, LRU cache eviction, TTL expiry, cache key stability, LangChain handler, decorator patterns (positional + keyword args), offline fallback.

See `examples/trading_bot.ipynb` for an interactive walkthrough.
