"""Tests for sync/async HaltChainClient, validate decorator, PolicyCache, and LangChain handler."""
from __future__ import annotations
import time
import pytest
import respx
import httpx

from haltchain import AsyncHaltChainClient, HaltChainClient
from haltchain.cache import PolicyCache
from haltchain.exceptions import (
    CircuitBreakerError,
    GoalClarificationRequiredError,
    PolicyViolationError,
    ValidatorUnavailableError,
    ValidationError,
)
from haltchain.langchain_handler import HaltChainCallbackHandler

BASE = "https://haltchain-consensus.fly.dev"
ALLOW_RESP  = {"decision": "ALLOW",  "reason": "ok", "policy": "OK"}
DENY_RESP   = {"decision": "DENY",   "reason": "amount exceeds limit", "policy": "MAX_TRANSFER"}
CB_RESP     = {"decision": "CIRCUIT_BREAK", "reason": "rate exceeded", "policy": "RATE_LIMIT"}
CLARIFICATION_RESP = {
    "decision": "GOAL_CLARIFICATION_REQUIRED",
    "reason": "Goal drift detected: mean similarity 0.120 is below threshold 0.300. Re-declare intent via POST /goals.",
    "policy": "GOAL_CLARIFICATION_REQUIRED",
}

# ── Sync client

@respx.mock
def test_sync_allow():
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=ALLOW_RESP))
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE)
    result = c.check({"type": "transfer", "amount": 100})
    assert result["decision"] == "ALLOW"

@respx.mock
def test_sync_deny_raises():
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=DENY_RESP))
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE)
    with pytest.raises(PolicyViolationError):
        c.check({"type": "transfer", "amount": 99_000})

@respx.mock
def test_sync_circuit_break_raises():
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=CB_RESP))
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE)
    with pytest.raises(CircuitBreakerError):
        c.check({"type": "transfer", "amount": 1})

@respx.mock
def test_sync_validator_down_cache_miss_denies():
    respx.post(f"{BASE}/validate").mock(side_effect=httpx.ConnectError("down"))
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE, cache_ttl=60)
    with pytest.raises(ValidatorUnavailableError):
        c.check({"type": "transfer", "amount": 100})

@respx.mock
def test_sync_validator_down_cache_hit_allows():
    respx.post(f"{BASE}/validate").mock(side_effect=httpx.ConnectError("down"))
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE, cache_ttl=60)
    c.cache.put("bot", {"type": "transfer", "amount": 100}, "ALLOW", "cached", "POLICY")
    result = c.check({"type": "transfer", "amount": 100})
    assert result["decision"] == "ALLOW"
    assert result.get("cached") is True

@respx.mock
def test_sync_cache_populates_on_live_response():
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=ALLOW_RESP))
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE, cache_ttl=60)
    action = {"type": "transfer", "amount": 50}
    c.check(action)
    assert c.cache.size() == 1
    hit = c.cache.get("bot", action)
    assert hit is not None
    assert hit.decision == "ALLOW"

@respx.mock
def test_sync_cache_ttl_expiry_denies():
    respx.post(f"{BASE}/validate").mock(side_effect=httpx.ConnectError("down"))
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE, cache_ttl=0.001)
    action = {"type": "transfer", "amount": 100}
    c.cache.put("bot", action, "ALLOW", "ok", "P")
    time.sleep(0.02)
    with pytest.raises(ValidatorUnavailableError):
        c.check(action)


@respx.mock
def test_sync_check_with_context_builds_metadata():
    captured_json = None

    def _capture(request: httpx.Request):
        nonlocal captured_json
        captured_json = request.read().decode()
        return httpx.Response(200, json=ALLOW_RESP)

    respx.post(f"{BASE}/validate").mock(side_effect=_capture)
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE)

    c.check_with_context(
        {"type": "db_read", "endpoint": "user-db"},
        conversation_id="conv-1",
        declared_services=["user-db", "audit"],
        requested_columns=9,
        task_necessary_columns=3,
        registered_schema_fields=["name", "email"],
        payload_fields=["name", "email", "ssn"],
        gdpr_deletion_requested=False,
        retention_days_requested=30,
    )

    assert captured_json is not None
    assert '"conversation_id":"conv-1"' in captured_json
    assert '"declared_services":["user-db","audit"]' in captured_json
    assert '"accessed_service":"user-db"' in captured_json
    assert '"requested_columns":9' in captured_json
    assert '"task_necessary_columns":3' in captured_json
    assert '"retention_days_requested":30' in captured_json


@respx.mock
def test_sync_check_with_context_emits_multimodal_summary():
    captured_json = None

    def _capture(request: httpx.Request):
        nonlocal captured_json
        captured_json = request.read().decode()
        return httpx.Response(200, json=ALLOW_RESP)

    respx.post(f"{BASE}/validate").mock(side_effect=_capture)
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE)

    c.check_with_context(
        {"type": "tool_call", "endpoint": "code-index"},
        multimodal_summary={
            "text_summary": "sudden intent shift",
            "code_summary": "unsafe call path",
            "tool_summary": "repeated privileged tool use",
            "vision_summary": "ocr mismatch in screenshot",
        },
    )

    assert captured_json is not None
    assert '"multimodal_summary"' in captured_json
    assert '"text_summary":"sudden intent shift"' in captured_json
    assert '"code_summary":"unsafe call path"' in captured_json
    assert '"tool_summary":"repeated privileged tool use"' in captured_json
    assert '"vision_summary":"ocr mismatch in screenshot"' in captured_json


@respx.mock
def test_sync_get_risk_advisories_returns_typed_list():
    advisory = {
        "id": 7,
        "source_agent_id": "agent-source",
        "target_agent_id": "bot",
        "policy_code": "TOKEN_RATE_EXCEEDED",
        "reason": "peer failure mode",
        "trigger_transaction_id": "tx-1",
        "created_at": "2026-03-12T00:00:00Z",
    }
    respx.get(f"{BASE}/risk/advisories/bot").mock(
        return_value=httpx.Response(200, json={"advisories": [advisory]})
    )
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE)
    advisories = c.poll_risk_advisories()
    assert len(advisories) == 1
    assert advisories[0]["id"] == 7
    assert advisories[0]["policy_code"] == "TOKEN_RATE_EXCEEDED"

@respx.mock
def test_validate_decorator_allow():
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=ALLOW_RESP))
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE)

    @c.validate
    def do_thing(order: dict) -> str:
        return "done"

    assert do_thing({"type": "transfer", "amount": 10}) == "done"

@respx.mock
def test_validate_decorator_deny_prevents_execution():
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=DENY_RESP))
    called = []
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE)

    @c.validate
    def do_thing(order: dict) -> str:
        called.append(True)
        return "done"

    with pytest.raises(PolicyViolationError):
        do_thing({"type": "transfer", "amount": 99_000})
    assert called == [], "function must not execute on DENY"

# ── Async client

@pytest.mark.asyncio
@respx.mock
async def test_async_allow():
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=ALLOW_RESP))
    async with AsyncHaltChainClient(agent_id="abot", api_key="k", base_url=BASE) as ac:
        result = await ac.check({"type": "transfer", "amount": 100})
    assert result["decision"] == "ALLOW"

@pytest.mark.asyncio
@respx.mock
async def test_async_deny_raises():
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=DENY_RESP))
    async with AsyncHaltChainClient(agent_id="abot", api_key="k", base_url=BASE) as ac:
        with pytest.raises(PolicyViolationError):
            await ac.check({"type": "transfer", "amount": 99_000})

@pytest.mark.asyncio
@respx.mock
async def test_async_offline_deny():
    respx.post(f"{BASE}/validate").mock(side_effect=httpx.ConnectError("down"))
    async with AsyncHaltChainClient(agent_id="abot", api_key="k", base_url=BASE) as ac:
        with pytest.raises(ValidatorUnavailableError):
            await ac.check({"type": "transfer", "amount": 100})

@pytest.mark.asyncio
@respx.mock
async def test_async_validate_decorator():
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=ALLOW_RESP))
    async with AsyncHaltChainClient(agent_id="abot", api_key="k", base_url=BASE) as ac:
        @ac.validate
        async def do_async(order: dict) -> str:
            return "async done"
        assert await do_async({"type": "transfer", "amount": 10}) == "async done"


@pytest.mark.asyncio
@respx.mock
async def test_async_check_with_context_builds_metadata():
    captured_json = None

    def _capture(request: httpx.Request):
        nonlocal captured_json
        captured_json = request.read().decode()
        return httpx.Response(200, json=ALLOW_RESP)

    respx.post(f"{BASE}/validate").mock(side_effect=_capture)

    async with AsyncHaltChainClient(agent_id="abot", api_key="k", base_url=BASE) as ac:
        await ac.check_with_context(
            {"type": "data_export", "endpoint": "analytics"},
            conversation_id="conv-async",
            requested_columns=4,
            task_necessary_columns=2,
            gdpr_deletion_requested=True,
        )

    assert captured_json is not None
    assert '"conversation_id":"conv-async"' in captured_json
    assert '"accessed_service":"analytics"' in captured_json
    assert '"requested_columns":4' in captured_json
    assert '"task_necessary_columns":2' in captured_json
    assert '"gdpr_deletion_requested":true' in captured_json


@pytest.mark.asyncio
@respx.mock
async def test_async_check_with_context_emits_multimodal_summary():
    captured_json = None

    def _capture(request: httpx.Request):
        nonlocal captured_json
        captured_json = request.read().decode()
        return httpx.Response(200, json=ALLOW_RESP)

    respx.post(f"{BASE}/validate").mock(side_effect=_capture)

    async with AsyncHaltChainClient(agent_id="abot", api_key="k", base_url=BASE) as ac:
        await ac.check_with_context(
            {"type": "tool_call", "endpoint": "vision-inspect"},
            multimodal_summary={
                "text_summary": "drift in user objective",
                "vision_summary": "frame mismatch",
            },
        )

    assert captured_json is not None
    assert '"multimodal_summary"' in captured_json
    assert '"text_summary":"drift in user objective"' in captured_json
    assert '"vision_summary":"frame mismatch"' in captured_json


@pytest.mark.asyncio
@respx.mock
async def test_async_get_risk_advisories_returns_typed_list():
    advisory = {
        "id": 11,
        "source_agent_id": "agent-source",
        "target_agent_id": "abot",
        "policy_code": "TOKEN_RATE_EXCEEDED",
        "reason": "peer failure mode",
        "trigger_transaction_id": "tx-2",
        "created_at": "2026-03-12T00:00:00Z",
    }
    respx.get(f"{BASE}/risk/advisories/abot").mock(
        return_value=httpx.Response(200, json={"advisories": [advisory]})
    )
    async with AsyncHaltChainClient(agent_id="abot", api_key="k", base_url=BASE) as ac:
        advisories = await ac.apoll_risk_advisories()
    assert len(advisories) == 1
    assert advisories[0]["id"] == 11
    assert advisories[0]["policy_code"] == "TOKEN_RATE_EXCEEDED"

# ── Policy cache

def test_cache_lru_eviction():
    c = PolicyCache(ttl=60, max_size=3)
    for i in range(4):
        c.put("bot", {"type": "x", "n": i}, "ALLOW", "", "")
    assert c.size() == 3

def test_cache_key_is_stable():
    c = PolicyCache(ttl=60)
    action = {"type": "transfer", "amount": 100, "currency": "USD"}
    c.put("bot", action, "ALLOW", "", "")
    assert c.get("bot", action) is not None
    action2 = {"currency": "USD", "amount": 100, "type": "transfer"}
    assert c.get("bot", action2) is not None

# ── LangChain handler

@respx.mock
def test_langchain_handler_allows_tool():
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=ALLOW_RESP))
    c = HaltChainClient(agent_id="lc", api_key="k", base_url=BASE)
    h = HaltChainCallbackHandler(client=c)
    h.on_tool_start({"name": "some_tool"}, '{"amount": 10}')

@respx.mock
def test_langchain_handler_blocks_tool():
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=DENY_RESP))
    c = HaltChainClient(agent_id="lc", api_key="k", base_url=BASE)
    h = HaltChainCallbackHandler(client=c)
    with pytest.raises(PolicyViolationError):
        h.on_tool_start({"name": "transfer_money"}, '{"amount": 99000}')

@respx.mock
def test_langchain_tool_action_map():
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=ALLOW_RESP))
    c = HaltChainClient(agent_id="lc", api_key="k", base_url=BASE)
    h = HaltChainCallbackHandler(
        client=c,
        tool_action_map={
            "pay": lambda inp: {"type": "transfer", "amount": float(inp.get("amount", 0))},
        },
    )
    captured = None
    orig_check = c.check
    def capture_check(action, *a, **kw):
        nonlocal captured
        captured = action
        return orig_check(action, *a, **kw)
    c.check = capture_check

    h.on_tool_start({"name": "pay"}, '{"amount": 50}')
    assert captured == {"type": "transfer", "amount": 50.0}


@respx.mock
def test_langchain_handler_forwards_auto_metadata():
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=ALLOW_RESP))
    c = HaltChainClient(agent_id="lc", api_key="k", base_url=BASE)
    h = HaltChainCallbackHandler(client=c)

    captured_action = None
    captured_metadata = None
    orig_check = c.check

    def capture_check(action, *a, **kw):
        nonlocal captured_action, captured_metadata
        captured_action = action
        captured_metadata = kw.get("metadata")
        return orig_check(action, *a, **kw)

    c.check = capture_check

    h.on_tool_start(
        {"name": "db_read"},
        '{"requested_columns": 8, "task_necessary_columns": 3, "retention_days_requested": 30}',
        run_id="run-123",
    )

    assert captured_action is not None
    assert captured_metadata is not None
    assert captured_metadata["conversation_id"] == "run-123"
    assert captured_metadata["accessed_service"] == "db_read"
    assert captured_metadata["requested_columns"] == 8
    assert captured_metadata["task_necessary_columns"] == 3
    assert captured_metadata["retention_days_requested"] == 30


@respx.mock
def test_langchain_handler_custom_metadata_builder():
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=ALLOW_RESP))
    c = HaltChainClient(agent_id="lc", api_key="k", base_url=BASE)
    h = HaltChainCallbackHandler(
        client=c,
        metadata_builder=lambda action, ctx: {
            "conversation_id": "conv-custom",
            "declared_services": ["svc-a", "svc-b"],
            "accessed_service": action.get("endpoint") or ctx["tool_name"],
        },
    )

    captured_metadata = None
    orig_check = c.check

    def capture_check(action, *a, **kw):
        nonlocal captured_metadata
        captured_metadata = kw.get("metadata")
        return orig_check(action, *a, **kw)

    c.check = capture_check
    h.on_tool_start({"name": "http_call"}, '{"endpoint": "user-db"}', run_id="run-x")

    assert captured_metadata == {
        "conversation_id": "conv-custom",
        "declared_services": ["svc-a", "svc-b"],
        "accessed_service": "user-db",
    }

@respx.mock
def test_validate_decorator_reads_action_from_kwargs():
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=ALLOW_RESP))
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE)

    @c.validate
    def do_thing(*, action: dict) -> str:
        return "done"

    assert do_thing(action={"type": "transfer", "amount": 10}) == "done"


@pytest.mark.asyncio
@respx.mock
async def test_async_validate_decorator_reads_action_from_kwargs():
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=ALLOW_RESP))
    async with AsyncHaltChainClient(agent_id="abot", api_key="k", base_url=BASE) as ac:
        @ac.validate
        async def do_thing(*, action: dict) -> str:
            return "done"

        assert await do_thing(action={"type": "transfer", "amount": 10}) == "done"


def test_cache_lru_recency_updates_on_get():
    c = PolicyCache(ttl=60, max_size=2)
    a0 = {"type": "x", "n": 0}
    a1 = {"type": "x", "n": 1}
    a2 = {"type": "x", "n": 2}

    c.put("bot", a0, "ALLOW", "", "")
    c.put("bot", a1, "ALLOW", "", "")
    assert c.get("bot", a0) is not None

    c.put("bot", a2, "ALLOW", "", "")

    assert c.get("bot", a0) is not None
    assert c.get("bot", a1) is None
    assert c.get("bot", a2) is not None

# ── Session-aware check

@respx.mock
def test_sync_check_passes_session_id():
    captured_json = None

    def _capture(request: httpx.Request):
        nonlocal captured_json
        import json as _json
        captured_json = _json.loads(request.read().decode())
        return httpx.Response(200, json=ALLOW_RESP)

    respx.post(f"{BASE}/validate").mock(side_effect=_capture)
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE)
    c.check({"type": "transfer", "amount": 10}, session_id="sess-42")
    assert captured_json is not None
    assert captured_json["session_id"] == "sess-42"


@respx.mock
def test_sync_check_no_session_id_omits_field():
    captured_json = None

    def _capture(request: httpx.Request):
        nonlocal captured_json
        import json as _json
        captured_json = _json.loads(request.read().decode())
        return httpx.Response(200, json=ALLOW_RESP)

    respx.post(f"{BASE}/validate").mock(side_effect=_capture)
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE)
    c.check({"type": "transfer", "amount": 10})
    assert captured_json is not None
    assert "session_id" not in captured_json


@respx.mock
def test_sync_check_with_context_passes_session_id():
    captured_json = None

    def _capture(request: httpx.Request):
        nonlocal captured_json
        import json as _json
        captured_json = _json.loads(request.read().decode())
        return httpx.Response(200, json=ALLOW_RESP)

    respx.post(f"{BASE}/validate").mock(side_effect=_capture)
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE)
    c.check_with_context(
        {"type": "transfer", "amount": 10},
        session_id="sess-99",
        conversation_id="conv-1",
    )
    assert captured_json is not None
    assert captured_json["session_id"] == "sess-99"


@pytest.mark.asyncio
@respx.mock
async def test_async_check_passes_session_id():
    captured_json = None

    def _capture(request: httpx.Request):
        nonlocal captured_json
        import json as _json
        captured_json = _json.loads(request.read().decode())
        return httpx.Response(200, json=ALLOW_RESP)

    respx.post(f"{BASE}/validate").mock(side_effect=_capture)
    async with AsyncHaltChainClient(agent_id="abot", api_key="k", base_url=BASE) as ac:
        await ac.check({"type": "transfer", "amount": 10}, session_id="sess-async")
    assert captured_json is not None
    assert captured_json["session_id"] == "sess-async"


@pytest.mark.asyncio
@respx.mock
async def test_async_check_with_context_passes_session_id():
    captured_json = None

    def _capture(request: httpx.Request):
        nonlocal captured_json
        import json as _json
        captured_json = _json.loads(request.read().decode())
        return httpx.Response(200, json=ALLOW_RESP)

    respx.post(f"{BASE}/validate").mock(side_effect=_capture)
    async with AsyncHaltChainClient(agent_id="abot", api_key="k", base_url=BASE) as ac:
        await ac.check_with_context(
            {"type": "transfer", "amount": 10},
            session_id="sess-ctx-async",
        )
    assert captured_json is not None
    assert captured_json["session_id"] == "sess-ctx-async"
