"""Tests for goal declaration, revocation, drift, and goal clarification contract."""
from __future__ import annotations
import pytest
import respx
import httpx

from haltchain import AsyncHaltChainClient, HaltChainClient
from haltchain.exceptions import (
    GoalClarificationRequiredError,
    PolicyViolationError,
    ValidationError,
)

BASE = "https://haltchain-consensus.fly.dev"
ALLOW_RESP  = {"decision": "ALLOW",  "reason": "ok", "policy": "OK"}
CLARIFICATION_RESP = {
    "decision": "GOAL_CLARIFICATION_REQUIRED",
    "reason": "Goal drift detected: mean similarity 0.120 is below threshold 0.300. Re-declare intent via POST /goals.",
    "policy": "GOAL_CLARIFICATION_REQUIRED",
}
GOAL_DECLARED_RESP = {"agent_id": "bot", "session_id": "s1", "intent": "trade stocks", "status": "declared"}
GOAL_REVOKED_RESP  = {"status": "revoked"}
DRIFT_STATUS_RESP  = {"agent_id": "bot", "session_id": "s1", "semantic_drift": 0.15, "drift_velocity": 0.02}

# ── Goal clarification contract

@respx.mock
def test_sync_goal_clarification_raises_specific_error():
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=CLARIFICATION_RESP))
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE)
    with pytest.raises(GoalClarificationRequiredError) as exc_info:
        c.check({"type": "transfer", "amount": 100})
    assert exc_info.value.policy == "GOAL_CLARIFICATION_REQUIRED"
    assert "drift" in exc_info.value.reason.lower()


@respx.mock
def test_sync_goal_clarification_is_policy_violation_subclass():
    """GoalClarificationRequiredError should be catchable as PolicyViolationError."""
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=CLARIFICATION_RESP))
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE)
    with pytest.raises(PolicyViolationError):
        c.check({"type": "transfer", "amount": 100})


@pytest.mark.asyncio
@respx.mock
async def test_async_goal_clarification_raises_specific_error():
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=CLARIFICATION_RESP))
    async with AsyncHaltChainClient(agent_id="abot", api_key="k", base_url=BASE) as ac:
        with pytest.raises(GoalClarificationRequiredError) as exc_info:
            await ac.check({"type": "transfer", "amount": 100})
        assert exc_info.value.policy == "GOAL_CLARIFICATION_REQUIRED"

# ── Goal lifecycle (sync)

@respx.mock
def test_sync_declare_goal():
    respx.post(f"{BASE}/goals").mock(return_value=httpx.Response(200, json=GOAL_DECLARED_RESP))
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE)
    result = c.declare_goal("s1", "trade stocks")
    assert result["status"] == "declared"


@respx.mock
def test_sync_declare_goal_empty_intent_raises():
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE)
    with pytest.raises(ValueError, match="must not be empty"):
        c.declare_goal("s1", "   ")


@respx.mock
def test_sync_declare_goal_empty_session_raises():
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE)
    with pytest.raises(ValueError, match="must not be empty"):
        c.declare_goal("", "some intent")


@respx.mock
def test_sync_declare_goal_server_error_raises():
    respx.post(f"{BASE}/goals").mock(
        return_value=httpx.Response(500, json={"error": "internal"})
    )
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE)
    with pytest.raises(ValidationError, match="500"):
        c.declare_goal("s1", "trade stocks")


@respx.mock
def test_sync_revoke_goal():
    respx.request("DELETE", f"{BASE}/goals/bot/s1").mock(
        return_value=httpx.Response(200, json=GOAL_REVOKED_RESP)
    )
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE)
    result = c.revoke_goal("s1")
    assert result["status"] == "revoked"


@respx.mock
def test_sync_revoke_goal_not_found():
    respx.request("DELETE", f"{BASE}/goals/bot/s-missing").mock(
        return_value=httpx.Response(404, json={"error": "goal not found"})
    )
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE)
    with pytest.raises(ValidationError, match="404"):
        c.revoke_goal("s-missing")


@respx.mock
def test_sync_revoke_goal_empty_session_raises():
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE)
    with pytest.raises(ValueError, match="must not be empty"):
        c.revoke_goal("  ")


@respx.mock
def test_sync_drift_status():
    respx.get(f"{BASE}/drift/bot/s1").mock(
        return_value=httpx.Response(200, json=DRIFT_STATUS_RESP)
    )
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE)
    result = c.drift_status("s1")
    assert result["semantic_drift"] == 0.15


@respx.mock
def test_sync_drift_status_empty_session_raises():
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE)
    with pytest.raises(ValueError, match="must not be empty"):
        c.drift_status("")


@respx.mock
def test_sync_drift_status_server_error():
    respx.get(f"{BASE}/drift/bot/s1").mock(
        return_value=httpx.Response(500, json={"error": "internal"})
    )
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE)
    with pytest.raises(ValidationError, match="500"):
        c.drift_status("s1")


# ── Goal lifecycle (async)

@pytest.mark.asyncio
@respx.mock
async def test_async_declare_goal():
    respx.post(f"{BASE}/goals").mock(return_value=httpx.Response(200, json=GOAL_DECLARED_RESP))
    async with AsyncHaltChainClient(agent_id="bot", api_key="k", base_url=BASE) as ac:
        result = await ac.adeclare_goal("s1", "trade stocks")
    assert result["status"] == "declared"


@pytest.mark.asyncio
@respx.mock
async def test_async_declare_goal_empty_raises():
    async with AsyncHaltChainClient(agent_id="bot", api_key="k", base_url=BASE) as ac:
        with pytest.raises(ValueError, match="must not be empty"):
            await ac.adeclare_goal("s1", "")


@pytest.mark.asyncio
@respx.mock
async def test_async_declare_goal_server_error():
    respx.post(f"{BASE}/goals").mock(
        return_value=httpx.Response(400, json={"error": "bad"})
    )
    async with AsyncHaltChainClient(agent_id="bot", api_key="k", base_url=BASE) as ac:
        with pytest.raises(ValidationError, match="400"):
            await ac.adeclare_goal("s1", "intent")


@pytest.mark.asyncio
@respx.mock
async def test_async_revoke_goal():
    respx.request("DELETE", f"{BASE}/goals/bot/s1").mock(
        return_value=httpx.Response(200, json=GOAL_REVOKED_RESP)
    )
    async with AsyncHaltChainClient(agent_id="bot", api_key="k", base_url=BASE) as ac:
        result = await ac.arevoke_goal("s1")
    assert result["status"] == "revoked"


@pytest.mark.asyncio
@respx.mock
async def test_async_revoke_goal_not_found():
    respx.request("DELETE", f"{BASE}/goals/bot/s-x").mock(
        return_value=httpx.Response(404, json={"error": "goal not found"})
    )
    async with AsyncHaltChainClient(agent_id="bot", api_key="k", base_url=BASE) as ac:
        with pytest.raises(ValidationError, match="404"):
            await ac.arevoke_goal("s-x")


@pytest.mark.asyncio
@respx.mock
async def test_async_revoke_goal_empty_raises():
    async with AsyncHaltChainClient(agent_id="bot", api_key="k", base_url=BASE) as ac:
        with pytest.raises(ValueError, match="must not be empty"):
            await ac.arevoke_goal("  ")


@pytest.mark.asyncio
@respx.mock
async def test_async_drift_status():
    respx.get(f"{BASE}/drift/bot/s1").mock(
        return_value=httpx.Response(200, json=DRIFT_STATUS_RESP)
    )
    async with AsyncHaltChainClient(agent_id="bot", api_key="k", base_url=BASE) as ac:
        result = await ac.adrift_status("s1")
    assert result["semantic_drift"] == 0.15


@pytest.mark.asyncio
@respx.mock
async def test_async_drift_status_empty_raises():
    async with AsyncHaltChainClient(agent_id="bot", api_key="k", base_url=BASE) as ac:
        with pytest.raises(ValueError, match="must not be empty"):
            await ac.adrift_status("")
