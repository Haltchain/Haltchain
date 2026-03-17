from __future__ import annotations

import os
from uuid import uuid4

import pytest

from haltchain import AsyncHaltChainClient, HaltChainClient
from haltchain.exceptions import (
    CircuitBreakerError,
    PolicyViolationError,
    SignatureVerificationError,
    ValidatorUnavailableError,
)


CONTRACT_URL = os.getenv("HALTCHAIN_CONTRACT_URL")
API_KEY = os.getenv("HALTCHAIN_CONTRACT_API_KEY", "dev-key")

KNOWN_DECISION_CODES = {
    "ALLOW",
    "DENY",
    "CIRCUIT_BREAK",
    "GOAL_CLARIFICATION_REQUIRED",
}


pytestmark = pytest.mark.skipif(
    not CONTRACT_URL,
    reason="Set HALTCHAIN_CONTRACT_URL to run SDK/API contract tests",
)


def _assert_known_decision(result: dict) -> None:
    decision = result.get("decision")
    assert decision in KNOWN_DECISION_CODES, f"Unknown decision code from API: {decision!r}"


def test_contract_sync_decision_codes_and_metadata() -> None:
    assert CONTRACT_URL is not None
    with HaltChainClient(
        agent_id=f"contract-sync-{uuid4().hex[:8]}",
        api_key=API_KEY,
        base_url=CONTRACT_URL,
        verify_signatures=False,
        cache_ttl=0,
    ) as client:
        allow = client.check({"type": "transfer", "amount": 100, "currency": "USD"})
        _assert_known_decision(allow)
        assert allow["decision"] == "ALLOW"

        with pytest.raises(PolicyViolationError):
            client.check({"type": "transfer", "amount": 10_000, "currency": "USD"})

        with pytest.raises(CircuitBreakerError):
            client.check(
                {"type": "api_call", "endpoint": "/internal"},
                metadata={"api_rate_limit_pct": 99},
            )

        # Metadata and session_id contract: request should be accepted by API without schema errors.
        m = client.check_with_context(
            {"type": "db_read", "endpoint": "user-db"},
            session_id=f"session-{uuid4().hex[:8]}",
            conversation_id=f"conv-{uuid4().hex[:8]}",
            declared_services=["user-db"],
            requested_columns=3,
            task_necessary_columns=3,
            registered_schema_fields=["name", "email"],
            payload_fields=["name", "email"],
            gdpr_deletion_requested=False,
            retention_days_requested=30,
        )
        _assert_known_decision(m)


@pytest.mark.asyncio
async def test_contract_async_decision_codes_and_metadata() -> None:
    assert CONTRACT_URL is not None
    async with AsyncHaltChainClient(
        agent_id=f"contract-async-{uuid4().hex[:8]}",
        api_key=API_KEY,
        base_url=CONTRACT_URL,
        verify_signatures=False,
        cache_ttl=0,
    ) as client:
        allow = await client.check({"type": "transfer", "amount": 100, "currency": "USD"})
        _assert_known_decision(allow)
        assert allow["decision"] == "ALLOW"

        with pytest.raises(PolicyViolationError):
            await client.check({"type": "transfer", "amount": 10_000, "currency": "USD"})

        with pytest.raises(CircuitBreakerError):
            await client.check(
                {"type": "api_call", "endpoint": "/internal"},
                metadata={"api_rate_limit_pct": 99},
            )

        m = await client.check_with_context(
            {"type": "db_read", "endpoint": "analytics"},
            session_id=f"session-{uuid4().hex[:8]}",
            conversation_id=f"conv-{uuid4().hex[:8]}",
            declared_services=["analytics"],
            requested_columns=2,
            task_necessary_columns=2,
            gdpr_deletion_requested=False,
            retention_days_requested=14,
        )
        _assert_known_decision(m)


def test_contract_sync_signature_verification() -> None:
    assert CONTRACT_URL is not None
    with HaltChainClient(
        agent_id=f"contract-sig-{uuid4().hex[:8]}",
        api_key=API_KEY,
        base_url=CONTRACT_URL,
        verify_signatures=True,
        strict_signatures=True,
        cache_ttl=0,
    ) as client:
        result = client.check({"type": "transfer", "amount": 100, "currency": "USD"})
        _assert_known_decision(result)
        assert result["decision"] == "ALLOW"
        assert client.verification_info["verifier_loaded"] is True


@pytest.mark.asyncio
async def test_contract_async_signature_verification() -> None:
    assert CONTRACT_URL is not None
    async with AsyncHaltChainClient(
        agent_id=f"contract-asig-{uuid4().hex[:8]}",
        api_key=API_KEY,
        base_url=CONTRACT_URL,
        verify_signatures=True,
        strict_signatures=True,
        cache_ttl=0,
    ) as client:
        result = await client.check({"type": "transfer", "amount": 100, "currency": "USD"})
        _assert_known_decision(result)
        assert result["decision"] == "ALLOW"
        assert client.verification_info["verifier_loaded"] is True


def test_contract_goal_endpoints_sync() -> None:
    assert CONTRACT_URL is not None
    session = f"goal-sync-{uuid4().hex[:8]}"
    with HaltChainClient(
        agent_id=f"contract-goal-sync-{uuid4().hex[:8]}",
        api_key=API_KEY,
        base_url=CONTRACT_URL,
        verify_signatures=False,
        cache_ttl=0,
    ) as client:
        declared = client.declare_goal(session, "trade only within approved limits")
        assert declared.get("status") == "declared"

        drift = client.drift_status(session)
        assert "semantic_drift" in drift
        assert "drift_velocity" in drift

        revoked = client.revoke_goal(session)
        assert revoked.get("status") == "revoked"


@pytest.mark.asyncio
async def test_contract_goal_endpoints_async() -> None:
    assert CONTRACT_URL is not None
    session = f"goal-async-{uuid4().hex[:8]}"
    async with AsyncHaltChainClient(
        agent_id=f"contract-goal-async-{uuid4().hex[:8]}",
        api_key=API_KEY,
        base_url=CONTRACT_URL,
        verify_signatures=False,
        cache_ttl=0,
    ) as client:
        declared = await client.adeclare_goal(session, "serve only declared user scope")
        assert declared.get("status") == "declared"

        drift = await client.adrift_status(session)
        assert "semantic_drift" in drift
        assert "drift_velocity" in drift

        revoked = await client.arevoke_goal(session)
        assert revoked.get("status") == "revoked"


def test_contract_fail_secure_offline_sync() -> None:
    with HaltChainClient(
        agent_id=f"contract-offline-{uuid4().hex[:8]}",
        api_key=API_KEY,
        base_url="http://127.0.0.1:9",
        verify_signatures=False,
        cache_ttl=0,
        timeout=0.3,
    ) as client:
        with pytest.raises(ValidatorUnavailableError):
            client.check({"type": "transfer", "amount": 100, "currency": "USD"})


def test_contract_strict_signature_blocks_on_key_fetch_failure() -> None:
    assert CONTRACT_URL is not None
    with HaltChainClient(
        agent_id=f"contract-strict-key-{uuid4().hex[:8]}",
        api_key=API_KEY,
        base_url=CONTRACT_URL,
        verify_signatures=True,
        strict_signatures=True,
        cache_ttl=0,
    ) as client:
        client._pubkey_url = f"{CONTRACT_URL.rstrip('/')}/public-key-missing"
        with pytest.raises(SignatureVerificationError):
            client.check({"type": "transfer", "amount": 100, "currency": "USD"})
