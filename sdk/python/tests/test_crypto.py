"""Tests for nonce store, HMAC signing, signature verification, key pinning, and TOFU."""
from __future__ import annotations
import base64
import hmac
import hashlib
import uuid
import pytest
import respx
import httpx
from datetime import datetime, timedelta, timezone

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    _CRYPTO_AVAILABLE = True
except ImportError:  # pragma: no cover
    _CRYPTO_AVAILABLE = False

from haltchain import AsyncHaltChainClient, HaltChainClient
from haltchain.crypto import (
    SignatureVerifier,
    _NonceStore,
    _canonical_message,
    canonical_decision_payload,
    sign_request,
)
from haltchain.exceptions import KeyRotationError, SignatureVerificationError

BASE = "https://haltchain-consensus.fly.dev"
ALLOW_RESP = {"decision": "ALLOW", "reason": "ok", "policy": "OK"}

_needs_crypto = pytest.mark.skipif(not _CRYPTO_AVAILABLE, reason="cryptography not installed")


def _ts(delta_seconds: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=delta_seconds)).isoformat()


def _gen_keypair() -> tuple[Ed25519PrivateKey, str, str]:
    """Returns (private_key, public_key_b64, key_id)."""
    if not _CRYPTO_AVAILABLE:
        pytest.skip("cryptography not installed")
    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv, base64.b64encode(raw).decode(), str(uuid.uuid4())


def _sign_response(priv: Ed25519PrivateKey, key_id: str, response: dict) -> dict:
    """Attach a valid SignedEnvelope to a response dict."""
    nonce = str(uuid.uuid4())
    signed_at = datetime.now(timezone.utc).isoformat()
    payload = canonical_decision_payload(
        response.get("transaction_id", "tx-1"),
        response.get("decision", "ALLOW"),
        response.get("agent_id", "bot"),
        response.get("timestamp", signed_at),
    )
    message = _canonical_message(payload, nonce, signed_at)
    sig_bytes = priv.sign(message)
    return {
        **response,
        "transaction_id": response.get("transaction_id", "tx-1"),
        "timestamp": response.get("timestamp", signed_at),
        "sig": {
            "nonce": nonce,
            "signed_at": signed_at,
            "key_id": key_id,
            "signature": base64.b64encode(sig_bytes).decode(),
        },
    }

# ── Nonce store

def test_nonce_store_rejects_replay():
    ns = _NonceStore()
    assert ns.check_and_insert("abc123") is True
    assert ns.check_and_insert("abc123") is False


def test_nonce_store_accepts_fresh_signed_at():
    ns = _NonceStore(ttl=300)
    assert ns.check_and_insert("n1", _ts(0)) is True


def test_nonce_store_rejects_stale_signed_at():
    ns = _NonceStore(ttl=300)
    assert ns.check_and_insert("n2", _ts(-301)) is False


def test_nonce_store_rejects_future_signed_at():
    ns = _NonceStore(ttl=300)
    assert ns.check_and_insert("n3", _ts(+301)) is False


def test_nonce_store_rejects_malformed_signed_at():
    ns = _NonceStore(ttl=300)
    assert ns.check_and_insert("n4", "not-a-date") is False

# ── HMAC signing

def test_sign_request_produces_valid_hmac():
    nonce, timestamp, sig = sign_request("agent1", "secret_key")
    canon = f"agent1\0{nonce}\0{timestamp}".encode()
    expected = hmac.new("secret_key".encode(), canon, hashlib.sha256).hexdigest()
    assert sig == expected


def test_sign_request_unique_nonces():
    _, _, sig1 = sign_request("agent1", "k")
    _, _, sig2 = sign_request("agent1", "k")
    assert sig1 != sig2


@respx.mock
def test_request_body_omits_api_key():
    """api_key must not appear in the JSON body — it lives only in X-API-Key header."""
    captured_body = {}

    def capture(request):
        captured_body.update(request.content and __import__("json").loads(request.content) or {})
        return httpx.Response(200, json=ALLOW_RESP)

    respx.post(f"{BASE}/validate").mock(side_effect=capture)
    c = HaltChainClient(agent_id="bot", api_key="secret_key", base_url=BASE,
                        verify_signatures=False)
    c.check({"type": "transfer"})
    assert "api_key" not in captured_body

# ── Strict mode — sync

@respx.mock
def test_strict_pubkey_fetch_fail_blocks():
    """Strict mode: if public-key endpoint unreachable, validate must raise."""
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=ALLOW_RESP))
    respx.get(f"{BASE}/public-key").mock(side_effect=httpx.ConnectError("down"))
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE, verify_signatures=True, strict_signatures=True)
    with pytest.raises(SignatureVerificationError, match="Cannot fetch validator public key"):
        c.check({"type": "transfer", "amount": 10})


@respx.mock
def test_strict_missing_sig_in_response_blocks():
    """Strict mode: response without sig envelope raises SignatureVerificationError."""
    priv, pub_b64, kid = _gen_keypair()
    respx.get(f"{BASE}/public-key").mock(return_value=httpx.Response(200, json={"public_key_b64": pub_b64, "key_id": kid}))
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=ALLOW_RESP))
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE, verify_signatures=True, strict_signatures=True)
    with pytest.raises(SignatureVerificationError, match="no signature envelope"):
        c.check({"type": "transfer", "amount": 10})


@respx.mock
def test_strict_bad_signature_blocks():
    """Strict mode: tampered signature raises SignatureVerificationError."""
    priv, pub_b64, kid = _gen_keypair()
    signed = _sign_response(priv, kid, {**ALLOW_RESP, "agent_id": "bot"})
    bad_sig = base64.b64encode(b"\x00" * 64).decode()
    signed["sig"]["signature"] = bad_sig

    respx.get(f"{BASE}/public-key").mock(return_value=httpx.Response(200, json={"public_key_b64": pub_b64, "key_id": kid}))
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=signed))
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE, verify_signatures=True, strict_signatures=True)
    with pytest.raises(SignatureVerificationError):
        c.check({"type": "transfer", "amount": 10})


@respx.mock
def test_strict_valid_signature_allows():
    """Strict mode: valid signature passes through cleanly."""
    priv, pub_b64, kid = _gen_keypair()
    signed = _sign_response(priv, kid, {**ALLOW_RESP, "agent_id": "bot"})
    respx.get(f"{BASE}/public-key").mock(return_value=httpx.Response(200, json={"public_key_b64": pub_b64, "key_id": kid}))
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=signed))
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE, verify_signatures=True, strict_signatures=True)
    result = c.check({"type": "transfer", "amount": 10})
    assert result["decision"] == "ALLOW"


@respx.mock
def test_relaxed_pubkey_fetch_fail_continues():
    """Relaxed (strict_signatures=False): pubkey unreachable is a soft failure — check proceeds."""
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=ALLOW_RESP))
    respx.get(f"{BASE}/public-key").mock(side_effect=httpx.ConnectError("down"))
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE, verify_signatures=True, strict_signatures=False)
    result = c.check({"type": "transfer", "amount": 10})
    assert result["decision"] == "ALLOW"

# ── Key pinning / TOFU — sync

@respx.mock
def test_tofu_pins_key_id_on_first_fetch():
    """First fetch stores key_id as trusted."""
    priv, pub_b64, kid = _gen_keypair()
    signed = _sign_response(priv, kid, {**ALLOW_RESP, "agent_id": "bot"})
    respx.get(f"{BASE}/public-key").mock(return_value=httpx.Response(200, json={"public_key_b64": pub_b64, "key_id": kid}))
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=signed))
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE, verify_signatures=True, strict_signatures=True)
    c.check({"type": "transfer", "amount": 10})
    assert c.verification_info["trusted_key_id"] == kid
    assert c.verification_info["verifier_loaded"] is True


@respx.mock
def test_pinned_key_id_accepted_when_matching():
    """Constructor-pinned key_id is accepted when server returns the same key."""
    priv, pub_b64, kid = _gen_keypair()
    signed = _sign_response(priv, kid, {**ALLOW_RESP, "agent_id": "bot"})
    respx.get(f"{BASE}/public-key").mock(return_value=httpx.Response(200, json={"public_key_b64": pub_b64, "key_id": kid}))
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=signed))
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE, verify_signatures=True, strict_signatures=True, pinned_key_id=kid)
    result = c.check({"type": "transfer", "amount": 10})
    assert result["decision"] == "ALLOW"


@respx.mock
def test_pinned_key_id_rejected_on_mismatch():
    """Constructor-pinned key_id rejects a different key from server."""
    priv, pub_b64, kid = _gen_keypair()
    respx.get(f"{BASE}/public-key").mock(return_value=httpx.Response(200, json={"public_key_b64": pub_b64, "key_id": kid}))
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=ALLOW_RESP))
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE, verify_signatures=True, strict_signatures=True, pinned_key_id="expected-key-id")
    with pytest.raises(KeyRotationError) as exc_info:
        c.check({"type": "transfer", "amount": 10})
    assert exc_info.value.trusted_key_id == "expected-key-id"
    assert exc_info.value.received_key_id == kid


@respx.mock
def test_key_rotation_rejected_by_default():
    """After TOFU pin, a new key_id from the server is rejected (trust_on_rotation=False)."""
    priv1, pub_b64_1, kid1 = _gen_keypair()
    priv2, pub_b64_2, kid2 = _gen_keypair()
    signed1 = _sign_response(priv1, kid1, {**ALLOW_RESP, "agent_id": "bot"})
    signed2 = _sign_response(priv2, kid2, {**ALLOW_RESP, "agent_id": "bot"})

    with respx.mock:
        respx.get(f"{BASE}/public-key").mock(return_value=httpx.Response(200, json={"public_key_b64": pub_b64_1, "key_id": kid1}))
        respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=signed1))
        c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE, verify_signatures=True, strict_signatures=True)
        c.check({"type": "transfer", "amount": 10})
        assert c._trusted_key_id == kid1

    c._verifier = None
    with respx.mock:
        respx.get(f"{BASE}/public-key").mock(return_value=httpx.Response(200, json={"public_key_b64": pub_b64_2, "key_id": kid2}))
        respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=signed2))
        with pytest.raises(KeyRotationError) as exc_info:
            c.check({"type": "transfer", "amount": 10})
        assert exc_info.value.trusted_key_id == kid1
        assert exc_info.value.received_key_id == kid2


@respx.mock
def test_key_rotation_accepted_with_trust_on_rotation():
    """With trust_on_rotation=True, a new key_id is accepted and re-pinned."""
    priv1, pub_b64_1, kid1 = _gen_keypair()
    priv2, pub_b64_2, kid2 = _gen_keypair()
    signed1 = _sign_response(priv1, kid1, {**ALLOW_RESP, "agent_id": "bot"})
    signed2 = _sign_response(priv2, kid2, {**ALLOW_RESP, "agent_id": "bot"})

    with respx.mock:
        respx.get(f"{BASE}/public-key").mock(return_value=httpx.Response(200, json={"public_key_b64": pub_b64_1, "key_id": kid1}))
        respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=signed1))
        c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE, verify_signatures=True, strict_signatures=True, trust_on_rotation=True)
        c.check({"type": "transfer", "amount": 10})

    c._verifier = None
    with respx.mock:
        respx.get(f"{BASE}/public-key").mock(return_value=httpx.Response(200, json={"public_key_b64": pub_b64_2, "key_id": kid2}))
        respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=signed2))
        result = c.check({"type": "transfer", "amount": 10})
    assert result["decision"] == "ALLOW"
    assert c._trusted_key_id == kid2


@respx.mock
def test_trust_new_key_clears_and_repins():
    """trust_new_key() resets pin state; next call accepts the server's current key."""
    priv1, pub_b64_1, kid1 = _gen_keypair()
    priv2, pub_b64_2, kid2 = _gen_keypair()
    signed1 = _sign_response(priv1, kid1, {**ALLOW_RESP, "agent_id": "bot"})
    signed2 = _sign_response(priv2, kid2, {**ALLOW_RESP, "agent_id": "bot"})

    with respx.mock:
        respx.get(f"{BASE}/public-key").mock(return_value=httpx.Response(200, json={"public_key_b64": pub_b64_1, "key_id": kid1}))
        respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=signed1))
        c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE, verify_signatures=True, strict_signatures=True)
        c.check({"type": "transfer", "amount": 10})

    c.trust_new_key()
    assert c._trusted_key_id is None
    assert c._verifier is None

    with respx.mock:
        respx.get(f"{BASE}/public-key").mock(return_value=httpx.Response(200, json={"public_key_b64": pub_b64_2, "key_id": kid2}))
        respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=signed2))
        result = c.check({"type": "transfer", "amount": 10})
    assert result["decision"] == "ALLOW"
    assert c._trusted_key_id == kid2


def test_verifier_key_id_mismatch_in_envelope_raises():
    """SignatureVerifier.verify_response raises KeyRotationError when envelope key_id differs."""
    priv, pub_b64, kid = _gen_keypair()
    verifier = SignatureVerifier(pub_b64, key_id=kid)
    nonce = str(uuid.uuid4())
    signed_at = datetime.now(timezone.utc).isoformat()
    payload = canonical_decision_payload("tx-1", "ALLOW", "bot", signed_at)
    message = _canonical_message(payload, nonce, signed_at)
    sig_bytes = priv.sign(message)
    response = {
        "transaction_id": "tx-1",
        "decision": "ALLOW",
        "agent_id": "bot",
        "timestamp": signed_at,
        "sig": {
            "nonce": nonce,
            "signed_at": signed_at,
            "key_id": "rotated-different-key-id",
            "signature": base64.b64encode(sig_bytes).decode(),
        },
    }
    with pytest.raises(KeyRotationError):
        verifier.verify_response(response, "bot")


def test_key_rotation_error_is_signature_verification_error():
    """KeyRotationError is catchable as SignatureVerificationError."""
    with pytest.raises(SignatureVerificationError):
        raise KeyRotationError(trusted_key_id="old", received_key_id="new")

# ── Strict mode — async

@pytest.mark.asyncio
@respx.mock
async def test_async_strict_pubkey_fetch_fail_blocks():
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=ALLOW_RESP))
    respx.get(f"{BASE}/public-key").mock(side_effect=httpx.ConnectError("down"))
    async with AsyncHaltChainClient(agent_id="abot", api_key="k", base_url=BASE, verify_signatures=True, strict_signatures=True) as ac:
        with pytest.raises(SignatureVerificationError, match="Cannot fetch validator public key"):
            await ac.check({"type": "transfer", "amount": 10})


@pytest.mark.asyncio
@respx.mock
async def test_async_strict_missing_sig_blocks():
    priv, pub_b64, kid = _gen_keypair()
    respx.get(f"{BASE}/public-key").mock(return_value=httpx.Response(200, json={"public_key_b64": pub_b64, "key_id": kid}))
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=ALLOW_RESP))
    async with AsyncHaltChainClient(agent_id="abot", api_key="k", base_url=BASE, verify_signatures=True, strict_signatures=True) as ac:
        with pytest.raises(SignatureVerificationError, match="no signature envelope"):
            await ac.check({"type": "transfer", "amount": 10})


@pytest.mark.asyncio
@respx.mock
async def test_async_strict_valid_signature_allows():
    priv, pub_b64, kid = _gen_keypair()
    signed = _sign_response(priv, kid, {**ALLOW_RESP, "agent_id": "abot"})
    respx.get(f"{BASE}/public-key").mock(return_value=httpx.Response(200, json={"public_key_b64": pub_b64, "key_id": kid}))
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=signed))
    async with AsyncHaltChainClient(agent_id="abot", api_key="k", base_url=BASE, verify_signatures=True, strict_signatures=True) as ac:
        result = await ac.check({"type": "transfer", "amount": 10})
    assert result["decision"] == "ALLOW"


@pytest.mark.asyncio
@respx.mock
async def test_async_relaxed_pubkey_fail_continues():
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=ALLOW_RESP))
    respx.get(f"{BASE}/public-key").mock(side_effect=httpx.ConnectError("down"))
    async with AsyncHaltChainClient(agent_id="abot", api_key="k", base_url=BASE, verify_signatures=True, strict_signatures=False) as ac:
        result = await ac.check({"type": "transfer", "amount": 10})
    assert result["decision"] == "ALLOW"


@pytest.mark.asyncio
@respx.mock
async def test_async_pinned_key_id_rejected_on_mismatch():
    priv, pub_b64, kid = _gen_keypair()
    respx.get(f"{BASE}/public-key").mock(return_value=httpx.Response(200, json={"public_key_b64": pub_b64, "key_id": kid}))
    respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=ALLOW_RESP))
    async with AsyncHaltChainClient(agent_id="abot", api_key="k", base_url=BASE, verify_signatures=True, strict_signatures=True, pinned_key_id="pinned-key") as ac:
        with pytest.raises(KeyRotationError) as exc_info:
            await ac.check({"type": "transfer", "amount": 10})
    assert exc_info.value.trusted_key_id == "pinned-key"
    assert exc_info.value.received_key_id == kid


@pytest.mark.asyncio
@respx.mock
async def test_async_trust_new_key_repins():
    priv1, pub_b64_1, kid1 = _gen_keypair()
    priv2, pub_b64_2, kid2 = _gen_keypair()
    signed1 = _sign_response(priv1, kid1, {**ALLOW_RESP, "agent_id": "abot"})
    signed2 = _sign_response(priv2, kid2, {**ALLOW_RESP, "agent_id": "abot"})

    ac = AsyncHaltChainClient(agent_id="abot", api_key="k", base_url=BASE, verify_signatures=True, strict_signatures=True)
    try:
        with respx.mock:
            respx.get(f"{BASE}/public-key").mock(return_value=httpx.Response(200, json={"public_key_b64": pub_b64_1, "key_id": kid1}))
            respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=signed1))
            await ac.check({"type": "transfer", "amount": 10})
        assert ac._trusted_key_id == kid1

        ac.trust_new_key()

        with respx.mock:
            respx.get(f"{BASE}/public-key").mock(return_value=httpx.Response(200, json={"public_key_b64": pub_b64_2, "key_id": kid2}))
            respx.post(f"{BASE}/validate").mock(return_value=httpx.Response(200, json=signed2))
            result = await ac.check({"type": "transfer", "amount": 10})
        assert result["decision"] == "ALLOW"
        assert ac._trusted_key_id == kid2
    finally:
        await ac.aclose()

# ── Security diagnostics

def test_verification_info_defaults():
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE)
    info = c.verification_info
    assert info["verify_signatures"] is True
    assert info["strict_signatures"] is False
    assert info["trust_on_rotation"] is False
    assert info["verifier_loaded"] is False
    assert info["trusted_key_id"] is None


def test_verification_info_with_pin():
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE, pinned_key_id="known-key")
    info = c.verification_info
    assert info["trusted_key_id"] == "known-key"


def test_verification_info_disabled():
    c = HaltChainClient(agent_id="bot", api_key="k", base_url=BASE, verify_signatures=False)
    info = c.verification_info
    assert info["verify_signatures"] is False
    assert info["strict_signatures"] is False


def test_async_verification_info_defaults():
    ac = AsyncHaltChainClient(agent_id="abot", api_key="k", base_url=BASE)
    info = ac.verification_info
    assert info["verify_signatures"] is True
    assert info["strict_signatures"] is False
    assert info["verifier_loaded"] is False
    assert info["trusted_key_id"] is None
