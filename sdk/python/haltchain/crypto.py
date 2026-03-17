from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import time
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Optional

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False

from .exceptions import KeyRotationError, SignatureVerificationError


def _canonical_message(payload: str, nonce: str, signed_at: str) -> bytes:
    """Mirrors the Rust canonical_message() — null-byte separated fields."""
    return f"{payload}\0{nonce}\0{signed_at}".encode()


def canonical_decision_payload(
    transaction_id: str,
    decision: str,
    agent_id: str,
    timestamp: str,
) -> str:
    """Mirrors SigningService::canonical_decision_payload in Rust."""
    return f"{transaction_id}\0{decision}\0{agent_id}\0{timestamp}"


class SignatureVerifier:
    """
    Verifies Ed25519 signatures embedded in HaltChain validator responses.

    Fetch the current public key from GET /public-key then pass `public_key_b64`
    to this class. Call `verify_response()` on each response dict.
    """

    def __init__(self, public_key_b64: str, key_id: str = "") -> None:
        if not _CRYPTO_AVAILABLE:
            raise ImportError(
                "Install 'cryptography' for signature verification: "
                "pip install haltchain[crypto]"
            )
        raw = base64.b64decode(public_key_b64)
        self._public_key: Ed25519PublicKey = Ed25519PublicKey.from_public_bytes(raw)
        self._nonces = _NonceStore()
        self.key_id = key_id  # tracks which server keypair this verifier was built from

    def verify_response(self, response: dict, agent_id: str) -> None:
        """
        Verifies the `sig` envelope in a validator response.

        Raises SignatureVerificationError on:
          - missing / malformed envelope
          - key_id mismatch (server rotation not yet acknowledged by client)
          - invalid signature
          - replayed nonce (already seen within 5 min)
        """
        sig = response.get("sig")
        if sig is None:
            raise SignatureVerificationError("Response contains no signature envelope")

        try:
            nonce = sig["nonce"]
            signed_at = sig["signed_at"]
            signature_b64 = sig["signature"]
            envelope_key_id = sig.get("key_id", "")
        except KeyError as exc:
            raise SignatureVerificationError(f"Malformed envelope — missing field: {exc}") from exc

        # Key rotation guard: if both sides advertise key_ids, they must match.
        if self.key_id and envelope_key_id and envelope_key_id != self.key_id:
            raise KeyRotationError(
                trusted_key_id=self.key_id,
                received_key_id=envelope_key_id,
            )

        if not self._nonces.check_and_insert(nonce, signed_at):
            raise SignatureVerificationError("Signature verification failed")

        payload = canonical_decision_payload(
            response.get("transaction_id", ""),
            response.get("decision", ""),
            agent_id,
            response.get("timestamp", ""),
        )
        message = _canonical_message(payload, nonce, signed_at)
        try:
            signature = base64.b64decode(signature_b64)
            self._public_key.verify(signature, message)
        except Exception as exc:
            raise SignatureVerificationError("Signature verification failed") from exc


class _NonceStore:
    """
    Time-bounded in-memory nonce tracker.

    Uses an OrderedDict for O(1) insertion / lookup and efficient FIFO eviction.
    TTL default: 300 s (matches the Rust NonceStore).
    """

    def __init__(self, ttl: float = 300.0, max_size: int = 50_000) -> None:
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._ttl = ttl
        self._max = max_size

    def check_and_insert(self, nonce: str, signed_at: Optional[str] = None) -> bool:
        """Returns True and records the nonce if fresh; False on replay or stale timestamp."""
        now = time.monotonic()
        self._evict(now)
        if nonce in self._seen:
            return False
        if signed_at is not None and not self._valid_window(signed_at):
            return False
        self._seen[nonce] = now
        return True

    def _valid_window(self, signed_at_iso: str) -> bool:
        """Rejects timestamps more than TTL seconds away from now (in either direction)."""
        try:
            ts = datetime.fromisoformat(signed_at_iso.replace("Z", "+00:00"))
            age = abs((datetime.now(timezone.utc) - ts).total_seconds())
            return age <= self._ttl
        except (ValueError, TypeError):
            return False

    def _evict(self, now: float) -> None:
        cutoff = now - self._ttl
        while self._seen:
            _, ts = next(iter(self._seen.items()))
            if ts < cutoff or len(self._seen) > self._max:
                self._seen.popitem(last=False)
            else:
                break


def sign_request(agent_id: str, api_key: str) -> tuple[str, str, str]:
    """
    Creates a signed outbound request envelope.

    Returns (nonce, timestamp, hex_signature).
    Canonical form: ``{agent_id}\\0{nonce}\\0{timestamp}`` — HMAC-SHA256 with api_key.
    """
    nonce = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    canon = f"{agent_id}\0{nonce}\0{timestamp}".encode()
    sig = _hmac.new(api_key.encode(), canon, hashlib.sha256).hexdigest()
    return nonce, timestamp, sig
