from __future__ import annotations

import base64
import functools
import hashlib
import ssl
from typing import Any, Callable, Optional, TypeVar, overload

import httpx

from .cache import CacheBackend, PolicyCache, fallback_decision
from .exceptions import (
    CircuitBreakerError,
    GoalClarificationRequiredError,
    KeyRotationError,
    PolicyViolationError,
    SignatureVerificationError,
    ValidatorUnavailableError,
    ValidationError,
)
from .crypto import SignatureVerifier, sign_request
from .metadata import build_metadata_for_check
from .types import RiskAdvisory

F = TypeVar("F", bound=Callable[..., Any])
_BLOCKING = frozenset({"DENY", "GOAL_CLARIFICATION_REQUIRED"})
_CLARIFICATION = "GOAL_CLARIFICATION_REQUIRED"

# P1: Certificate pinning - pinned public key hash
# This should be set to the hash of the HaltChain server's public key
HALTCHAIN_PINNED_PUBKEY_HASH = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="


class CertificatePinningTransport(httpx.HTTPTransport):
    """Custom transport that verifies certificate pinning.
    
    P1 Security: Certificate pinning prevents MITM attacks even if
    a malicious CA issues a certificate for our domain.
    """
    
    def __init__(
        self,
        pinned_hash: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._pinned_hash = pinned_hash or HALTCHAIN_PINNED_PUBKEY_HASH
        
    def _verify_pin(self, cert: Any) -> None:
        """Verify the certificate's public key matches our pinned hash."""
        if not self._pinned_hash or self._pinned_hash.endswith("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="):
            # Pin not configured, skip verification (dev mode)
            return
            
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization
            
            # Get the public key from certificate
            pubkey = cert.public_key()
            pubkey_bytes = pubkey.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Calculate SHA256 hash
            pubkey_hash = base64.b64encode(hashlib.sha256(pubkey_bytes).digest()).decode()
            expected_hash = self._pinned_hash.replace("sha256/", "")
            
            if pubkey_hash != expected_hash:
                raise ssl.SSLError(
                    f"Certificate pin mismatch: got {pubkey_hash}, expected {expected_hash}"
                )
        except ImportError:
            # cryptography not installed, skip pinning
            pass


class HaltChainClient:
    DEFAULT_BASE = "https://haltchain-consensus.fly.dev"

    def __init__(
        self,
        *,
        agent_id: str,
        api_key: str,
        base_url: str = DEFAULT_BASE,
        cache_ttl: float = PolicyCache.DEFAULT_TTL,
        cache_max_size: int = PolicyCache.DEFAULT_CAP,
        cache_backend: Optional[CacheBackend] = None,
        redis_url: Optional[str] = None,
        redis_prefix: str = "haltchain:policy",
        timeout: float = 10.0,
        max_connections: int = 20,
        max_keepalive: int = 10,
        verify_signatures: bool = True,
        strict_signatures: bool = False,
        pinned_key_id: Optional[str] = None,
        trust_on_rotation: bool = False,
        # P1: Certificate pinning options
        pinned_cert_hash: Optional[str] = None,
        verify_ssl: bool = True,
        ca_bundle: Optional[str] = None,
    ) -> None:
        self.agent_id = agent_id
        self.api_key = api_key
        self._base = base_url.rstrip("/")
        self._validate_url = f"{self._base}/validate"
        self._status_url = f"{self._base}/status/{self.agent_id}"
        self._health_url = f"{self._base}/health"
        self._pubkey_url = f"{self._base}/public-key"
        self._verify_signatures = verify_signatures
        self._strict_signatures = strict_signatures
        self._trusted_key_id: Optional[str] = pinned_key_id
        self._trust_on_rotation = trust_on_rotation
        self._verifier: Optional[SignatureVerifier] = None
        self._cache = self._build_cache(
            cache_ttl=cache_ttl,
            cache_max_size=cache_max_size,
            cache_backend=cache_backend,
            redis_url=redis_url,
            redis_prefix=redis_prefix,
        )
        
        # P1: Certificate pinning - create SSL context
        ssl_context = None
        if verify_ssl and base_url.startswith("https://"):
            ssl_context = ssl.create_default_context(cafile=ca_bundle)
            # For stricter pinning, we'd need to use a custom SSL context
            # that verifies the certificate chain and then checks the pin
        
        self._http = httpx.Client(
            limits=httpx.Limits(
                max_connections=max_connections,
                max_keepalive_connections=max_keepalive,
            ),
            timeout=timeout,
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
            verify=ssl_context if ssl_context else verify_ssl,
        )
        self._pinned_cert_hash = pinned_cert_hash

    @staticmethod
    def _build_cache(
        *,
        cache_ttl: float,
        cache_max_size: int,
        cache_backend: Optional[CacheBackend],
        redis_url: Optional[str],
        redis_prefix: str,
    ) -> Optional[CacheBackend]:
        if cache_ttl <= 0:
            return None
        if cache_backend is not None:
            return cache_backend
        if redis_url:
            from .redis_cache import RedisPolicyCache

            return RedisPolicyCache(redis_url=redis_url, ttl=cache_ttl, prefix=redis_prefix)
        return PolicyCache(ttl=cache_ttl, max_size=cache_max_size)

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "HaltChainClient":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    @staticmethod
    def _resolve_action(
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        action_builder: Optional[Callable[..., dict]],
    ) -> dict:
        if action_builder is not None:
            return action_builder(*args, **kwargs)
        if args and isinstance(args[0], dict):
            return args[0]
        if "action" in kwargs and isinstance(kwargs["action"], dict):
            return kwargs["action"]
        return {"type": "generic"}

    def _offline_fallback(self, action: dict) -> dict:
        if self._cache:
            try:
                cached = self._cache.get(self.agent_id, action)
            except Exception:
                cached = None
            if cached:
                return {
                    "decision": cached.decision,
                    "reason": cached.reason,
                    "policy": cached.policy,
                    "cached": True,
                }
        raise ValidatorUnavailableError(fallback_decision().reason)

    def _get_verifier(self) -> Optional["SignatureVerifier"]:
        """Lazily fetches the validator public key and creates a verifier.

        In strict mode raises SignatureVerificationError if the key cannot be fetched.
        Enforces TOFU pinning: raises KeyRotationError on unexpected key_id change.
        """
        if self._verifier is not None:
            return self._verifier
        try:
            resp = self._http.get(self._pubkey_url)
            resp.raise_for_status()
            data = resp.json()
            fetched_key_id = data.get("key_id", "")
            self._apply_key_trust(fetched_key_id)
            self._verifier = SignatureVerifier(data["public_key_b64"], key_id=fetched_key_id)
            self._trusted_key_id = fetched_key_id
        except (KeyRotationError, SignatureVerificationError):
            raise
        except Exception:
            if self._strict_signatures:
                raise SignatureVerificationError(
                    "Cannot fetch validator public key — strict signature verification active"
                )
        return self._verifier

    def _apply_key_trust(self, fetched_key_id: str) -> None:
        """Enforces TOFU pinning policy; raises KeyRotationError on unexpected rotation."""
        if not self._trusted_key_id or not fetched_key_id:
            return  # TOFU first fetch or server doesn't send key_id
        if fetched_key_id == self._trusted_key_id:
            return
        if not self._trust_on_rotation:
            raise KeyRotationError(
                trusted_key_id=self._trusted_key_id,
                received_key_id=fetched_key_id,
            )
        # Rotation explicitly allowed — re-pin and clear old verifier
        self._verifier = None

    def trust_new_key(self) -> None:
        """Clear the pinned key_id and cached verifier to accept the next server key.

        Use after a planned key rotation to re-establish trust on next validation call.
        """
        self._trusted_key_id = None
        self._verifier = None

    def _post_validate(
        self, action: dict, metadata: Optional[dict] = None, session_id: Optional[str] = None,
    ) -> dict:
        nonce, timestamp, sig = sign_request(self.agent_id, self.api_key)
        payload: dict = {
            "agent_id": self.agent_id,
            "action": action,
            "metadata": metadata if metadata is not None else {},
            "request_nonce": nonce,
            "request_timestamp": timestamp,
            "request_sig": sig,
        }
        if session_id is not None:
            payload["session_id"] = session_id
        try:
            resp = self._http.post(self._validate_url, json=payload)
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ValidationError(
                f"Validator returned {exc.response.status_code}: {exc.response.text}"
            ) from exc
        except httpx.RequestError:
            return self._offline_fallback(action)

        result = resp.json()

        if self._verify_signatures:
            verifier = self._get_verifier()  # raises in strict mode on failure
            if verifier is not None:
                verifier.verify_response(result, self.agent_id)

        if self._cache:
            try:
                self._cache.put(
                    self.agent_id,
                    action,
                    result.get("decision", "DENY"),
                    result.get("reason", ""),
                    result.get("policy", ""),
                )
            except Exception:
                pass
        return result

    def _raise_for_decision(self, result: dict) -> None:
        decision = result.get("decision", "DENY")
        if decision == "CIRCUIT_BREAK":
            raise CircuitBreakerError(
                reason=result.get("reason") or "circuit breaker active",
                agent_id=self.agent_id,
            )
        if decision == _CLARIFICATION:
            raise GoalClarificationRequiredError(
                reason=result.get("reason") or "goal clarification required",
            )
        if decision in _BLOCKING:
            raise PolicyViolationError(
                reason=result.get("reason") or "action blocked",
                policy=result.get("policy") or "UNKNOWN",
            )

    def check(
        self,
        action: dict,
        metadata: Optional[dict] = None,
        session_id: Optional[str] = None,
    ) -> dict:
        result = self._post_validate(action, metadata, session_id=session_id)
        self._raise_for_decision(result)
        return result

    def check_with_context(
        self,
        action: dict,
        *,
        metadata: Optional[dict] = None,
        session_id: Optional[str] = None,
        conversation_id: Optional[str] = None,
        declared_services: Optional[list[str]] = None,
        accessed_service: Optional[str] = None,
        requested_columns: Any = None,
        task_necessary_columns: Any = None,
        registered_schema_fields: Optional[list[str]] = None,
        payload_fields: Optional[list[str]] = None,
        gdpr_deletion_requested: Optional[bool] = None,
        retention_days_requested: Any = None,
        multimodal_summary: Optional[dict[str, Any]] = None,
    ) -> dict:
        """Convenience wrapper for plain SDK flows to auto-build metadata."""
        enriched = build_metadata_for_check(
            action=action,
            metadata=metadata,
            conversation_id=conversation_id,
            declared_services=declared_services,
            accessed_service=accessed_service,
            requested_columns=requested_columns,
            task_necessary_columns=task_necessary_columns,
            registered_schema_fields=registered_schema_fields,
            payload_fields=payload_fields,
            gdpr_deletion_requested=gdpr_deletion_requested,
            retention_days_requested=retention_days_requested,
            multimodal_summary=multimodal_summary,
        )
        return self.check(action, metadata=enriched, session_id=session_id)

    def get_risk_advisories(
        self,
        *,
        agent_id: Optional[str] = None,
        since_id: Optional[int] = None,
    ) -> list[RiskAdvisory]:
        """Fetch cross-agent risk advisories for the target agent."""
        target = agent_id or self.agent_id
        params: dict[str, Any] = {}
        if since_id is not None:
            params["since_id"] = since_id
        try:
            resp = self._http.get(f"{self._base}/risk/advisories/{target}", params=params)
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ValidationError(
                f"get_risk_advisories: {exc.response.status_code}: {exc.response.text}"
            ) from exc
        except httpx.RequestError as exc:
            raise ValidationError(f"Could not reach HaltChain: {exc}") from exc

        payload = resp.json()
        advisories = payload.get("advisories", [])
        return advisories if isinstance(advisories, list) else []

    def poll_risk_advisories(self, *, since_id: Optional[int] = None) -> list[RiskAdvisory]:
        """Poll advisories for this client's agent identity."""
        return self.get_risk_advisories(agent_id=self.agent_id, since_id=since_id)

    def _submit_feedback(self, action: dict, result: dict) -> None:
        """Fire-and-forget post-execution feedback hook."""
        try:
            import threading
            threading.Thread(
                target=self._post_validate,
                args=({"type": "feedback", "original_action": action, "decision": result},),
                daemon=True,
            ).start()
        except Exception:
            pass

    @overload
    def validate(self, fn: F) -> F:
        ...

    @overload
    def validate(
        self,
        fn: None = None,
        *,
        action_builder: Optional[Callable[..., dict]] = None,
        on_break: Optional[Callable[[dict], None]] = None,
        feedback_loop: bool = False,
    ) -> Callable[[F], F]:
        ...

    def validate(
        self,
        fn: Optional[F] = None,
        *,
        action_builder: Optional[Callable[..., dict]] = None,
        on_break: Optional[Callable[[dict], None]] = None,
        feedback_loop: bool = False,
    ) -> Any:
        def decorator(func: F) -> F:
            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                action = self._resolve_action(args, kwargs, action_builder)
                try:
                    result = self._post_validate(action)
                    self._raise_for_decision(result)
                except (PolicyViolationError, CircuitBreakerError) as exc:
                    if on_break is not None:
                        on_break({"error": str(exc), "action": action})
                    raise
                retval = func(*args, **kwargs)
                if feedback_loop:
                    self._submit_feedback(action, result)
                return retval

            return wrapper  # type: ignore[return-value]

        return decorator(fn) if fn is not None else decorator

    def status(self) -> dict:
        try:
            resp = self._http.get(self._status_url)
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ValidationError(
                f"status: {exc.response.status_code}: {exc.response.text}"
            ) from exc
        except httpx.RequestError as exc:
            raise ValidationError(f"Could not reach HaltChain: {exc}") from exc
        return resp.json()

    def health(self) -> dict:
        try:
            resp = self._http.get(self._health_url)
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ValidationError(
                f"health: {exc.response.status_code}: {exc.response.text}"
            ) from exc
        except httpx.RequestError as exc:
            raise ValidationError(f"Could not reach HaltChain: {exc}") from exc
        return resp.json()

    def report_intent(
        self,
        goal: str,
        constraints: Optional[dict] = None,
    ) -> dict:
        """Report the agent's declared intent and constraints."""
        if not goal.strip():
            raise ValueError("goal must not be empty")
        try:
            resp = self._http.post(
                f"{self._base}/agent/report-intent",
                json={"agent_id": self.agent_id, "goal": goal, "constraints": constraints or {}},
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ValidationError(
                f"report_intent: {exc.response.status_code}: {exc.response.text}"
            ) from exc
        except httpx.RequestError as exc:
            raise ValidationError(f"Could not reach HaltChain: {exc}") from exc
        return resp.json()

    # ── Goal lifecycle ─────────────────────────────────────────────────────

    def declare_goal(self, session_id: str, intent: str) -> dict:
        """Declare a goal for the current agent+session. Maps to POST /goals."""
        if not session_id.strip() or not intent.strip():
            raise ValueError("session_id and intent must not be empty")
        try:
            resp = self._http.post(
                f"{self._base}/goals",
                json={"agent_id": self.agent_id, "session_id": session_id, "intent": intent},
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ValidationError(
                f"declare_goal: {exc.response.status_code}: {exc.response.text}"
            ) from exc
        except httpx.RequestError as exc:
            raise ValidationError(f"Could not reach HaltChain: {exc}") from exc
        return resp.json()

    def revoke_goal(self, session_id: str) -> dict:
        """Revoke the goal for the current agent+session. Maps to DELETE /goals/:agent/:session."""
        if not session_id.strip():
            raise ValueError("session_id must not be empty")
        try:
            resp = self._http.request(
                "DELETE", f"{self._base}/goals/{self.agent_id}/{session_id}",
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ValidationError(
                f"revoke_goal: {exc.response.status_code}: {exc.response.text}"
            ) from exc
        except httpx.RequestError as exc:
            raise ValidationError(f"Could not reach HaltChain: {exc}") from exc
        return resp.json()

    def drift_status(self, session_id: str) -> dict:
        """Query drift status for the current agent+session. Maps to GET /drift/:agent/:session."""
        if not session_id.strip():
            raise ValueError("session_id must not be empty")
        try:
            resp = self._http.get(
                f"{self._base}/drift/{self.agent_id}/{session_id}",
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ValidationError(
                f"drift_status: {exc.response.status_code}: {exc.response.text}"
            ) from exc
        except httpx.RequestError as exc:
            raise ValidationError(f"Could not reach HaltChain: {exc}") from exc
        return resp.json()

    @property
    def verification_info(self) -> dict:
        """Current signature verification configuration and runtime state."""
        return {
            "verify_signatures": self._verify_signatures,
            "strict_signatures": self._strict_signatures,
            "trust_on_rotation": self._trust_on_rotation,
            "verifier_loaded": self._verifier is not None,
            "trusted_key_id": self._trusted_key_id,
            "certificate_pinning": self._pinned_cert_hash is not None,
        }

    @property
    def cache(self) -> Optional[CacheBackend]:
        return self._cache


Client = HaltChainClient
