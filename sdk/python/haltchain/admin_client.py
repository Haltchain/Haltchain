"""Admin SDK client — separate from the runtime agent client.

Wraps the /admin/* endpoints:
  GET  /admin/review-queue
  POST /admin/review-queue/:tx_id/outcome
  GET  /admin/thresholds
  PATCH /admin/thresholds
  GET  /admin/ab-variants
  POST /admin/ab-variants

Idempotency
-----------
``submit_outcome`` and ``patch_threshold`` accept an optional ``idempotency_key``
argument.  When provided it is sent as the ``X-Idempotency-Key`` request header
so that the server can de-duplicate repeat submissions.  When the server does not
support idempotency keys the header is silently ignored.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import httpx

from .exceptions import ValidationError
from .types import FeedbackOutcome, OutcomePayload, ReviewEntry, ThresholdPatchPayload, VariantConfig


class AdminClient:
    """Synchronous SDK wrapper for HaltChain admin operations.

    Kept intentionally separate from :class:`~haltchain.HaltChainClient` so
    that admin credentials are never bundled into runtime agent code.
    """

    DEFAULT_BASE = "https://haltchain-consensus.fly.dev"

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str = DEFAULT_BASE,
        timeout: float = 15.0,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._http = httpx.Client(
            timeout=timeout,
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
        )

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "AdminClient":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    #Review queue

    def review_queue(self) -> List[ReviewEntry]:
        """Return all pending review entries (outcome not yet submitted)."""
        try:
            resp = self._http.get(f"{self._base}/admin/review-queue")
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ValidationError(
                f"review_queue: {exc.response.status_code}: {exc.response.text}"
            ) from exc
        except httpx.RequestError as exc:
            raise ValidationError(f"Could not reach HaltChain: {exc}") from exc
        return resp.json().get("pending", [])

    def submit_outcome(
        self,
        tx_id: str,
        outcome: OutcomePayload,
        *,
        idempotency_key: Optional[str] = None,
    ) -> dict:
        """Submit a review outcome for a transaction.

        Args:
            tx_id: The transaction ID from the review queue.
            outcome: Typed payload; ``verdict`` must be a :class:`FeedbackOutcome` value.
            idempotency_key: Optional caller-supplied key sent as ``X-Idempotency-Key``.
                Repeat calls with the same key will not create duplicate side effects
                (when the server supports it).

        Raises:
            ValueError: If ``outcome["verdict"]`` is not a valid :class:`FeedbackOutcome`.
            ValidationError: On 4xx/5xx HTTP responses or network errors.
        """
        if not tx_id.strip():
            raise ValueError("tx_id must not be empty")
        FeedbackOutcome.validate(outcome.get("verdict", ""))

        headers: Dict[str, str] = {}
        if idempotency_key:
            headers["X-Idempotency-Key"] = idempotency_key

        try:
            resp = self._http.post(
                f"{self._base}/admin/review-queue/{tx_id}/outcome",
                json=dict(outcome),
                headers=headers,
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ValidationError(
                f"submit_outcome: {exc.response.status_code}: {exc.response.text}"
            ) from exc
        except httpx.RequestError as exc:
            raise ValidationError(f"Could not reach HaltChain: {exc}") from exc
        return resp.json()

    #Thresholds

    def get_thresholds(self) -> Dict[str, float]:
        """Return current threshold overrides as a ``{key: value}`` dict."""
        try:
            resp = self._http.get(f"{self._base}/admin/thresholds")
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ValidationError(
                f"get_thresholds: {exc.response.status_code}: {exc.response.text}"
            ) from exc
        except httpx.RequestError as exc:
            raise ValidationError(f"Could not reach HaltChain: {exc}") from exc
        return resp.json().get("thresholds", {})

    def patch_threshold(
        self,
        key: str,
        value: float,
        *,
        idempotency_key: Optional[str] = None,
    ) -> dict:
        """Update a single threshold.

        Args:
            key: Threshold name (e.g. ``"max_transfer_usd"``).
            value: New numeric value.
            idempotency_key: Optional key sent as ``X-Idempotency-Key``.

        Raises:
            ValueError: If ``key`` is empty.
            ValidationError: On HTTP or network errors.
        """
        if not key.strip():
            raise ValueError("key must not be empty")

        headers: Dict[str, str] = {}
        if idempotency_key:
            headers["X-Idempotency-Key"] = idempotency_key

        body: ThresholdPatchPayload = {"key": key, "value": value}
        try:
            resp = self._http.patch(
                f"{self._base}/admin/thresholds",
                json=dict(body),
                headers=headers,
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ValidationError(
                f"patch_threshold: {exc.response.status_code}: {exc.response.text}"
            ) from exc
        except httpx.RequestError as exc:
            raise ValidationError(f"Could not reach HaltChain: {exc}") from exc
        return resp.json()

    #A/B variants

    def list_variants(self) -> List[dict]:
        """Return all A/B policy variants."""
        try:
            resp = self._http.get(f"{self._base}/admin/ab-variants")
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ValidationError(
                f"list_variants: {exc.response.status_code}: {exc.response.text}"
            ) from exc
        except httpx.RequestError as exc:
            raise ValidationError(f"Could not reach HaltChain: {exc}") from exc
        return resp.json().get("variants", [])

    def create_variant(self, variant: VariantConfig) -> dict:
        """Create a new A/B policy variant.

        Args:
            variant: Must include at least ``name``.

        Raises:
            ValueError: If ``variant["name"]`` is missing or empty.
            ValidationError: On HTTP or network errors.
        """
        if not variant.get("name", "").strip():
            raise ValueError("variant name must not be empty")

        try:
            resp = self._http.post(
                f"{self._base}/admin/ab-variants",
                json=dict(variant),
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ValidationError(
                f"create_variant: {exc.response.status_code}: {exc.response.text}"
            ) from exc
        except httpx.RequestError as exc:
            raise ValidationError(f"Could not reach HaltChain: {exc}") from exc
        return resp.json()
