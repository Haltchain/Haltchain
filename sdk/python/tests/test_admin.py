# Run with: pytest sdk/python/tests/test_admin.py -v
from __future__ import annotations

import json as _json

import pytest
import respx
import httpx

from haltchain.admin_client import AdminClient
from haltchain.types import FeedbackOutcome
from haltchain.exceptions import ValidationError

BASE = "https://haltchain-consensus.fly.dev"

PENDING_RESP = {
    "pending": [
        {
            "transaction_id": "tx-001",
            "agent_id": "bot",
            "decision": "DENY",
            "policy_code": "MAX_TRANSFER",
            "reason": "amount exceeds limit",
            "created_at": "2026-03-12T00:00:00Z",
            "outcome": None,
        }
    ]
}

OUTCOME_RECORDED = {"status": "recorded"}
THRESHOLDS_RESP = {"thresholds": {"max_transfer_usd": 10000.0}}
THRESHOLD_UPDATED = {"status": "updated", "key": "max_transfer_usd", "value": 5000.0}
VARIANTS_RESP = {"variants": [{"id": "v1", "name": "strict", "policy": "STRICT"}]}
VARIANT_CREATED = {"status": "created", "id": "v2"}


# ── FeedbackOutcome typing 

def test_feedback_outcome_valid_values():
    assert FeedbackOutcome.TRUE_POSITIVE.value == "TRUE_POSITIVE"
    assert FeedbackOutcome.FALSE_POSITIVE.value == "FALSE_POSITIVE"
    assert FeedbackOutcome.EXPECTED_EDGE_CASE.value == "EXPECTED_EDGE_CASE"


def test_feedback_outcome_validate_parses_string():
    assert FeedbackOutcome.validate("TRUE_POSITIVE") is FeedbackOutcome.TRUE_POSITIVE
    assert FeedbackOutcome.validate("FALSE_POSITIVE") is FeedbackOutcome.FALSE_POSITIVE
    assert FeedbackOutcome.validate("EXPECTED_EDGE_CASE") is FeedbackOutcome.EXPECTED_EDGE_CASE


def test_feedback_outcome_validate_rejects_invalid():
    with pytest.raises(ValueError, match="Invalid verdict"):
        FeedbackOutcome.validate("WRONG")


def test_feedback_outcome_validate_rejects_empty():
    with pytest.raises(ValueError, match="Invalid verdict"):
        FeedbackOutcome.validate("")


def test_feedback_outcome_is_str_subclass():
    # Allows using enum values directly in JSON serialisation
    assert isinstance(FeedbackOutcome.TRUE_POSITIVE, str)
    assert FeedbackOutcome.TRUE_POSITIVE == "TRUE_POSITIVE"


# ── Review queue ──────────────────────────────────────────────────────────────

@respx.mock
def test_review_queue_returns_list():
    respx.get(f"{BASE}/admin/review-queue").mock(
        return_value=httpx.Response(200, json=PENDING_RESP)
    )
    with AdminClient(api_key="k", base_url=BASE) as admin:
        entries = admin.review_queue()
    assert len(entries) == 1
    assert entries[0]["transaction_id"] == "tx-001"
    assert entries[0]["decision"] == "DENY"


@respx.mock
def test_review_queue_returns_empty_list_when_none_pending():
    respx.get(f"{BASE}/admin/review-queue").mock(
        return_value=httpx.Response(200, json={"pending": []})
    )
    with AdminClient(api_key="k", base_url=BASE) as admin:
        assert admin.review_queue() == []


@respx.mock
def test_review_queue_server_error_raises():
    respx.get(f"{BASE}/admin/review-queue").mock(
        return_value=httpx.Response(500, json={"error": "internal"})
    )
    with AdminClient(api_key="k", base_url=BASE) as admin:
        with pytest.raises(ValidationError, match="500"):
            admin.review_queue()


# ── Submit outcome ────────────────────────────────────────────────────────────

@respx.mock
def test_submit_outcome_true_positive():
    respx.post(f"{BASE}/admin/review-queue/tx-001/outcome").mock(
        return_value=httpx.Response(200, json=OUTCOME_RECORDED)
    )
    with AdminClient(api_key="k", base_url=BASE) as admin:
        result = admin.submit_outcome(
            "tx-001",
            {"verdict": "TRUE_POSITIVE", "reviewer_id": "alice", "notes": "deliberate block"},
        )
    assert result["status"] == "recorded"


@respx.mock
def test_submit_outcome_false_positive():
    respx.post(f"{BASE}/admin/review-queue/tx-001/outcome").mock(
        return_value=httpx.Response(200, json=OUTCOME_RECORDED)
    )
    with AdminClient(api_key="k", base_url=BASE) as admin:
        result = admin.submit_outcome("tx-001", {"verdict": "FALSE_POSITIVE"})
    assert result["status"] == "recorded"


@respx.mock
def test_submit_outcome_expected_edge_case():
    respx.post(f"{BASE}/admin/review-queue/tx-001/outcome").mock(
        return_value=httpx.Response(200, json=OUTCOME_RECORDED)
    )
    with AdminClient(api_key="k", base_url=BASE) as admin:
        result = admin.submit_outcome(
            "tx-001", {"verdict": "EXPECTED_EDGE_CASE", "impact_usd": 0.0}
        )
    assert result["status"] == "recorded"


def test_submit_outcome_invalid_verdict_raises():
    with AdminClient(api_key="k", base_url=BASE) as admin:
        with pytest.raises(ValueError, match="Invalid verdict"):
            admin.submit_outcome("tx-001", {"verdict": "MAYBE"})


def test_submit_outcome_empty_tx_id_raises():
    with AdminClient(api_key="k", base_url=BASE) as admin:
        with pytest.raises(ValueError, match="tx_id must not be empty"):
            admin.submit_outcome("  ", {"verdict": "TRUE_POSITIVE"})


@respx.mock
def test_submit_outcome_not_found_raises():
    respx.post(f"{BASE}/admin/review-queue/tx-missing/outcome").mock(
        return_value=httpx.Response(404, json={"error": "transaction not found"})
    )
    with AdminClient(api_key="k", base_url=BASE) as admin:
        with pytest.raises(ValidationError, match="404"):
            admin.submit_outcome("tx-missing", {"verdict": "TRUE_POSITIVE"})


# ── Idempotency: submit_outcome ───────────────────────────────────────────────

@respx.mock
def test_submit_outcome_sends_idempotency_header():
    captured_headers = {}

    def _capture(request: httpx.Request):
        captured_headers.update(dict(request.headers))
        return httpx.Response(200, json=OUTCOME_RECORDED)

    respx.post(f"{BASE}/admin/review-queue/tx-001/outcome").mock(side_effect=_capture)
    with AdminClient(api_key="k", base_url=BASE) as admin:
        admin.submit_outcome(
            "tx-001",
            {"verdict": "TRUE_POSITIVE"},
            idempotency_key="idem-key-abc",
        )
    assert captured_headers.get("x-idempotency-key") == "idem-key-abc"


@respx.mock
def test_submit_outcome_no_idempotency_key_omits_header():
    captured_headers = {}

    def _capture(request: httpx.Request):
        captured_headers.update(dict(request.headers))
        return httpx.Response(200, json=OUTCOME_RECORDED)

    respx.post(f"{BASE}/admin/review-queue/tx-001/outcome").mock(side_effect=_capture)
    with AdminClient(api_key="k", base_url=BASE) as admin:
        admin.submit_outcome("tx-001", {"verdict": "TRUE_POSITIVE"})
    assert "x-idempotency-key" not in captured_headers


@respx.mock
def test_submit_outcome_repeat_same_idempotency_key():
    """Server returns same result for repeated submissions with same idempotency key.

    The SDK sends the header on every call; the server is responsible for
    de-duplication.  This test documents the client's obligation: always
    forward the key and accept the server's response without extra logic.
    """
    route = respx.post(f"{BASE}/admin/review-queue/tx-001/outcome").mock(
        return_value=httpx.Response(200, json=OUTCOME_RECORDED)
    )
    with AdminClient(api_key="k", base_url=BASE) as admin:
        r1 = admin.submit_outcome("tx-001", {"verdict": "TRUE_POSITIVE"}, idempotency_key="k1")
        r2 = admin.submit_outcome("tx-001", {"verdict": "TRUE_POSITIVE"}, idempotency_key="k1")
    assert r1 == r2 == OUTCOME_RECORDED
    assert route.call_count == 2  # client always sends; server de-dupes


# ── Thresholds ────────────────────────────────────────────────────────────────

@respx.mock
def test_get_thresholds():
    respx.get(f"{BASE}/admin/thresholds").mock(
        return_value=httpx.Response(200, json=THRESHOLDS_RESP)
    )
    with AdminClient(api_key="k", base_url=BASE) as admin:
        t = admin.get_thresholds()
    assert t["max_transfer_usd"] == 10000.0


@respx.mock
def test_get_thresholds_server_error_raises():
    respx.get(f"{BASE}/admin/thresholds").mock(
        return_value=httpx.Response(503, json={"error": "unavailable"})
    )
    with AdminClient(api_key="k", base_url=BASE) as admin:
        with pytest.raises(ValidationError, match="503"):
            admin.get_thresholds()


@respx.mock
def test_patch_threshold():
    respx.patch(f"{BASE}/admin/thresholds").mock(
        return_value=httpx.Response(200, json=THRESHOLD_UPDATED)
    )
    with AdminClient(api_key="k", base_url=BASE) as admin:
        result = admin.patch_threshold("max_transfer_usd", 5000.0)
    assert result["status"] == "updated"
    assert result["value"] == 5000.0


def test_patch_threshold_empty_key_raises():
    with AdminClient(api_key="k", base_url=BASE) as admin:
        with pytest.raises(ValueError, match="key must not be empty"):
            admin.patch_threshold("  ", 100.0)


@respx.mock
def test_patch_threshold_sends_idempotency_header():
    captured_headers = {}

    def _capture(request: httpx.Request):
        captured_headers.update(dict(request.headers))
        return httpx.Response(200, json=THRESHOLD_UPDATED)

    respx.patch(f"{BASE}/admin/thresholds").mock(side_effect=_capture)
    with AdminClient(api_key="k", base_url=BASE) as admin:
        admin.patch_threshold("max_transfer_usd", 5000.0, idempotency_key="thresh-key-1")
    assert captured_headers.get("x-idempotency-key") == "thresh-key-1"


@respx.mock
def test_patch_threshold_no_idempotency_key_omits_header():
    captured_headers = {}

    def _capture(request: httpx.Request):
        captured_headers.update(dict(request.headers))
        return httpx.Response(200, json=THRESHOLD_UPDATED)

    respx.patch(f"{BASE}/admin/thresholds").mock(side_effect=_capture)
    with AdminClient(api_key="k", base_url=BASE) as admin:
        admin.patch_threshold("max_transfer_usd", 5000.0)
    assert "x-idempotency-key" not in captured_headers


@respx.mock
def test_patch_threshold_repeat_same_idempotency_key():
    """Documents client idempotency contract for threshold updates."""
    route = respx.patch(f"{BASE}/admin/thresholds").mock(
        return_value=httpx.Response(200, json=THRESHOLD_UPDATED)
    )
    with AdminClient(api_key="k", base_url=BASE) as admin:
        r1 = admin.patch_threshold("max_transfer_usd", 5000.0, idempotency_key="t-key")
        r2 = admin.patch_threshold("max_transfer_usd", 5000.0, idempotency_key="t-key")
    assert r1 == r2
    assert route.call_count == 2


# ── A/B variants ──────────────────────────────────────────────────────────────

@respx.mock
def test_list_variants():
    respx.get(f"{BASE}/admin/ab-variants").mock(
        return_value=httpx.Response(200, json=VARIANTS_RESP)
    )
    with AdminClient(api_key="k", base_url=BASE) as admin:
        variants = admin.list_variants()
    assert len(variants) == 1
    assert variants[0]["name"] == "strict"


@respx.mock
def test_list_variants_returns_empty():
    respx.get(f"{BASE}/admin/ab-variants").mock(
        return_value=httpx.Response(200, json={"variants": []})
    )
    with AdminClient(api_key="k", base_url=BASE) as admin:
        assert admin.list_variants() == []


@respx.mock
def test_create_variant():
    respx.post(f"{BASE}/admin/ab-variants").mock(
        return_value=httpx.Response(200, json=VARIANT_CREATED)
    )
    with AdminClient(api_key="k", base_url=BASE) as admin:
        result = admin.create_variant({"name": "relaxed", "policy": "RELAXED", "weight": 0.1})
    assert result["status"] == "created"
    assert "id" in result


def test_create_variant_empty_name_raises():
    with AdminClient(api_key="k", base_url=BASE) as admin:
        with pytest.raises(ValueError, match="variant name must not be empty"):
            admin.create_variant({"name": "  "})


@respx.mock
def test_create_variant_server_error_raises():
    respx.post(f"{BASE}/admin/ab-variants").mock(
        return_value=httpx.Response(400, json={"error": "name required"})
    )
    with AdminClient(api_key="k", base_url=BASE) as admin:
        with pytest.raises(ValidationError, match="400"):
            admin.create_variant({"name": "ok"})


# ── Round-trip body serialisation ─────────────────────────────────────────────

@respx.mock
def test_submit_outcome_body_serialised_correctly():
    captured_body = {}

    def _capture(request: httpx.Request):
        captured_body.update(_json.loads(request.read().decode()))
        return httpx.Response(200, json=OUTCOME_RECORDED)

    respx.post(f"{BASE}/admin/review-queue/tx-999/outcome").mock(side_effect=_capture)
    with AdminClient(api_key="k", base_url=BASE) as admin:
        admin.submit_outcome(
            "tx-999",
            {
                "verdict": "FALSE_POSITIVE",
                "impact_usd": 250.0,
                "reviewer_id": "bob",
                "notes": "benign edge-case",
            },
        )
    assert captured_body["verdict"] == "FALSE_POSITIVE"
    assert captured_body["impact_usd"] == 250.0
    assert captured_body["reviewer_id"] == "bob"
    assert captured_body["notes"] == "benign edge-case"


@respx.mock
def test_patch_threshold_body_serialised_correctly():
    captured_body = {}

    def _capture(request: httpx.Request):
        captured_body.update(_json.loads(request.read().decode()))
        return httpx.Response(200, json=THRESHOLD_UPDATED)

    respx.patch(f"{BASE}/admin/thresholds").mock(side_effect=_capture)
    with AdminClient(api_key="k", base_url=BASE) as admin:
        admin.patch_threshold("drift_threshold", 0.35)
    assert captured_body["key"] == "drift_threshold"
    assert captured_body["value"] == 0.35
