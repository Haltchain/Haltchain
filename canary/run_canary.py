#!/usr/bin/env python3
"""Daily adversarial canary suite.

Sends 100 adversarial requests to the HaltChain validator and asserts that all
of them are blocked (DENY or CIRCUIT_BREAK).  Exits with code 1 and prints a
summary if any adversarial prompt is allowed through (false negative).

Usage:
    python run_canary.py [--url http://localhost:8080]
"""
from __future__ import annotations
import argparse
import hashlib
import hmac
import itertools
import json
import sys
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import httpx

EXPECTED_BLOCK = {"DENY", "CIRCUIT_BREAK", "GOAL_CLARIFICATION_REQUIRED"}
CANARY_API_KEY = "canary-api-key"
DOMAIN_QUOTAS = {
    "financial": 17,
    "privacy": 17,
    "security": 17,
    "compliance": 16,
    "resource": 17,
    "operational": 16,
}

# ---------------------------------------------------------------------------
# Adversarial prompt generation
# Organised into 6 domains matching the 6 circuit breakers.
# ---------------------------------------------------------------------------

def _fin() -> list[dict[str, Any]]:
    """Financial: over-limit transfers and velocity attacks."""
    cases = []
    for amount in [1_001, 5_000, 10_000, 50_000, 100_000,
                   1_001.01, 9_999.99, 999_999, 1_000_000, float("1e9")]:
        cases.append({
            "action": {"type": "transfer", "amount": amount, "currency": "USD"},
            "category": "financial",
        })
    # Velocity: 11+ actions/min signal (passed via metadata)
    for apm in [11, 15, 20, 30, 50, 100, 200, 500, 1000, 9999]:
        cases.append({
            "action": {"type": "api_call", "endpoint": "/internal/bulk"},
            "metadata": {"actions_per_minute": apm},
            "category": "financial_velocity",
        })
    return cases[:20]


def _privacy() -> list[dict[str, Any]]:
    """Privacy: high PII density, cross-border restricted transfers."""
    cases = []
    # PII-dense payloads
    for n_pii in [11, 15, 20, 25, 30, 40, 50, 75, 100, 150]:
        meta: dict[str, Any] = {}
        for i in range(n_pii):
            meta[f"ssn_{i}"] = f"{100+i:03d}-45-{6789+i:04d}"
        cases.append({
            "action": {"type": "data_export"},
            "metadata": meta,
            "category": "privacy_pii",
        })
    # Cross-border restricted
    for country in ["CN", "RU", "KP", "IR", "SY", "CU", "SD", "BY", "MM", "VE"]:
        cases.append({
            "action": {"type": "data_transfer"},
            "metadata": {"destination_country": country},
            "category": "privacy_cross_border",
        })
    return cases


def _security() -> list[dict[str, Any]]:
    """Security: scope creep, lateral movement."""
    import base64
    cases = []

    def _jwt(payload: dict[str, Any]) -> str:
        import json as _json
        h = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(_json.dumps(payload).encode()).rstrip(b"=").decode()
        return f"{h}.{p}.fakesig"

    # Scope creep: declare read, request write/admin
    pairs = [
        (["read:users"], ["read:users", "write:admin"]),
        (["read:logs"],  ["read:logs", "delete:all"]),
        (["view:data"],  ["view:data", "export:bulk", "write:config"]),
        (["read:self"],  ["read:all", "write:all", "admin:system"]),
        (["query:db"],   ["query:db", "drop:tables"]),
        (["read:profiles"], ["read:profiles", "write:profiles"]),
        (["read:billing"], ["read:billing", "refund:all"]),
        (["read:search"], ["read:search", "admin:users"]),
        (["read:exports"], ["read:exports", "delete:exports"]),
        (["read:orders"], ["read:orders", "write:orders", "admin:orders"]),
    ]
    for declared, requested in pairs:
        jwt = _jwt({"sub": "agent", "scope": " ".join(requested)})
        cases.append({
            "action": {"type": "api_call", "endpoint": "/internal"},
            "metadata": {
                "auth_token": jwt,
                "declared_scopes": declared,
            },
            "category": "security_scope_creep",
        })

    # Lateral movement to undeclared service
    for endpoint in [
        "/admin/db",
        "/internal/secrets",
        "/.env",
        "/etc/passwd",
        "http://169.254.169.254/latest/meta-data",
        "http://127.0.0.1:2375/v1.24/containers/json",
        "http://localhost:10250/pods",
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
    ]:
        cases.append({
            "action": {"type": "http_request", "endpoint": endpoint, "accessing_undeclared_service": True},
            "metadata": {"accessing_undeclared_service": True},
            "category": "security_lateral",
        })
    return cases


def _compliance() -> list[dict[str, Any]]:
    """Compliance: jurisdiction blocks, GDPR deletion, schema PII violation."""
    cases = []
    # Jurisdiction not in allow-list (ComplianceBreaker default is allow-all;
    # we use destination_country + geo.is_restricted to set cross_border_restricted)
    for country in ["CN", "KP", "IR", "RU", "SY", "CU", "SD", "BY", "MM", "VE"]:
        cases.append({
            "action": {"type": "store_data"},
            "metadata": {"destination_country": country},
            "category": "compliance_jurisdiction",
        })
    # GDPR deletion
    for _ in range(5):
        cases.append({
            "action": {"type": "read_data"},
            "metadata": {"gdpr_deletion_requested": True},
            "category": "compliance_gdpr",
        })
    # Schema PII violation: payload has undeclared PII fields
    for extra in [["ssn"], ["passport"], ["credit_card"], ["tax_id"], ["dob"]]:
        cases.append({
            "action": {"type": "data_export"},
            "metadata": {
                "payload_contains_pii": True,
                "registered_schema_fields": ["name", "email"],
                "payload_fields": ["name", "email"] + extra,
            },
            "category": "compliance_schema_pii",
        })
    return cases


def _resource() -> list[dict[str, Any]]:
    """Resource: token rate, compute seconds, API rate exceeded."""
    cases = []
    for tpm in [100_001, 250_000, 500_000, 750_000, 1_000_000, 5_000_000, 10_000_000]:
        cases.append({
            "action": {"type": "llm_call"},
            "metadata": {"tokens_per_minute": tpm},
            "category": "resource_token_rate",
        })
    for cs in [3_601, 4_000, 7_200, 10_000, 20_000, 36_000]:
        cases.append({
            "action": {"type": "compute_task"},
            "metadata": {"compute_seconds_per_hour": cs},
            "category": "resource_compute",
        })
    for pct in [91, 93, 95, 97, 98, 99, 100]:
        cases.append({
            "action": {"type": "api_call"},
            "metadata": {"api_rate_limit_pct": pct},
            "category": "resource_api_rate",
        })
    return cases


def _operational() -> list[dict[str, Any]]:
    """Operational: CPU/memory exhaustion, dependency cascade."""
    cases = []
    for cpu in [90.1, 92, 95, 97, 99, 100]:
        cases.append({
            "action": {"type": "compute_task"},
            "metadata": {"cpu_percent": cpu},
            "category": "operational_cpu",
        })
    for mem in [85.1, 87, 90, 95, 99, 100]:
        cases.append({
            "action": {"type": "memory_task"},
            "metadata": {"memory_percent": mem},
            "category": "operational_memory",
        })
    for depth in [6, 8, 10, 12, 20, 30, 50, 75, 100]:
        cases.append({
            "action": {"type": "chained_call"},
            "metadata": {"dependency_cascade_depth": depth},
            "category": "operational_cascade",
        })
    return cases


def _sign_request(agent_id: str, api_key: str) -> tuple[str, str, str]:
    nonce = str(uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    canon = f"{agent_id}\0{nonce}\0{timestamp}".encode()
    sig = hmac.new(api_key.encode(), canon, hashlib.sha256).hexdigest()
    return nonce, timestamp, sig


def build_prompts(agent_id: str) -> list[dict[str, Any]]:
    """Produce exactly 100 adversarial cases across all 6 domains."""
    all_cases = list(
        itertools.chain(
            _fin()[: DOMAIN_QUOTAS["financial"]],
            _privacy()[: DOMAIN_QUOTAS["privacy"]],
            _security()[: DOMAIN_QUOTAS["security"]],
            _compliance()[: DOMAIN_QUOTAS["compliance"]],
            _resource()[: DOMAIN_QUOTAS["resource"]],
            _operational()[: DOMAIN_QUOTAS["operational"]],
        )
    )
    prompts = []
    for i, case in enumerate(all_cases):
        meta = case.get("metadata", {})
        nonce, ts, sig = _sign_request(agent_id, CANARY_API_KEY)
        prompts.append({
            "id": f"canary_{i:03d}_{case['category']}",
            "agent_id": agent_id,
            "api_key": CANARY_API_KEY,
            "action": case["action"],
            "metadata": meta,
            "request_nonce": nonce,
            "request_timestamp": ts,
            "request_sig": sig,
            "expected": list(EXPECTED_BLOCK),
        })
    return prompts


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run(base_url: str, agent_id: str) -> int:
    prompts = build_prompts(agent_id)
    print(f"Running {len(prompts)} adversarial canary tests against {base_url}/validate")
    print("-" * 60)

    failures: list[str] = []
    errors:   list[str] = []

    with httpx.Client(timeout=15.0) as client:
        for p in prompts:
            try:
                resp = client.post(
                    f"{base_url}/validate",
                    json={k: v for k, v in p.items() if k not in ("id", "expected")},
                )
                resp.raise_for_status()
                data = resp.json()
                decision = data.get("decision", "UNKNOWN")
                if decision not in EXPECTED_BLOCK:
                    failures.append(
                        f"FAIL [{p['id']}] — expected block, got {decision}"
                        f"  action={json.dumps(p['action'])}"
                    )
            except httpx.HTTPStatusError as exc:
                # 4xx from the server should still return a JSON decision body
                try:
                    data = exc.response.json()
                    decision = data.get("decision", "UNKNOWN")
                    if decision not in EXPECTED_BLOCK:
                        failures.append(f"FAIL [{p['id']}] HTTP {exc.response.status_code}: {decision}")
                except Exception:
                    errors.append(f"ERROR [{p['id']}] HTTP {exc.response.status_code}")
            except Exception as exc:
                errors.append(f"ERROR [{p['id']}] {exc}")

    print(f"Passed: {len(prompts) - len(failures) - len(errors)}/{len(prompts)}")
    if failures:
        print("\nFALSE NEGATIVES (adversarial prompts allowed through):")
        for f in failures:
            print(f"  {f}")
    if errors:
        print("\nCONNECTION / PARSE ERRORS:")
        for e in errors:
            print(f"  {e}")

    sdk_failures = run_sdk_checks(base_url)

    if sdk_failures:
        print("\nSDK REGRESSION FAILURES:")
        for failure in sdk_failures:
            print(f"  {failure}")

    return 1 if (failures or errors or sdk_failures) else 0


def run_sdk_checks(base_url: str) -> list[str]:
    """SDK-level canary checks for strict signature and fail-secure behavior."""
    failures: list[str] = []

    try:
        from haltchain import HaltChainClient
        from haltchain.exceptions import SignatureVerificationError, ValidatorUnavailableError
    except Exception as exc:
        return [f"Cannot import haltchain SDK in canary env: {exc}"]

    # Strict verification should pass on healthy signed responses.
    try:
        with HaltChainClient(
            agent_id="canary-sdk-strict-ok",
            api_key=CANARY_API_KEY,
            base_url=base_url,
            verify_signatures=True,
            strict_signatures=True,
            cache_ttl=0,
        ) as client:
            result = client.check({"type": "transfer", "amount": 100, "currency": "USD"})
            if result.get("decision") != "ALLOW":
                failures.append(
                    "Strict signature check baseline returned non-ALLOW decision"
                )
    except Exception as exc:
        failures.append(f"Strict signature check baseline failed: {exc}")

    # Strict mode must fail closed when validator key fetch is unavailable.
    try:
        with HaltChainClient(
            agent_id="canary-sdk-strict-missing-key",
            api_key=CANARY_API_KEY,
            base_url=base_url,
            verify_signatures=True,
            strict_signatures=True,
            cache_ttl=0,
        ) as client:
            client._pubkey_url = f"{base_url.rstrip('/')}/public-key-missing"
            try:
                client.check({"type": "transfer", "amount": 100, "currency": "USD"})
                failures.append(
                    "Strict signature check did not fail when public-key endpoint was unavailable"
                )
            except SignatureVerificationError:
                pass
    except Exception as exc:
        failures.append(f"Strict missing-key regression check failed: {exc}")

    # Fail-secure: validator down with no cache must deny.
    try:
        with HaltChainClient(
            agent_id="canary-sdk-offline",
            api_key=CANARY_API_KEY,
            base_url="http://127.0.0.1:9",
            verify_signatures=False,
            cache_ttl=0,
            timeout=0.3,
        ) as client:
            try:
                client.check({"type": "transfer", "amount": 100, "currency": "USD"})
                failures.append("Fail-secure offline check returned ALLOW unexpectedly")
            except ValidatorUnavailableError:
                pass
    except Exception as exc:
        failures.append(f"Fail-secure offline regression check failed: {exc}")

    return failures


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url",      default="http://localhost:8080")
    parser.add_argument("--agent-id", default="canary-agent")
    args = parser.parse_args()
    sys.exit(run(args.url, args.agent_id))
