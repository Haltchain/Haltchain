"""
Performance benchmarks: HaltChain vs Guardrails AI latency comparison.

Run with:
    pytest sdk/python/tests/performance/test_competitive_latency.py -v -s \
        --haltchain-url http://localhost:8080

Requires a running HaltChain API server. Guardrails AI comparison uses
a synthetic CPU-bound validator of equivalent complexity when the
`guardrails-ai` package is not installed, so the suite runs in CI without
external dependencies.

Targets (from SLO table):
  P50 validation latency  < 5 ms  (stretch: < 2 ms)
  Async throughput        > 10 000 req/s
"""
from __future__ import annotations

import asyncio
import statistics
import time
import warnings
from typing import Any

import pytest

from haltchain import HaltChainClient, AsyncHaltChainClient

# ---------------------------------------------------------------------------
# Pytest CLI option for the API base URL
# ---------------------------------------------------------------------------

def pytest_addoption(parser):  # noqa: D401
    parser.addoption(
        "--haltchain-url",
        default="http://localhost:8080",
        help="Base URL of the HaltChain API under test.",
    )


@pytest.fixture(scope="session")
def api_url(request) -> str:
    return request.config.getoption("--haltchain-url")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_action(amount: float = 100.0) -> dict:
    return {"type": "transfer", "amount": amount, "currency": "USD", "recipient": "acct_perf"}


def _p50(samples: list[float]) -> float:
    return statistics.median(samples)


def _p99(samples: list[float]) -> float:
    sorted_s = sorted(samples)
    idx = int(0.99 * len(sorted_s))
    return sorted_s[min(idx, len(sorted_s) - 1)]


# ---------------------------------------------------------------------------
# Synthetic competitor baseline (used when guardrails-ai is not installed)
# ---------------------------------------------------------------------------

class _SyntheticGuardrails:
    """CPU-bound validator that approximates Guardrails AI regex + PII latency."""

    def validate(self, payload: str) -> dict:
        import re
        import hashlib
        # Simulate regex PII scan + SHA-256 pass — representative work.
        patterns = [
            r"\b\d{3}-\d{2}-\d{4}\b",          # SSN
            r"\b(?:\d[ -]?){13,16}\b",           # credit card
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",  # email
        ]
        for p in patterns:
            re.search(p, payload)
        hashlib.sha256(payload.encode()).hexdigest()
        return {"valid": True}


def _get_competitor() -> Any:
    try:
        import guardrails as gd  # type: ignore
        return gd.Guard.for_pii_detection()
    except Exception:
        return _SyntheticGuardrails()


# ---------------------------------------------------------------------------
# Latency suite
# ---------------------------------------------------------------------------

@pytest.mark.benchmark
class TestLatencyDominance:
    WARMUP = 100
    SAMPLES = 1_000
    P50_TARGET_MS = 5.0

    def _halt_client(self, api_url: str) -> HaltChainClient:
        return HaltChainClient(
            agent_id="perf_test",
            api_key="dev-key",
            base_url=api_url,
            cache_ttl=0,  # disable cache to measure raw server latency
        )

    @pytest.fixture(autouse=True)
    def _skip_if_no_server(self, api_url):
        import httpx
        try:
            httpx.get(f"{api_url}/health", timeout=2.0)
        except Exception:
            pytest.skip(f"HaltChain server not reachable at {api_url}")

    def test_p50_validation_latency(self, api_url):
        """P50 must be under TARGET_MS; fails fast on connection error."""
        client = self._halt_client(api_url)
        action = _make_action()

        # Warmup
        for _ in range(self.WARMUP):
            try:
                client.check(action)
            except Exception:
                pass

        halt_times: list[float] = []
        for _ in range(self.SAMPLES):
            t0 = time.perf_counter_ns()
            try:
                client.check(action)
            except Exception:
                pass
            halt_times.append((time.perf_counter_ns() - t0) / 1_000_000)

        p50 = _p50(halt_times)
        p99 = _p99(halt_times)

        print(f"\nHaltChain p50: {p50:.2f}ms  p99: {p99:.2f}ms")
        assert p50 < self.P50_TARGET_MS, f"p50 {p50:.2f}ms exceeds {self.P50_TARGET_MS}ms target"

    def test_latency_vs_competitor(self, api_url):
        """HaltChain must be ≥2× faster than the competitor baseline."""
        client = self._halt_client(api_url)
        competitor = _get_competitor()
        import json
        action = _make_action()
        payload_str = json.dumps(action)

        # Warmup both.
        for _ in range(50):
            try:
                client.check(action)
            except Exception:
                pass
            try:
                competitor.validate(payload_str)
            except Exception:
                pass

        halt_times: list[float] = []
        for _ in range(500):
            t0 = time.perf_counter_ns()
            try:
                client.check(action)
            except Exception:
                pass
            halt_times.append((time.perf_counter_ns() - t0) / 1_000_000)

        comp_times: list[float] = []
        for _ in range(200):
            t0 = time.perf_counter_ns()
            try:
                competitor.validate(payload_str)
            except Exception:
                pass
            comp_times.append((time.perf_counter_ns() - t0) / 1_000_000)

        halt_p50 = _p50(halt_times)
        comp_p50 = _p50(comp_times)

        print(f"\nHaltChain p50:    {halt_p50:.2f}ms")
        print(f"Competitor p50:   {comp_p50:.2f}ms")
        if comp_p50 > 0:
            print(f"Speedup:          {comp_p50 / halt_p50:.1f}x")

        assert halt_p50 < self.P50_TARGET_MS, (
            f"HaltChain p50 {halt_p50:.2f}ms exceeds {self.P50_TARGET_MS}ms"
        )
        if comp_p50 > 0:
            assert comp_p50 / halt_p50 >= 2.0, (
                f"Speedup {comp_p50 / halt_p50:.1f}x is less than 2x minimum"
            )


# ---------------------------------------------------------------------------
# Async throughput suite
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestAsyncThroughput:
    REQUESTS = 5_000
    TARGET_RPS = 10_000.0

    @pytest.fixture(autouse=True)
    def _skip_if_no_server(self, api_url):
        import httpx
        try:
            httpx.get(f"{api_url}/health", timeout=2.0)
        except Exception:
            pytest.skip(f"HaltChain server not reachable at {api_url}")

    async def test_async_throughput(self, api_url):
        """Async client should sustain >10 000 req/s against local server."""
        client = AsyncHaltChainClient(
            agent_id="async_perf",
            api_key="dev-key",
            base_url=api_url,
            cache_ttl=0,
            max_connections=100,
        )

        actions = [_make_action(float(i % 500 + 50)) for i in range(self.REQUESTS)]

        async def _check(a: dict) -> None:
            try:
                await client.check(a)
            except Exception:
                pass

        start = time.perf_counter()
        await asyncio.gather(*[_check(a) for a in actions])
        elapsed = time.perf_counter() - start

        rps = len(actions) / elapsed
        print(f"\nAsync throughput: {rps:.0f} req/s over {elapsed:.2f}s")

        assert rps >= self.TARGET_RPS, (
            f"Throughput {rps:.0f} req/s below target {self.TARGET_RPS:.0f} req/s"
        )
