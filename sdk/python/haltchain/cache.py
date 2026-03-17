from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional, Protocol


@dataclass
class CachedDecision:
    decision: str
    reason: str
    policy: str
    cached_at: float = field(default_factory=time.monotonic)

    def is_fresh(self, ttl: float, now: float) -> bool:
        return (now - self.cached_at) < ttl


_DENY_FALLBACK = CachedDecision(
    decision="DENY",
    reason="validator unreachable and no cached policy",
    policy="OFFLINE_FALLBACK",
)


class CacheBackend(Protocol):
    def get(self, agent_id: str, action: dict) -> Optional[CachedDecision]:
        ...

    def put(
        self,
        agent_id: str,
        action: dict,
        decision: str,
        reason: str,
        policy: str,
    ) -> None:
        ...

    def clear(self) -> None:
        ...

    def size(self) -> int:
        ...


class PolicyCache:
    DEFAULT_TTL = 60.0
    DEFAULT_CAP = 2_000

    def __init__(self, ttl: float = DEFAULT_TTL, max_size: int = DEFAULT_CAP) -> None:
        self._ttl = ttl
        self._max_size = max_size
        self._store: OrderedDict[str, CachedDecision] = OrderedDict()
        self._lock = threading.RLock()

    @staticmethod
    def key_for(agent_id: str, action: dict) -> str:
        blob = json.dumps(
            {"a": agent_id, "x": action},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hashlib.blake2b(blob.encode("utf-8"), digest_size=12).hexdigest()

    def get(self, agent_id: str, action: dict) -> Optional[CachedDecision]:
        key = self.key_for(agent_id, action)
        now = time.monotonic()
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            if not entry.is_fresh(self._ttl, now):
                self._store.pop(key, None)
                return None
            self._store.move_to_end(key)
            return entry

    def put(
        self,
        agent_id: str,
        action: dict,
        decision: str,
        reason: str,
        policy: str,
    ) -> None:
        key = self.key_for(agent_id, action)
        with self._lock:
            if key in self._store:
                self._store.pop(key)
            self._store[key] = CachedDecision(decision=decision, reason=reason, policy=policy)
            while len(self._store) > self._max_size:
                self._store.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def size(self) -> int:
        with self._lock:
            return len(self._store)


def fallback_decision() -> CachedDecision:
    return _DENY_FALLBACK
