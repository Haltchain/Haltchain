from __future__ import annotations

import json
import os
import time
from typing import Optional

from .cache import CachedDecision, PolicyCache


class RedisPolicyCache:
    """Redis-backed policy cache with AUTH support and optional encryption.
    
    P0 Security: Supports Redis AUTH password authentication and TLS encryption.
    Environment variables:
    - REDIS_PASSWORD: Password for Redis AUTH
    - REDIS_SSL: Set to "true" to enable TLS
    - REDIS_SSL_CA_CERTS: Path to CA certificates for TLS verification
    - REDIS_ENCRYPTION_KEY: Base64-encoded key for cache value encryption
    """
    
    def __init__(
        self,
        *,
        redis_url: str,
        ttl: float,
        prefix: str = "haltchain:policy",
    ) -> None:
        try:
            import redis
        except ImportError as exc:
            raise ImportError("Redis cache requires `pip install haltchain[redis]`.") from exc

        # P0: Parse Redis URL and add authentication if available
        password = os.environ.get("REDIS_PASSWORD")
        use_ssl = os.environ.get("REDIS_SSL", "").lower() == "true"
        ssl_ca_certs = os.environ.get("REDIS_SSL_CA_CERTS")
        
        # Build connection kwargs
        connection_kwargs: dict = {"decode_responses": True}
        
        if use_ssl:
            connection_kwargs["ssl"] = True
            if ssl_ca_certs:
                connection_kwargs["ssl_ca_certs"] = ssl_ca_certs
                connection_kwargs["ssl_cert_reqs"] = "required"
        
        # Parse URL and create client
        if password and "://" in redis_url:
            # Inject password into URL if not present
            if "@" not in redis_url.split("://")[1]:
                protocol = redis_url.split("://")[0]
                host_part = redis_url.split("://")[1]
                redis_url = f"{protocol}://:{password}@{host_part}"
        
        self._redis = redis.Redis.from_url(redis_url, **connection_kwargs)
        
        # Test connection and AUTH
        try:
            self._redis.ping()
        except redis.AuthenticationError as e:
            raise redis.AuthenticationError(
                "Redis authentication failed. Check REDIS_PASSWORD."
            ) from e
        except redis.ConnectionError as e:
            raise redis.ConnectionError(
                f"Could not connect to Redis. URL: {redis_url.replace(password or '', '***') if password else redis_url}"
            ) from e
        
        self._ttl = max(1, int(ttl))
        self._prefix = prefix
        
        # P0: Encryption support for sensitive cache data
        self._encryption_key = os.environ.get("REDIS_ENCRYPTION_KEY")
        if self._encryption_key:
            try:
                import base64
                self._encryption_key = base64.b64decode(self._encryption_key)
            except Exception:
                raise ValueError("REDIS_ENCRYPTION_KEY must be base64-encoded")

    def _key(self, agent_id: str, action: dict) -> str:
        return f"{self._prefix}:{PolicyCache.key_for(agent_id, action)}"

    def _encrypt(self, data: str) -> str:
        """Encrypt cache value if encryption key is configured."""
        if not self._encryption_key:
            return data
        try:
            from cryptography.fernet import Fernet
            # Use key as Fernet key (must be 32 bytes base64-encoded)
            import base64
            fernet_key = base64.urlsafe_b64encode(self._encryption_key[:32].ljust(32, b'\0'))
            f = Fernet(fernet_key)
            return f.encrypt(data.encode()).decode()
        except ImportError:
            # cryptography not installed, skip encryption
            return data

    def _decrypt(self, data: str) -> Optional[str]:
        """Decrypt cache value if encryption key is configured."""
        if not self._encryption_key:
            return data
        try:
            from cryptography.fernet import Fernet
            import base64
            fernet_key = base64.urlsafe_b64encode(self._encryption_key[:32].ljust(32, b'\0'))
            f = Fernet(fernet_key)
            return f.decrypt(data.encode()).decode()
        except Exception:
            # Decryption failed, return None to trigger cache miss
            return None

    @staticmethod
    def _pack(decision: str, reason: str, policy: str) -> str:
        # cached_at omitted: Redis SETEX owns TTL, no need for wall/monotonic clock
        return json.dumps(
            {"decision": decision, "reason": reason, "policy": policy},
            separators=(",", ":"),
            ensure_ascii=False,
        )

    @staticmethod
    def _unpack(raw: str) -> Optional[CachedDecision]:
        try:
            data = json.loads(raw)
            # If Redis returned a value it's still live (SETEX handles expiry)
            return CachedDecision(
                decision=data.get("decision", "DENY"),
                reason=data.get("reason", ""),
                policy=data.get("policy", ""),
                cached_at=time.monotonic(),
            )
        except (TypeError, ValueError, json.JSONDecodeError):
            return None

    def get(self, agent_id: str, action: dict) -> Optional[CachedDecision]:
        raw = self._redis.get(self._key(agent_id, action))
        if raw is None:
            return None
        # Decrypt if needed
        decrypted = self._decrypt(raw) if self._encryption_key else raw
        if decrypted is None:
            return None
        return self._unpack(decrypted)

    def put(
        self,
        agent_id: str,
        action: dict,
        decision: str,
        reason: str,
        policy: str,
    ) -> None:
        packed = self._pack(decision, reason, policy)
        # Encrypt if needed
        if self._encryption_key:
            packed = self._encrypt(packed)
        self._redis.setex(self._key(agent_id, action), self._ttl, packed)

    def clear(self) -> None:
        keys = list(self._redis.scan_iter(f"{self._prefix}:*"))
        if keys:
            self._redis.delete(*keys)

    def size(self) -> int:
        return sum(1 for _ in self._redis.scan_iter(f"{self._prefix}:*"))


class AsyncRedisPolicyCache:
    """Async Redis-backed policy cache with AUTH support and optional encryption."""
    
    def __init__(
        self,
        *,
        redis_url: str,
        ttl: float,
        prefix: str = "haltchain:policy",
    ) -> None:
        try:
            from redis import asyncio as redis_async
        except ImportError as exc:
            raise ImportError("Redis cache requires `pip install haltchain[redis]`.") from exc

        # P0: Parse Redis URL and add authentication if available
        password = os.environ.get("REDIS_PASSWORD")
        use_ssl = os.environ.get("REDIS_SSL", "").lower() == "true"
        ssl_ca_certs = os.environ.get("REDIS_SSL_CA_CERTS")
        
        # Build connection kwargs
        connection_kwargs: dict = {"decode_responses": True}
        
        if use_ssl:
            connection_kwargs["ssl"] = True
            if ssl_ca_certs:
                connection_kwargs["ssl_ca_certs"] = ssl_ca_certs
                connection_kwargs["ssl_cert_reqs"] = "required"
        
        # Inject password into URL if not present
        if password and "://" in redis_url and "@" not in redis_url.split("://")[1]:
            protocol = redis_url.split("://")[0]
            host_part = redis_url.split("://")[1]
            redis_url = f"{protocol}://:{password}@{host_part}"
        
        self._redis = redis_async.Redis.from_url(redis_url, **connection_kwargs)
        self._ttl = max(1, int(ttl))
        self._prefix = prefix
        
        # P0: Encryption support
        self._encryption_key = os.environ.get("REDIS_ENCRYPTION_KEY")
        if self._encryption_key:
            try:
                import base64
                self._encryption_key = base64.b64decode(self._encryption_key)
            except Exception:
                raise ValueError("REDIS_ENCRYPTION_KEY must be base64-encoded")

    def _key(self, agent_id: str, action: dict) -> str:
        return f"{self._prefix}:{PolicyCache.key_for(agent_id, action)}"

    def _encrypt(self, data: str) -> str:
        """Encrypt cache value if encryption key is configured."""
        if not self._encryption_key:
            return data
        try:
            from cryptography.fernet import Fernet
            import base64
            fernet_key = base64.urlsafe_b64encode(self._encryption_key[:32].ljust(32, b'\0'))
            f = Fernet(fernet_key)
            return f.encrypt(data.encode()).decode()
        except ImportError:
            return data

    def _decrypt(self, data: str) -> Optional[str]:
        """Decrypt cache value if encryption key is configured."""
        if not self._encryption_key:
            return data
        try:
            from cryptography.fernet import Fernet
            import base64
            fernet_key = base64.urlsafe_b64encode(self._encryption_key[:32].ljust(32, b'\0'))
            f = Fernet(fernet_key)
            return f.decrypt(data.encode()).decode()
        except Exception:
            return None

    @staticmethod
    def _pack(decision: str, reason: str, policy: str) -> str:
        return json.dumps(
            {"decision": decision, "reason": reason, "policy": policy},
            separators=(",", ":"),
            ensure_ascii=False,
        )

    @staticmethod
    def _unpack(raw: str) -> Optional[CachedDecision]:
        try:
            data = json.loads(raw)
            return CachedDecision(
                decision=data.get("decision", "DENY"),
                reason=data.get("reason", ""),
                policy=data.get("policy", ""),
                cached_at=time.monotonic(),
            )
        except (TypeError, ValueError, json.JSONDecodeError):
            return None

    async def get(self, agent_id: str, action: dict) -> Optional[CachedDecision]:
        raw = await self._redis.get(self._key(agent_id, action))
        if raw is None:
            return None
        decrypted = self._decrypt(raw) if self._encryption_key else raw
        if decrypted is None:
            return None
        return self._unpack(decrypted)

    async def put(
        self,
        agent_id: str,
        action: dict,
        decision: str,
        reason: str,
        policy: str,
    ) -> None:
        packed = self._pack(decision, reason, policy)
        if self._encryption_key:
            packed = self._encrypt(packed)
        await self._redis.setex(self._key(agent_id, action), self._ttl, packed)

    async def clear(self) -> None:
        keys = [k async for k in self._redis.scan_iter(f"{self._prefix}:*")]
        if keys:
            await self._redis.delete(*keys)

    async def size(self) -> int:
        return sum(1 async for _ in self._redis.scan_iter(f"{self._prefix}:*"))

    async def aclose(self) -> None:
        await self._redis.aclose()
