"""Nonce registries for replay protection.

Fail-closed: if the registry cannot confirm a nonce is being used for the
first time, the nonce is treated as unusable and execution is denied.

``NonceRegistry`` is the Redis-backed registry for multi-instance
production. ``InMemoryNonceRegistry`` is a single-process registry for dev
and single-instance pilots — it still rejects replays within the process,
but it is not shared across instances and does not survive a restart.
"""

from __future__ import annotations

import time
from typing import Dict


class NonceRegistry:
    def __init__(self, redis_client, prefix: str = "mcc:nonce:") -> None:
        self._redis = redis_client
        self._prefix = prefix

    async def consume(self, nonce: str, ttl_seconds: int = 300) -> bool:
        """Atomically claim a nonce. True only on first use; False on replay
        or whenever the registry cannot confirm first use (fail-closed)."""
        if not nonce or not isinstance(nonce, str):
            return False
        try:
            stored = await self._redis.set(
                self._prefix + nonce, "1", nx=True, ex=ttl_seconds
            )
            return bool(stored)
        except Exception:
            return False


class InMemoryNonceRegistry:
    """Single-process replay protection (dev / single-instance pilots).

    Same async ``consume`` contract as ``NonceRegistry``. Fail-closed on a
    non-string/empty nonce and on replay. Expired entries are purged lazily.
    Not shared across processes — use ``NonceRegistry`` (Redis) for that.
    """

    def __init__(self) -> None:
        self._seen: Dict[str, float] = {}

    async def consume(self, nonce: str, ttl_seconds: int = 300) -> bool:
        if not nonce or not isinstance(nonce, str):
            return False
        now = time.monotonic()
        if self._seen:
            for stale in [k for k, exp in self._seen.items() if exp <= now]:
                self._seen.pop(stale, None)
        if nonce in self._seen:
            return False
        self._seen[nonce] = now + ttl_seconds
        return True
