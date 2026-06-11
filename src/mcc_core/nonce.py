"""Redis-backed nonce registry for replay protection.

Fail-closed: if Redis is unavailable or errors, the replay state is
unknown, so the nonce is treated as unusable and execution is denied.
"""

from __future__ import annotations


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
