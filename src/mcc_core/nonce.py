"""Nonce registries for replay protection.

Fail-closed by construction: if a registry cannot confirm a nonce is being
used for the first time — replay, outage, timeout, or any indeterminate
answer — the nonce is treated as unusable and execution is denied.

* ``RedisNonceRegistry``    — production, multi-instance. Atomic ``SET NX EX``;
                              a single shared Redis makes replay protection
                              hold across every gate instance.
* ``InMemoryNonceRegistry`` — local development and single-instance pilots.
                              Rejects replays within one process only; not
                              shared across instances, not durable.
* ``NonceRegistry``         — backward-compatible alias of
                              ``RedisNonceRegistry`` (kept for existing call
                              sites that inject a Redis-like client).

``nonce_registry_from_env`` selects the backend from configuration and
*refuses to silently fall back* from Redis to in-memory: in an enforcement
deployment a misconfigured or missing Redis is an error, not a downgrade.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any, Dict, Mapping, Optional

# Defensive bounds applied to every derived nonce TTL. The TTL is computed
# upstream from the decision token's validity window (see ExecutionGate); these
# bounds stop a malformed or hostile window from requesting a 0/negative or
# unbounded expiry on the Redis key.
DEFAULT_OP_TIMEOUT_SECONDS = 0.5
DEFAULT_MIN_TTL_SECONDS = 1
DEFAULT_MAX_TTL_SECONDS = 900


class NonceConfigError(Exception):
    """Raised when the nonce backend is misconfigured (fail-closed at startup)."""


class RedisNonceRegistry:
    """Production replay protection backed by Redis ``SET NX EX``.

    The claim is atomic: ``SET key 1 NX EX ttl`` either creates the key (first
    use → True) or does nothing because it already exists (replay → None). A
    single Redis shared by every gate instance therefore rejects cross-instance
    replays — the property in-memory protection cannot provide.

    Fail-closed: an unreachable Redis, a slow Redis (operation timeout), or any
    return value that is not an unambiguous success is treated as "cannot
    confirm first use" and denies. The registry never raises out of
    ``consume`` — it returns ``False``.
    """

    def __init__(
        self,
        redis_client: Any,
        *,
        namespace: str = "mcc:nonce:",
        op_timeout_seconds: float = DEFAULT_OP_TIMEOUT_SECONDS,
        min_ttl_seconds: int = DEFAULT_MIN_TTL_SECONDS,
        max_ttl_seconds: int = DEFAULT_MAX_TTL_SECONDS,
    ) -> None:
        self._redis = redis_client
        self._namespace = namespace
        self._op_timeout_seconds = op_timeout_seconds
        self._min_ttl_seconds = min_ttl_seconds
        self._max_ttl_seconds = max_ttl_seconds

    @classmethod
    def from_url(
        cls,
        url: str,
        *,
        namespace: str = "mcc:nonce:",
        op_timeout_seconds: float = DEFAULT_OP_TIMEOUT_SECONDS,
        connect_timeout_seconds: float = 1.0,
        min_ttl_seconds: int = DEFAULT_MIN_TTL_SECONDS,
        max_ttl_seconds: int = DEFAULT_MAX_TTL_SECONDS,
    ) -> "RedisNonceRegistry":
        """Build a registry from a ``redis://`` URL.

        Connection is lazy (no I/O here), so construction succeeds even before
        Redis is reachable; the first ``consume`` is where an outage surfaces
        — and it surfaces as a denial, not a fallback.
        """
        import redis.asyncio as redis  # local import: optional in dev

        client = redis.from_url(
            url,
            socket_timeout=op_timeout_seconds,
            socket_connect_timeout=connect_timeout_seconds,
            decode_responses=True,
        )
        return cls(
            client,
            namespace=namespace,
            op_timeout_seconds=op_timeout_seconds,
            min_ttl_seconds=min_ttl_seconds,
            max_ttl_seconds=max_ttl_seconds,
        )

    def _bounded_ttl(self, ttl_seconds: int) -> int:
        try:
            ttl = int(ttl_seconds)
        except (TypeError, ValueError):
            return self._min_ttl_seconds
        return max(self._min_ttl_seconds, min(self._max_ttl_seconds, ttl))

    async def consume(self, nonce: str, ttl_seconds: int = 300) -> bool:
        if not nonce or not isinstance(nonce, str):
            return False
        ttl = self._bounded_ttl(ttl_seconds)
        try:
            stored = await asyncio.wait_for(
                self._redis.set(self._namespace + nonce, "1", nx=True, ex=ttl),
                timeout=self._op_timeout_seconds,
            )
        except Exception:
            # Unreachable, timed out, connection reset, etc. -> fail closed.
            return False
        if stored is True:
            return True  # first use: the key was created
        if stored is None:
            return False  # replay: key already existed (NX no-op)
        # Anything else is an answer we cannot interpret as a definite first
        # use. Fail closed rather than guess.
        return False


# Backward-compatible name. Existing call sites inject a Redis-like client
# positionally — that contract is unchanged.
NonceRegistry = RedisNonceRegistry


class InMemoryNonceRegistry:
    """Single-process replay protection (dev / single-instance pilots).

    Same async ``consume`` contract as ``RedisNonceRegistry``. Fail-closed on a
    non-string/empty nonce and on replay. Expired entries are purged lazily.
    Not shared across processes and not durable — use ``RedisNonceRegistry``
    for any multi-instance or enforcement deployment.
    """

    def __init__(self) -> None:
        self._seen: Dict[str, float] = {}

    async def consume(self, nonce: str, ttl_seconds: int = 300) -> bool:
        if not nonce or not isinstance(nonce, str):
            return False
        import time

        now = time.monotonic()
        if self._seen:
            for stale in [k for k, exp in self._seen.items() if exp <= now]:
                self._seen.pop(stale, None)
        if nonce in self._seen:
            return False
        self._seen[nonce] = now + ttl_seconds
        return True


def nonce_registry_from_env(env: Optional[Mapping[str, str]] = None):
    """Select a nonce registry from configuration.

    * ``MCC_NONCE_BACKEND=memory`` (default) -> ``InMemoryNonceRegistry``.
    * ``MCC_NONCE_BACKEND=redis``            -> ``RedisNonceRegistry`` built
      from ``MCC_REDIS_URL``.

    Refuses to silently fall back: selecting ``redis`` without a usable
    ``MCC_REDIS_URL`` raises ``NonceConfigError`` instead of quietly returning
    an in-memory registry. An enforcement deployment that asked for Redis must
    fail to start rather than run with unshared, non-durable replay state.
    """
    env = os.environ if env is None else env
    backend = env.get("MCC_NONCE_BACKEND", "memory").strip().lower()

    if backend in ("memory", "inmemory", "in-memory"):
        return InMemoryNonceRegistry()

    if backend == "redis":
        from . import redis_keys
        from .redis_client import RedisConfigError, redis_client_from_env

        try:
            client = redis_client_from_env(env)
        except RedisConfigError as exc:
            raise NonceConfigError(
                "MCC_NONCE_BACKEND=redis requires MCC_REDIS_URL; refusing to "
                f"fall back to in-memory replay protection ({exc})"
            )
        return RedisNonceRegistry(client, namespace=redis_keys.prefix("nonce", env))

    raise NonceConfigError(
        f"unknown MCC_NONCE_BACKEND={backend!r}; expected 'memory' or 'redis'"
    )
