"""Business-operation idempotency.

Distinct from nonce replay protection. The nonce makes a *single decision
token* one-time; idempotency makes a *business operation* exactly-once even
across different, separately-signed tokens that share an ``idempotency_key``.

Lifecycle of a key:

    (absent) --reserve--> RESERVED --execute--> EXECUTED   (terminal)
                              |
                              +--fail/release--> (absent)   (retryable)

* First reservation wins; a duplicate while RESERVED or EXECUTED is denied.
* EXECUTED is terminal: the operation can never execute again.
* A RESERVED record carries a TTL, so a crashed executor's reservation is
  recovered automatically when the TTL lapses (stale-RESERVED recovery).
* fail/release frees the key for a legitimate retry.

Fail-closed: a registry that cannot give a definite answer denies the
reservation. ``idempotency_registry_from_env`` refuses to silently fall back
from Redis to in-memory in an enforcement deployment.
"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Tuple

DEFAULT_RESERVATION_TTL_SECONDS = 120
DEFAULT_EXECUTED_TTL_SECONDS = 86_400  # remember completed operations for a day
DEFAULT_OP_TIMEOUT_SECONDS = 0.5


class IdempotencyState(str, Enum):
    RESERVED = "RESERVED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    RELEASED = "RELEASED"


class ReserveStatus(str, Enum):
    RESERVED = "RESERVED"          # this caller won the reservation; proceed
    DUPLICATE_INFLIGHT = "DUPLICATE_INFLIGHT"   # another caller holds RESERVED
    DUPLICATE_EXECUTED = "DUPLICATE_EXECUTED"   # operation already completed
    ERROR = "ERROR"               # indeterminate -> fail closed


@dataclass(frozen=True)
class ReserveResult:
    status: ReserveStatus
    reason: str
    binding: Optional[str] = None  # binding recorded by the holder, if known

    @property
    def ok(self) -> bool:
        """May this caller proceed to execute?"""
        return self.status == ReserveStatus.RESERVED


def _encode(state: IdempotencyState, binding: str) -> str:
    return f"{state.value}|{binding}"


def _decode(raw: str) -> Tuple[Optional[IdempotencyState], str]:
    head, _, binding = raw.partition("|")
    try:
        return IdempotencyState(head), binding
    except ValueError:
        return None, binding


class InMemoryIdempotencyRegistry:
    """Single-process idempotency (dev / tests). Atomic by virtue of running
    its whole critical section without awaiting."""

    def __init__(self) -> None:
        self._store: Dict[str, Tuple[str, float]] = {}  # key -> (encoded, expires_at)

    def _live(self, key: str, now: float) -> Optional[str]:
        entry = self._store.get(key)
        if entry is None:
            return None
        encoded, expires_at = entry
        if expires_at <= now:
            self._store.pop(key, None)
            return None
        return encoded

    async def reserve(
        self,
        key: str,
        *,
        binding: str = "",
        ttl_seconds: int = DEFAULT_RESERVATION_TTL_SECONDS,
    ) -> ReserveResult:
        if not key or not isinstance(key, str):
            return ReserveResult(ReserveStatus.ERROR, "invalid idempotency key")
        now = time.monotonic()
        encoded = self._live(key, now)
        if encoded is None:
            self._store[key] = (_encode(IdempotencyState.RESERVED, binding), now + ttl_seconds)
            return ReserveResult(ReserveStatus.RESERVED, "reserved", binding)
        state, held = _decode(encoded)
        if state == IdempotencyState.EXECUTED:
            return ReserveResult(ReserveStatus.DUPLICATE_EXECUTED, "operation already executed", held)
        return ReserveResult(ReserveStatus.DUPLICATE_INFLIGHT, "operation already reserved", held)

    async def mark_executed(
        self, key: str, *, binding: str = "", ttl_seconds: int = DEFAULT_EXECUTED_TTL_SECONDS
    ) -> bool:
        self._store[key] = (_encode(IdempotencyState.EXECUTED, binding), time.monotonic() + ttl_seconds)
        return True

    async def mark_failed(self, key: str) -> bool:
        self._store.pop(key, None)  # freed for retry
        return True

    async def release(self, key: str) -> bool:
        self._store.pop(key, None)
        return True

    async def get_state(self, key: str) -> Optional[IdempotencyState]:
        encoded = self._live(key, time.monotonic())
        if encoded is None:
            return None
        return _decode(encoded)[0]


class RedisIdempotencyRegistry:
    """Durable, multi-instance idempotency backed by Redis.

    The atomic moment that matters — winning the first reservation — is a single
    ``SET key RESERVED|binding NX EX ttl``: exactly one concurrent caller
    creates the key. EXECUTED is written with a long TTL so completed operations
    survive restarts and are remembered across instances. fail/release delete
    the key (freeing it for retry); a crashed holder's RESERVED record simply
    lapses via its TTL.

    Fail-closed: any Redis error or timeout yields ``ReserveStatus.ERROR``.
    """

    def __init__(
        self,
        redis_client: Any,
        *,
        namespace: str = "mcc:idem:",
        op_timeout_seconds: float = DEFAULT_OP_TIMEOUT_SECONDS,
        executed_ttl_seconds: int = DEFAULT_EXECUTED_TTL_SECONDS,
    ) -> None:
        self._redis = redis_client
        self._namespace = namespace
        self._op_timeout = op_timeout_seconds
        self._executed_ttl = executed_ttl_seconds

    @classmethod
    def from_url(cls, url: str, **kwargs: Any) -> "RedisIdempotencyRegistry":
        import redis.asyncio as redis

        op_timeout = kwargs.get("op_timeout_seconds", DEFAULT_OP_TIMEOUT_SECONDS)
        client = redis.from_url(
            url,
            socket_timeout=op_timeout,
            socket_connect_timeout=kwargs.pop("connect_timeout_seconds", 1.0),
            decode_responses=True,
        )
        return cls(client, **kwargs)

    def _key(self, key: str) -> str:
        return self._namespace + key

    async def _call(self, coro):
        return await asyncio.wait_for(coro, timeout=self._op_timeout)

    async def reserve(
        self,
        key: str,
        *,
        binding: str = "",
        ttl_seconds: int = DEFAULT_RESERVATION_TTL_SECONDS,
    ) -> ReserveResult:
        if not key or not isinstance(key, str):
            return ReserveResult(ReserveStatus.ERROR, "invalid idempotency key")
        rkey = self._key(key)
        value = _encode(IdempotencyState.RESERVED, binding)
        try:
            created = await self._call(self._redis.set(rkey, value, nx=True, ex=ttl_seconds))
            if created is True:
                return ReserveResult(ReserveStatus.RESERVED, "reserved", binding)
            if created is not None:
                return ReserveResult(ReserveStatus.ERROR, "indeterminate set result")
            current = await self._call(self._redis.get(rkey))
        except Exception:
            return ReserveResult(ReserveStatus.ERROR, "idempotency registry unavailable; fail-closed")
        if current is None:
            # The record lapsed between SET and GET; treat as indeterminate and
            # deny rather than racing — the caller can retry safely.
            return ReserveResult(ReserveStatus.ERROR, "reservation state indeterminate; fail-closed")
        state, held = _decode(current)
        if state == IdempotencyState.EXECUTED:
            return ReserveResult(ReserveStatus.DUPLICATE_EXECUTED, "operation already executed", held)
        return ReserveResult(ReserveStatus.DUPLICATE_INFLIGHT, "operation already reserved", held)

    async def mark_executed(
        self, key: str, *, binding: str = "", ttl_seconds: Optional[int] = None
    ) -> bool:
        ttl = self._executed_ttl if ttl_seconds is None else ttl_seconds
        try:
            await self._call(
                self._redis.set(self._key(key), _encode(IdempotencyState.EXECUTED, binding), ex=ttl)
            )
            return True
        except Exception:
            return False

    async def mark_failed(self, key: str) -> bool:
        try:
            await self._call(self._redis.delete(self._key(key)))
            return True
        except Exception:
            return False

    async def release(self, key: str) -> bool:
        return await self.mark_failed(key)

    async def get_state(self, key: str) -> Optional[IdempotencyState]:
        try:
            current = await self._call(self._redis.get(self._key(key)))
        except Exception:
            return None
        if current is None:
            return None
        return _decode(current)[0]


class IdempotencyConfigError(Exception):
    """Raised when the idempotency backend is misconfigured (fail-closed start)."""


def idempotency_registry_from_env(env: Optional[Mapping[str, str]] = None):
    """Select an idempotency registry from configuration.

    ``MCC_IDEMPOTENCY_BACKEND=memory`` (default) or ``redis`` (requires
    ``MCC_REDIS_URL``). Refuses to silently fall back to in-memory when Redis is
    requested but unconfigured.
    """
    env = os.environ if env is None else env
    backend = env.get("MCC_IDEMPOTENCY_BACKEND", "memory").strip().lower()
    if backend in ("memory", "inmemory", "in-memory"):
        return InMemoryIdempotencyRegistry()
    if backend == "redis":
        from . import redis_keys
        from .redis_client import RedisConfigError, redis_client_from_env

        try:
            client = redis_client_from_env(env)
        except RedisConfigError as exc:
            raise IdempotencyConfigError(
                "MCC_IDEMPOTENCY_BACKEND=redis requires MCC_REDIS_URL; refusing to "
                f"fall back to in-memory idempotency ({exc})"
            )
        return RedisIdempotencyRegistry(client, namespace=redis_keys.prefix("idem", env))
    raise IdempotencyConfigError(
        f"unknown MCC_IDEMPOTENCY_BACKEND={backend!r}; expected 'memory' or 'redis'"
    )
