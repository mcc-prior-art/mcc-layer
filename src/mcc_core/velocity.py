"""Atomic velocity and aggregate controls.

Velocity limits cap *aggregate* behaviour over a time window — distinct from
idempotency (which dedupes one operation) and the nonce (which dedupes one
token). A limit aggregates by configurable dimensions (actor, source resource,
destination, action, policy scope) and can cap:

* the number of actions per window;
* the cumulative numeric amount per window (for numeric action profiles);
* the number of new destinations/beneficiaries per window.

Capacity is *reserved atomically before execution*, which is what stops
transaction splitting: four individually valid transactions cannot each pass
the same remaining ceiling, because each reservation is serialized and the one
that would cross the ceiling is refused (and any partial reservation refunded).
Cumulative ceilings therefore hold across related but separately-signed
transactions.

Fail-closed: a registry that cannot reserve denies. The configured ``on_exceed``
verdict (ALLOW / CONSTRAIN / ESCALATE / DENY) decides what an over-limit
reservation returns.
"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field
from typing import Any, List, Mapping, Optional, Tuple

from .core import Verdict
from .profiles import VelocityDescriptor

DEFAULT_OP_TIMEOUT_SECONDS = 0.5


@dataclass(frozen=True)
class VelocityLimit:
    """A single aggregate ceiling over a window, scoped by ``aggregate_by``."""

    name: str
    window_seconds: int
    max_count: Optional[int] = None
    max_amount: Optional[float] = None
    max_new_destinations: Optional[int] = None
    aggregate_by: Tuple[str, ...] = ("actor",)
    on_exceed: Verdict = Verdict.DENY

    def scope_key(self, descriptor: VelocityDescriptor, now: float) -> str:
        bucket = int(now // self.window_seconds)
        dims = ":".join(f"{d}={descriptor.dimensions.get(d)}" for d in self.aggregate_by)
        return f"{self.name}|{dims}|w{bucket}"

    @classmethod
    def from_config(cls, item: dict) -> "VelocityLimit":
        on_exceed = item.get("on_exceed")
        return cls(
            name=item["name"],
            window_seconds=int(item["window_seconds"]),
            max_count=item.get("max_count"),
            max_amount=item.get("max_amount"),
            max_new_destinations=item.get("max_new_destinations"),
            aggregate_by=tuple(item.get("aggregate_by", ("actor",))),
            on_exceed=Verdict(on_exceed) if on_exceed else Verdict.DENY,
        )


@dataclass(frozen=True)
class VelocityOutcome:
    verdict: Verdict
    reason: str
    reserved: bool
    breaches: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.verdict in (Verdict.ALLOW, Verdict.CONSTRAIN)


class InMemoryVelocityRegistry:
    """Single-process velocity (dev / tests). Atomic: each ``reserve`` runs its
    whole check-and-commit without awaiting, so concurrent reservations are
    serialized and cannot independently pass the same remaining limit."""

    def __init__(self) -> None:
        # scope_key -> {"count", "sum", "dests": set, "exp"}
        self._state: dict = {}

    def _bucket(self, scope: str, window: int, now: float) -> dict:
        entry = self._state.get(scope)
        if entry is None or entry["exp"] <= now:
            entry = {"count": 0, "sum": 0.0, "dests": set(), "exp": now + window}
            self._state[scope] = entry
        return entry

    async def reserve(
        self, limit: VelocityLimit, descriptor: VelocityDescriptor, *, now: Optional[float] = None
    ) -> VelocityOutcome:
        now = time.monotonic() if now is None else now
        scope = limit.scope_key(descriptor, now)
        entry = self._bucket(scope, limit.window_seconds, now)

        breaches: List[str] = []
        new_dest = (
            descriptor.destination is not None
            and descriptor.destination not in entry["dests"]
        )
        if limit.max_count is not None and entry["count"] + 1 > limit.max_count:
            breaches.append(f"count {entry['count'] + 1} > max {limit.max_count}")
        if (
            limit.max_amount is not None
            and descriptor.amount is not None
            and entry["sum"] + descriptor.amount > limit.max_amount
        ):
            breaches.append(
                f"amount {entry['sum'] + descriptor.amount} > max {limit.max_amount}"
            )
        if (
            limit.max_new_destinations is not None
            and new_dest
            and len(entry["dests"]) + 1 > limit.max_new_destinations
        ):
            breaches.append(
                f"new destinations {len(entry['dests']) + 1} > max {limit.max_new_destinations}"
            )

        if breaches:
            return VelocityOutcome(
                verdict=limit.on_exceed,
                reason=f"velocity limit '{limit.name}' exceeded: {'; '.join(breaches)}",
                reserved=False,
                breaches=breaches,
            )

        # Commit the reservation.
        entry["count"] += 1
        if descriptor.amount is not None:
            entry["sum"] += descriptor.amount
        if new_dest:
            entry["dests"].add(descriptor.destination)
        return VelocityOutcome(Verdict.ALLOW, f"within velocity limit '{limit.name}'", True)

    async def release(
        self, limit: VelocityLimit, descriptor: VelocityDescriptor, *, now: Optional[float] = None
    ) -> bool:
        now = time.monotonic() if now is None else now
        entry = self._state.get(limit.scope_key(descriptor, now))
        if entry is None:
            return True
        entry["count"] = max(0, entry["count"] - 1)
        if descriptor.amount is not None:
            entry["sum"] = max(0.0, entry["sum"] - descriptor.amount)
        return True


class RedisVelocityRegistry:
    """Durable, multi-instance velocity backed by Redis.

    Each dimension is reserved with an atomic Redis primitive — ``INCR`` for the
    count, ``INCRBYFLOAT`` for the cumulative amount, ``SADD``/``SCARD`` for
    distinct destinations — and any reservation that crosses a ceiling is
    refunded before denying. Because every increment is atomic and serialized by
    Redis, the total reserved never exceeds the ceiling: splitting across
    separately-signed transactions cannot bypass the aggregate.

    Fail-closed: any Redis error/timeout denies.
    """

    def __init__(
        self,
        redis_client: Any,
        *,
        namespace: str = "mcc:vel:",
        op_timeout_seconds: float = DEFAULT_OP_TIMEOUT_SECONDS,
    ) -> None:
        self._redis = redis_client
        self._namespace = namespace
        self._op_timeout = op_timeout_seconds

    @classmethod
    def from_url(cls, url: str, **kwargs: Any) -> "RedisVelocityRegistry":
        import redis.asyncio as redis

        op_timeout = kwargs.get("op_timeout_seconds", DEFAULT_OP_TIMEOUT_SECONDS)
        client = redis.from_url(
            url,
            socket_timeout=op_timeout,
            socket_connect_timeout=kwargs.pop("connect_timeout_seconds", 1.0),
            decode_responses=True,
        )
        return cls(client, **kwargs)

    async def _c(self, coro):
        return await asyncio.wait_for(coro, timeout=self._op_timeout)

    async def reserve(
        self, limit: VelocityLimit, descriptor: VelocityDescriptor, *, now: Optional[float] = None
    ) -> VelocityOutcome:
        now = time.time() if now is None else now
        scope = self._namespace + limit.scope_key(descriptor, now)
        count_key, sum_key, dest_key = scope + ":count", scope + ":sum", scope + ":dests"
        breaches: List[str] = []
        did_count = did_amount = False
        added_dest = False
        try:
            if limit.max_count is not None:
                post = int(await self._c(self._redis.incr(count_key)))
                await self._c(self._redis.expire(count_key, limit.window_seconds))
                did_count = True
                if post > limit.max_count:
                    breaches.append(f"count {post} > max {limit.max_count}")

            if limit.max_amount is not None and descriptor.amount is not None and not breaches:
                post_sum = float(await self._c(self._redis.incrbyfloat(sum_key, descriptor.amount)))
                await self._c(self._redis.expire(sum_key, limit.window_seconds))
                did_amount = True
                if post_sum > limit.max_amount:
                    breaches.append(f"amount {post_sum} > max {limit.max_amount}")

            if (
                limit.max_new_destinations is not None
                and descriptor.destination is not None
                and not breaches
            ):
                added = int(await self._c(self._redis.sadd(dest_key, descriptor.destination)))
                await self._c(self._redis.expire(dest_key, limit.window_seconds))
                added_dest = added == 1
                card = int(await self._c(self._redis.scard(dest_key)))
                if card > limit.max_new_destinations:
                    breaches.append(f"new destinations {card} > max {limit.max_new_destinations}")

            if breaches:
                # Refund anything we reserved before denying.
                if did_count:
                    await self._c(self._redis.decr(count_key))
                if did_amount:
                    await self._c(self._redis.incrbyfloat(sum_key, -descriptor.amount))
                if added_dest:
                    await self._c(self._redis.srem(dest_key, descriptor.destination))
                return VelocityOutcome(
                    limit.on_exceed,
                    f"velocity limit '{limit.name}' exceeded: {'; '.join(breaches)}",
                    reserved=False,
                    breaches=breaches,
                )
        except Exception:
            return VelocityOutcome(
                Verdict.DENY,
                f"velocity registry unavailable for '{limit.name}'; fail-closed",
                reserved=False,
            )
        return VelocityOutcome(Verdict.ALLOW, f"within velocity limit '{limit.name}'", True)

    async def release(
        self, limit: VelocityLimit, descriptor: VelocityDescriptor, *, now: Optional[float] = None
    ) -> bool:
        now = time.time() if now is None else now
        scope = self._namespace + limit.scope_key(descriptor, now)
        try:
            if limit.max_count is not None:
                await self._c(self._redis.decr(scope + ":count"))
            if limit.max_amount is not None and descriptor.amount is not None:
                await self._c(self._redis.incrbyfloat(scope + ":sum", -descriptor.amount))
            return True
        except Exception:
            return False


class VelocityConfigError(Exception):
    """Raised when the velocity backend is misconfigured (fail-closed start)."""


def velocity_registry_from_env(env: Optional[Mapping[str, str]] = None):
    """Select a velocity registry from configuration. ``MCC_VELOCITY_BACKEND``
    is ``memory`` (default) or ``redis`` (requires ``MCC_REDIS_URL``). No silent
    fallback from Redis to in-memory."""
    env = os.environ if env is None else env
    backend = env.get("MCC_VELOCITY_BACKEND", "memory").strip().lower()
    if backend in ("memory", "inmemory", "in-memory"):
        return InMemoryVelocityRegistry()
    if backend == "redis":
        url = env.get("MCC_REDIS_URL", "").strip()
        if not url:
            raise VelocityConfigError(
                "MCC_VELOCITY_BACKEND=redis requires MCC_REDIS_URL; refusing to "
                "fall back to in-memory velocity in an enforcement deployment"
            )
        return RedisVelocityRegistry.from_url(url)
    raise VelocityConfigError(
        f"unknown MCC_VELOCITY_BACKEND={backend!r}; expected 'memory' or 'redis'"
    )
