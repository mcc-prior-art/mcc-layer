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


def _finite_nonneg(value: Any) -> bool:
    """A usable aggregate amount: a real, finite, non-negative number (and not a
    bool). NaN, infinity, negatives, and non-numerics are rejected so a malformed
    or hostile amount cannot decrement an aggregate or poison the counter."""
    import math

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return math.isfinite(value) and value >= 0


# Atomic velocity reservation. The whole check-increment-(refund) decision runs
# as ONE Redis Lua script, so concurrent callers cannot observe the same old
# counter and both bypass a ceiling, no partial multi-field state is visible,
# and a breach refund happens inside the same atomic step (no refund-window
# race). TTL is set only on first touch of each key (never extended).
#   KEYS: 1=count 2=sum 3=dests
#   ARGV: 1=has_count 2=max_count 3=has_amount 4=amount 5=max_amount
#         6=has_dest 7=destination 8=max_new_dest 9=window_seconds
_RESERVE_LUA = """
local window = tonumber(ARGV[9])
local breaches = {}
local did_count, did_amount, added_dest = false, false, false
if ARGV[1] == '1' then
  local c = redis.call('INCR', KEYS[1])
  if c == 1 then redis.call('EXPIRE', KEYS[1], window) end
  did_count = true
  if tonumber(ARGV[2]) >= 0 and c > tonumber(ARGV[2]) then
    breaches[#breaches+1] = 'count ' .. c .. ' > max ' .. ARGV[2]
  end
end
if ARGV[3] == '1' and #breaches == 0 then
  local s = redis.call('INCRBYFLOAT', KEYS[2], ARGV[4])
  if redis.call('TTL', KEYS[2]) < 0 then redis.call('EXPIRE', KEYS[2], window) end
  did_amount = true
  if tonumber(ARGV[5]) >= 0 and tonumber(s) > tonumber(ARGV[5]) then
    breaches[#breaches+1] = 'amount ' .. s .. ' > max ' .. ARGV[5]
  end
end
if ARGV[6] == '1' and #breaches == 0 then
  local added = redis.call('SADD', KEYS[3], ARGV[7])
  if redis.call('TTL', KEYS[3]) < 0 then redis.call('EXPIRE', KEYS[3], window) end
  added_dest = (added == 1)
  local card = redis.call('SCARD', KEYS[3])
  if tonumber(ARGV[8]) >= 0 and card > tonumber(ARGV[8]) then
    breaches[#breaches+1] = 'new destinations ' .. card .. ' > max ' .. ARGV[8]
  end
end
if #breaches > 0 then
  if did_count then redis.call('DECR', KEYS[1]) end
  if did_amount then redis.call('INCRBYFLOAT', KEYS[2], '-' .. ARGV[4]) end
  if added_dest then redis.call('SREM', KEYS[3], ARGV[7]) end
  return {0, table.concat(breaches, '; ')}
end
return {1, 'ok'}
"""


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
        from . import redis_keys

        bucket = int(now // self.window_seconds)
        # Hash each (attacker-controlled) dimension value so raw actor / resource
        # / beneficiary identifiers are never embedded in a Redis key, and ``:``
        # injection cannot forge a collision. Distinct values still map to
        # distinct, stable scopes (isolation preserved).
        dims = ":".join(
            f"{d}={redis_keys.hash_component(descriptor.dimensions.get(d))}"
            for d in self.aggregate_by
        )
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
        use_amount = limit.max_amount is not None and descriptor.amount is not None
        if use_amount and not _finite_nonneg(descriptor.amount):
            return VelocityOutcome(
                Verdict.DENY,
                f"velocity limit '{limit.name}': invalid amount {descriptor.amount!r}; fail-closed",
                reserved=False,
            )
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

        # Validate the amount BEFORE any Redis op: a malformed, NaN, infinite,
        # negative, or non-numeric amount must never reach an INCRBYFLOAT (which
        # could otherwise decrement the aggregate and bypass the ceiling).
        use_amount = limit.max_amount is not None and descriptor.amount is not None
        if use_amount and not _finite_nonneg(descriptor.amount):
            return VelocityOutcome(
                Verdict.DENY,
                f"velocity limit '{limit.name}': invalid amount {descriptor.amount!r}; fail-closed",
                reserved=False,
            )

        from . import redis_keys

        scope = self._namespace + limit.scope_key(descriptor, now)
        count_key, sum_key, dest_key = scope + ":count", scope + ":sum", scope + ":dests"
        # Hash the destination set member too (no raw beneficiary in Redis).
        dest = redis_keys.hash_component(descriptor.destination) if descriptor.destination is not None else ""
        argv = [
            "1" if limit.max_count is not None else "0",
            str(limit.max_count if limit.max_count is not None else -1),
            "1" if use_amount else "0",
            repr(float(descriptor.amount)) if use_amount else "0",
            repr(float(limit.max_amount)) if limit.max_amount is not None else "-1",
            "1" if (limit.max_new_destinations is not None and descriptor.destination is not None) else "0",
            dest,
            str(limit.max_new_destinations if limit.max_new_destinations is not None else -1),
            str(int(limit.window_seconds)),
        ]
        try:
            res = await self._c(self._redis.eval(_RESERVE_LUA, 3, count_key, sum_key, dest_key, *argv))
        except Exception:
            return VelocityOutcome(
                Verdict.DENY,
                f"velocity registry unavailable for '{limit.name}'; fail-closed",
                reserved=False,
            )
        # Script returns {1,'ok'} or {0,'breach; breach'}. Anything else is
        # indeterminate -> fail closed.
        try:
            ok = int(res[0]) == 1
            detail = res[1] if len(res) > 1 else ""
            if isinstance(detail, bytes):
                detail = detail.decode("utf-8", "replace")
        except (TypeError, IndexError, ValueError):
            return VelocityOutcome(
                Verdict.DENY,
                f"velocity limit '{limit.name}': malformed registry response; fail-closed",
                reserved=False,
            )
        if ok:
            return VelocityOutcome(Verdict.ALLOW, f"within velocity limit '{limit.name}'", True)
        breaches = [b for b in str(detail).split("; ") if b]
        return VelocityOutcome(
            limit.on_exceed,
            f"velocity limit '{limit.name}' exceeded: {detail}",
            reserved=False,
            breaches=breaches,
        )

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
        from . import redis_keys
        from .redis_client import RedisConfigError, redis_client_from_env

        try:
            client = redis_client_from_env(env)
        except RedisConfigError as exc:
            raise VelocityConfigError(
                "MCC_VELOCITY_BACKEND=redis requires MCC_REDIS_URL; refusing to "
                f"fall back to in-memory velocity ({exc})"
            )
        return RedisVelocityRegistry(client, namespace=redis_keys.prefix("vel", env))
    raise VelocityConfigError(
        f"unknown MCC_VELOCITY_BACKEND={backend!r}; expected 'memory' or 'redis'"
    )
