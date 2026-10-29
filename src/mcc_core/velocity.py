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
import uuid
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


# Atomic sliding-window velocity reservation. The whole prune-check-commit
# decision runs as ONE Redis Lua script, so concurrent callers cannot observe
# the same stale aggregate and both bypass a ceiling, and no partial state is
# ever visible between the prune and the commit.
#
# The scope is a single ZSET of individual reservation events (score = the
# event's ``now``, member = a unique id carrying its amount/destination),
# not three fixed-window counters. Each call prunes events older than
# ``now - window_seconds`` before evaluating the ceiling, so the ceiling holds
# over *any* trailing ``window_seconds`` span -- not just one aligned to a
# ``now // window_seconds`` clock boundary. A fixed/tumbling window resets at
# such a boundary regardless of how recently prior reservations were made,
# which would let two individually-valid reservations placed a few seconds
# either side of the boundary each see an (incorrectly) empty aggregate and
# together exceed the ceiling by up to 2x -- this sliding log has no such
# boundary. Only a successful reservation adds a new member; a breach adds
# nothing, so no compensating refund is needed on the deny path.
#   KEYS: 1 = the scope's event ZSET
#   ARGV: 1=now 2=window_seconds
#         3=has_count 4=max_count
#         5=has_amount 6=amount 7=max_amount
#         8=has_dest_limit 9=destination(hashed) 10=max_new_destinations
#         11=unique reservation id
_RESERVE_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])

-- Prune events outside the trailing window (exclusive lower bound: an event
-- exactly ``window`` seconds old has already aged out).
redis.call('ZREMRANGEBYSCORE', key, '-inf', '(' .. (now - window))

local members = redis.call('ZRANGE', key, 0, -1)
local count = #members
local total_amount = 0.0
local dests = {}
local ndest = 0
for _, m in ipairs(members) do
  local amt_str, dest_str = string.match(m, '^[^:]*:([^:]*):(.*)$')
  if amt_str ~= nil and amt_str ~= '' then
    total_amount = total_amount + tonumber(amt_str)
  end
  if dest_str ~= nil and dest_str ~= '' and dests[dest_str] == nil then
    dests[dest_str] = true
    ndest = ndest + 1
  end
end

local breaches = {}
local prospective_count = count + 1
if ARGV[3] == '1' and tonumber(ARGV[4]) >= 0 and prospective_count > tonumber(ARGV[4]) then
  breaches[#breaches+1] = 'count ' .. prospective_count .. ' > max ' .. ARGV[4]
end

local use_amount = ARGV[5] == '1'
local prospective_amount = total_amount
if use_amount then
  prospective_amount = total_amount + tonumber(ARGV[6])
  if tonumber(ARGV[7]) >= 0 and prospective_amount > tonumber(ARGV[7]) then
    breaches[#breaches+1] = 'amount ' .. prospective_amount .. ' > max ' .. ARGV[7]
  end
end

local dest_val = ARGV[9]
local new_dest = dest_val ~= '' and dests[dest_val] == nil
local prospective_dests = ndest + (new_dest and 1 or 0)
if ARGV[8] == '1' and new_dest and tonumber(ARGV[10]) >= 0 and prospective_dests > tonumber(ARGV[10]) then
  breaches[#breaches+1] = 'new destinations ' .. prospective_dests .. ' > max ' .. ARGV[10]
end

if #breaches > 0 then
  return {0, table.concat(breaches, '; ')}
end

local amount_repr = use_amount and ARGV[6] or ''
local member = ARGV[11] .. ':' .. amount_repr .. ':' .. dest_val
redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, window)
return {1, 'ok'}
"""

# Removes exactly one event at this ``now`` -- the one the matching ``reserve``
# call (same scope, same ``now``) just added. Correlation is explicit and
# deterministic, not "the first score match": among every member at this
# exact ``now``, only one whose encoded amount/destination also matches this
# release's own descriptor is removed, so a sibling reservation made by a
# DIFFERENT operation at the identical timestamp -- with a different amount
# and/or destination -- is never mistakenly evicted (proven by
# tests/test_velocity.py::test_release_correlates_by_amount_and_destination_not_just_timestamp).
# Atomically finds-then-removes inside one script so a concurrent reservation
# landing mid-search cannot race the removal. Idempotent / tolerant: no
# match is not an error (over-release is a no-op, mirroring the in-memory
# backend). Among members that are themselves value-identical (same ts,
# amount, destination -- genuinely fungible units), which one is removed
# does not affect any future aggregate decision.
#   KEYS: 1 = the scope's event ZSET
#   ARGV: 1 = now, 2 = amount_repr ('' if this limit doesn't track amount),
#         3 = destination (hashed, '' if none)
_RELEASE_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local target_amount = ARGV[2]
local target_dest = ARGV[3]
local matches = redis.call('ZRANGEBYSCORE', key, now, now)
for _, m in ipairs(matches) do
  local amt_str, dest_str = string.match(m, '^[^:]*:([^:]*):(.*)$')
  if amt_str == target_amount and dest_str == target_dest then
    redis.call('ZREM', key, m)
    return 1
  end
end
return 0
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

        # Time-independent: the sliding window (below) prunes by age, not by a
        # fixed calendar-aligned bucket, so the scope itself does not vary with
        # ``now``. (Prior to the sliding-window rewrite this key embedded a
        # ``now // window_seconds`` bucket; a fixed, calendar-aligned bucket
        # boundary let two individually-valid reservations either side of a
        # bucket edge each see an empty/reset aggregate, permitting up to 2x
        # the configured ceiling through a window in the worst case. The scope
        # is now stable and the window slides against the actual age of each
        # reservation instead.)
        #
        # Hash each (attacker-controlled) dimension value so raw actor / resource
        # / beneficiary identifiers are never embedded in a Redis key, and ``:``
        # injection cannot forge a collision. Distinct values still map to
        # distinct, stable scopes (isolation preserved).
        dims = ":".join(
            f"{d}={redis_keys.hash_component(descriptor.dimensions.get(d))}"
            for d in self.aggregate_by
        )
        return f"{self.name}|{dims}"

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
    # The exact ``now`` this reservation was actually stored under --
    # whatever the caller passed, or (when the caller passed ``now=None``,
    # the production shape) whatever this registry resolved internally.
    # A caller that must later release THIS SPECIFIC reservation needs to
    # pass this exact value back to ``release()``, not re-resolve its own:
    # both registries correlate release-by-timestamp, and two independent
    # ``time.monotonic()``/``time.time()`` calls microseconds apart are
    # essentially never equal -- passing a freshly-resolved ``now`` to
    # ``release()`` instead of this one silently fails to find the event,
    # leaking the reservation until the sliding window ages it out. Only
    # populated on a successful reservation (``reserved=True``); ``None``
    # otherwise (nothing to correlate a release against).
    now: Optional[float] = None

    @property
    def ok(self) -> bool:
        return self.verdict in (Verdict.ALLOW, Verdict.CONSTRAIN)


class InMemoryVelocityRegistry:
    """Single-process velocity (dev / tests). Atomic: each ``reserve`` runs its
    whole check-and-commit without awaiting, so concurrent reservations are
    serialized and cannot independently pass the same remaining limit.

    Sliding window (exact, log-based): each successful reservation is recorded
    as a timestamped event; every call prunes events older than
    ``now - window_seconds`` before checking the ceiling. This is deliberately
    NOT a fixed/tumbling window keyed by ``now // window_seconds`` — a fixed
    window resets its aggregate at a calendar-aligned boundary regardless of
    how recently prior reservations were made, which would let two
    individually-valid reservations placed a few seconds either side of a
    boundary each see an (incorrectly) empty aggregate and together exceed the
    ceiling by up to 2x. The sliding log has no such boundary: the ceiling
    holds over *any* trailing ``window_seconds`` span, not just one aligned to
    the clock.
    """

    def __init__(self) -> None:
        # scope_key -> list of {"ts": float, "amount": Optional[float], "destination": Optional[str]},
        # ordered oldest-first, holding only reservations still inside *some*
        # window as of the last prune (a scope's own configured window_seconds
        # -- distinct scopes never share a list, so no cross-limit skew).
        self._state: dict = {}

    @staticmethod
    def _prune(events: List[dict], window: int, now: float) -> List[dict]:
        # Window is [now - window, now] -- inclusive at the trailing edge, so
        # an event exactly ``window_seconds`` old still counts (the more
        # conservative reading for a governance ceiling: expire strictly-older
        # events only). This must match RedisVelocityRegistry's
        # ZREMRANGEBYSCORE('-inf', '(' .. cutoff) exactly, which removes only
        # scores strictly less than cutoff -- a score equal to cutoff survives
        # there too. The two backends must observe identical governance
        # behavior for identical inputs; this boundary is exercised directly
        # by tests/test_velocity.py::test_event_exactly_at_window_edge_still_counts.
        cutoff = now - window
        return [e for e in events if e["ts"] >= cutoff]

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
        events = self._prune(self._state.get(scope, []), limit.window_seconds, now)
        # Commit the prune regardless of this reservation's outcome -- pruning
        # is monotonic cleanup, not part of the reservation being decided.
        self._state[scope] = events

        breaches: List[str] = []
        prospective_count = len(events) + 1
        if limit.max_count is not None and prospective_count > limit.max_count:
            breaches.append(f"count {prospective_count} > max {limit.max_count}")

        prior_sum = sum(e["amount"] for e in events if e["amount"] is not None)
        prospective_sum = prior_sum + descriptor.amount if use_amount else prior_sum
        if use_amount and prospective_sum > limit.max_amount:
            breaches.append(f"amount {prospective_sum} > max {limit.max_amount}")

        dests = {e["destination"] for e in events if e["destination"] is not None}
        new_dest = descriptor.destination is not None and descriptor.destination not in dests
        prospective_dests = len(dests) + (1 if new_dest else 0)
        if (
            limit.max_new_destinations is not None
            and new_dest
            and prospective_dests > limit.max_new_destinations
        ):
            breaches.append(
                f"new destinations {prospective_dests} > max {limit.max_new_destinations}"
            )

        if breaches:
            return VelocityOutcome(
                verdict=limit.on_exceed,
                reason=f"velocity limit '{limit.name}' exceeded: {'; '.join(breaches)}",
                reserved=False,
                breaches=breaches,
            )

        # Commit the reservation as a new event in the sliding log.
        events.append({
            "ts": now,
            "amount": descriptor.amount if use_amount else None,
            "destination": descriptor.destination,
        })
        return VelocityOutcome(Verdict.ALLOW, f"within velocity limit '{limit.name}'", True, now=now)

    async def release(
        self, limit: VelocityLimit, descriptor: VelocityDescriptor, *, now: Optional[float] = None
    ) -> bool:
        """Undo the single reservation event committed by the matching
        ``reserve`` call for this exact ``(limit, descriptor, now)`` -- used
        to roll back an earlier-reserved dimension when a later dimension in
        the same operation breaches (coordinator step (d)).

        Correlation is explicit and deterministic, not "whatever's newest":
        a candidate event must match on ``ts == now`` AND the same stored
        ``amount``/``destination`` this exact ``descriptor`` would have
        contributed (recomputing ``use_amount`` identically to ``reserve``,
        so a limit that doesn't track amount matches on the same stored
        ``None`` it wrote, not the caller's raw ``descriptor.amount``).
        This distinguishes this operation's own reservation from a sibling
        operation's reservation made at the identical ``now`` with a
        *different* amount and/or destination -- proven by
        ``tests/test_velocity.py::test_release_correlates_by_amount_and_destination_not_just_timestamp``.
        Tolerant no-op if nothing matches (over-release is not an error).
        Among multiple candidates that are themselves value-identical (same
        ts, amount, destination -- i.e. genuinely fungible units), which
        specific one is removed does not affect any future aggregate
        decision, since they contribute identically to count/sum/destination
        accounting either way."""
        now = time.monotonic() if now is None else now
        events = self._state.get(limit.scope_key(descriptor, now))
        if not events:
            return True
        use_amount = limit.max_amount is not None and descriptor.amount is not None
        target_amount = descriptor.amount if use_amount else None
        for i in range(len(events) - 1, -1, -1):
            e = events[i]
            if e["ts"] == now and e["amount"] == target_amount and e["destination"] == descriptor.destination:
                events.pop(i)
                break
        return True


class RedisVelocityRegistry:
    """Durable, multi-instance velocity backed by Redis.

    Sliding window (exact, log-based), mirroring ``InMemoryVelocityRegistry``:
    each scope is a single ZSET of individual reservation events (score = the
    event's timestamp), pruned to the trailing ``window_seconds`` span and
    re-evaluated on every call, all inside one atomic Lua script (``EVAL``).
    Because the whole prune-check-commit sequence is one atomic script
    execution serialized by Redis, the total reserved within any trailing
    window never exceeds the ceiling: splitting across separately-signed
    transactions, or across separate MCC-Core instances sharing this Redis,
    cannot bypass the aggregate. Unlike a fixed/tumbling window keyed by
    ``now // window_seconds``, there is no calendar-aligned boundary at which
    the aggregate resets regardless of how recently prior reservations were
    made.

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
        # negative, or non-numeric amount must never reach the aggregate (which
        # could otherwise poison the sum and bypass the ceiling).
        use_amount = limit.max_amount is not None and descriptor.amount is not None
        if use_amount and not _finite_nonneg(descriptor.amount):
            return VelocityOutcome(
                Verdict.DENY,
                f"velocity limit '{limit.name}': invalid amount {descriptor.amount!r}; fail-closed",
                reserved=False,
            )

        from . import redis_keys

        key = self._namespace + limit.scope_key(descriptor, now) + ":events"
        # Hash the destination member too (no raw beneficiary in Redis).
        dest = redis_keys.hash_component(descriptor.destination) if descriptor.destination is not None else ""
        # A genuinely unique id per reservation ATTEMPT (not derived from the
        # value/time), so two reservations that happen to share the exact same
        # (now, amount, destination) -- e.g. two identical split payments in
        # the same instant -- occupy distinct ZSET members instead of colliding
        # into one (which would silently under-count the aggregate).
        reservation_id = uuid.uuid4().hex
        argv = [
            repr(float(now)),
            str(int(limit.window_seconds)),
            "1" if limit.max_count is not None else "0",
            str(limit.max_count if limit.max_count is not None else -1),
            "1" if use_amount else "0",
            repr(float(descriptor.amount)) if use_amount else "0",
            repr(float(limit.max_amount)) if limit.max_amount is not None else "-1",
            "1" if (limit.max_new_destinations is not None and descriptor.destination is not None) else "0",
            dest,
            str(limit.max_new_destinations if limit.max_new_destinations is not None else -1),
            reservation_id,
        ]
        try:
            res = await self._c(self._redis.eval(_RESERVE_LUA, 1, key, *argv))
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
            return VelocityOutcome(Verdict.ALLOW, f"within velocity limit '{limit.name}'", True, now=now)
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
        """Undo one reservation event at this exact ``now`` -- used to roll
        back an earlier-reserved dimension when a later dimension in the same
        operation breaches. Correlates explicitly by amount/destination (see
        ``_RELEASE_LUA``), not just timestamp, so a sibling reservation from a
        different operation at the identical ``now`` is never evicted by
        mistake. Tolerant: no matching event is not an error."""
        now = time.time() if now is None else now
        from . import redis_keys

        key = self._namespace + limit.scope_key(descriptor, now) + ":events"
        use_amount = limit.max_amount is not None and descriptor.amount is not None
        amount_repr = repr(float(descriptor.amount)) if use_amount else ""
        dest = redis_keys.hash_component(descriptor.destination) if descriptor.destination is not None else ""
        try:
            await self._c(
                self._redis.eval(_RELEASE_LUA, 1, key, repr(float(now)), amount_repr, dest)
            )
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
