"""Automated AuditLog integrity verification and fail-closed enforcement.

P2-A3: closes a gap PR #128 (``docs/AUDITLOG_OPTIMIZATION.md``, Round 2 §7)
explicitly left open -- the O(tail) hot-path read used by
``AuditLog.append()``/``__init__`` deliberately no longer scans the whole
file, so it no longer incidentally notices HISTORICAL corruption earlier in
the chain. This module is the control that was promised instead: an
explicit, periodic, off-hot-path full-chain verification, plus mandatory
fail-closed enforcement at the two places executable authority actually
leaves the system -- token issuance (``gateway/governance_service.py``) and
actuation dispatch (``src/mcc_core/coordinator.py``).

State machine
-------------
    UNVERIFIED -- no verification pass has completed yet (startup default).
    VERIFYING  -- a verification pass is in flight, in THIS process.
    HEALTHY    -- the most recently completed pass found the chain intact,
                  AND that result is still "fresh" (see below).
    UNHEALTHY  -- the most recent pass failed, OR the last known-HEALTHY
                  result is stale, OR the shared state backend cannot
                  currently be reached/read.

Only ``HEALTHY`` ever satisfies a gate check. Every other state blocks --
deliberately simple and boolean-shaped for callers (fail-closed by
construction: an unrecognized or unreachable state is never treated as
"probably fine").

The one invariant every caller of this module must understand
----------------------------------------------------------------
``HEALTHY`` only proves the chain was intact AS OF ``last_verified_at``. It
is **not** a per-request, real-time guarantee -- a full-chain scan is an
O(file size) operation and is deliberately kept off ``append()``'s hot path
(see ``AuditLog.verify_chain_safe()`` below), so it cannot be re-run on
every governed request. This is exactly why:

* periodic re-verification (``start_periodic_verification``) is REQUIRED,
  not optional, for ``HEALTHY`` to keep meaning anything over time -- a
  monitor that is only ever run once at startup and never again would let
  ``HEALTHY`` silently go stale forever, and
* ``freshness_grace_seconds`` exists at all -- a stored ``HEALTHY`` whose
  ``last_verified_at`` is older than this bound is reported as
  ``UNHEALTHY`` by :meth:`AuditIntegrityMonitor.current_state`, specifically
  to catch a periodic verifier that has silently died (crashed, wedged, or
  was never started) without anyone noticing a stale green light.

The worst-case detection latency for a genuine corruption introduced
between two passes is therefore bounded by (periodic interval + one pass's
own run time), and a corruption introduced and then somehow "fixed" back to
looking intact between two passes is NOT something this control can ever
detect -- it only ever sees point-in-time snapshots. State this honestly;
never claim continuous, real-time protection this design cannot provide.

Multi-worker / cross-process consistency
-----------------------------------------
Each worker's local, in-process state is not the source of truth --
:class:`IntegrityStateRegistry` is, exactly like this codebase's existing
nonce/idempotency/velocity/challenge/approval/revocation registries
(``nonce.py``, ``challenge.py``, et al.): an ``InMemoryIntegrityStateRegistry``
for single-process/dev use, and a ``RedisIntegrityStateRegistry`` shared by
every worker/instance in a real deployment, so one worker's corruption
detection is visible to every other worker immediately, and a crashed and
restarted verifier can never resurrect a stale ``HEALTHY`` over a newer
``UNHEALTHY`` (every write is a monotonic-generation compare-and-set, never
a blind overwrite).

Concurrency with ``append()``
------------------------------
A full-chain verification pass reuses ``AuditLog``'s OWN existing
inter-process lock (``AuditLog._locked()`` -- the same ``fcntl.flock`` used
by ``append()``'s critical section) via the one new method this module
requires on ``AuditLog``, ``verify_chain_safe()``. No new locking primitive
is introduced, and ``append()`` itself is completely unmodified: a
verification pass can never race a concurrent writer, and a writer is
blocked for the duration of one pass's lock hold, exactly as it already is
by a sibling ``append()`` call.
"""

from __future__ import annotations

import asyncio
import os
import threading
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Optional

from .audit import AuditLog
from .trusted_time import (
    LocalTimeSource,
    TimeTrustError,
    TrustedTimeSource,
    _validate_positive_finite,
)

DEFAULT_OP_TIMEOUT_SECONDS = 0.5
# A stored HEALTHY result older than this (relative to the trusted time
# source) is reported as UNHEALTHY -- the "periodic verifier silently
# died" bypass this module exists to close. Generous enough to tolerate
# normal pass-to-pass jitter at the default periodic interval below,
# tight enough that a genuinely dead verifier is caught within minutes,
# not hours.
DEFAULT_FRESHNESS_GRACE_SECONDS = 180.0
# Default cadence for the background verification pass. Independent of,
# and much coarser-grained than, any per-request path -- this is an
# O(file size) operation and is never run inline with a governed request.
DEFAULT_PERIODIC_INTERVAL_SECONDS = 60.0


class IntegrityState(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    VERIFYING = "VERIFYING"
    HEALTHY = "HEALTHY"
    UNHEALTHY = "UNHEALTHY"


def is_healthy(state: "IntegrityState") -> bool:
    """The one boolean-shaped question every gate actually asks. Defined
    once here so no call site re-derives "is this state good enough" with
    its own (potentially inconsistent) comparison."""
    return state == IntegrityState.HEALTHY


@dataclass(frozen=True)
class IntegrityStatus:
    state: IntegrityState
    reason: str
    last_verified_at: Optional[int] = None
    generation: int = 0


class IntegrityConfigError(Exception):
    """Raised when the integrity-state backend is misconfigured (fail-closed
    at startup) -- mirrors ``NonceConfigError``/``ChallengeConfigError``."""


class IntegrityBackendUnavailable(Exception):
    """Raised BY a registry (never by the public monitor API) when the
    shared backend cannot be reached to read or write integrity state.
    :meth:`AuditIntegrityMonitor.current_state` and
    :meth:`AuditIntegrityMonitor.verify_once` always catch this and
    resolve to ``IntegrityState.UNHEALTHY`` -- an unreachable backend is
    never silently treated as "skip the check" or "assume healthy"."""


# ---------------------------------------------------------------------------
# Registries
# ---------------------------------------------------------------------------


class InMemoryIntegrityStateRegistry:
    """Single-process integrity-state store (dev / single-instance pilots).
    Not shared across processes and not durable -- use
    ``RedisIntegrityStateRegistry`` for any multi-instance deployment."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._generation = 0
        self._status: Optional[IntegrityStatus] = None

    async def allocate_generation(self) -> int:
        with self._lock:
            self._generation += 1
            return self._generation

    async def set_if_newer(
        self, *, generation: int, state: "IntegrityState", reason: str, verified_at: int
    ) -> bool:
        with self._lock:
            if self._status is not None and generation <= self._status.generation:
                return False
            self._status = IntegrityStatus(
                state=state, reason=reason, last_verified_at=verified_at, generation=generation
            )
            return True

    async def get(self) -> Optional[IntegrityStatus]:
        with self._lock:
            return self._status


# Lua CAS: only applies the write if the new generation is strictly greater
# than whatever generation is currently stored -- the primitive that makes
# a crashed-and-restarted verifier (or a slow/delayed write racing a newer
# one) unable to resurrect a stale result over a newer one. Mirrors the
# atomic-compare-and-set style already used throughout this codebase's
# other Redis registries (see idempotency.py's ``_RESERVE_LUA`` family).
_SET_IF_NEWER_LUA = """
local cur = redis.call('HGET', KEYS[1], 'generation')
if cur and tonumber(cur) >= tonumber(ARGV[1]) then
    return 0
end
redis.call('HSET', KEYS[1],
    'generation', ARGV[1], 'state', ARGV[2], 'last_verified_at', ARGV[3], 'reason', ARGV[4])
return 1
"""


class RedisIntegrityStateRegistry:
    """Durable, multi-instance integrity-state store. One shared Redis hash
    key holds the current status; generation allocation is a plain atomic
    ``INCR`` on a sibling key; writes are a Lua compare-and-set so a stale
    write (from a crashed-and-restarted verifier, or one racing a newer
    pass) can never overwrite a newer result. Fail-closed on any Redis
    error/timeout/malformed record: every method raises
    ``IntegrityBackendUnavailable`` rather than returning an ambiguous
    value a caller might mistake for "no record yet"."""

    def __init__(
        self,
        redis_client: Any,
        *,
        key: str = "mcc:v1:default:integrity",
        op_timeout_seconds: float = DEFAULT_OP_TIMEOUT_SECONDS,
    ) -> None:
        self._redis = redis_client
        self._key = key
        self._gen_key = key + ":gen"
        self._op_timeout = op_timeout_seconds

    @classmethod
    def from_url(cls, url: str, **kwargs: Any) -> "RedisIntegrityStateRegistry":
        import redis.asyncio as redis  # local import: optional dependency in dev

        op_timeout = kwargs.pop("op_timeout_seconds", DEFAULT_OP_TIMEOUT_SECONDS)
        connect_timeout = kwargs.pop("connect_timeout_seconds", 1.0)
        client = redis.from_url(
            url, socket_timeout=op_timeout, socket_connect_timeout=connect_timeout,
            decode_responses=True,
        )
        return cls(client, op_timeout_seconds=op_timeout, **kwargs)

    async def _c(self, coro: Any) -> Any:
        return await asyncio.wait_for(coro, timeout=self._op_timeout)

    async def allocate_generation(self) -> int:
        try:
            return int(await self._c(self._redis.incr(self._gen_key)))
        except Exception as exc:  # noqa: BLE001 - any failure is "cannot allocate"
            raise IntegrityBackendUnavailable(
                f"could not allocate an integrity-verification generation: {exc}"
            ) from exc

    async def set_if_newer(
        self, *, generation: int, state: "IntegrityState", reason: str, verified_at: int
    ) -> bool:
        state_value = state.value if isinstance(state, IntegrityState) else str(state)
        try:
            res = await self._c(
                self._redis.eval(
                    _SET_IF_NEWER_LUA, 1, self._key,
                    str(int(generation)), state_value, str(int(verified_at)),
                    (reason or "")[:2000],
                )
            )
        except Exception as exc:  # noqa: BLE001
            raise IntegrityBackendUnavailable(
                f"could not persist integrity state: {exc}"
            ) from exc
        return bool(res)

    async def get(self) -> Optional[IntegrityStatus]:
        try:
            raw = await self._c(self._redis.hgetall(self._key))
        except Exception as exc:  # noqa: BLE001
            raise IntegrityBackendUnavailable(
                f"could not read integrity state: {exc}"
            ) from exc
        if not raw:
            return None
        try:
            return IntegrityStatus(
                state=IntegrityState(raw["state"]),
                reason=raw.get("reason", ""),
                last_verified_at=int(raw["last_verified_at"]),
                generation=int(raw["generation"]),
            )
        except (KeyError, ValueError) as exc:
            raise IntegrityBackendUnavailable(
                f"malformed integrity-state record in backend: {exc}"
            ) from exc


def integrity_state_registry_from_env(env: Optional[Mapping[str, str]] = None) -> Any:
    """Select an integrity-state registry from configuration.

    * ``MCC_AUDIT_INTEGRITY_BACKEND=memory`` (default) -> in-process only.
    * ``MCC_AUDIT_INTEGRITY_BACKEND=redis``            -> shared across every
      worker/instance, built from ``MCC_REDIS_URL``.

    Refuses to silently fall back: selecting ``redis`` without a usable
    ``MCC_REDIS_URL`` raises ``IntegrityConfigError`` instead of quietly
    returning an in-memory registry -- mirrors ``nonce_registry_from_env``/
    ``challenge_registry_from_env``.
    """
    env = os.environ if env is None else env
    backend = env.get("MCC_AUDIT_INTEGRITY_BACKEND", "memory").strip().lower()
    if backend in ("memory", "inmemory", "in-memory"):
        return InMemoryIntegrityStateRegistry()
    if backend == "redis":
        from . import redis_keys
        from .redis_client import RedisConfigError, redis_client_from_env

        try:
            client = redis_client_from_env(env)
        except RedisConfigError as exc:
            raise IntegrityConfigError(
                "MCC_AUDIT_INTEGRITY_BACKEND=redis requires MCC_REDIS_URL; refusing to "
                f"fall back to in-memory (non-shared) integrity state ({exc})"
            ) from exc
        return RedisIntegrityStateRegistry(
            client, key=redis_keys.singleton_key("integrity", env)
        )
    raise IntegrityConfigError(
        f"unknown MCC_AUDIT_INTEGRITY_BACKEND={backend!r}; expected 'memory' or 'redis'"
    )


# ---------------------------------------------------------------------------
# Monitor
# ---------------------------------------------------------------------------


class AuditIntegrityMonitor:
    """Runs full-chain verification passes and exposes the resulting
    fail-closed :class:`IntegrityState` to the two enforcement boundaries
    (``gateway/governance_service.py``'s issuance gate,
    ``src/mcc_core/coordinator.py``'s dispatch gate).

    ``VERIFYING`` is reported only for the lifetime of a ``verify_once()``
    call IN THIS PROCESS -- it is a local, transient flag, never written to
    the shared registry. Every OTHER process asking
    ``current_state()`` during that window sees whatever durable result
    (``HEALTHY``/``UNHEALTHY``/absent -> ``UNVERIFIED``) the registry
    currently holds, which is the only state that actually matters for a
    cross-process fail-closed decision: the shared registry's job is to
    hold the last COMPLETED outcome, not to broadcast every worker's
    transient in-flight status (a remote ``VERIFYING`` flag would need its
    own expiry/liveness tracking to avoid looking identical to a wedged
    verifier -- strictly more complexity for no additional protection, since
    callers must already fail closed on anything other than a fresh
    ``HEALTHY``).
    """

    def __init__(
        self,
        audit_log: AuditLog,
        registry: Any,
        *,
        allow_empty_bootstrap: bool = False,
        freshness_grace_seconds: float = DEFAULT_FRESHNESS_GRACE_SECONDS,
        periodic_interval_seconds: float = DEFAULT_PERIODIC_INTERVAL_SECONDS,
        time_source: Optional[TrustedTimeSource] = None,
    ) -> None:
        self._audit = audit_log
        self._registry = registry
        # Explicit trusted-bootstrap policy: a missing/empty audit file is
        # UNHEALTHY by default (fail-closed) -- "never silently accept
        # corrupted audit data" applies just as much to "there is no audit
        # data at all" as it does to a malformed record. Only an operator
        # who explicitly opts in here is asserting "a fresh start really is
        # trusted here," never an implicit default.
        self._allow_empty_bootstrap = allow_empty_bootstrap
        self._freshness_grace_seconds = _validate_positive_finite(
            freshness_grace_seconds, "freshness_grace_seconds"
        )
        self._default_periodic_interval_seconds = _validate_positive_finite(
            periodic_interval_seconds, "periodic_interval_seconds"
        )
        self._time_source: TrustedTimeSource = time_source or LocalTimeSource()
        self._run_lock = asyncio.Lock()
        self._verifying = False
        self._periodic_task: Optional["asyncio.Task[None]"] = None
        self._stop_event: Optional[asyncio.Event] = None

    # ---- the one full-chain pass ----

    async def verify_once(self) -> IntegrityState:
        """Run exactly one full-chain verification pass and durably record
        the result. Safe to call concurrently from multiple workers (the
        registry, not local state, is authoritative) and safe to call
        concurrently with ``AuditLog.append()`` (the pass is performed
        inside ``AuditLog.verify_chain_safe()``, which holds the SAME
        inter-process lock ``append()`` does)."""
        async with self._run_lock:
            self._verifying = True
            try:
                return await self._verify_once_locked()
            finally:
                self._verifying = False

    async def _verify_once_locked(self) -> IntegrityState:
        try:
            now = await self._time_source.now()
        except TimeTrustError as exc:
            # Cannot even timestamp this pass trustworthily -- fail closed
            # rather than ever record a result (HEALTHY above all) under
            # an unverified clock. Never falls back to an unchecked local
            # clock, matching every other trusted-time call site in this
            # codebase.
            return IntegrityState.UNHEALTHY

        try:
            generation = await self._registry.allocate_generation()
        except IntegrityBackendUnavailable:
            # Cannot even allocate a generation -> cannot durably record
            # any outcome of this pass -> fail closed without attempting
            # the (possibly expensive) scan at all.
            return IntegrityState.UNHEALTHY

        ok: bool
        reason: str
        path = self._audit.path
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            # Explicit trusted-bootstrap policy (see __init__). This check
            # happens outside AuditLog's own lock -- a tiny, strictly
            # SAFE race window: if a concurrent append() creates/extends
            # the file a moment later, the worst case is that this pass
            # treats a now-nonexistent "empty" state as bootstrap when a
            # real record already exists, which the NEXT pass (run at the
            # configured periodic interval) sees and correctly verifies.
            # It can never cause a genuinely corrupted, non-empty file to
            # be mistaken for an empty one.
            if self._allow_empty_bootstrap:
                ok, reason = True, "audit file missing or empty; trusted empty bootstrap"
            else:
                ok, reason = False, (
                    "AUDIT_FILE_MISSING_OR_EMPTY: no audit data exists and "
                    "allow_empty_bootstrap is False; fail-closed (an explicit "
                    "trusted-bootstrap decision is required)"
                )
        else:
            try:
                ok = await asyncio.to_thread(self._audit.verify_chain_safe)
            except Exception as exc:  # noqa: BLE001 - AuditLockError or any I/O failure
                ok = False
                exc = exc  # noqa: PLW2901 - keep name for the f-string below
                reason = f"VERIFICATION_ERROR: {type(exc).__name__}: {exc}"
            else:
                reason = "chain intact" if ok else "hash-chain verification failed"

        state = IntegrityState.HEALTHY if ok else IntegrityState.UNHEALTHY
        try:
            await self._registry.set_if_newer(
                generation=generation, state=state, reason=reason, verified_at=now,
            )
        except IntegrityBackendUnavailable:
            # The scan itself may have succeeded, but the result could not
            # be durably recorded -- a result no one else can observe is
            # not a healthy result. Fail closed.
            return IntegrityState.UNHEALTHY
        return state

    async def run_startup_verification(self) -> IntegrityState:
        """Run one verification pass synchronously. Callers (e.g.
        ``build_governance_service()``) must await this BEFORE issuing any
        executable authority -- this is what turns ``UNVERIFIED`` into a
        real, evidence-backed state before the process does anything else."""
        return await self.verify_once()

    # ---- the fail-closed read every gate calls ----

    async def current_state(self) -> IntegrityState:
        """The single question every enforcement boundary asks. Fail-closed
        on every ambiguous or unfavorable answer: an unreachable registry,
        a stale HEALTHY, a genuinely UNHEALTHY result, or no result at all
        (``UNVERIFIED``) are all reported as something other than
        ``HEALTHY`` -- only a FRESH, explicitly recorded ``HEALTHY`` pass
        ever satisfies ``is_healthy()``."""
        if self._verifying:
            return IntegrityState.VERIFYING
        try:
            status = await self._registry.get()
        except IntegrityBackendUnavailable:
            return IntegrityState.UNHEALTHY
        if status is None:
            return IntegrityState.UNVERIFIED
        if status.state != IntegrityState.HEALTHY:
            # verify_once() only ever persists HEALTHY or UNHEALTHY -- this
            # is always UNHEALTHY in practice, returned via status.state
            # rather than a hardcoded constant so a malformed/unexpected
            # stored value is surfaced verbatim rather than silently
            # coerced.
            return status.state
        try:
            now = await self._time_source.now()
        except TimeTrustError:
            return IntegrityState.UNHEALTHY
        age = now - (status.last_verified_at or 0)
        if age > self._freshness_grace_seconds:
            return IntegrityState.UNHEALTHY
        return IntegrityState.HEALTHY

    async def status(self) -> Optional[IntegrityStatus]:
        """The raw stored status (for diagnostics/``/ready`` reporting), not
        the freshness-adjusted fail-closed state -- use ``current_state()``
        for any enforcement decision."""
        try:
            return await self._registry.get()
        except IntegrityBackendUnavailable:
            return None

    # ---- periodic background verification ----

    def start_periodic_verification(
        self, interval_seconds: Optional[float] = None
    ) -> "asyncio.Task[None]":
        """Start (or return the already-running) background verification
        loop on THIS event loop. Must be called from a running event loop
        (e.g. an HTTP framework's startup hook) -- never from inside
        ``build_governance_service()`` itself, which runs before any loop
        exists. Each pass is ``verify_once()``, entirely off any
        request-handling path; the blocking file I/O inside it is itself
        offloaded to a worker thread (``asyncio.to_thread``), so this loop
        never blocks other coroutines even for a large audit file."""
        if self._periodic_task is not None and not self._periodic_task.done():
            return self._periodic_task
        interval = _validate_positive_finite(
            interval_seconds if interval_seconds is not None
            else self._default_periodic_interval_seconds,
            "interval_seconds",
        )
        self._stop_event = asyncio.Event()

        async def _loop() -> None:
            stop_event = self._stop_event
            assert stop_event is not None
            while not stop_event.is_set():
                try:
                    await self.verify_once()
                except Exception:  # noqa: BLE001
                    # verify_once() is designed to never raise for ordinary
                    # failures (it records UNHEALTHY instead) -- this is a
                    # last-resort guard so a genuinely unexpected exception
                    # can never silently kill the loop without at least
                    # letting it try again next interval. It never causes a
                    # HEALTHY result to be recorded.
                    pass
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=interval)
                except asyncio.TimeoutError:
                    pass

        self._periodic_task = asyncio.ensure_future(_loop())
        return self._periodic_task

    async def stop_periodic_verification(self) -> None:
        if self._stop_event is not None:
            self._stop_event.set()
        task, self._periodic_task = self._periodic_task, None
        if task is not None:
            try:
                await asyncio.wait_for(task, timeout=5.0)
            except asyncio.TimeoutError:
                task.cancel()
            except asyncio.CancelledError:
                pass
