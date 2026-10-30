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
    VERIFYING  -- diagnostic only (e.g. ``/ready``): a verification pass is
                  in flight, in THIS process. NEVER consulted by
                  ``current_state()``'s gating decision (hardening-round
                  Finding 4) -- a pass happening to be running right now
                  does not make the last DURABLY RECORDED result any less
                  trustworthy, so gating never blocks on this alone.
    HEALTHY    -- the most recently completed pass found the chain intact,
                  that result is still "fresh" (see below), AND (when
                  known) it was computed over THIS worker's own audit log,
                  not a different one sharing the same registry key
                  (hardening-round Finding 3).
    UNHEALTHY  -- the most recent pass failed, OR the last known-HEALTHY
                  result is stale, OR it belongs to a different audit log
                  than this worker's own, OR the shared state backend
                  cannot currently be reached/read.

Only ``HEALTHY`` ever satisfies a gate check. Every other state blocks --
deliberately simple and boolean-shaped for callers (fail-closed by
construction: an unrecognized or unreachable state is never treated as
"probably fine").

Trusted bootstrap is ONE-TIME, not a standing permission
----------------------------------------------------------
``allow_empty_bootstrap=True`` only ever has effect for a genuinely fresh
deployment that has NEVER recorded anything. The moment this audit log is
observed non-empty -- by this process's own ``AuditLog.prev_hash`` (zero
delay) or by a durable, cross-worker, one-way registry latch
(``mark_initialized``/``is_initialized``) -- an empty/missing file is
UNHEALTHY forever after, regardless of ``allow_empty_bootstrap``'s
configured value. There is no method anywhere in this module that clears
that latch; a confirmed-corrupted deployment's recovery is always an
explicit, out-of-band operator action (see
``docs/AUDIT_INTEGRITY_ENFORCEMENT.md``), never something a code path here
does automatically.

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

**Deployment invariant (mechanically checked, not merely assumed):** every
worker sharing one integrity-state registry key MUST point at the exact
same physical audit log, on shared, consistent storage. This is no longer
just documented -- ``current_state()`` compares the registry's recorded
``log_identity`` (an ``AuditLog.genesis_fingerprint_safe()`` fingerprint)
against THIS worker's own most recently observed identity and fails closed
on a mismatch, so a worker that is (via misconfiguration, or a
corrupted/replaced local file) actually looking at a DIFFERENT audit log
can never silently inherit another worker's ``HEALTHY`` result for itself.

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

from .audit import GENESIS, AuditLog
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
    # Finding 3 (hardening round): an identity fingerprint for the SPECIFIC
    # audit log this result was computed over (AuditLog.genesis_fingerprint_safe()).
    # None only for a result recorded while the file was empty/missing (no
    # genesis record exists yet to fingerprint). See AuditIntegrityMonitor's
    # own identity check in current_state().
    log_identity: Optional[str] = None


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
        # Finding 1 (hardening round, P1): a durable (for this process's
        # lifetime), ONE-WAY latch -- once the audit log has ever been
        # observed genuinely non-empty, it stays "initialized" forever.
        # Nothing in this class ever clears it; there is deliberately no
        # method that does.
        self._initialized = False

    async def allocate_generation(self) -> int:
        with self._lock:
            self._generation += 1
            return self._generation

    async def set_if_newer(
        self, *, generation: int, state: "IntegrityState", reason: str, verified_at: int,
        log_identity: Optional[str] = None,
    ) -> bool:
        with self._lock:
            if self._status is not None and generation <= self._status.generation:
                return False
            # A pass that observed an empty/missing file (log_identity is
            # None) must never blank out a previously-recorded identity --
            # it simply has nothing new to report about identity.
            prior_identity = self._status.log_identity if self._status is not None else None
            self._status = IntegrityStatus(
                state=state, reason=reason, last_verified_at=verified_at, generation=generation,
                log_identity=log_identity if log_identity is not None else prior_identity,
            )
            return True

    async def get(self) -> Optional[IntegrityStatus]:
        with self._lock:
            return self._status

    async def mark_initialized(self) -> None:
        with self._lock:
            self._initialized = True

    async def is_initialized(self) -> bool:
        with self._lock:
            return self._initialized

    async def aclose(self) -> None:
        """No real connection to tear down -- present only so callers can
        treat every registry backend uniformly (see
        ``AuditIntegrityMonitor.reset_connections_for_new_event_loop``)."""
        return None


# Lua CAS: only applies the write if the new generation is strictly greater
# than whatever generation is currently stored -- the primitive that makes
# a crashed-and-restarted verifier (or a slow/delayed write racing a newer
# one) unable to resurrect a stale result over a newer one. Mirrors the
# atomic-compare-and-set style already used throughout this codebase's
# other Redis registries (see idempotency.py's ``_RESERVE_LUA`` family).
# ARGV[5] (log_identity) is only applied when non-empty -- a pass that
# observed an empty/missing file has no identity to report and must never
# blank out a previously-recorded one (Finding 3, hardening round).
_SET_IF_NEWER_LUA = """
local cur = redis.call('HGET', KEYS[1], 'generation')
if cur and tonumber(cur) >= tonumber(ARGV[1]) then
    return 0
end
redis.call('HSET', KEYS[1],
    'generation', ARGV[1], 'state', ARGV[2], 'last_verified_at', ARGV[3], 'reason', ARGV[4])
if ARGV[5] ~= '' then
    redis.call('HSET', KEYS[1], 'log_identity', ARGV[5])
end
return 1
"""

# Finding 1 (hardening round, P1): SET ... NX is the atomic, race-safe
# primitive for a durable, cross-worker, ONE-WAY "has this audit log ever
# been observed genuinely initialized" latch -- the first writer wins, every
# later writer is a no-op, and there is deliberately no DEL/reset exposed
# anywhere in this module (an authorized disaster-recovery reset is an
# explicit, out-of-band operator action -- see
# docs/AUDIT_INTEGRITY_ENFORCEMENT.md -- never an in-band API call).
_BOOTSTRAP_LATCH_VALUE = "1"


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
        self._bootstrap_key = key + ":bootstrap"
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
        self, *, generation: int, state: "IntegrityState", reason: str, verified_at: int,
        log_identity: Optional[str] = None,
    ) -> bool:
        state_value = state.value if isinstance(state, IntegrityState) else str(state)
        try:
            res = await self._c(
                self._redis.eval(
                    _SET_IF_NEWER_LUA, 1, self._key,
                    str(int(generation)), state_value, str(int(verified_at)),
                    (reason or "")[:2000], (log_identity or ""),
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
                log_identity=raw.get("log_identity") or None,
            )
        except (KeyError, ValueError) as exc:
            raise IntegrityBackendUnavailable(
                f"malformed integrity-state record in backend: {exc}"
            ) from exc

    async def mark_initialized(self) -> None:
        """Atomic, idempotent, one-way latch (Finding 1, hardening round):
        the first call durably records "this audit log has been observed
        genuinely initialized"; every later call -- from any worker -- is a
        no-op against the same key. There is deliberately no method on this
        class that clears it."""
        try:
            await self._c(self._redis.set(self._bootstrap_key, _BOOTSTRAP_LATCH_VALUE, nx=True))
        except Exception as exc:  # noqa: BLE001
            raise IntegrityBackendUnavailable(
                f"could not persist audit-log initialization latch: {exc}"
            ) from exc

    async def is_initialized(self) -> bool:
        try:
            val = await self._c(self._redis.get(self._bootstrap_key))
        except Exception as exc:  # noqa: BLE001
            raise IntegrityBackendUnavailable(
                f"could not read audit-log initialization latch: {exc}"
            ) from exc
        return val is not None

    async def aclose(self) -> None:
        """Disconnect this registry's Redis connections (Finding 2,
        hardening round). Call this inside the SAME event loop that first
        used this registry's client, immediately before that loop is torn
        down (e.g. at the end of a throwaway ``asyncio.run()`` startup
        check), so a LATER, different event loop (the real server loop)
        lazily establishes brand-new connections rather than reusing
        transport objects bound to a now-closed loop. Best-effort: a
        failure here is not fatal (the client will simply reconnect fresh
        on next use regardless)."""
        try:
            await self._redis.aclose()
        except Exception:  # noqa: BLE001
            pass


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
        # Finding 3 (hardening round): this worker's OWN most recently
        # observed identity fingerprint for the audit log it is itself
        # configured against (AuditLog.genesis_fingerprint_safe(), set by
        # this instance's own verify_once() passes). Compared against the
        # shared registry's recorded identity in current_state() -- never
        # blindly inherited. None until this instance's own first pass
        # over a genuinely non-empty file completes.
        self._last_observed_identity: Optional[str] = None

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

        # Finding 1 (hardening round, P1): the trusted-bootstrap policy
        # (``allow_empty_bootstrap``) is a ONE-TIME grant for a genuinely
        # fresh deployment -- never a standing permission to treat a LATER
        # empty/missing file (deletion, truncation, unauthorized
        # replacement, after real history already existed) as a fresh
        # bootstrap. ``ever_initialized`` is true the moment EITHER (a)
        # this process's own AuditLog has itself durably appended at least
        # one entry (``prev_hash`` advances off GENESIS instantly, with
        # zero delay, the moment that happens -- no registry round trip
        # needed to protect the very process that is doing the writing),
        # or (b) the durable, cross-process, one-way registry latch is
        # already set (by this worker's own prior pass, or by any other
        # worker's). Once true, it can never again become false here.
        try:
            ever_initialized = await self._registry.is_initialized()
        except IntegrityBackendUnavailable:
            return IntegrityState.UNHEALTHY
        if not ever_initialized and self._audit.prev_hash != GENESIS:
            ever_initialized = True

        ok: bool
        reason: str
        observed_identity: Optional[str] = None
        path = self._audit.path
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            # This check happens outside AuditLog's own lock -- a tiny,
            # strictly SAFE race window: if a concurrent append()
            # creates/extends the file a moment later, the worst case is
            # that this pass treats a now-nonexistent "empty" state as
            # bootstrap when a real record already exists, which the NEXT
            # pass (or this same process's own ``ever_initialized`` fast
            # path above, for every pass after that append lands) sees and
            # correctly verifies. It can never cause a genuinely corrupted,
            # non-empty file to be mistaken for an empty one.
            if ever_initialized:
                ok, reason = False, (
                    "AUDIT_FILE_MISSING_OR_EMPTY_AFTER_INITIALIZATION: audit history was "
                    "previously initialized (observed non-empty); an empty/missing file "
                    "now indicates deletion, truncation, or unauthorized replacement -- "
                    "not a fresh bootstrap -- fail-closed regardless of allow_empty_bootstrap"
                )
            elif self._allow_empty_bootstrap:
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
                reason = f"VERIFICATION_ERROR: {type(exc).__name__}: {exc}"
            else:
                reason = "chain intact" if ok else "hash-chain verification failed"
            # The file is genuinely non-empty -- latch "initialized"
            # durably (idempotent SET-if-not-exists; a cheap no-op once
            # already set by this worker or any other). Always attempted
            # on every non-empty pass, not only the first one THIS
            # instance notices via its own prev_hash fast path above, so
            # the durable, cross-worker latch converges as soon as
            # possible regardless of which worker's pass first observes
            # non-emptiness. Corrupt-but-nonempty latches too: that is
            # also definitely not "a fresh bootstrap" either. If this
            # durable write cannot be confirmed, the result of this pass
            # cannot be trusted as durably recorded -- fail closed.
            try:
                await self._registry.mark_initialized()
            except IntegrityBackendUnavailable:
                return IntegrityState.UNHEALTHY
            try:
                observed_identity = await asyncio.to_thread(self._audit.genesis_fingerprint_safe)
            except Exception:  # noqa: BLE001
                observed_identity = None
            if observed_identity is not None:
                self._last_observed_identity = observed_identity

        state = IntegrityState.HEALTHY if ok else IntegrityState.UNHEALTHY
        try:
            await self._registry.set_if_newer(
                generation=generation, state=state, reason=reason, verified_at=now,
                log_identity=observed_identity,
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
        a stale HEALTHY, an identity mismatch, a genuinely UNHEALTHY
        result, or no result at all (``UNVERIFIED``) are all reported as
        something other than ``HEALTHY`` -- only a FRESH, explicitly
        recorded ``HEALTHY`` pass, over THIS worker's own audit log, ever
        satisfies ``is_healthy()``.

        Finding 4 (hardening round): deliberately does NOT consult
        ``self._verifying`` -- a verification pass happening to be in
        flight in THIS process right now does not, by itself, make the
        last DURABLY RECORDED result any less trustworthy, so gating must
        never block on that alone (that would turn every routine periodic
        pass into an avoidable, self-inflicted mini-outage with no
        corresponding security benefit). ``self._verifying`` remains
        available as diagnostic-only information via
        ``verification_in_progress`` (e.g. for ``/ready`` reporting).
        """
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
        # Finding 3 (hardening round): a stored HEALTHY result is only
        # trustworthy for THIS worker if it was computed over the SAME
        # underlying audit log this worker is itself configured against --
        # never blindly inherited across workers that might (via
        # misconfiguration, or a corrupted/replaced local file) be looking
        # at something different. Skipped only while this worker has not
        # yet completed its OWN first pass over a non-empty file
        # (``_last_observed_identity`` is still None) -- every production
        # deployment path runs a mandatory synchronous startup
        # verification before this monitor is ever wired into a gate (see
        # ``run_startup_verification``), so that window is not reachable
        # from a real enforcement decision in practice.
        if (
            status.log_identity is not None
            and self._last_observed_identity is not None
            and status.log_identity != self._last_observed_identity
        ):
            return IntegrityState.UNHEALTHY
        try:
            now = await self._time_source.now()
        except TimeTrustError:
            return IntegrityState.UNHEALTHY
        age = now - (status.last_verified_at or 0)
        if age > self._freshness_grace_seconds:
            return IntegrityState.UNHEALTHY
        return IntegrityState.HEALTHY

    @property
    def verification_in_progress(self) -> bool:
        """Diagnostic only (e.g. ``/ready``) -- NEVER consulted by
        ``current_state()`` for a gating decision (see Finding 4's fix
        above)."""
        return self._verifying

    async def reset_connections_for_new_event_loop(self) -> None:
        """Finding 2 (hardening round): tear down this monitor's registry
        backend connections (if any), still inside the SAME event loop
        that first used them, immediately before that loop is torn down.
        Call this right after a one-off synchronous startup check (e.g.
        inside the same ``asyncio.run(...)`` call, before it returns) so a
        LATER, different event loop (the real server loop that will run
        the periodic task and every live request's ``current_state()``
        call) lazily establishes fresh connections instead of reusing
        transport objects bound to a now-closed loop -- redis-py's asyncio
        client does not tolerate being used across event loops. A no-op
        for a registry with nothing to disconnect (e.g.
        ``InMemoryIntegrityStateRegistry``).
        """
        closer = getattr(self._registry, "aclose", None)
        if closer is not None:
            await closer()

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
