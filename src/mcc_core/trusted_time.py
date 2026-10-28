"""Trusted time: a reusable, testable clock-trust boundary for every
security-critical validity-window check in this codebase (approval
expiration, mandate `nbf`/`exp`, decision-token `nbf`/`exp`).

Why this exists
----------------
Every wall-clock check in this codebase used to resolve an unchecked
``time.time()`` independently, per call site, per process. A single
gateway instance is fine in isolation, but a FLEET of gateway instances
each trusting its own local clock has no guarantee those clocks agree.
A gateway instance whose clock lags true time will accept an approval or
mandate as "not yet expired" after a correctly-clocked instance would
correctly reject it — not because of a logic bug in the expiry check
itself (see ``approvals.py``'s ``_logically_expired`` / the Lua TTL fix),
but because the INPUT to that check (``now``) was never verified to be
trustworthy in the first place.

This module does not change what "expired" means; it changes where
``now`` comes from and what happens when it cannot be trusted.

Design
------
* :class:`TrustedTimeSource` is the boundary every security-critical
  default-``now`` resolution in ``approvals.py``/``mandate.py``/
  ``governance_service.py`` goes through, replacing a bare ``time.time()``
  fallback.
* :class:`LocalTimeSource` is the explicit, zero-new-dependency choice for
  deployments that do not run Redis (or run a single gateway instance):
  this process's own clock, with the SAME operational assumption this
  repo has always had (keep it NTP-synchronized) — now named and
  testable rather than implicit.
* :class:`RedisTimeSource` is the shared-authority choice for Redis-backed
  (multi-instance) deployments: every instance asks the SAME Redis
  server's ``TIME`` command, which by construction eliminates
  INTER-INSTANCE clock skew (there is only one clock being asked). A
  shared clock is not automatically a TRUSTWORTHY one, so every sample is
  validated before use: availability (the call must succeed within a
  bounded timeout), freshness (the round trip itself must not have taken
  so long the sample is stale by the time it's used), skew against this
  process's own local clock (catches a misconfigured/wrong Redis server
  clock — a single shared wrong clock is still wrong), and rollback
  (a later sample may never report an earlier time than a previously
  observed one, beyond a small tolerance for legitimate NTP slew).
* On any failure, :class:`TimeTrustError` is raised with a stable
  ``reason`` code (``CLOCK_UNTRUSTED``, ``CLOCK_SKEW_EXCEEDED``,
  ``CLOCK_ROLLBACK_DETECTED``). Callers in this codebase NEVER catch this
  and silently fall back to an unchecked ``time.time()`` — they fail
  closed (deny / block / refuse), per
  ``gateway/governance_service.py``, ``src/mcc_core/approvals.py``, and
  ``src/mcc_core/mandate.py``.

Deterministic testing stays separate from this module entirely: every
function this module feeds (``ApprovalService.request/approve/deny/
invalidate/consume``, ``MandateVerifier.verify``) already accepts an
explicit ``now: Optional[int]`` parameter. When a caller supplies one,
IT is used verbatim and this module is never consulted — that explicit
parameter (reachable only from test code and from values this process
itself already resolved, never from an HTTP request body or other
caller-controlled input) is, and remains, the sole "isolated test
interface" for synthetic-clock determinism. This module only supplies
the DEFAULT when no explicit ``now`` is given.
"""

from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from typing import Any, Mapping, Optional

DEFAULT_MAX_SKEW_SECONDS = 5.0
DEFAULT_MAX_ROUND_TRIP_SECONDS = 2.0
DEFAULT_ROLLBACK_TOLERANCE_SECONDS = 1.0
DEFAULT_OP_TIMEOUT_SECONDS = 1.0


class TimeTrustError(Exception):
    """Raised when a trusted-time source cannot produce a trustworthy
    ``now``. Carries a stable ``reason`` code; callers fail closed and
    never substitute an unchecked local clock."""

    def __init__(self, reason: str, detail: str) -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}")


class TrustedTimeSource(ABC):
    """A source of trustworthy wall-clock time, in whole seconds since the
    epoch. Raises :class:`TimeTrustError` (never returns a value it cannot
    stand behind) when it cannot currently produce one."""

    @abstractmethod
    async def now(self) -> int: ...


class LocalTimeSource(TrustedTimeSource):
    """This process's own clock. The explicit choice for deployments that
    do not run Redis, or that run a single gateway instance — introduces
    no new dependency and matches this repo's pre-existing behavior
    exactly. Operationally requires this clock to be NTP-synchronized;
    that requirement is now explicit and named rather than silently
    assumed inside a bare ``time.time()`` call."""

    async def now(self) -> int:
        return int(time.time())


class RedisTimeSource(TrustedTimeSource):
    """A shared authoritative clock for Redis-backed, multi-instance
    deployments: every instance asks the SAME Redis server's own ``TIME``
    command, eliminating inter-instance skew by construction. Every
    sample is independently validated (availability, freshness, skew
    against this process's own clock, rollback) before being trusted —
    a shared clock is not automatically a trustworthy one."""

    def __init__(
        self,
        redis_client: Any,
        *,
        max_skew_seconds: float = DEFAULT_MAX_SKEW_SECONDS,
        max_round_trip_seconds: float = DEFAULT_MAX_ROUND_TRIP_SECONDS,
        rollback_tolerance_seconds: float = DEFAULT_ROLLBACK_TOLERANCE_SECONDS,
        op_timeout_seconds: float = DEFAULT_OP_TIMEOUT_SECONDS,
    ) -> None:
        self._redis = redis_client
        self._max_skew = max_skew_seconds
        self._max_round_trip = max_round_trip_seconds
        self._rollback_tolerance = rollback_tolerance_seconds
        self._op_timeout = op_timeout_seconds
        self._last_seen: Optional[int] = None

    async def now(self) -> int:
        t_before = time.time()
        try:
            secs, _micros = await asyncio.wait_for(
                self._redis.time(), timeout=self._op_timeout
            )
        except Exception as exc:
            raise TimeTrustError(
                "CLOCK_UNTRUSTED", f"redis TIME unavailable: {exc}"
            ) from exc
        t_after = time.time()

        round_trip = t_after - t_before
        if round_trip > self._max_round_trip:
            raise TimeTrustError(
                "CLOCK_UNTRUSTED",
                f"stale sample: round-trip {round_trip:.3f}s exceeds "
                f"{self._max_round_trip:.3f}s; the returned timestamp "
                "cannot be trusted as current",
            )

        redis_now = int(secs)
        # Midpoint estimate of this process's own clock at the moment the
        # sample was in flight -- a fairer comparison than either endpoint
        # alone for a round trip that took measurable time.
        local_reference = (t_before + t_after) / 2.0
        skew = abs(redis_now - local_reference)
        if skew > self._max_skew:
            raise TimeTrustError(
                "CLOCK_SKEW_EXCEEDED",
                f"redis clock drift {skew:.3f}s exceeds the {self._max_skew:.3f}s "
                "trust margin against this process's own clock",
            )

        if self._last_seen is not None and redis_now < self._last_seen - self._rollback_tolerance:
            raise TimeTrustError(
                "CLOCK_ROLLBACK_DETECTED",
                f"redis TIME returned {redis_now}, which is before a previously "
                f"observed {self._last_seen} (tolerance {self._rollback_tolerance:.3f}s)",
            )
        self._last_seen = max(self._last_seen or redis_now, redis_now)
        return redis_now


class TimeTrustConfigError(Exception):
    """Raised when the time-trust backend is misconfigured (fail-closed start)."""


def trusted_time_source_from_env(env: Optional[Mapping[str, str]] = None) -> TrustedTimeSource:
    """Build the default :class:`TrustedTimeSource` for this process from the
    environment. Defaults to :class:`LocalTimeSource` -- Redis is never an
    unconditional dependency; a deployment opts into the shared-clock
    behavior explicitly via ``MCC_TIME_TRUST_BACKEND=redis``."""
    import os

    env = os.environ if env is None else env
    backend = env.get("MCC_TIME_TRUST_BACKEND", "local").strip().lower()
    if backend in ("local", "", "none"):
        return LocalTimeSource()
    if backend == "redis":
        from .redis_client import RedisConfigError, redis_client_from_env

        try:
            client = redis_client_from_env(env)
        except RedisConfigError as exc:
            raise TimeTrustConfigError(
                "MCC_TIME_TRUST_BACKEND=redis requires MCC_REDIS_URL; refusing to "
                f"start with an unverified time source ({exc})"
            ) from exc

        def _f(key: str, default: float) -> float:
            v = env.get(key)
            try:
                return float(v) if v not in (None, "") else default
            except (TypeError, ValueError):
                return default

        return RedisTimeSource(
            client,
            max_skew_seconds=_f("MCC_CLOCK_MAX_SKEW_SECONDS", DEFAULT_MAX_SKEW_SECONDS),
            max_round_trip_seconds=_f(
                "MCC_CLOCK_MAX_ROUND_TRIP_SECONDS", DEFAULT_MAX_ROUND_TRIP_SECONDS
            ),
            rollback_tolerance_seconds=_f(
                "MCC_CLOCK_ROLLBACK_TOLERANCE_SECONDS", DEFAULT_ROLLBACK_TOLERANCE_SECONDS
            ),
        )
    raise TimeTrustConfigError(
        f"unknown MCC_TIME_TRUST_BACKEND={backend!r}; expected 'local' or 'redis'"
    )
