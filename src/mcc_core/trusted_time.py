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
import math
import time
from abc import ABC, abstractmethod
from typing import Any, Mapping, Optional

DEFAULT_MAX_SKEW_SECONDS = 5.0
DEFAULT_MAX_ROUND_TRIP_SECONDS = 2.0
DEFAULT_ROLLBACK_TOLERANCE_SECONDS = 1.0
DEFAULT_OP_TIMEOUT_SECONDS = 1.0

# An upper bound past which a configured threshold is not a meaningful
# trust margin anymore (e.g. years) -- rejected as an unsafe configuration
# range rather than silently accepted as "basically disables the check".
_MAX_SAFE_THRESHOLD_SECONDS = 86_400.0  # 24h


def _validate_positive_finite(value: Any, field_name: str) -> float:
    """Fail closed on a NaN, infinite, non-numeric, non-positive, or
    absurdly large threshold -- any of these would silently disable (NaN/
    inf: every comparison against them is False; non-positive: the check
    rejects every real sample) or render meaningless the trust check this
    value configures. Never clamps or coerces: an unsafe value is a
    configuration error, raised at construction time, not papered over."""
    try:
        v = float(value)
    except (TypeError, ValueError) as exc:
        raise TimeTrustConfigError(f"{field_name}={value!r} is not a valid number") from exc
    if math.isnan(v):
        raise TimeTrustConfigError(f"{field_name} must not be NaN")
    if math.isinf(v):
        raise TimeTrustConfigError(f"{field_name} must not be infinite")
    if v <= 0:
        raise TimeTrustConfigError(f"{field_name}={v!r} must be a positive number")
    if v > _MAX_SAFE_THRESHOLD_SECONDS:
        raise TimeTrustConfigError(
            f"{field_name}={v!r} exceeds the safe configuration range "
            f"(> {_MAX_SAFE_THRESHOLD_SECONDS:.0f}s); refusing a threshold "
            "wide enough to be meaningless"
        )
    return v


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
        # Validated here, not just at the env-parsing boundary, so every
        # construction path (direct, test, or env-driven) is protected: a
        # NaN or infinite threshold would make `skew > max_skew` always
        # False in Python, SILENTLY DISABLING the check it exists to
        # enforce; a negative or zero one would make every real clock
        # reading fail the round-trip/skew bound spuriously. Fail closed
        # at construction time, never at first use.
        self._max_skew = _validate_positive_finite(max_skew_seconds, "max_skew_seconds")
        self._max_round_trip = _validate_positive_finite(
            max_round_trip_seconds, "max_round_trip_seconds"
        )
        self._rollback_tolerance = _validate_positive_finite(
            rollback_tolerance_seconds, "rollback_tolerance_seconds"
        )
        self._op_timeout = _validate_positive_finite(op_timeout_seconds, "op_timeout_seconds")
        self._last_seen: Optional[int] = None

    async def now(self) -> int:
        # Two independent clock pairs are sampled around the SAME Redis
        # call, each used only for the comparison it is actually valid
        # for:
        #   * wall_before/wall_after (time.time()): a genuine UTC/epoch
        #     sample, required to compare against Redis TIME's own
        #     epoch-based reply for the skew check below. Monotonic time
        #     has no epoch and cannot stand in for this.
        #   * mono_before/mono_after (time.monotonic()): a pure DURATION
        #     measurement for the round-trip/freshness check. Using
        #     time.time() for a duration is unsafe: an NTP step or manual
        #     wall-clock adjustment DURING the round trip would corrupt
        #     the measured elapsed time -- a backward step could make a
        #     genuinely slow (stale) round trip look instantaneous
        #     (silently accepting a stale sample), and a forward step
        #     could make a genuinely fast round trip look like it
        #     exceeded the bound (a spurious CLOCK_UNTRUSTED). monotonic()
        #     is immune to both by definition: it never jumps.
        wall_before = time.time()
        mono_before = time.monotonic()
        try:
            secs, _micros = await asyncio.wait_for(
                self._redis.time(), timeout=self._op_timeout
            )
        except Exception as exc:
            raise TimeTrustError(
                "CLOCK_UNTRUSTED", f"redis TIME unavailable: {exc}"
            ) from exc
        wall_after = time.time()
        mono_after = time.monotonic()

        round_trip = mono_after - mono_before
        if round_trip > self._max_round_trip:
            raise TimeTrustError(
                "CLOCK_UNTRUSTED",
                f"stale sample: round-trip {round_trip:.3f}s exceeds "
                f"{self._max_round_trip:.3f}s; the returned timestamp "
                "cannot be trusted as current",
            )

        redis_now = int(secs)
        # Midpoint estimate of this process's own wall clock at the moment
        # the sample was in flight -- a fairer comparison than either
        # endpoint alone for a round trip that took measurable time. This
        # MUST be wall-clock (not monotonic): it is compared directly
        # against Redis TIME's epoch-seconds reply.
        local_reference = (wall_before + wall_after) / 2.0
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
            if v in (None, ""):
                return default
            # An explicitly-set value that fails to parse as a plain
            # number is a configuration error, raised here rather than
            # silently replaced by the default -- RedisTimeSource's own
            # constructor additionally rejects NaN/infinite/non-positive/
            # absurdly-large values (the ones a bare ``float()`` parse
            # would NOT catch, e.g. "nan"/"inf" parse successfully).
            try:
                return float(v)
            except (TypeError, ValueError) as exc:
                raise TimeTrustConfigError(f"{key}={v!r} is not a valid number") from exc

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
