"""PR #122 round 5, item 2: ``RedisTimeSource.now()`` must measure its own
round-trip/freshness duration with ``time.monotonic()``, never
``time.time()``.

Why this matters
-----------------
``round_trip`` (the freshness/staleness bound) is a DURATION: "how long did
this Redis call actually take". ``time.time()`` is NOT safe for measuring a
duration, because it can jump -- forward or backward -- at any moment due to
NTP step corrections or a manual wall-clock adjustment. If such a jump
happens WHILE the Redis TIME call is in flight:

* A BACKWARD wall-clock jump during a genuinely SLOW round trip could make
  ``wall_after - wall_before`` come out small or even negative, silently
  masking a stale sample that should have been rejected as
  ``CLOCK_UNTRUSTED``.
* A FORWARD wall-clock jump during a genuinely FAST round trip could make
  ``wall_after - wall_before`` come out larger than the configured bound,
  causing a spurious ``CLOCK_UNTRUSTED`` rejection of a perfectly healthy
  sample.

``time.monotonic()`` is immune to both: it never jumps, by definition, so it
is the only clock immune to the exact adversarial condition this module
exists to defend against (an untrustworthy ambient clock).

The skew check (comparing Redis TIME's epoch-seconds reply against this
process's own clock) is a different kind of comparison -- a genuine UTC/
epoch comparison -- and correctly continues to use ``time.time()``, which
has no substitute there (``time.monotonic()`` has no epoch).

These tests mock ``time.time``/``time.monotonic`` to deterministically
inject a wall-clock jump DURING one ``now()`` call, without any real
``sleep()``, and assert the round-trip check reacts to the MONOTONIC gap
only -- never to the simulated wall-clock jump.
"""

from __future__ import annotations

import asyncio
import sys
import time as _time_module

import pytest

from mcc_core.trusted_time import RedisTimeSource, TimeTrustError

run = asyncio.run


class _StubRedis:
    """Returns a fixed TIME reply; the actual redis round trip is not what
    is under test here -- the wall-clock/monotonic sampling around it is."""

    def __init__(self, reply_secs: int):
        self._reply_secs = reply_secs

    async def time(self):
        return (self._reply_secs, 0)


def _sequence(monkeypatch, *, wall_values, mono_values):
    """Patches time.time()/time.monotonic() to return successive values
    from each list, in order, but ONLY for calls made directly from
    mcc_core.trusted_time itself -- deterministically standing in for
    the exact two calls RedisTimeSource.now() makes to each clock.

    ``time`` is a single process-wide module, so patching it unconditionally
    would also reach asyncio's own internal scheduling (``asyncio.wait_for``'s
    ``call_later`` consults ``time.monotonic()`` for its own timeout
    bookkeeping) and interleave an extra, unpredictable call into the
    sequence. Calls from any other module (identified by the immediate
    caller's ``__name__``) fall through to the REAL clock, so the event
    loop keeps working normally and only the two calls under test are
    deterministically controlled.
    """
    real_time, real_monotonic = _time_module.time, _time_module.monotonic
    wall_it = iter(wall_values)
    mono_it = iter(mono_values)

    def fake_time():
        if sys._getframe(1).f_globals.get("__name__") == "mcc_core.trusted_time":
            return next(wall_it)
        return real_time()

    def fake_monotonic():
        if sys._getframe(1).f_globals.get("__name__") == "mcc_core.trusted_time":
            return next(mono_it)
        return real_monotonic()

    monkeypatch.setattr("mcc_core.trusted_time.time.time", fake_time)
    monkeypatch.setattr("mcc_core.trusted_time.time.monotonic", fake_monotonic)


# --------------------------------------------------------------------------
# 1. A BACKWARD wall-clock jump during a genuinely SLOW round trip must
# still be caught as stale -- the backward wall-clock jump must not mask
# it. This is exactly the defect the old time.time()-based measurement had:
# wall_after - wall_before would have come out NEGATIVE (not > the bound),
# silently treating a stale sample as fresh.
# --------------------------------------------------------------------------

def test_backward_wall_clock_jump_during_slow_round_trip_still_rejected(monkeypatch):
    # Wall clock: starts at 1000.0, then (because of a simulated NTP step
    # backward correction arriving mid-call) reports 500.0 afterward --
    # wall_after - wall_before = -500.0, which an old time.time()-based
    # measurement would have treated as "well under any bound", masking
    # staleness.
    #
    # Monotonic clock: starts at 500.0, ends at 500.3 -- a genuine 0.3s
    # elapsed, correctly exceeding the 0.05s bound configured below.
    _sequence(
        monkeypatch,
        wall_values=[1000.0, 500.0],
        mono_values=[500.0, 500.3],
    )
    src = RedisTimeSource(_StubRedis(500), max_round_trip_seconds=0.05)
    with pytest.raises(TimeTrustError) as exc_info:
        run(src.now())
    assert exc_info.value.reason == "CLOCK_UNTRUSTED"
    assert "round-trip" in exc_info.value.detail


# --------------------------------------------------------------------------
# 2. A FORWARD wall-clock jump during a genuinely FAST round trip must NOT
# cause a spurious rejection -- the old time.time()-based measurement would
# have seen wall_after - wall_before = +1000.0s (far exceeding any sane
# bound) purely because of the jump, not because the call was slow.
# --------------------------------------------------------------------------

def test_forward_wall_clock_jump_during_fast_round_trip_not_spuriously_rejected(monkeypatch):
    # Wall clock: starts at 1000.0, then (simulated NTP step forward) jumps
    # to 2000.0 -- a 1000s apparent gap that is NOT real elapsed time.
    #
    # Monotonic clock: starts at 500.0, ends at 500.01 -- a genuine 10ms
    # elapsed, well within the 2.0s default round-trip bound.
    _sequence(
        monkeypatch,
        wall_values=[1000.0, 2000.0],
        mono_values=[500.0, 500.01],
    )
    # redis_now chosen to match the midpoint of the (jumped) wall samples
    # so the skew check -- which correctly still uses wall-clock -- passes
    # cleanly and does not confound this round-trip-only assertion.
    midpoint = int((1000.0 + 2000.0) / 2.0)
    src = RedisTimeSource(_StubRedis(midpoint), max_skew_seconds=60.0)
    result = run(src.now())
    assert result == midpoint


# --------------------------------------------------------------------------
# 3. The skew check must still use genuine wall-clock time (it is a real
# UTC/epoch comparison against Redis TIME's own epoch reply) -- a forward
# OR backward jump in the MONOTONIC clock (which has no epoch and could
# never be compared to Redis TIME meaningfully) must have no bearing on it.
# --------------------------------------------------------------------------

def test_skew_check_still_uses_wall_clock_not_monotonic(monkeypatch):
    # Wall clock pair brackets a redis reply that is 100s ahead of the
    # local wall-clock midpoint -- must be rejected as CLOCK_SKEW_EXCEEDED
    # regardless of whatever the monotonic clock happens to report.
    base_wall = _time_module.time()
    _sequence(
        monkeypatch,
        wall_values=[base_wall, base_wall],
        mono_values=[500.0, 500.01],
    )
    src = RedisTimeSource(_StubRedis(int(base_wall) + 100), max_skew_seconds=5.0)
    with pytest.raises(TimeTrustError) as exc_info:
        run(src.now())
    assert exc_info.value.reason == "CLOCK_SKEW_EXCEEDED"


# --------------------------------------------------------------------------
# 4. Non-vacuity control: with NO clock jump at all (wall and monotonic
# gaps agree), a healthy fast round trip and matching skew both pass --
# confirms the mocking harness itself is not the reason the above tests
# pass.
# --------------------------------------------------------------------------

def test_no_jump_healthy_sample_still_accepted(monkeypatch):
    base_wall = _time_module.time()
    _sequence(
        monkeypatch,
        wall_values=[base_wall, base_wall + 0.01],
        mono_values=[500.0, 500.01],
    )
    src = RedisTimeSource(_StubRedis(int(base_wall)), max_skew_seconds=5.0, max_round_trip_seconds=2.0)
    result = run(src.now())
    assert result == int(base_wall)
