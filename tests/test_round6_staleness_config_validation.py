"""PR #122 round 6, Finding 2: ``_max_dispatch_staleness_from_env()``
(gateway/governance_api.py) and ``EnforcementCoordinator.__init__``
(src/mcc_core/coordinator.py) must reject NaN and infinite
``max_dispatch_staleness_seconds`` values -- not just non-positive ones.

Root cause: ``float("nan")`` and ``float("inf")``/``float("Infinity")``
all parse successfully without raising, and the pre-fix validation was
only ``if value <= 0: raise``. Both ``nan <= 0`` and ``inf <= 0`` are
False in Python, so both were ACCEPTED. Downstream, the coordinator's
comparison ``staleness > self.max_dispatch_staleness_seconds`` is ALWAYS
False when the right-hand side is NaN or +infinity (any comparison
against NaN is False; nothing finite exceeds +infinity) -- so either
value silently disabled the dispatch-staleness protection while still
looking "configured" (as opposed to the honest, explicit
``off``/``0``/``disabled``/``none``).

Confirmed before any fix (see the module docstring in
gateway/governance_api.py's own round-6 comment and the direct
reproduction in the PR report); fixed by routing both validation paths
through the same ``_validate_positive_finite`` helper
``RedisTimeSource`` already uses.
"""

from __future__ import annotations

import math
import tempfile
from pathlib import Path

import pytest

from gateway.governance_api import _max_dispatch_staleness_from_env
from mcc_core import (
    AuditLog,
    EnforcementCoordinator,
    ExecutionGate,
    InMemoryIdempotencyRegistry,
    InMemoryNonceRegistry,
    InMemoryVelocityRegistry,
    ProfileRegistry,
    SigningKey,
)
from mcc_core.trusted_time import TimeTrustConfigError

NON_FINITE_RAW_VALUES = ["nan", "NaN", "NAN", "inf", "Infinity", "infinity", "+inf"]


# --------------------------------------------------------------------------
# 1. Environment parsing: every spelling of NaN/+infinity is rejected, not
# silently accepted as a value that would disable the protection while
# looking configured.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("raw", NON_FINITE_RAW_VALUES)
def test_env_parsing_rejects_nan_and_infinity(raw):
    with pytest.raises(RuntimeError) as exc_info:
        _max_dispatch_staleness_from_env({"MCC_MAX_DISPATCH_STALENESS_SECONDS": raw})
    assert "nan" in str(exc_info.value).lower() or "infinite" in str(exc_info.value).lower()


def test_env_parsing_rejects_negative_infinity_too():
    """-inf was already rejected by the pre-fix ``value <= 0`` check
    (non-vacuity control: this one case did NOT need the fix)."""
    with pytest.raises(RuntimeError):
        _max_dispatch_staleness_from_env({"MCC_MAX_DISPATCH_STALENESS_SECONDS": "-inf"})


def test_env_parsing_still_accepts_valid_values():
    assert _max_dispatch_staleness_from_env({"MCC_MAX_DISPATCH_STALENESS_SECONDS": "30"}) == 30.0
    assert _max_dispatch_staleness_from_env({"MCC_MAX_DISPATCH_STALENESS_SECONDS": "0.5"}) == 0.5
    assert _max_dispatch_staleness_from_env({}) == 30.0  # default
    assert _max_dispatch_staleness_from_env({"MCC_MAX_DISPATCH_STALENESS_SECONDS": "off"}) is None


def test_env_parsing_still_rejects_non_numeric_and_non_positive():
    with pytest.raises(RuntimeError):
        _max_dispatch_staleness_from_env({"MCC_MAX_DISPATCH_STALENESS_SECONDS": "not-a-number"})
    # "0" is the explicit, honest disable spelling (alongside off/disabled/
    # none) -- handled before numeric parsing, so it is accepted, not
    # rejected.
    assert _max_dispatch_staleness_from_env({"MCC_MAX_DISPATCH_STALENESS_SECONDS": "0"}) is None
    with pytest.raises(RuntimeError):
        _max_dispatch_staleness_from_env({"MCC_MAX_DISPATCH_STALENESS_SECONDS": "-5"})


# --------------------------------------------------------------------------
# 2. Direct EnforcementCoordinator construction: the SAME non-finite
# values must be rejected there too, not just at the env-parsing
# boundary -- a direct caller (another deployment wiring, a test, a
# future embedder) gets the identical protection.
# --------------------------------------------------------------------------

def _coordinator_kwargs():
    dk = SigningKey.generate("dk")
    gate = ExecutionGate(trusted_keys={dk.kid: dk.public_key()}, audience="gate",
                         nonce_registry=InMemoryNonceRegistry(), policy_hash="sha256:p")
    tmp = Path(tempfile.mkdtemp(prefix="mcc-round6-staleness-cfg-"))
    audit = AuditLog(str(tmp / "audit.jsonl"))
    return dict(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(), velocity=InMemoryVelocityRegistry(),
        audit=audit, profiles=ProfileRegistry.default_pilot(),
    )


@pytest.mark.parametrize("bad_value", [float("nan"), float("inf"), float("-inf"), -5.0, 0.0])
def test_direct_construction_rejects_invalid_values(bad_value):
    with pytest.raises(TimeTrustConfigError):
        EnforcementCoordinator(max_dispatch_staleness_seconds=bad_value, **_coordinator_kwargs())


def test_direct_construction_accepts_valid_values_and_none():
    coord = EnforcementCoordinator(max_dispatch_staleness_seconds=30.0, **_coordinator_kwargs())
    assert coord.max_dispatch_staleness_seconds == 30.0
    coord_disabled = EnforcementCoordinator(max_dispatch_staleness_seconds=None, **_coordinator_kwargs())
    assert coord_disabled.max_dispatch_staleness_seconds is None


# --------------------------------------------------------------------------
# 3. The actual exploit the bug enabled, demonstrated directly: a NaN or
# +infinity bound makes the coordinator's own staleness comparison always
# False, regardless of how large the real gap is -- confirming WHY
# rejecting these values at configuration time matters, independent of
# the config-loader tests above.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("bad_bound", [float("nan"), float("inf")])
def test_non_finite_bound_would_have_silently_disabled_the_staleness_comparison(bad_bound):
    """Direct demonstration of the exploit this fix closes: with the
    pre-fix (unvalidated) bound in place, an arbitrarily large real-world
    staleness gap would never be flagged. This test exercises the raw
    comparison the coordinator performs, independent of how the bound
    was configured, to make the mechanism of the bug explicit."""
    arbitrarily_large_gap = 10_000_000.0
    assert not (arbitrarily_large_gap > bad_bound), (
        f"a {bad_bound!r} bound must never reach this comparison -- if it "
        "does, the staleness protection is silently inert"
    )
    # Contrast: a validated, finite, positive bound correctly flags the
    # same gap.
    valid_bound = 30.0
    assert arbitrarily_large_gap > valid_bound
