"""PR #122 round 5: authorization-to-dispatch staleness.

Investigates the real-time gap between EnforcementCoordinator.enforce()'s
trusted-time authorization checks (gate/consensus/challenge/approval,
resolved against ONE ``trusted_now`` near the top of the call) and the
actual durable dispatch commit (step f) several awaits later (idempotency
reserve, velocity reserve, audit-before-actuation). A slow backend in that
window could otherwise let a token that was genuinely valid WHEN CHECKED
reach actuation long after it would have expired by true wall-clock time.

The fix (``max_dispatch_staleness_seconds``) does NOT re-verify or
re-consume the token/mandate/approval/challenge -- it re-samples the same
trusted time source and measures elapsed real time, failing closed (with
the same pre-dispatch release semantics every other pre-(f) failure in
this class already uses) when that gap is excessive.

Uses a ``_SequenceTimeSource`` that returns PRESET values on successive
calls (simulating a real delay deterministically, without an actual
``sleep()``) -- the first call is the authorization-time ``trusted_now``;
the second is the dispatch-time staleness check. This is exactly
equivalent to a real slow backend consuming that much wall-clock time
between the two calls.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from mcc_core import (
    ActuationStatus,
    AuditLog,
    DecisionEngine,
    EnforcementCoordinator,
    ExecutionGate,
    InMemoryIdempotencyRegistry,
    InMemoryNonceRegistry,
    InMemoryVelocityRegistry,
    ProfileRegistry,
    SigningKey,
)
from mcc_core.trusted_time import TrustedTimeSource

run = asyncio.run
ACTION = "generic_op"
PAYLOAD = {"value": 1}
ACTOR = "agent/ops"
RESOURCE = "res-1"
POLICY_HASH = "sha256:p"


class _SequenceTimeSource(TrustedTimeSource):
    """Returns successive preset values -- deterministically simulates
    real elapsed time between two calls without an actual sleep()."""

    def __init__(self, values):
        self._values = list(values)
        self._i = 0

    async def now(self) -> int:
        v = self._values[min(self._i, len(self._values) - 1)]
        self._i += 1
        return v


def _build(tmp_path, *, time_source, max_dispatch_staleness_seconds):
    dk = SigningKey.generate("dk")
    engine = DecisionEngine(signing_key=dk, issuer="mcc/test", audience="gate",
                            policy_id="pilot/v1", policy_hash=POLICY_HASH, token_ttl_seconds=600)
    gate = ExecutionGate(trusted_keys={dk.kid: dk.public_key()}, audience="gate",
                         nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY_HASH,
                         time_source=time_source)
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    idempotency = InMemoryIdempotencyRegistry()
    coord = EnforcementCoordinator(
        gate=gate, idempotency=idempotency, velocity=InMemoryVelocityRegistry(),
        audit=audit, profiles=ProfileRegistry.default_pilot(),
        time_source=time_source, max_dispatch_staleness_seconds=max_dispatch_staleness_seconds,
    )
    return engine, coord, idempotency


def _token(engine, *, now, idem="op-staleness-1"):
    return engine.issue_token(
        verdict="ALLOW", subject=ACTOR, action=ACTION, payload=PAYLOAD,
        idempotency_key=idem, actor_id=ACTOR, resource_id=RESOURCE, nonce="n1",
        tenant_id="tenant-1", now=now,
    )


def _runner(record):
    async def executor():
        record.append("executed")
        return "upstream-ok"
    return executor


# --------------------------------------------------------------------------
# 1. Reproduction: an excessive real-time gap between authorization and
# dispatch is detected and fails closed, with zero actuator invocations,
# WITHOUT re-verifying or re-consuming the token (gate.verify() ran once;
# the nonce was consumed exactly once by it).
# --------------------------------------------------------------------------

def test_excessive_dispatch_staleness_blocks_with_zero_actuator_calls(tmp_path):
    t0 = 1_000_000
    delayed_dispatch = t0 + 60  # 60s "elapsed" during idempotency/velocity/audit
    ts = _SequenceTimeSource([t0, delayed_dispatch])
    engine, coord, idempotency = _build(tmp_path, time_source=ts, max_dispatch_staleness_seconds=5.0)

    token = _token(engine, now=t0)
    seen = []
    res = run(coord.enforce(token=token, action=ACTION, payload=PAYLOAD, executor=_runner(seen),
                            request_binding={"actor_id": ACTOR, "resource_id": RESOURCE,
                                            "transaction_id": None, "tenant_id": "tenant-1"}))
    assert res.status == ActuationStatus.BLOCKED
    assert "AUTHORIZATION_STALE" in res.reason
    assert seen == [], "actuator must never be invoked when the dispatch gap exceeds the bound"


def test_dispatch_staleness_releases_the_idempotency_reservation_for_retry(tmp_path):
    """The staleness block must behave exactly like every other pre-(f)
    failure in this class: the logical-operation reservation is released,
    not left dangling -- a fresh, independently-valid authorization for
    the SAME idempotency_key must be admittable again (never a second
    consumption of the ORIGINAL token; this is a NEW enforce() call with
    its own token, exactly how a legitimate retry works today)."""
    t0 = 2_000_000
    delayed_dispatch = t0 + 60
    ts = _SequenceTimeSource([t0, delayed_dispatch, t0, t0])
    engine, coord, idempotency = _build(tmp_path, time_source=ts, max_dispatch_staleness_seconds=5.0)

    token = _token(engine, now=t0, idem="op-staleness-retry")
    seen = []
    first = run(coord.enforce(token=token, action=ACTION, payload=PAYLOAD, executor=_runner(seen),
                              request_binding={"actor_id": ACTOR, "resource_id": RESOURCE,
                                              "transaction_id": None, "tenant_id": "tenant-1"}))
    assert first.status == ActuationStatus.BLOCKED

    state = run(idempotency.get_state("op-staleness-retry", tenant_id="tenant-1"))
    assert state is None, "the reservation must be fully released, not left RESERVED forever"

    # A fresh token (new nonce, new decision) for the same idempotency_key,
    # with the time source now reporting NO excess staleness, executes
    # normally -- confirms this is fail-closed-and-retryable, not a
    # permanent, silent loss of the ability to ever execute this operation.
    token2 = engine.issue_token(
        verdict="ALLOW", subject=ACTOR, action=ACTION, payload=PAYLOAD,
        idempotency_key="op-staleness-retry", actor_id=ACTOR, resource_id=RESOURCE, nonce="n2",
        tenant_id="tenant-1", now=t0,
    )
    second = run(coord.enforce(token=token2, action=ACTION, payload=PAYLOAD, executor=_runner(seen),
                               request_binding={"actor_id": ACTOR, "resource_id": RESOURCE,
                                               "transaction_id": None, "tenant_id": "tenant-1"}))
    assert second.status == ActuationStatus.EXECUTED
    assert seen == ["executed"]


def test_dispatch_within_bound_executes_normally(tmp_path):
    """Non-vacuity / sanity: a SMALL gap (well within the bound) must not
    be spuriously blocked."""
    t0 = 3_000_000
    small_gap = t0 + 1
    ts = _SequenceTimeSource([t0, small_gap])
    engine, coord, idempotency = _build(tmp_path, time_source=ts, max_dispatch_staleness_seconds=30.0)

    token = _token(engine, now=t0, idem="op-staleness-ok")
    seen = []
    res = run(coord.enforce(token=token, action=ACTION, payload=PAYLOAD, executor=_runner(seen),
                            request_binding={"actor_id": ACTOR, "resource_id": RESOURCE,
                                            "transaction_id": None, "tenant_id": "tenant-1"}))
    assert res.status == ActuationStatus.EXECUTED
    assert seen == ["executed"]


def test_staleness_check_disabled_by_default_preserves_prior_behavior(tmp_path):
    """When max_dispatch_staleness_seconds is not configured (None, the
    class default), the elapsed-GAP-vs-fixed-bound check is NOT applied --
    confirms THAT control is a strictly additive, opt-in, zero-behavior-
    change-when-unconfigured feature.

    The gap here (500s) is deliberately large relative to a typical
    staleness bound (e.g. the 30s default this repo ships) -- large enough
    that, were the gap check active, it would trip -- but still well
    within this test's own 600s token TTL (see ``_build()``), so the
    UNCONDITIONAL token-exp recheck (round 6, Finding 1 -- see
    ``test_token_expired_before_dispatch_blocks_even_within_staleness_bound``
    below, which deliberately exercises the opposite case) correctly does
    not fire either. This isolates the assertion to the opt-in gap
    feature's own on/off behavior, not a coincidental token expiry."""
    t0 = 4_000_000
    large_gap_within_token_ttl = t0 + 500
    ts = _SequenceTimeSource([t0, large_gap_within_token_ttl])
    engine, coord, idempotency = _build(tmp_path, time_source=ts, max_dispatch_staleness_seconds=None)

    token = _token(engine, now=t0, idem="op-staleness-disabled")
    seen = []
    res = run(coord.enforce(token=token, action=ACTION, payload=PAYLOAD, executor=_runner(seen),
                            request_binding={"actor_id": ACTOR, "resource_id": RESOURCE,
                                            "transaction_id": None, "tenant_id": "tenant-1"}))
    assert res.status == ActuationStatus.EXECUTED
    assert seen == ["executed"]


# --------------------------------------------------------------------------
# 6. Round 6, Finding 1: the token's OWN exp must be rechecked at dispatch
# UNCONDITIONALLY -- even when the elapsed gap stays within the configured
# (or even a disabled) staleness bound, and even when the gap is far
# smaller than that bound. A short-TTL token that genuinely expires during
# the idempotency/velocity/audit steps must never reach the executor
# merely because the overall GAP looked small.
# --------------------------------------------------------------------------

def test_token_expired_before_dispatch_blocks_even_within_staleness_bound(tmp_path):
    """Reproduction + regression: a 5-second-TTL token, with a dispatch
    delay of only 10 seconds (comfortably inside a generous 30-second
    staleness bound), has nonetheless genuinely expired by true
    wall-clock time by the moment of dispatch. Confirmed non-vacuous: this
    exact scenario, run against the pre-round-6 code, resulted in
    ActuationStatus.EXECUTED with the actuator invoked (see PR #122's
    round 6 report) -- the elapsed-gap check alone cannot catch this,
    because 10s < 30s regardless of the token's own (much shorter) TTL."""
    t0 = 5_000_000
    short_ttl_seconds = 5
    delayed_dispatch = t0 + 10  # within the 30s staleness bound, past the 5s token TTL
    ts = _SequenceTimeSource([t0, delayed_dispatch])

    dk = SigningKey.generate("dk")
    engine = DecisionEngine(signing_key=dk, issuer="mcc/test", audience="gate",
                            policy_id="pilot/v1", policy_hash=POLICY_HASH,
                            token_ttl_seconds=short_ttl_seconds)
    gate = ExecutionGate(trusted_keys={dk.kid: dk.public_key()}, audience="gate",
                         nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY_HASH,
                         time_source=ts)
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    coord = EnforcementCoordinator(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(), velocity=InMemoryVelocityRegistry(),
        audit=audit, profiles=ProfileRegistry.default_pilot(),
        time_source=ts, max_dispatch_staleness_seconds=30.0,
    )
    token = engine.issue_token(
        verdict="ALLOW", subject=ACTOR, action=ACTION, payload=PAYLOAD,
        idempotency_key="op-token-expiry-1", actor_id=ACTOR, resource_id=RESOURCE, nonce="n1",
        tenant_id="tenant-1", now=t0,
    )
    seen: list = []
    res = run(coord.enforce(token=token, action=ACTION, payload=PAYLOAD, executor=_runner(seen),
                            request_binding={"actor_id": ACTOR, "resource_id": RESOURCE,
                                            "transaction_id": None, "tenant_id": "tenant-1"}))
    assert res.status == ActuationStatus.BLOCKED
    assert "TOKEN_EXPIRED_BEFORE_DISPATCH" in res.reason
    assert seen == [], "the actuator must never run with a token already expired by dispatch time"


def test_token_expired_before_dispatch_blocks_even_with_staleness_check_disabled(tmp_path):
    """Same scenario as above, but with max_dispatch_staleness_seconds=None
    (the opt-in gap feature fully disabled) -- confirms the token-expiry
    recheck is UNCONDITIONAL, never contingent on that separate feature
    being configured."""
    t0 = 6_000_000
    short_ttl_seconds = 5
    delayed_dispatch = t0 + 10
    ts = _SequenceTimeSource([t0, delayed_dispatch])

    dk = SigningKey.generate("dk")
    engine = DecisionEngine(signing_key=dk, issuer="mcc/test", audience="gate",
                            policy_id="pilot/v1", policy_hash=POLICY_HASH,
                            token_ttl_seconds=short_ttl_seconds)
    gate = ExecutionGate(trusted_keys={dk.kid: dk.public_key()}, audience="gate",
                         nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY_HASH,
                         time_source=ts)
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    coord = EnforcementCoordinator(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(), velocity=InMemoryVelocityRegistry(),
        audit=audit, profiles=ProfileRegistry.default_pilot(),
        time_source=ts, max_dispatch_staleness_seconds=None,
    )
    token = engine.issue_token(
        verdict="ALLOW", subject=ACTOR, action=ACTION, payload=PAYLOAD,
        idempotency_key="op-token-expiry-2", actor_id=ACTOR, resource_id=RESOURCE, nonce="n1",
        tenant_id="tenant-1", now=t0,
    )
    seen: list = []
    res = run(coord.enforce(token=token, action=ACTION, payload=PAYLOAD, executor=_runner(seen),
                            request_binding={"actor_id": ACTOR, "resource_id": RESOURCE,
                                            "transaction_id": None, "tenant_id": "tenant-1"}))
    assert res.status == ActuationStatus.BLOCKED
    assert "TOKEN_EXPIRED_BEFORE_DISPATCH" in res.reason
    assert seen == []


def test_token_not_yet_expired_at_dispatch_executes_normally(tmp_path):
    """Non-vacuity / sanity: a token still comfortably valid at dispatch
    time (TTL far exceeds the real gap) must not be spuriously blocked by
    the new recheck."""
    t0 = 7_000_000
    small_gap = t0 + 1
    ts = _SequenceTimeSource([t0, small_gap])

    dk = SigningKey.generate("dk")
    engine = DecisionEngine(signing_key=dk, issuer="mcc/test", audience="gate",
                            policy_id="pilot/v1", policy_hash=POLICY_HASH, token_ttl_seconds=600)
    gate = ExecutionGate(trusted_keys={dk.kid: dk.public_key()}, audience="gate",
                         nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY_HASH,
                         time_source=ts)
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    coord = EnforcementCoordinator(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(), velocity=InMemoryVelocityRegistry(),
        audit=audit, profiles=ProfileRegistry.default_pilot(),
        time_source=ts, max_dispatch_staleness_seconds=30.0,
    )
    token = engine.issue_token(
        verdict="ALLOW", subject=ACTOR, action=ACTION, payload=PAYLOAD,
        idempotency_key="op-token-expiry-3", actor_id=ACTOR, resource_id=RESOURCE, nonce="n1",
        tenant_id="tenant-1", now=t0,
    )
    seen: list = []
    res = run(coord.enforce(token=token, action=ACTION, payload=PAYLOAD, executor=_runner(seen),
                            request_binding={"actor_id": ACTOR, "resource_id": RESOURCE,
                                            "transaction_id": None, "tenant_id": "tenant-1"}))
    assert res.status == ActuationStatus.EXECUTED
    assert seen == ["executed"]


def test_token_expiry_recheck_releases_reservation_for_retry(tmp_path):
    """Same release-and-retry guarantee Item 1's original staleness check
    had: the token-expiry block must release the idempotency reservation
    (never leave it dangling), and a fresh token for the SAME
    idempotency_key must be admittable again -- never a second consumption
    of the original (expired) token's own nonce."""
    t0 = 8_000_000
    delayed_dispatch = t0 + 10
    ts = _SequenceTimeSource([t0, delayed_dispatch, t0, t0])

    dk = SigningKey.generate("dk")
    engine = DecisionEngine(signing_key=dk, issuer="mcc/test", audience="gate",
                            policy_id="pilot/v1", policy_hash=POLICY_HASH, token_ttl_seconds=5)
    gate = ExecutionGate(trusted_keys={dk.kid: dk.public_key()}, audience="gate",
                         nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY_HASH,
                         time_source=ts)
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    idempotency = InMemoryIdempotencyRegistry()
    coord = EnforcementCoordinator(
        gate=gate, idempotency=idempotency, velocity=InMemoryVelocityRegistry(),
        audit=audit, profiles=ProfileRegistry.default_pilot(),
        time_source=ts, max_dispatch_staleness_seconds=30.0,
    )
    token = engine.issue_token(
        verdict="ALLOW", subject=ACTOR, action=ACTION, payload=PAYLOAD,
        idempotency_key="op-token-expiry-retry", actor_id=ACTOR, resource_id=RESOURCE, nonce="n1",
        tenant_id="tenant-1", now=t0,
    )
    seen: list = []
    first = run(coord.enforce(token=token, action=ACTION, payload=PAYLOAD, executor=_runner(seen),
                              request_binding={"actor_id": ACTOR, "resource_id": RESOURCE,
                                              "transaction_id": None, "tenant_id": "tenant-1"}))
    assert first.status == ActuationStatus.BLOCKED

    state = run(idempotency.get_state("op-token-expiry-retry", tenant_id="tenant-1"))
    assert state is None, "the reservation must be fully released, not left RESERVED forever"

    # A fresh, independently-issued token (new nonce) -- never a second
    # consumption of the original, already-burned-by-the-gate nonce --
    # for the same idempotency_key, issued fresh (not expired), executes
    # normally.
    token2 = engine.issue_token(
        verdict="ALLOW", subject=ACTOR, action=ACTION, payload=PAYLOAD,
        idempotency_key="op-token-expiry-retry", actor_id=ACTOR, resource_id=RESOURCE, nonce="n2",
        tenant_id="tenant-1", now=t0,
    )
    second = run(coord.enforce(token=token2, action=ACTION, payload=PAYLOAD, executor=_runner(seen),
                               request_binding={"actor_id": ACTOR, "resource_id": RESOURCE,
                                               "transaction_id": None, "tenant_id": "tenant-1"}))
    assert second.status == ActuationStatus.EXECUTED
    assert seen == ["executed"]


def test_staleness_check_fails_closed_when_time_source_untrusted_at_dispatch(tmp_path):
    from mcc_core.trusted_time import TimeTrustError

    class _OkThenUntrusted(TrustedTimeSource):
        def __init__(self):
            self._i = 0

        async def now(self):
            self._i += 1
            if self._i == 1:
                return 5_000_000
            raise TimeTrustError("CLOCK_UNTRUSTED", "simulated: lost trust between authorization and dispatch")

    ts = _OkThenUntrusted()
    engine, coord, idempotency = _build(tmp_path, time_source=ts, max_dispatch_staleness_seconds=30.0)
    token = _token(engine, now=5_000_000, idem="op-staleness-untrusted")
    seen = []
    res = run(coord.enforce(token=token, action=ACTION, payload=PAYLOAD, executor=_runner(seen),
                            request_binding={"actor_id": ACTOR, "resource_id": RESOURCE,
                                            "transaction_id": None, "tenant_id": "tenant-1"}))
    assert res.status == ActuationStatus.BLOCKED
    assert "CLOCK_UNTRUSTED" in res.reason
    assert seen == []
