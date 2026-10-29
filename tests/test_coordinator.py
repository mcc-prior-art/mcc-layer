"""EnforcementCoordinator tests: the explicit a-h execution order and the
cross-cutting guarantees that depend on it.
"""

import asyncio
import json
from pathlib import Path

from mcc_core import (
    ActuationStatus,
    AuditLog,
    DecisionEngine,
    EnforcementCoordinator,
    ExecutionGate,
    IdempotencyState,
    InMemoryIdempotencyRegistry,
    InMemoryNonceRegistry,
    InMemoryVelocityRegistry,
    PaymentProfile,
    ProfileRegistry,
    RedisIdempotencyRegistry,
    ReserveStatus,
    SigningKey,
    VelocityDescriptor,
    VelocityLimit,
    Verdict,
)

run = asyncio.run
NOW = 1_780_000_000
PROFILE = PaymentProfile()


class DownRedis:
    def __getattr__(self, _n):
        async def boom(*a, **k):
            raise ConnectionError("down")
        return boom


def build(tmp_path, *, limits=None, idempotency=None, velocity=None):
    key = SigningKey.generate("k1")
    engine = DecisionEngine(
        signing_key=key, issuer="mcc/test", audience="gate",
        policy_id="pilot/v1", policy_hash="sha256:p", token_ttl_seconds=60,
    )
    gate = ExecutionGate(
        trusted_keys={key.kid: key.public_key()}, audience="gate",
        nonce_registry=InMemoryNonceRegistry(), policy_hash="sha256:p",
    )
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    coord = EnforcementCoordinator(
        gate=gate,
        idempotency=idempotency or InMemoryIdempotencyRegistry(),
        velocity=velocity or InMemoryVelocityRegistry(),
        audit=audit,
        profiles=ProfileRegistry.default_pilot(),
        velocity_limits_for=lambda action: (limits or []),
    )
    return engine, coord, audit


def payment(engine, *, idem, amount=1000, actor="actor-1", txn=None, beneficiary="ben-1", tenant="tenant-1", now=NOW):
    ctx = {"source": "acct-1", "beneficiary_id": beneficiary, "amount": amount, "currency": "usd"}
    payload = PROFILE.canonical_payload(ctx)
    token = engine.issue_token(
        verdict="ALLOW", subject=actor, action="send_payment", payload=payload,
        transaction_id=txn or idem, idempotency_key=idem, actor_id=actor,
        resource_id="acct-1", auth_claims=PROFILE.auth_claims(ctx), now=now,
        tenant_id=tenant,
    )
    return token, payload


def runner(record):
    async def executor():
        record.append("executed")
        return "upstream-ok"
    return executor


# ---- Happy path + ordering ----

def test_happy_path_executes_and_finalizes(tmp_path):
    engine, coord, audit = build(tmp_path)
    token, payload = payment(engine, idem="op-1")
    seen = []
    res = run(coord.enforce(token=token, action="send_payment", payload=payload,
                            executor=runner(seen), now=NOW))
    assert res.status == ActuationStatus.EXECUTED
    assert res.execution == "upstream-ok"
    assert seen == ["executed"]
    assert run(coord.idempotency.get_state("op-1", tenant_id="tenant-1")).state.value == "EXECUTED"


def test_audit_before_actuation_ordering(tmp_path):
    engine, coord, audit = build(tmp_path)
    token, payload = payment(engine, idem="op-1")
    run(coord.enforce(token=token, action="send_payment", payload=payload,
                      executor=runner([]), now=NOW))
    entries = [json.loads(l) for l in Path(audit.path).read_text().splitlines() if l.strip()]
    kinds = [e.get("kind") for e in entries]
    assert "pre_actuation" in kinds and "actuation_result" in kinds
    assert kinds.index("pre_actuation") < kinds.index("actuation_result")


# ---- Replay / shared idempotency key ----

def test_same_token_replay_blocked(tmp_path):
    engine, coord, audit = build(tmp_path)
    token, payload = payment(engine, idem="op-1")
    first = run(coord.enforce(token=token, action="send_payment", payload=payload,
                              executor=runner([]), now=NOW))
    second = run(coord.enforce(token=token, action="send_payment", payload=payload,
                               executor=runner([]), now=NOW))
    assert first.status == ActuationStatus.EXECUTED
    assert second.status == ActuationStatus.BLOCKED  # nonce already consumed


def test_different_tokens_same_idempotency_key_blocked(tmp_path):
    engine, coord, audit = build(tmp_path)
    t1, p1 = payment(engine, idem="op-shared", txn="txn-A")
    t2, p2 = payment(engine, idem="op-shared", txn="txn-B")  # distinct token, same idem key
    first = run(coord.enforce(token=t1, action="send_payment", payload=p1,
                              executor=runner([]), now=NOW))
    second = run(coord.enforce(token=t2, action="send_payment", payload=p2,
                               executor=runner([]), now=NOW))
    assert first.status == ActuationStatus.EXECUTED
    assert second.status == ActuationStatus.BLOCKED
    assert "executed" in second.reason.lower()


def test_concurrent_duplicate_exactly_one_winner(tmp_path):
    engine, coord, audit = build(tmp_path)
    tokens = [payment(engine, idem="op-shared", txn=f"txn-{i}") for i in range(8)]
    seen = []

    async def race():
        return await asyncio.gather(*[
            coord.enforce(token=t, action="send_payment", payload=p,
                          executor=runner(seen), now=NOW)
            for t, p in tokens
        ])

    results = run(race())
    executed = [r for r in results if r.status == ActuationStatus.EXECUTED]
    assert len(executed) == 1
    assert seen == ["executed"]  # the side effect ran exactly once


# ---- Velocity / anti-splitting through the coordinator ----

def test_four_tokens_cannot_bypass_cumulative_ceiling(tmp_path):
    limit = VelocityLimit(name="amt", window_seconds=3600, max_amount=10000,
                          aggregate_by=("actor",))
    engine, coord, audit = build(tmp_path, limits=[limit])
    statuses = []
    for i in range(4):
        token, payload = payment(engine, idem=f"op-{i}", amount=3000, beneficiary=f"ben-{i}")
        res = run(coord.enforce(token=token, action="send_payment", payload=payload,
                                executor=runner([]), now=NOW))
        statuses.append(res.status)
    assert statuses[:3] == [ActuationStatus.EXECUTED] * 3
    assert statuses[3] == ActuationStatus.BLOCKED


def test_concurrent_aggregate_race_never_overspends(tmp_path):
    limit = VelocityLimit(name="amt", window_seconds=3600, max_amount=10000,
                          aggregate_by=("actor",))
    engine, coord, audit = build(tmp_path, limits=[limit])
    tokens = [payment(engine, idem=f"op-{i}", amount=3000, beneficiary=f"ben-{i}")
              for i in range(12)]

    async def race():
        return await asyncio.gather(*[
            coord.enforce(token=t, action="send_payment", payload=p,
                          executor=runner([]), now=NOW)
            for t, p in tokens
        ])

    results = run(race())
    executed = [r for r in results if r.status == ActuationStatus.EXECUTED]
    assert len(executed) * 3000 <= 10000  # ceiling never bypassed


def test_velocity_release_matches_its_own_reservation_in_production_shape(tmp_path):
    """Regression: reserve()/release() each resolve their OWN fresh clock
    reading whenever the caller passes ``now=None`` -- the universal
    production shape (the coordinator is never called with an explicit
    ``now`` in production; see test_velocity.py's static call-site guard).
    Both registries correlate a release to its reservation by exact
    timestamp equality, so re-resolving a fresh ``now`` at release time
    (instead of carrying back the exact value the reservation was stored
    under) makes the release silently no-op: it reports success but leaves
    the reservation in place, leaking budget until the window ages it out.

    This drives TWO limits through the coordinator with ``now`` omitted
    entirely end-to-end (real wall-clock issuance + real wall-clock
    enforcement, not the fixed ``NOW`` constant every other test in this
    file uses). The first limit's reservation succeeds; the second,
    tiny limit then breaches and aborts the operation pre-dispatch, which
    must genuinely release the first limit's reservation. A direct
    follow-up reservation against the first limit for its full ceiling
    then proves whether the earlier reservation actually went away.
    """
    small = VelocityLimit(name="small", window_seconds=3600, max_amount=10_000,
                          aggregate_by=("actor",))
    tiny = VelocityLimit(name="tiny", window_seconds=3600, max_amount=1,
                         aggregate_by=("actor",))
    engine, coord, audit = build(tmp_path, limits=[small, tiny])

    token, payload = payment(engine, idem="op-1", amount=100, now=None)
    res = run(coord.enforce(token=token, action="send_payment", payload=payload,
                            executor=runner([])))  # now omitted: production shape
    assert res.status == ActuationStatus.BLOCKED
    assert "tiny" in res.reason.lower()

    # If `small`'s reservation from the blocked attempt above was genuinely
    # released, its full 10_000 ceiling is still free to reserve in one
    # shot. If it leaked (the pre-fix bug), this over-reserves and DENYs.
    descriptor = VelocityDescriptor(
        dimensions={"actor": "actor-1"}, amount=10_000.0, currency="USD",
        destination="ben-1",
    )
    outcome = run(coord.velocity.reserve(small, descriptor, now=None))
    assert outcome.verdict == Verdict.ALLOW
    assert outcome.ok


# ---- Fail-closed ----

def test_idempotency_outage_fails_closed(tmp_path):
    engine, coord, audit = build(
        tmp_path, idempotency=RedisIdempotencyRegistry(DownRedis())
    )
    token, payload = payment(engine, idem="op-1")
    res = run(coord.enforce(token=token, action="send_payment", payload=payload,
                            executor=runner([]), now=NOW))
    assert res.status == ActuationStatus.BLOCKED
    assert "fail-closed" in res.reason.lower()


def test_binding_mismatch_blocks_before_execution(tmp_path):
    engine, coord, audit = build(tmp_path)
    token, payload = payment(engine, idem="op-1", actor="actor-1")
    seen = []
    res = run(coord.enforce(token=token, action="send_payment", payload=payload,
                            executor=runner(seen),
                            request_binding={"actor_id": "actor-EVIL"}, now=NOW))
    assert res.status == ActuationStatus.BLOCKED
    assert seen == []  # never executed


# ---- Execution exception after dispatch commitment -> UNKNOWN, NOT released ----
# (Round 17 remediation: a raise after the durable dispatch boundary must
# NEVER free the logical operation for another admission -- the external
# side effect may already have occurred. See docs/DURABLE_OPERATION_SAFETY.md
# and the Round-16 blocker this replaces, "current failure handling may
# release/delete logical-operation ownership".)

def test_execution_exception_marks_unknown_not_released(tmp_path):
    engine, coord, audit = build(tmp_path)
    token, payload = payment(engine, idem="op-1")

    async def boom():
        raise RuntimeError("upstream 500")

    res = run(coord.enforce(token=token, action="send_payment", payload=payload,
                            executor=boom, now=NOW))
    assert res.status == ActuationStatus.EXECUTION_FAILED
    record = run(coord.idempotency.get_state("op-1", tenant_id="tenant-1"))
    assert record is not None
    assert record.state == IdempotencyState.UNKNOWN


def test_fresh_authorization_for_unknown_operation_blocks_second_actuation(tmp_path):
    """Test scenario 5 / 18: a fresh, independently valid authorization
    (different token, different nonce, same idempotency_key) for an UNKNOWN
    operation must never trigger a second actuation attempt."""
    engine, coord, audit = build(tmp_path)
    token1, payload1 = payment(engine, idem="op-1", txn="txn-A")

    async def boom():
        raise RuntimeError("upstream 500")

    first = run(coord.enforce(token=token1, action="send_payment", payload=payload1,
                              executor=boom, now=NOW))
    assert first.status == ActuationStatus.EXECUTION_FAILED
    assert run(coord.idempotency.get_state("op-1", tenant_id="tenant-1")).state == IdempotencyState.UNKNOWN

    token2, payload2 = payment(engine, idem="op-1", txn="txn-B")  # fresh, valid, different nonce
    seen = []
    second = run(coord.enforce(token=token2, action="send_payment", payload=payload2,
                               executor=runner(seen), now=NOW))
    assert second.status == ActuationStatus.BLOCKED
    assert seen == []  # the actuator was never invoked a second time


def test_no_second_actuator_invocation_after_ambiguous_first_attempt(tmp_path):
    """Round 18 requirement 8's mutation detector: the safety property this
    checks is PURELY "does a second actuator invocation ever become
    possible" -- deliberately independent of which exact intermediate
    state label (``UNKNOWN`` vs ``DISPATCH_OWNED``) the first attempt left
    behind. A detector that instead (or also) asserts an exact state label
    can fail on a harmless label technicality without ever proving a real
    duplicate execution is possible -- see ``mutation/defects.py``'s
    ``idempotency-reserve-reopens-pending-states`` and the explicit
    instruction not to count such a detector."""
    engine, coord, audit = build(tmp_path)
    token1, payload1 = payment(engine, idem="op-1", txn="txn-A")

    async def boom():
        raise RuntimeError("upstream 500")

    first_seen = []

    async def boom_after_count():
        first_seen.append("executed")
        raise RuntimeError("upstream 500")

    first = run(coord.enforce(token=token1, action="send_payment", payload=payload1,
                              executor=boom_after_count, now=NOW))
    assert first.status == ActuationStatus.EXECUTION_FAILED
    assert first_seen == ["executed"]  # the first (only legitimate) invocation

    token2, payload2 = payment(engine, idem="op-1", txn="txn-B")
    second_seen = []
    second = run(coord.enforce(token=token2, action="send_payment", payload=payload2,
                               executor=runner(second_seen), now=NOW))
    assert second.status == ActuationStatus.BLOCKED
    assert second_seen == []  # no second invocation, whatever the intermediate state is named


def test_two_valid_tokens_same_key_at_most_one_side_effect(tmp_path):
    """Test scenario 23: two separately-signed, independently valid
    authorizations for the same logical operation -> at most one external
    side effect."""
    engine, coord, audit = build(tmp_path)
    t1, p1 = payment(engine, idem="op-shared", txn="txn-A")
    t2, p2 = payment(engine, idem="op-shared", txn="txn-B")
    seen = []
    first = run(coord.enforce(token=t1, action="send_payment", payload=p1,
                              executor=runner(seen), now=NOW))
    second = run(coord.enforce(token=t2, action="send_payment", payload=p2,
                               executor=runner(seen), now=NOW))
    assert first.status == ActuationStatus.EXECUTED
    assert second.status == ActuationStatus.BLOCKED
    assert seen == ["executed"]  # the actuator ran exactly once


# ---- BINDING_CONFLICT: same idempotency_key, different operation ----

def test_binding_conflict_different_payload_same_key(tmp_path):
    engine, coord, audit = build(tmp_path)
    t1, p1 = payment(engine, idem="op-1", txn="txn-A", amount=1000)
    t2, p2 = payment(engine, idem="op-1", txn="txn-B", amount=9999)  # different payload
    seen = []
    first = run(coord.enforce(token=t1, action="send_payment", payload=p1,
                              executor=runner(seen), now=NOW))
    second = run(coord.enforce(token=t2, action="send_payment", payload=p2,
                               executor=runner(seen), now=NOW))
    assert first.status == ActuationStatus.EXECUTED
    assert second.status == ActuationStatus.BLOCKED
    assert "different" in second.reason.lower() or "conflict" in second.reason.lower()
    assert seen == ["executed"]  # zero additional actuator calls


def test_binding_conflict_different_action_same_key(tmp_path):
    engine, coord, audit = build(tmp_path)
    t1, p1 = payment(engine, idem="op-1", txn="txn-A")
    generic_payload = {"note": "unrelated generic-profile action"}
    t2 = engine.issue_token(
        verdict="ALLOW", subject="actor-1", action="close_issue", payload=generic_payload,
        transaction_id="txn-B", idempotency_key="op-1", actor_id="actor-1",
        resource_id="acct-1", now=NOW, tenant_id="tenant-1",
    )
    seen = []
    first = run(coord.enforce(token=t1, action="send_payment", payload=p1,
                              executor=runner(seen), now=NOW))
    second = run(coord.enforce(token=t2, action="close_issue", payload=generic_payload,
                               executor=runner(seen), now=NOW))
    assert first.status == ActuationStatus.EXECUTED
    assert second.status == ActuationStatus.BLOCKED
    assert seen == ["executed"]


def test_binding_conflict_different_resource_same_key(tmp_path):
    engine, coord, audit = build(tmp_path)
    t1, p1 = payment(engine, idem="op-1", txn="txn-A")
    ctx = {"source": "acct-2", "beneficiary_id": "ben-1", "amount": 1000, "currency": "usd"}
    p2 = PROFILE.canonical_payload(ctx)
    t2 = engine.issue_token(
        verdict="ALLOW", subject="actor-1", action="send_payment", payload=p2,
        transaction_id="txn-B", idempotency_key="op-1", actor_id="actor-1",
        resource_id="acct-2",  # different resource than t1's "acct-1"
        auth_claims=PROFILE.auth_claims(ctx), now=NOW, tenant_id="tenant-1",
    )
    seen = []
    first = run(coord.enforce(token=t1, action="send_payment", payload=p1,
                              executor=runner(seen), now=NOW))
    second = run(coord.enforce(token=t2, action="send_payment", payload=p2,
                               executor=runner(seen), now=NOW))
    assert first.status == ActuationStatus.EXECUTED
    assert second.status == ActuationStatus.BLOCKED
    assert seen == ["executed"]


# ---- Durable dispatch boundary: fencing + no false EXECUTED ----

class _UnfinalizableIdempotency(InMemoryIdempotencyRegistry):
    """A registry that admits and commits dispatch normally but always fails
    to durably persist EXECUTED -- models a backend outage occurring exactly
    between a successful external call and the durable success write."""

    async def mark_executed(self, key, *, tenant_id, fence, binding="", result_ref=None):
        return False


def test_durable_executed_persistence_failure_yields_unknown_not_false_success(tmp_path):
    engine, coord, audit = build(tmp_path, idempotency=_UnfinalizableIdempotency())
    token, payload = payment(engine, idem="op-1")
    seen = []
    res = run(coord.enforce(token=token, action="send_payment", payload=payload,
                            executor=runner(seen), now=NOW))
    assert seen == ["executed"]  # the external call genuinely happened
    assert res.status == ActuationStatus.EXECUTION_FAILED  # never a false EXECUTED
    assert run(coord.idempotency.get_state("op-1", tenant_id="tenant-1")).state == IdempotencyState.UNKNOWN
    # Not retry-eligible: a fresh valid token for the same key is blocked.
    token2, payload2 = payment(engine, idem="op-1", txn="txn-B")
    seen2 = []
    second = run(coord.enforce(token=token2, action="send_payment", payload=payload2,
                               executor=runner(seen2), now=NOW))
    assert second.status == ActuationStatus.BLOCKED
    assert seen2 == []


def test_stale_fence_cannot_mark_executed_or_release(tmp_path):
    """Test scenarios 15/16: a stale owner (wrong fence) can neither finalize
    nor release/fail an operation it does not currently own."""
    reg = InMemoryIdempotencyRegistry()
    first = run(reg.reserve("op-1", binding="b", tenant_id="tenant-1"))
    assert first.ok
    stale_fence = first.fence
    # A legitimate recovery cycle: release, then a fresh reservation gets a
    # NEW fence.
    assert run(reg.release("op-1", fence=stale_fence, tenant_id="tenant-1"))
    second = run(reg.reserve("op-1", binding="b", tenant_id="tenant-1"))
    assert second.ok and second.fence != stale_fence
    assert run(reg.commit_dispatch("op-1", fence=second.fence, tenant_id="tenant-1"))
    # The stale (first) fence can no longer affect the (new) current owner.
    assert run(reg.mark_executed("op-1", fence=stale_fence, binding="b", tenant_id="tenant-1")) is False
    assert run(reg.mark_unknown("op-1", fence=stale_fence, tenant_id="tenant-1")) is False
    assert run(reg.release("op-1", fence=stale_fence, tenant_id="tenant-1")) is False
    # The legitimate (current) owner still can.
    assert run(reg.mark_executed("op-1", fence=second.fence, binding="b", tenant_id="tenant-1"))
    record = run(reg.get_state("op-1", tenant_id="tenant-1"))
    assert record.state == IdempotencyState.EXECUTED


class _RaisingAudit:
    """Models an audit backend that cannot durably confirm the
    pre-enforcement decision (test scenario 9)."""

    def append(self, record):
        raise IOError("disk full; cannot fsync audit entry")


def test_audit_before_actuation_failure_zero_actuator_calls(tmp_path):
    engine, coord, _audit = build(tmp_path)
    coord.audit = _RaisingAudit()  # every self.audit.append(...) call now raises
    token, payload = payment(engine, idem="op-1")
    seen = []
    res = run(coord.enforce(token=token, action="send_payment", payload=payload,
                            executor=runner(seen), now=NOW))
    assert res.status == ActuationStatus.BLOCKED
    assert "audit-before-actuation" in res.reason.lower()
    assert seen == []  # zero actuator calls
    # Pre-dispatch failure: the logical operation is released, safe to retry.
    assert run(coord.idempotency.get_state("op-1", tenant_id="tenant-1")) is None


def test_dispatch_ownership_committed_before_executor_invoked(tmp_path):
    """Test scenario 6: after ``commit_dispatch`` succeeds, the operation is
    durably DISPATCH_OWNED even if the executor is never actually called
    (models a crash between commitment and invocation) -- no automatic
    redispatch is possible because ``reserve`` on the same key is blocked."""
    reg = InMemoryIdempotencyRegistry()
    reserved = run(reg.reserve("op-1", binding="b", tenant_id="tenant-1"))
    assert run(reg.commit_dispatch("op-1", fence=reserved.fence, tenant_id="tenant-1"))
    record = run(reg.get_state("op-1", tenant_id="tenant-1"))
    assert record.state == IdempotencyState.DISPATCH_OWNED
    retry = run(reg.reserve("op-1", binding="b", tenant_id="tenant-1"))
    assert not retry.ok
    assert retry.status == ReserveStatus.DUPLICATE_INFLIGHT
