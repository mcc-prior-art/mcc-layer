"""P2-A Low-Latency Authority Plane: adversarial/negative-control suite.

Distinct from the benchmark harness (``benchmarks/``): this suite does not
measure latency, it proves that nothing on the governed path can be
bypassed, and every negative case asserts the EXACT actuator-call count
(never just a status string) via the real, instrumented ``Stack.seen``
list built in ``benchmarks/workload.py`` -- the same real
``DecisionEngine``/``ExecutionGate``/``EnforcementCoordinator`` every
other path in this repository uses, not a parallel or simplified one.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from benchmarks.workload import POLICY_HASH, RESOURCE, build_stack, context, now
from mcc_core import InMemoryRevocationRegistry, VelocityLimit
from mcc_core.mandate import RevocationStatus

run = asyncio.run


# ---- 1. Non-vacuity baselines: both authority paths genuinely execute ----

def test_baseline_mandate_executes_exactly_once():
    s = build_stack()
    m = s.mandate(now=now())
    out = run(s.exec_mandate(m, idempotency_key="op-1"))
    assert out.status == "EXECUTED"
    assert s.seen == [("send_payment", context())]


def test_baseline_delegation_executes_exactly_once():
    s = build_stack()
    d = s.delegation(now=now())
    out = run(s.exec_delegation(d, idempotency_key="op-1"))
    assert out.status == "EXECUTED"
    assert s.seen == [("send_payment", context())]


# ---- 2. DENY: scope and unclampable constraint breaches ----

def test_mandate_action_outside_scope_denied_zero_actuator_calls():
    s = build_stack()
    m = s.mandate(now=now(), action_scope=["some_other_action"])
    out = run(s.exec_mandate(m, idempotency_key="op-deny-scope"))
    assert out.status == "BLOCKED"
    assert s.seen == []


def test_mandate_unclampable_currency_breach_denied_zero_actuator_calls():
    s = build_stack()
    # allowed_currency is an enum-membership constraint -- not numeric, so
    # apply_constraints() cannot rewrite it into compliance; a mismatch
    # must DENY, never silently forward a different currency.
    m = s.mandate(now=now(), constraints={"allowed_currency": ["USD"]})
    out = run(s.exec_mandate(m, idempotency_key="op-deny-currency"))
    assert out.status == "BLOCKED"
    assert out.decision == "DENY"
    assert s.seen == []


# ---- 3. CONSTRAIN: a clampable breach executes the CLAMPED payload, never
# the originally-proposed one ----

def test_mandate_amount_breach_clamped_and_executes_clamped_payload_only():
    s = build_stack()
    m = s.mandate(now=now(), constraints={"max_amount": 10.0})
    out = run(s.exec_mandate(m, idempotency_key="op-constrain", context=context(amount=100.0)))
    assert out.status == "EXECUTED"
    assert out.decision == "CONSTRAIN"
    # Exactly one actuator call, carrying the CLAMPED amount (10.0), never
    # the originally-proposed 100.0.
    assert len(s.seen) == 1
    assert s.seen[0][1]["amount"] == 10.0


# ---- 4. ESCALATE loop: approval executes once; replay is denied ----

def test_escalate_approval_executes_exactly_once_after_human_approval():
    s = build_stack()
    rec = run(s.service.create_approval(
        actor="agent/payments-bot", action="send_payment", resource=RESOURCE,
        tenant_id="tenant-1", payload=context(),
    ))
    approved = run(s.service.approve(rec["request_id"]))
    assert approved is not None
    out = run(s.service.execute_with_approval(
        mandate=approved, actor="agent/payments-bot", action="send_payment",
        resource=RESOURCE, context=context(), tenant_id="tenant-1",
        idempotency_key="op-escalate-1",
    ))
    assert out.status == "EXECUTED"
    assert s.seen == [("send_payment", context())]


def test_escalate_approval_replay_denied_zero_additional_actuator_calls():
    s = build_stack()
    rec = run(s.service.create_approval(
        actor="agent/payments-bot", action="send_payment", resource=RESOURCE,
        tenant_id="tenant-1", payload=context(),
    ))
    approved = run(s.service.approve(rec["request_id"]))
    first = run(s.service.execute_with_approval(
        mandate=approved, actor="agent/payments-bot", action="send_payment",
        resource=RESOURCE, context=context(), tenant_id="tenant-1",
        idempotency_key="op-escalate-replay-1",
    ))
    assert first.status == "EXECUTED"
    s.reset_seen()
    # Same single-use approval mandate, presented again for a FRESH logical
    # operation (a different idempotency_key, so idempotency dedup alone
    # cannot be the reason this is blocked) -- the approval itself is
    # single-use and must already be consumed.
    replay = run(s.service.execute_with_approval(
        mandate=approved, actor="agent/payments-bot", action="send_payment",
        resource=RESOURCE, context=context(), tenant_id="tenant-1",
        idempotency_key="op-escalate-replay-2",
    ))
    assert replay.status == "BLOCKED"
    assert s.seen == []


# ---- 5. Revocation and expiry, re-checked at actuation time ----

def test_mandate_revoked_between_issuance_and_actuation_denied_zero_actuator_calls():
    revocation = InMemoryRevocationRegistry()
    s = build_stack(revocation_registry=revocation)
    m = s.mandate(now=now(), revocation_required=True)
    run(revocation.revoke(m["mandate_id"]))
    out = run(s.exec_mandate(m, idempotency_key="op-revoked"))
    assert out.status == "BLOCKED"
    assert s.seen == []


def test_mandate_expired_denied_zero_actuator_calls():
    s = build_stack()
    n = now()
    m = s.mandate(now=n, not_before=n - 120, not_after=n - 60, issued_at=n - 120)
    out = run(s.exec_mandate(m, idempotency_key="op-expired"))
    assert out.status == "BLOCKED"
    assert s.seen == []


def test_delegation_expired_denied_zero_actuator_calls():
    s = build_stack()
    n = now()
    d = s.delegation(now=n, not_before=n - 120, not_after=n - 60, issued_at=n - 120)
    out = run(s.exec_delegation(d, idempotency_key="op-deleg-expired"))
    assert out.status == "BLOCKED"
    assert s.seen == []


# ---- 6. Payload substitution via the delegation path: the authority check
# reads the SAME canonical payload that would be dispatched, never a
# separately-asserted value ----

def test_delegation_recipient_substitution_denied_zero_actuator_calls():
    s = build_stack()
    d = s.delegation(now=now())
    out = run(s.exec_delegation(
        d, idempotency_key="op-sub-recipient", context=context(beneficiary_id="attacker-acct"),
    ))
    assert out.status == "BLOCKED"
    assert "RECIPIENT_SCOPE_MISMATCH" in out.reason
    assert s.seen == []


def test_delegation_currency_substitution_denied_zero_actuator_calls():
    s = build_stack()
    d = s.delegation(now=now())
    out = run(s.exec_delegation(d, idempotency_key="op-sub-currency", context=context(currency="USD")))
    assert out.status == "BLOCKED"
    assert "CURRENCY_MISMATCH" in out.reason
    assert s.seen == []


# ---- 7. Double-spend via transaction splitting against the delegation's
# own atomic cumulative ceiling ----

def test_delegation_double_spend_splitting_denied_on_breach_zero_extra_calls():
    s = build_stack()
    n = now()
    d = s.delegation(now=n, max_amount=50.0)
    out1 = run(s.exec_delegation(d, idempotency_key="op-split-1", context=context(amount=25.0)))
    out2 = run(s.exec_delegation(d, idempotency_key="op-split-2", context=context(amount=25.0)))
    out3 = run(s.exec_delegation(d, idempotency_key="op-split-3", context=context(amount=25.0)))
    assert [out1.status, out2.status] == ["EXECUTED", "EXECUTED"]
    assert out3.status == "BLOCKED"
    assert len(s.seen) == 2  # the third split never reached the actuator


def test_concurrent_contended_delegation_spend_never_exceeds_ceiling():
    s = build_stack()
    n = now()
    d = s.delegation(now=n, max_amount=100.0)

    async def race():
        return await asyncio.gather(*[
            s.exec_delegation(d, idempotency_key=f"op-race-{i}", context=context(amount=25.0))
            for i in range(12)
        ])

    results = run(race())
    executed = [r for r in results if r.status == "EXECUTED"]
    # 12 concurrent attempts at 25.0 against a 100.0 ceiling: at most 4 may
    # ever reach the actuator, however the race resolves.
    assert len(executed) <= 4
    assert len(s.seen) == len(executed)
    assert len(executed) * 25.0 <= 100.0


# ---- 8. Nonce single-use replay: the identical token presented twice ----

def test_identical_token_replay_denied_zero_additional_actuator_calls():
    s = build_stack()
    n = now()
    m = s.mandate(now=n)
    token = s.engine.issue_token(
        verdict="ALLOW", subject="agent/payments-bot", action="send_payment",
        payload=context(), idempotency_key="op-nonce-replay", actor_id="agent/payments-bot",
        resource_id=RESOURCE, tenant_id="tenant-1", mandate_id=m["mandate_id"], now=n,
    )

    async def enforce_once():
        return await s.coordinator.enforce(
            token=token, action="send_payment", payload=context(),
            executor=lambda: _record_and_return(s),
        )

    first = run(enforce_once())
    assert first.status.value == "EXECUTED"
    s.reset_seen()
    second = run(enforce_once())
    assert second.status.value == "BLOCKED"
    assert s.seen == []


async def _record_and_return(stack):
    stack.seen.append(("send_payment", context()))
    return {"ok": True}


# ---- 9. Clock uncertainty: an untrusted time source fails closed ----

def test_untrusted_time_source_blocks_with_zero_actuator_calls():
    from mcc_core.trusted_time import TimeTrustError, TrustedTimeSource

    class _BrokenTimeSource(TrustedTimeSource):
        async def now(self) -> int:
            raise TimeTrustError("CLOCK_UNTRUSTED", "simulated clock-trust failure")

    s = build_stack()
    s.service.time_source = _BrokenTimeSource()
    m = s.mandate(now=now())
    out = run(s.exec_mandate(m, idempotency_key="op-clock-untrusted"))
    assert out.status == "BLOCKED"
    assert s.seen == []
