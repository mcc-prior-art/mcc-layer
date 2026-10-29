"""P2-A3 -- fail-closed audit-integrity ENFORCEMENT at the two independent
boundaries: GovernanceService's issuance gate (``_integrity_gate``, called
before ``DecisionEngine.issue_token`` in ``execute_with_mandate`` /
``execute_with_delegation`` / ``execute_with_consensus``) and
EnforcementCoordinator's dispatch gate (the first statement of
``enforce()``).

Every BLOCKED scenario below asserts ZERO actuator calls. Every scenario
is paired with a non-vacuity companion (``integrity_monitor=None``, the
pre-P2-A3 baseline) proving the SAME scenario would otherwise have
executed -- i.e. the guard's absence is exactly what the positive test
would have caught.
"""

from __future__ import annotations

import asyncio
import tempfile
import time
from pathlib import Path

import pytest

from gateway.governance_service import GovernanceService
from mcc_core import (
    ApprovalService,
    AuditLog,
    ConsensusPolicy,
    ConsensusVerifier,
    DecisionEngine,
    EnforcementCoordinator,
    ExecutionGate,
    InMemoryApprovalRegistry,
    InMemoryIdempotencyRegistry,
    InMemoryNonceRegistry,
    InMemoryRevocationRegistry,
    InMemoryVelocityRegistry,
    ProfileRegistry,
    SigningKey,
    hash_payload,
    issue_mandate,
    issue_vote,
)
from mcc_core.audit_integrity import (
    AuditIntegrityMonitor,
    IntegrityState,
    InMemoryIntegrityStateRegistry,
)
from mcc_core.coordinator import ActuationStatus
from gateway.trust import TrustSet

run = asyncio.run

ACTION = "send_payment"
RESOURCE = "vendor-1"
POLICY_HASH = "sha256:" + "0" * 64


def _now() -> int:
    return int(time.time())


def _tmp_audit() -> AuditLog:
    d = tempfile.mkdtemp(prefix="mcc-p2a3-test-")
    return AuditLog(str(Path(d) / "audit.jsonl"))


def _raw_context(**overrides) -> dict:
    ctx = {"source": "acct-1", "beneficiary_id": RESOURCE, "amount": 100, "currency": "eur"}
    ctx.update(overrides)
    return ctx


def _healthy_monitor(audit: AuditLog) -> AuditIntegrityMonitor:
    # A real, intact chain -- at least one genuine append() -- not the
    # empty-bootstrap case (that is covered separately in
    # tests/test_audit_integrity.py).
    if not Path(audit.path).exists():
        audit.append({"seed": "healthy-monitor-fixture"})
    mon = AuditIntegrityMonitor(audit, InMemoryIntegrityStateRegistry())
    state = run(mon.verify_once())
    assert state == IntegrityState.HEALTHY
    return mon


def _unverified_monitor(audit: AuditLog) -> AuditIntegrityMonitor:
    # Never had verify_once() called -- UNVERIFIED, the real startup
    # condition before run_startup_verification() has completed.
    return AuditIntegrityMonitor(audit, InMemoryIntegrityStateRegistry())


def _unhealthy_monitor(audit: AuditLog) -> AuditIntegrityMonitor:
    """Genuine HISTORICAL corruption -- a broken hash link on a NON-LAST
    entry -- exactly the disclosed-scope-difference scenario PR #128
    documents: ``AuditLog.append()``'s own O(tail) tail-read never
    notices this (it only ever reads the true last line), so this
    deliberately does NOT confound the test with the audit log's own,
    separate, pre-existing "cannot append -> fail closed" behavior. Only
    the new P2-A3 full-chain ``verify_chain_safe()`` pass catches it."""
    for i in range(3):
        audit.append({"i": i})
    with open(audit.path, "r", encoding="utf-8") as fh:
        lines = fh.readlines()
    import json as _json

    mid = _json.loads(lines[1])
    mid["prev_hash"] = "deadbeef" * 8
    lines[1] = _json.dumps(mid) + "\n"
    with open(audit.path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)

    mon = AuditIntegrityMonitor(audit, InMemoryIntegrityStateRegistry())
    state = run(mon.verify_once())
    assert state == IntegrityState.UNHEALTHY
    return mon


class _CountingUpstream:
    def __init__(self) -> None:
        self.calls = 0

    async def __call__(self, action, payload):
        self.calls += 1
        return {"ok": True, "action": action, "payload": payload}


def _governance_service(*, mandate_key: SigningKey, integrity_monitor=None,
                        consensus_trusted_keys=None):
    signing_key = SigningKey.generate("gw-signing-1")
    engine = DecisionEngine(
        signing_key=signing_key, issuer="mcc/core", audience="pilot", policy_id="pilot/v1",
        policy_hash=POLICY_HASH,
    )
    gate = ExecutionGate(
        trusted_keys={signing_key.kid: signing_key.public_key()}, audience="pilot",
        nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY_HASH,
    )
    audit = _tmp_audit()
    if integrity_monitor is not None and integrity_monitor == "HEALTHY_FOR_THIS_AUDIT":
        integrity_monitor = _healthy_monitor(audit)
    coordinator = EnforcementCoordinator(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(),
        velocity=InMemoryVelocityRegistry(), audit=audit,
        profiles=ProfileRegistry.default_pilot(), revocation_registry=InMemoryRevocationRegistry(),
        integrity_monitor=integrity_monitor,
    )
    trust_set = TrustSet()
    trust_set.add_runtime_issuer("axlogiq/pilot", mandate_key.kid, mandate_key.public_key())
    approver_key = SigningKey.generate("approver-1")
    trust_set.add_runtime_issuer("mcc/approvals", approver_key.kid, approver_key.public_key())
    approvals = ApprovalService(InMemoryApprovalRegistry(), approver_key)

    upstream = _CountingUpstream()
    consensus_verifier = None
    if consensus_trusted_keys is not None:
        consensus_verifier = ConsensusVerifier(
            trusted_keys=consensus_trusted_keys, policy=ConsensusPolicy(threshold=2),
        )

    service = GovernanceService(
        engine=engine, coordinator=coordinator, trust_set=trust_set,
        revocation_registry=InMemoryRevocationRegistry(), approvals=approvals,
        profiles=ProfileRegistry.default_pilot(), upstream=upstream, policy_hash=POLICY_HASH,
        consensus_verifier=consensus_verifier,
        integrity_monitor=integrity_monitor,
    )
    service._test_audit = audit
    service._test_upstream = upstream
    return service


def _mandate(mandate_key: SigningKey, *, constraints=None):
    now = _now()
    return issue_mandate(
        mandate_key, issuer="axlogiq/pilot", subject="agent/payments-bot",
        action_scope=[ACTION], resource_scope=[RESOURCE],
        constraints=constraints or {}, not_before=now - 10, not_after=now + 3600,
        issued_at=now,
    )


# ===========================================================================
# 1. ISSUANCE boundary -- execute_with_mandate
# ===========================================================================


@pytest.mark.parametrize("monitor_factory", [_unverified_monitor, _unhealthy_monitor])
def test_mandate_issuance_blocked_when_integrity_not_healthy(monitor_factory):
    mandate_key = SigningKey.generate("issuer-1")
    audit = _tmp_audit()
    monitor = monitor_factory(audit)
    signing_key = SigningKey.generate("gw-signing-1")
    engine = DecisionEngine(signing_key=signing_key, issuer="mcc/core", audience="pilot",
                            policy_id="pilot/v1", policy_hash=POLICY_HASH)
    gate = ExecutionGate(trusted_keys={signing_key.kid: signing_key.public_key()},
                         audience="pilot", nonce_registry=InMemoryNonceRegistry(),
                         policy_hash=POLICY_HASH)
    coordinator = EnforcementCoordinator(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(), velocity=InMemoryVelocityRegistry(),
        audit=audit, profiles=ProfileRegistry.default_pilot(),
        revocation_registry=InMemoryRevocationRegistry(), integrity_monitor=monitor,
    )
    trust_set = TrustSet()
    trust_set.add_runtime_issuer("axlogiq/pilot", mandate_key.kid, mandate_key.public_key())
    approver_key = SigningKey.generate("approver-1")
    trust_set.add_runtime_issuer("mcc/approvals", approver_key.kid, approver_key.public_key())
    upstream = _CountingUpstream()
    original_issue_token = engine.issue_token
    issue_calls = {"n": 0}

    def counting_issue_token(*a, **kw):
        issue_calls["n"] += 1
        return original_issue_token(*a, **kw)

    engine.issue_token = counting_issue_token
    service = GovernanceService(
        engine=engine, coordinator=coordinator, trust_set=trust_set,
        revocation_registry=InMemoryRevocationRegistry(),
        approvals=ApprovalService(InMemoryApprovalRegistry(), approver_key),
        profiles=ProfileRegistry.default_pilot(), upstream=upstream, policy_hash=POLICY_HASH,
        integrity_monitor=monitor,
    )
    mandate = _mandate(mandate_key)
    out = run(service.execute_with_mandate(
        mandate=mandate, actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=_raw_context(), idempotency_key="op-1", tenant_id="tenant-1",
    ))
    assert out.status == "BLOCKED"
    assert "AUDIT_INTEGRITY_NOT_HEALTHY" in out.reason
    assert issue_calls["n"] == 0, "issue_token must never be called when integrity is not HEALTHY"
    assert upstream.calls == 0


def test_mandate_issuance_executes_when_integrity_healthy():
    mandate_key = SigningKey.generate("issuer-1")
    service = _governance_service(mandate_key=mandate_key, integrity_monitor="HEALTHY_FOR_THIS_AUDIT")
    mandate = _mandate(mandate_key)
    out = run(service.execute_with_mandate(
        mandate=mandate, actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=_raw_context(), idempotency_key="op-2", tenant_id="tenant-1",
    ))
    assert out.status == "EXECUTED"
    assert service._test_upstream.calls == 1


def test_mandate_non_vacuity_without_integrity_monitor_configured_still_executes():
    """The pre-P2-A3 baseline: integrity_monitor=None (never configured) ->
    unchanged behavior -> the SAME proposal that is BLOCKED above with an
    UNVERIFIED/UNHEALTHY monitor configured now executes normally. This
    proves the positive tests above have teeth: removing the guard changes
    the outcome."""
    mandate_key = SigningKey.generate("issuer-1")
    service = _governance_service(mandate_key=mandate_key, integrity_monitor=None)
    mandate = _mandate(mandate_key)
    out = run(service.execute_with_mandate(
        mandate=mandate, actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=_raw_context(), idempotency_key="op-3", tenant_id="tenant-1",
    ))
    assert out.status == "EXECUTED"
    assert service._test_upstream.calls == 1


# ===========================================================================
# 2. ISSUANCE boundary -- execute_with_consensus (independent call site)
# ===========================================================================


def _consensus_keys_and_votes(action, payload, actor, resource, nonce, policy_hash=POLICY_HASH, now=None):
    keys = {f"ev-{i}": SigningKey.generate(f"ev-{i}") for i in range(2)}
    trusted = {kid: k.public_key() for kid, k in keys.items()}
    now = now or _now()
    votes = [
        issue_vote(k, evaluator_id=kid, action=action, payload=payload, actor=actor,
                  resource=resource, policy_hash=policy_hash, nonce=nonce,
                  verdict="ALLOW", issued_at=now, not_before=now - 10, not_after=now + 900)
        for kid, k in keys.items()
    ]
    return trusted, votes


def test_consensus_issuance_blocked_when_integrity_unhealthy():
    mandate_key = SigningKey.generate("issuer-1")  # unused by consensus path, kept for harness parity
    service = _governance_service(mandate_key=mandate_key, integrity_monitor=None)
    audit = service._test_audit
    monitor = _unhealthy_monitor(audit)
    service.integrity_monitor = monitor
    service.coordinator.integrity_monitor = monitor

    context = _raw_context()
    canonical = ProfileRegistry.default_pilot().for_action(ACTION).canonical_payload(context)
    nonce = "nonce-consensus-1"
    trusted, votes = _consensus_keys_and_votes(
        ACTION, canonical, "agent/payments-bot", RESOURCE, nonce,
    )
    service.consensus_verifier = ConsensusVerifier(
        trusted_keys=trusted, policy=ConsensusPolicy(threshold=2),
    )
    out = run(service.execute_with_consensus(
        votes=votes, actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=context, idempotency_key="op-c1", tenant_id="tenant-1", nonce=nonce,
    ))
    assert out.status == "BLOCKED"
    assert "AUDIT_INTEGRITY_NOT_HEALTHY" in out.reason
    assert service._test_upstream.calls == 0


def test_consensus_issuance_executes_when_integrity_healthy():
    mandate_key = SigningKey.generate("issuer-1")
    service = _governance_service(mandate_key=mandate_key, integrity_monitor="HEALTHY_FOR_THIS_AUDIT")
    context = _raw_context()
    canonical = ProfileRegistry.default_pilot().for_action(ACTION).canonical_payload(context)
    nonce = "nonce-consensus-2"
    trusted, votes = _consensus_keys_and_votes(
        ACTION, canonical, "agent/payments-bot", RESOURCE, nonce,
    )
    service.consensus_verifier = ConsensusVerifier(
        trusted_keys=trusted, policy=ConsensusPolicy(threshold=2),
    )
    out = run(service.execute_with_consensus(
        votes=votes, actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=context, idempotency_key="op-c2", tenant_id="tenant-1", nonce=nonce,
    ))
    assert out.status == "EXECUTED"
    assert service._test_upstream.calls == 1


# ===========================================================================
# 3. The gate helper directly -- proves all 3 issuance call sites share it,
#    without needing to stand up delegation's full owner-trust harness.
# ===========================================================================


def test_integrity_gate_blocks_directly_when_unhealthy():
    mandate_key = SigningKey.generate("issuer-1")
    service = _governance_service(mandate_key=mandate_key, integrity_monitor=None)
    audit = service._test_audit
    monitor = _unhealthy_monitor(audit)
    service.integrity_monitor = monitor
    blocked = run(service._integrity_gate())
    assert blocked is not None
    assert blocked.status == "BLOCKED"


def test_integrity_gate_noop_when_unconfigured():
    mandate_key = SigningKey.generate("issuer-1")
    service = _governance_service(mandate_key=mandate_key, integrity_monitor=None)
    assert run(service._integrity_gate()) is None


def test_integrity_gate_noop_when_healthy():
    mandate_key = SigningKey.generate("issuer-1")
    service = _governance_service(mandate_key=mandate_key, integrity_monitor="HEALTHY_FOR_THIS_AUDIT")
    assert run(service._integrity_gate()) is None


# ===========================================================================
# 4. DISPATCH boundary -- EnforcementCoordinator.enforce() directly
#    (the "direct API bypass": a caller that never goes through
#    GovernanceService at all).
# ===========================================================================


class _FakeGate:
    class _R:
        allowed = True
        reason = "ok"

    async def verify(self, *a, **kw):
        return self._R()


class _FakeIdem:
    class _Res:
        ok = True
        fence = "fence-1"
        reason = ""

    async def reserve(self, *a, **kw):
        return self._Res()

    async def commit_dispatch(self, *a, **kw):
        return True

    async def mark_executed(self, *a, **kw):
        return True

    async def mark_unknown(self, *a, **kw):
        return True

    async def release(self, *a, **kw):
        return True


class _FakeVelocity:
    class _Outcome:
        ok = True
        reserved = False
        now = None
        verdict = None
        reason = ""
        breaches: list = []

    async def reserve(self, *a, **kw):
        return self._Outcome()

    async def release(self, *a, **kw):
        return True


def _bare_coordinator(audit: AuditLog, integrity_monitor=None) -> EnforcementCoordinator:
    return EnforcementCoordinator(
        gate=_FakeGate(), idempotency=_FakeIdem(), velocity=_FakeVelocity(), audit=audit,
        integrity_monitor=integrity_monitor,
    )


def _token(idem_key="k1", tenant_id="t1"):
    return {"idempotency_key": idem_key, "tenant_id": tenant_id, "decision": "ALLOW",
            "payload_hash": "h", "actor_id": "agent/x", "resource_id": "r1"}


@pytest.mark.parametrize("monitor_factory", [_unverified_monitor, _unhealthy_monitor])
def test_direct_coordinator_call_blocked_when_integrity_not_healthy(monitor_factory):
    audit = _tmp_audit()
    monitor = monitor_factory(audit)
    coord = _bare_coordinator(audit, integrity_monitor=monitor)
    calls = {"n": 0}

    async def executor():
        calls["n"] += 1
        return {"ok": True}

    result = run(coord.enforce(token=_token(), action=ACTION, payload={}, executor=executor))
    assert result.status == ActuationStatus.BLOCKED
    assert "AUDIT_INTEGRITY_NOT_HEALTHY" in result.reason
    assert calls["n"] == 0


def test_direct_coordinator_call_executes_when_integrity_healthy():
    audit = _tmp_audit()
    monitor = _healthy_monitor(audit)
    coord = _bare_coordinator(audit, integrity_monitor=monitor)
    calls = {"n": 0}

    async def executor():
        calls["n"] += 1
        return {"ok": True}

    result = run(coord.enforce(token=_token(), action=ACTION, payload={}, executor=executor))
    assert result.status == ActuationStatus.EXECUTED
    assert calls["n"] == 1


def test_direct_coordinator_non_vacuity_without_guard_configured_executes():
    """Non-vacuity: with integrity_monitor=None (never configured -- the
    pre-P2-A3 baseline), the IDENTICAL direct-API-bypass scenario above
    (an UNVERIFIED/UNHEALTHY chain) is NOT blocked -- proving the positive
    tests above actually depend on the guard, not on some other check."""
    audit = _tmp_audit()
    for i in range(3):
        audit.append({"i": i})
    with open(audit.path, "r", encoding="utf-8") as fh:
        lines = fh.readlines()
    import json as _json

    mid = _json.loads(lines[1])
    mid["prev_hash"] = "deadbeef" * 8
    lines[1] = _json.dumps(mid) + "\n"
    with open(audit.path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)  # genuinely corrupted (historical, non-last-line); still no guard configured
    coord = _bare_coordinator(audit, integrity_monitor=None)
    calls = {"n": 0}

    async def executor():
        calls["n"] += 1
        return {"ok": True}

    result = run(coord.enforce(token=_token(), action=ACTION, payload={}, executor=executor))
    assert result.status == ActuationStatus.EXECUTED
    assert calls["n"] == 1


# ===========================================================================
# 5. Restart scenario: a corrupted file on disk at process (re)start must
#    never permit even one execution before the startup pass completes.
# ===========================================================================


def test_restart_with_corrupted_file_blocks_before_any_execution():
    audit = _tmp_audit()
    # Simulate real activity, then corruption, then a process restart: a
    # FRESH monitor (as build_governance_service() would construct on
    # startup) must report UNVERIFIED until run_startup_verification()
    # completes, and UNHEALTHY once it does, against the corrupted file --
    # never a window where HEALTHY (or some other non-blocking state) is
    # assumed by default.
    for i in range(3):
        audit.append({"i": i})
    with open(audit.path, "a", encoding="utf-8") as fh:
        fh.write("CORRUPTED-AFTER-RESTART\n")

    fresh_monitor = AuditIntegrityMonitor(audit, InMemoryIntegrityStateRegistry())
    assert run(fresh_monitor.current_state()) == IntegrityState.UNVERIFIED

    coord = _bare_coordinator(audit, integrity_monitor=fresh_monitor)
    calls = {"n": 0}

    async def executor():
        calls["n"] += 1
        return {"ok": True}

    # A caller that races ahead of startup verification is still blocked
    # (UNVERIFIED is not HEALTHY).
    result = run(coord.enforce(token=_token("restart-1"), action=ACTION, payload={}, executor=executor))
    assert result.status == ActuationStatus.BLOCKED
    assert calls["n"] == 0

    startup_state = run(fresh_monitor.run_startup_verification())
    assert startup_state == IntegrityState.UNHEALTHY

    result2 = run(coord.enforce(token=_token("restart-2"), action=ACTION, payload={}, executor=executor))
    assert result2.status == ActuationStatus.BLOCKED
    assert calls["n"] == 0


# ===========================================================================
# 6. Healthy-path regression: ALLOW still executes exactly once (no
#    accidental double-execution introduced by the new gate).
# ===========================================================================


def test_healthy_allow_executes_exactly_once_end_to_end():
    mandate_key = SigningKey.generate("issuer-1")
    service = _governance_service(mandate_key=mandate_key, integrity_monitor="HEALTHY_FOR_THIS_AUDIT")
    mandate = _mandate(mandate_key)
    out = run(service.execute_with_mandate(
        mandate=mandate, actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=_raw_context(), idempotency_key="op-once", tenant_id="tenant-1",
    ))
    assert out.status == "EXECUTED"
    assert service._test_upstream.calls == 1

    # A second call with the SAME idempotency_key must still be exactly-one
    # (idempotency semantics unaffected by the new gate) -- not a second
    # execution, not a silent duplicate.
    out2 = run(service.execute_with_mandate(
        mandate=mandate, actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=_raw_context(), idempotency_key="op-once", tenant_id="tenant-1",
    ))
    assert out2.status == "BLOCKED"
    assert service._test_upstream.calls == 1


# ===========================================================================
# 7. Idempotency UNKNOWN semantics preserved when integrity is HEALTHY
#    (the new gate must not interfere with the EXECUTION_FAILED/UNKNOWN
#    path at all -- it only ever runs BEFORE dispatch).
# ===========================================================================


def test_unknown_outcome_semantics_preserved_when_integrity_healthy():
    audit = _tmp_audit()
    monitor = _healthy_monitor(audit)
    coord = _bare_coordinator(audit, integrity_monitor=monitor)

    async def failing_executor():
        raise RuntimeError("upstream timeout (simulated)")

    result = run(coord.enforce(token=_token("unknown-1"), action=ACTION, payload={},
                               executor=failing_executor))
    assert result.status == ActuationStatus.EXECUTION_FAILED
    assert "UNKNOWN" in result.reason or "unknown" in result.reason


# ===========================================================================
# 8. Backward-compatibility: not configuring integrity_monitor at all must
#    be byte-for-byte the pre-P2-A3 behavior (already exercised throughout
#    tests/test_coordinator.py and friends, unmodified by this PR -- see
#    the full-suite run reported separately). Spot-check here too.
# ===========================================================================


def test_coordinator_default_has_no_integrity_monitor():
    audit = _tmp_audit()
    coord = _bare_coordinator(audit)  # no integrity_monitor kwarg at all
    assert coord.integrity_monitor is None


def test_governance_service_default_has_no_integrity_monitor():
    mandate_key = SigningKey.generate("issuer-1")
    service = _governance_service(mandate_key=mandate_key)  # no integrity_monitor kwarg at all
    assert service.integrity_monitor is None
