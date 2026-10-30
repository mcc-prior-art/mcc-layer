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


# ===========================================================================
# 9. Hardening round, Finding 1 (P1): journal deletion/truncation AFTER a
#    legitimate initialization must never be absorbed as "a fresh
#    bootstrap", through BOTH enforcement boundaries, with zero actuator
#    calls -- even with allow_empty_bootstrap=True.
# ===========================================================================


@pytest.mark.parametrize("destroy", ["delete", "truncate_to_zero"])
def test_journal_deletion_after_initialization_blocks_direct_coordinator_call(destroy):
    audit = _tmp_audit()
    audit.append({"seed": "real-history"})
    registry = InMemoryIntegrityStateRegistry()
    monitor = AuditIntegrityMonitor(audit, registry, allow_empty_bootstrap=True)
    assert run(monitor.verify_once()) == IntegrityState.HEALTHY

    if destroy == "delete":
        Path(audit.path).unlink()
    else:
        Path(audit.path).write_text("", encoding="utf-8")

    # Same process, same AuditLog instance -- the zero-delay prev_hash fast
    # path closes the race window without waiting for another pass.
    second_pass = run(monitor.verify_once())
    assert second_pass == IntegrityState.UNHEALTHY

    coord = _bare_coordinator(audit, integrity_monitor=monitor)
    calls = {"n": 0}

    async def executor():
        calls["n"] += 1
        return {"ok": True}

    result = run(coord.enforce(token=_token("deletion-1"), action=ACTION, payload={}, executor=executor))
    assert result.status == ActuationStatus.BLOCKED
    assert "AUDIT_INTEGRITY_NOT_HEALTHY" in result.reason
    assert calls["n"] == 0


@pytest.mark.parametrize("destroy", ["delete", "truncate_to_zero"])
def test_journal_deletion_after_initialization_blocks_mandate_issuance(destroy):
    mandate_key = SigningKey.generate("issuer-1")
    audit = _tmp_audit()
    audit.append({"seed": "real-history"})
    registry = InMemoryIntegrityStateRegistry()
    monitor = AuditIntegrityMonitor(audit, registry, allow_empty_bootstrap=True)
    assert run(monitor.verify_once()) == IntegrityState.HEALTHY

    if destroy == "delete":
        Path(audit.path).unlink()
    else:
        Path(audit.path).write_text("", encoding="utf-8")
    assert run(monitor.verify_once()) == IntegrityState.UNHEALTHY

    coordinator = EnforcementCoordinator(
        gate=ExecutionGate(
            trusted_keys={}, audience="pilot", nonce_registry=InMemoryNonceRegistry(),
            policy_hash=POLICY_HASH,
        ),
        idempotency=InMemoryIdempotencyRegistry(), velocity=InMemoryVelocityRegistry(),
        audit=audit, profiles=ProfileRegistry.default_pilot(),
        revocation_registry=InMemoryRevocationRegistry(), integrity_monitor=monitor,
    )
    trust_set = TrustSet()
    trust_set.add_runtime_issuer("axlogiq/pilot", mandate_key.kid, mandate_key.public_key())
    approver_key = SigningKey.generate("approver-1")
    trust_set.add_runtime_issuer("mcc/approvals", approver_key.kid, approver_key.public_key())
    signing_key = SigningKey.generate("gw-signing-1")
    engine = DecisionEngine(signing_key=signing_key, issuer="mcc/core", audience="pilot",
                            policy_id="pilot/v1", policy_hash=POLICY_HASH)
    issue_calls = {"n": 0}
    original_issue_token = engine.issue_token

    def counting_issue_token(*a, **kw):
        issue_calls["n"] += 1
        return original_issue_token(*a, **kw)

    engine.issue_token = counting_issue_token
    upstream = _CountingUpstream()
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
        context=_raw_context(), idempotency_key="deletion-mandate-1", tenant_id="tenant-1",
    ))
    assert out.status == "BLOCKED"
    assert "AUDIT_INTEGRITY_NOT_HEALTHY" in out.reason
    assert issue_calls["n"] == 0, "issue_token must never be called after journal deletion"
    assert upstream.calls == 0


def test_non_vacuity_reusable_bootstrap_would_have_resurrected_healthy():
    """Non-vacuity companion: reproduces the PRE-FIX ``_verify_once_locked``
    logic directly (treat empty/missing as bootstrap on EVERY pass,
    without the one-way latch this hardening round adds) to prove the P1
    bug was real -- deleting the journal after legitimate initialization
    would otherwise have been silently absorbed as "a fresh bootstrap"
    and reported HEALTHY again."""
    audit = _tmp_audit()
    audit.append({"seed": "real-history"})
    registry = InMemoryIntegrityStateRegistry()
    monitor = AuditIntegrityMonitor(audit, registry, allow_empty_bootstrap=True)
    assert run(monitor.verify_once()) == IntegrityState.HEALTHY

    Path(audit.path).unlink()

    async def pre_fix_verify_once() -> IntegrityState:
        # The exact pre-fix branch this hardening round replaced: empty/
        # missing is ALWAYS eligible for allow_empty_bootstrap, with no
        # one-way "ever initialized" latch at all.
        import os as _os

        if not _os.path.exists(audit.path) or _os.path.getsize(audit.path) == 0:
            return IntegrityState.HEALTHY  # allow_empty_bootstrap=True, unconditionally
        return await monitor.verify_once()

    resurrected = run(pre_fix_verify_once())
    assert resurrected == IntegrityState.HEALTHY, (
        "expected the reproduced pre-fix logic to incorrectly resurrect "
        "HEALTHY after journal deletion -- if it no longer does, this "
        "non-vacuity check itself needs revisiting"
    )
    # And the ACTUAL fixed monitor, on the same destroyed file, correctly
    # fails closed instead.
    assert run(monitor.verify_once()) == IntegrityState.UNHEALTHY


# ===========================================================================
# 10. Hardening round, Finding 3: multi-worker integrity isolation -- a
#     worker whose OWN audit log differs from the one a shared registry's
#     HEALTHY result was computed over must never inherit it.
# ===========================================================================


def test_worker_with_different_audit_log_does_not_inherit_shared_healthy():
    """Second hardening round updated this test's own expectations: the
    write-path identity veto (keyed on PHYSICAL identity, not just the
    content fingerprint used when this test was first written) now
    rejects worker A's conflicting write OUTRIGHT, so it never even lands
    in the shared registry. Worker A's own pass correctly resolves to
    UNHEALTHY too, since it cannot prove it is looking at the log this key
    actually represents.

    THIRD hardening round updates this test's expectations AGAIN,
    deliberately, not as a weakening: the second round left worker B
    (whose write was never vetoed) reading HEALTHY undisturbed -- only
    the "losing" worker A was blocked. Independent review correctly
    identified that as its own residual gap: the mere EXISTENCE of a
    detected cross-worker identity conflict means the deployment's own
    invariant is violated for *some* worker, and nothing here can tell
    which one -- so letting B keep operating as if nothing happened was
    not safe. The global conflict latch this round adds means B is now
    ALSO correctly blocked once A's conflicting write is detected -- see
    test_fix_global_conflict_latch_blocks_every_worker_regardless_of_race_ordering
    above for the two-ordering, both-enforcement-boundary proof of this."""
    shared_registry = InMemoryIntegrityStateRegistry()

    # Worker B establishes trust in ITS OWN audit log first (exactly what
    # the mandatory synchronous startup verification does in every real
    # deployment path) -- its own identity is now cached locally.
    audit_b = _tmp_audit()
    audit_b.append({"seed": "worker-b-genuine-history"})
    mon_b = AuditIntegrityMonitor(audit_b, shared_registry)
    assert run(mon_b.verify_once()) == IntegrityState.HEALTHY
    assert run(mon_b.current_state()) == IntegrityState.HEALTHY

    # Worker A is misconfigured (or its local file was corrupted/replaced)
    # to point at a DIFFERENT audit log than worker B's, while sharing the
    # SAME registry key. A's own periodic pass now gets VETOED at the
    # registry's write path (different physical identity) -- it never
    # overwrites B's record.
    audit_a = _tmp_audit()
    audit_a.append({"seed": "worker-a-DIFFERENT-history"})
    mon_a = AuditIntegrityMonitor(audit_a, shared_registry)
    assert run(mon_a.verify_once()) == IntegrityState.UNHEALTHY, (
        "worker A's write must be vetoed -- it cannot prove it is looking "
        "at the log this shared key already represents"
    )
    assert mon_a.identity_conflict_detected is True

    coord_b = _bare_coordinator(audit_b, integrity_monitor=mon_b)
    coord_a = _bare_coordinator(audit_a, integrity_monitor=mon_a)
    calls = {"n": 0}

    async def executor():
        calls["n"] += 1
        return {"ok": True}

    # Third hardening round: A's rejected write latched a GLOBAL conflict
    # for this key -- B is NOW ALSO blocked, not "completely undisturbed"
    # as the second round left it. B's own record in the registry is
    # untouched (A's write never landed), but current_state() no longer
    # reads that record in isolation -- it checks the global latch first.
    assert run(shared_registry.is_conflicted()) is True
    assert run(mon_b.current_state()) == IntegrityState.UNHEALTHY
    result_b = run(coord_b.enforce(token=_token("cross-worker-b"), action=ACTION, payload={}, executor=executor))
    assert result_b.status == ActuationStatus.BLOCKED
    assert calls["n"] == 0

    # Worker A, correctly, can never claim HEALTHY while sharing this key
    # with a conflicting identity -- zero actuator calls on A's side.
    assert run(mon_a.current_state()) == IntegrityState.UNHEALTHY
    result_a = run(coord_a.enforce(token=_token("cross-worker-a"), action=ACTION, payload={}, executor=executor))
    assert result_a.status == ActuationStatus.BLOCKED
    assert calls["n"] == 0  # unchanged -- neither worker ever actuates


def test_non_vacuity_shared_healthy_without_identity_check_would_be_inherited():
    """Non-vacuity companion: reproduces the PRE-FIX current_state() logic
    (no identity comparison at all) to prove Finding 3's original bug was
    real. Worker A's deposit is written directly via ``set_if_newer``
    (rather than through ``mon_a.verify_once()``) deliberately WITHOUT a
    ``physical_identity`` argument -- reproducing the write path exactly as
    it existed before the second hardening round's identity veto, which is
    not what this specific (older, already-fixed-by-Finding-3) scenario is
    about. See ``test_non_vacuity_write_path_veto_absent_would_let_a_newer_
    generation_override_an_unresolved_conflict`` below for THIS round's own
    non-vacuity companion."""
    shared_registry = InMemoryIntegrityStateRegistry()

    audit_b = _tmp_audit()
    audit_b.append({"seed": "worker-b-genuine-history"})
    mon_b = AuditIntegrityMonitor(audit_b, shared_registry)
    assert run(mon_b.verify_once()) == IntegrityState.HEALTHY

    audit_a = _tmp_audit()
    audit_a.append({"seed": "worker-a-DIFFERENT-history"})
    fp_a = audit_a.genesis_fingerprint_safe()
    applied = run(shared_registry.set_if_newer(
        generation=2, state=IntegrityState.HEALTHY, reason="worker A: intact",
        verified_at=_now(), log_identity=fp_a,  # no physical_identity -> no veto possible
    ))
    assert applied is True

    async def pre_fix_current_state() -> IntegrityState:
        # The exact pre-fix logic: trust the registry's stored HEALTHY
        # verbatim (subject only to freshness), with no identity check.
        status = await shared_registry.get()
        if status is None:
            return IntegrityState.UNVERIFIED
        if status.state != IntegrityState.HEALTHY:
            return status.state
        return IntegrityState.HEALTHY

    inherited = run(pre_fix_current_state())
    assert inherited == IntegrityState.HEALTHY, (
        "expected the reproduced pre-fix logic to incorrectly inherit "
        "worker A's HEALTHY for worker B's own (different) log -- if it "
        "no longer does, this non-vacuity check itself needs revisiting"
    )
    # The ACTUAL fixed monitor correctly distinguishes them.
    assert run(mon_b.current_state()) == IntegrityState.UNHEALTHY


def test_content_fingerprint_mismatch_alone_still_fails_closed_without_physical_identity():
    """Defense-in-depth, isolated: current_state()'s SECONDARY
    (content-fingerprint) check still independently fails closed on a
    mismatch when NO physical identity is available to compare at all --
    e.g. a legacy record written before the second hardening round's
    physical-identity field existed. This is what Finding 3's original
    check still catches on its own, independent of the second round's
    write-path veto (which never had anything to check here -- the legacy
    write carries no physical identity, so the veto condition is never
    even reachable). This is the dedicated detector test for the
    ``audit-integrity-cross-worker-identity-check-disabled`` mutation
    defect, since the integration-level test above now also depends on
    the (separately, independently tested) write-path veto and would no
    longer catch THIS specific check being disabled on its own."""
    shared_registry = InMemoryIntegrityStateRegistry()
    applied = run(shared_registry.set_if_newer(
        generation=1, state=IntegrityState.HEALTHY, reason="legacy write (pre-second-round)",
        verified_at=_now(), log_identity="legacy-fingerprint-X",
    ))
    assert applied is True
    status = run(shared_registry.get())
    assert status.physical_identity is None  # the write-path veto never had anything to check

    audit_b = _tmp_audit()
    mon_b = AuditIntegrityMonitor(audit_b, shared_registry)
    mon_b._last_observed_identity = "a-totally-different-fingerprint"  # this worker's own

    assert run(mon_b.current_state()) == IntegrityState.UNHEALTHY, (
        "the content-fingerprint-only check must still fail closed on a "
        "mismatch when no physical identity is available to compare"
    )


# ===========================================================================
# Second hardening round: cross-worker identity-COLLISION fail-open.
#
# genesis_fingerprint_safe() hashes only the audit file's FIRST line. Two
# PHYSICALLY DIFFERENT files, cloned/bootstrapped from the same initial
# record, share this fingerprint even though their tails have since
# diverged. Independent review's exact scenario: Worker B detects a
# corrupted/divergent tail and records UNHEALTHY; Worker A subsequently
# verifies its own (genuinely intact, but DIFFERENT) log and records a
# NEWER HEALTHY -- the old generation-only write path (and the old
# content-fingerprint-only read check, which collides by construction
# here) let A's write silently override B's correctly-detected failure.
# ===========================================================================


def _cloned_genesis_logs(tmp_path_factory_dir):
    """Two physically distinct audit files, seeded with a BYTE-IDENTICAL
    first record (simulating "cloned from the same initial record"), with
    B's tail then corrupted/diverged while A's stays intact and
    append-valid. Returns (audit_a, audit_b)."""
    import tempfile

    # A valid legacy genesis trust anchor (LEGACY_GENESIS_HASH == "genesis"
    # -- see AuditLog.verify_chain) so a real append() chains onto it
    # correctly and verify_chain() accepts it as the trust anchor.
    seed = '{"hash": "genesis", "seed": "shared-initial-record"}\n'
    dir_a = Path(tempfile.mkdtemp(prefix="mcc-collision-a-"))
    dir_b = Path(tempfile.mkdtemp(prefix="mcc-collision-b-"))
    (dir_a / "audit.jsonl").write_text(seed, encoding="utf-8")
    (dir_b / "audit.jsonl").write_text(seed, encoding="utf-8")
    audit_a = AuditLog(str(dir_a / "audit.jsonl"))
    audit_b = AuditLog(str(dir_b / "audit.jsonl"))
    # A stays intact: append a real, valid entry through the normal API.
    audit_a.append({"i": 1})
    # B diverges: append a corrupted record directly (bypassing append()),
    # so its chain fails verify_chain_safe() while sharing A's first line.
    with open(audit_b.path, "a", encoding="utf-8") as fh:
        fh.write('{"hash": "deadbeef", "prev_hash": "not-a-real-link", "i": 1}\n')
    return audit_a, audit_b


def test_reproduction_cloned_genesis_collision_was_a_real_fail_open_pre_fix():
    """Step 1: deterministic reproduction against the EXACT pre-this-round
    write/read logic (generation-only CAS, content-fingerprint-only read
    check -- i.e. the state of this module immediately after the FIRST
    hardening round, before this one). Proves the vulnerability was real:
    on that logic, Worker B's own correctly-detected UNHEALTHY is silently
    overridden by Worker A's HEALTHY for a DIFFERENT physical log, and
    Worker B's current_state() incorrectly inherits it."""
    audit_a, audit_b = _cloned_genesis_logs(None)
    assert audit_a.genesis_fingerprint_safe() == audit_b.genesis_fingerprint_safe(), (
        "fixture invariant: both logs must share the cloned genesis fingerprint"
    )
    shared_registry = InMemoryIntegrityStateRegistry()

    # Worker B verifies first: genuinely corrupted -> UNHEALTHY, generation 1.
    ok_b = AuditLog.verify_chain(audit_b.path)
    assert ok_b is False
    fp = audit_b.genesis_fingerprint_safe()
    applied_b = run(shared_registry.set_if_newer(
        generation=1, state=IntegrityState.UNHEALTHY, reason="worker B: corrupted tail",
        verified_at=_now(), log_identity=fp,  # pre-this-round: no physical_identity existed
    ))
    assert applied_b is True

    # Worker A verifies second: genuinely intact (its OWN, different, file)
    # -> HEALTHY, HIGHER generation. Pre-this-round write path (generation-
    # only CAS) applies this unconditionally.
    ok_a = AuditLog.verify_chain(audit_a.path)
    assert ok_a is True
    applied_a = run(shared_registry.set_if_newer(
        generation=2, state=IntegrityState.HEALTHY, reason="worker A: intact",
        verified_at=_now(), log_identity=fp,
    ))
    assert applied_a is True, "pre-fix write path has no identity veto -- this write applies"

    async def pre_fix_current_state_content_fingerprint_only(worker_own_fp: str) -> IntegrityState:
        # Finding 3's ORIGINAL (first-hardening-round) read-side check:
        # content fingerprint only -- which COLLIDES here by construction.
        status = await shared_registry.get()
        if status is None:
            return IntegrityState.UNVERIFIED
        if status.state != IntegrityState.HEALTHY:
            return status.state
        if status.log_identity is not None and status.log_identity != worker_own_fp:
            return IntegrityState.UNHEALTHY
        return IntegrityState.HEALTHY

    inherited = run(pre_fix_current_state_content_fingerprint_only(fp))
    assert inherited == IntegrityState.HEALTHY, (
        "CONFIRMED: on the pre-this-round logic, worker B incorrectly "
        "inherits worker A's HEALTHY for a DIFFERENT, genuinely corrupted "
        "physical log -- the vulnerability is real, not hypothetical"
    )


def test_fix_cloned_genesis_collision_is_vetoed_at_the_write_path():
    """Step 2/3: the ACTUAL fixed classes. Worker A's write is now vetoed
    OUTRIGHT by the write-path physical-identity CAS (regardless of A's
    higher generation) -- Worker B's correctly-detected, UNRESOLVED
    failure is never silently overridden. Also proves both enforcement
    boundaries: zero actuator calls on either worker's side while this
    conflict stands."""
    audit_a, audit_b = _cloned_genesis_logs(None)
    shared_registry = InMemoryIntegrityStateRegistry()

    mon_b = AuditIntegrityMonitor(audit_b, shared_registry)
    assert run(mon_b.verify_once()) == IntegrityState.UNHEALTHY  # genuine corruption, correctly detected

    mon_a = AuditIntegrityMonitor(audit_a, shared_registry)
    assert run(mon_a.verify_once()) == IntegrityState.UNHEALTHY, (
        "Worker A's own intact-log result must be vetoed: it cannot prove "
        "it is looking at the log the shared key already represents"
    )
    assert mon_a.identity_conflict_detected is True

    # Worker B's UNRESOLVED failure stands, untouched, exactly as the
    # independent review's own wording requires: "a successful
    # verification on worker A must never override an unresolved failure
    # on worker B."
    assert run(mon_b.current_state()) == IntegrityState.UNHEALTHY
    status = run(shared_registry.get())
    assert status.state == IntegrityState.UNHEALTHY
    assert status.reason == "hash-chain verification failed"

    # Both enforcement boundaries, both workers: zero actuator calls.
    coord_b = _bare_coordinator(audit_b, integrity_monitor=mon_b)
    coord_a = _bare_coordinator(audit_a, integrity_monitor=mon_a)
    calls = {"n": 0}

    async def executor():
        calls["n"] += 1
        return {"ok": True}

    result_b = run(coord_b.enforce(token=_token("collision-dispatch-b"), action=ACTION, payload={}, executor=executor))
    assert result_b.status == ActuationStatus.BLOCKED
    result_a = run(coord_a.enforce(token=_token("collision-dispatch-a"), action=ACTION, payload={}, executor=executor))
    assert result_a.status == ActuationStatus.BLOCKED
    assert calls["n"] == 0

    mandate_key = SigningKey.generate("collision-issuer")
    service_b = _governance_service(mandate_key=mandate_key, integrity_monitor=mon_b)
    service_b._test_audit = audit_b
    out_b = run(service_b.execute_with_mandate(
        mandate=_mandate(mandate_key), actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=_raw_context(), idempotency_key="collision-issuance-b", tenant_id="tenant-1",
    ))
    assert out_b.status == "BLOCKED"
    assert "AUDIT_INTEGRITY_NOT_HEALTHY" in out_b.reason
    assert service_b._test_upstream.calls == 0


def test_non_vacuity_write_path_veto_absent_would_let_a_newer_generation_override_an_unresolved_conflict():
    """Non-vacuity companion for THIS round's fix: with the write-path
    identity veto removed (simulated by calling set_if_newer without a
    physical_identity, i.e. exactly the generation-only CAS this registry
    had before this round), the IDENTICAL scenario DOES let Worker A's
    write override Worker B's unresolved failure -- proving the positive
    test above actually depends on the veto, not on something else."""
    audit_a, audit_b = _cloned_genesis_logs(None)
    shared_registry = InMemoryIntegrityStateRegistry()
    fp = audit_b.genesis_fingerprint_safe()

    applied_b = run(shared_registry.set_if_newer(
        generation=1, state=IntegrityState.UNHEALTHY, reason="worker B: corrupted",
        verified_at=_now(), log_identity=fp,  # no physical_identity -> veto cannot fire
    ))
    assert applied_b is True
    applied_a = run(shared_registry.set_if_newer(
        generation=2, state=IntegrityState.HEALTHY, reason="worker A: intact",
        verified_at=_now(), log_identity=fp,  # no physical_identity -> veto cannot fire
    ))
    assert applied_a is True, (
        "without the physical-identity veto, A's higher-generation write "
        "incorrectly overrides B's unresolved failure -- confirming the "
        "positive test's veto is what actually prevents this"
    )
    status = run(shared_registry.get())
    assert status.state == IntegrityState.HEALTHY  # the bug, reproduced


def test_recovery_after_identity_conflict_requires_explicit_out_of_band_reset():
    """No silent recovery: retrying with the SAME conflicting identity
    changes nothing. A genuine, authorized recovery (e.g. an operator
    confirms which physical log is actually authoritative and
    re-provisions the shared integrity-state key) is always an explicit,
    out-of-band action -- modeled here, consistently with this module's
    existing bootstrap-latch recovery test
    (test_recovery_from_unhealthy_requires_an_explicit_new_pass), by
    provisioning a FRESH registry/key rather than any in-band clearing
    method (there is deliberately none)."""
    audit_a, audit_b = _cloned_genesis_logs(None)
    shared_registry = InMemoryIntegrityStateRegistry()

    mon_b = AuditIntegrityMonitor(audit_b, shared_registry)
    assert run(mon_b.verify_once()) == IntegrityState.UNHEALTHY
    mon_a = AuditIntegrityMonitor(audit_a, shared_registry)
    assert run(mon_a.verify_once()) == IntegrityState.UNHEALTHY

    # Retrying against the SAME key changes nothing -- no silent recovery.
    assert run(mon_a.verify_once()) == IntegrityState.UNHEALTHY
    assert run(mon_a.current_state()) == IntegrityState.UNHEALTHY

    # Explicit, out-of-band operator action: a fresh registry/key, after
    # the operator has independently confirmed worker A's log is the one
    # that should be authoritative going forward.
    fresh_registry = InMemoryIntegrityStateRegistry()
    mon_a_recovered = AuditIntegrityMonitor(audit_a, fresh_registry)
    assert run(mon_a_recovered.verify_once()) == IntegrityState.HEALTHY
    assert run(mon_a_recovered.current_state()) == IntegrityState.HEALTHY


# ===========================================================================
# Third hardening round -- the GLOBAL identity-conflict latch.
#
# The second round's write-path veto only protects the worker whose write
# gets rejected. If worker A writes HEALTHY FIRST (establishing the
# identity) and worker B's later, genuinely different, corrupted write is
# the one vetoed, worker A's own current_state() -- unaffected by B's
# rejected write -- keeps reading HEALTHY. This is the residual gap this
# round closes: a GLOBAL latch that, once ANY conflict is detected
# (regardless of which worker's write trips it), makes EVERY worker
# sharing the key report UNHEALTHY -- not only the one that lost the race.
# ===========================================================================


def test_non_vacuity_a_first_ordering_pre_this_round_a_would_stay_healthy():
    """Non-vacuity, Step 1: reproduce the EXACT residual gap against the
    pre-this-round logic (second-round write-path veto present, but no
    GLOBAL conflict latch). Worker A writes its genuinely intact result
    FIRST -- establishing the identity, so the veto never fires against
    A's own write. Worker B's later, genuinely corrupted, DIFFERENT
    identity is the one vetoed. On the pre-this-round logic, nothing about
    A's own subsequent current_state() is affected by B's rejected write
    -- it incorrectly stays HEALTHY, proving the gap was real."""
    audit_a, audit_b = _cloned_genesis_logs(None)
    shared_registry = InMemoryIntegrityStateRegistry()

    # Worker A verifies first: genuinely intact -> HEALTHY, establishes
    # the identity for this key (no conflict possible yet -- nothing else
    # has been recorded).
    ok_a = AuditLog.verify_chain(audit_a.path)
    assert ok_a is True
    fp_a = audit_a.physical_identity_safe()
    applied_a = run(shared_registry.set_if_newer(
        generation=1, state=IntegrityState.HEALTHY, reason="worker A: intact",
        verified_at=_now(), physical_identity=fp_a,
    ))
    assert applied_a is True

    # Worker B verifies second: genuinely corrupted, DIFFERENT physical
    # identity -> the write-path veto (second round's own fix) correctly
    # rejects it, regardless of B's higher generation.
    ok_b = AuditLog.verify_chain(audit_b.path)
    assert ok_b is False
    fp_b = audit_b.physical_identity_safe()
    assert fp_b != fp_a
    applied_b = run(shared_registry.set_if_newer(
        generation=2, state=IntegrityState.UNHEALTHY, reason="worker B: corrupted tail",
        verified_at=_now(), physical_identity=fp_b,
    ))
    assert applied_b is False, "B's conflicting write must still be vetoed (second round's fix)"

    async def pre_third_round_current_state(worker_own_physical_identity: str) -> IntegrityState:
        # The second-round read-side check ONLY: physical identity must
        # match THIS worker's own -- no awareness of a GLOBAL latch at
        # all, because none existed before this round.
        status = await shared_registry.get()
        if status is None:
            return IntegrityState.UNVERIFIED
        if status.state != IntegrityState.HEALTHY:
            return status.state
        if (
            status.physical_identity is not None
            and status.physical_identity != worker_own_physical_identity
        ):
            return IntegrityState.UNHEALTHY
        return IntegrityState.HEALTHY

    inherited_a = run(pre_third_round_current_state(fp_a))
    assert inherited_a == IntegrityState.HEALTHY, (
        "CONFIRMED: on the pre-this-round logic, worker A -- whose write "
        "was never vetoed -- incorrectly keeps reporting HEALTHY even "
        "though a genuine cross-worker identity conflict with worker B's "
        "DIFFERENT, corrupted log has been detected for this same key. "
        "The gap is real, not hypothetical."
    )


@pytest.mark.parametrize("ordering", ["a_first", "b_first"])
def test_fix_global_conflict_latch_blocks_every_worker_regardless_of_race_ordering(ordering):
    """The ACTUAL fix: regardless of which worker's write establishes the
    identity first, a detected conflict latches GLOBALLY -- BOTH workers'
    current_state() report UNHEALTHY, not only the one whose write was
    vetoed. Also proves both enforcement boundaries, for BOTH workers:
    zero actuator/issue_token calls while the conflict stands."""
    audit_a, audit_b = _cloned_genesis_logs(None)
    shared_registry = InMemoryIntegrityStateRegistry()
    mon_a = AuditIntegrityMonitor(audit_a, shared_registry)
    mon_b = AuditIntegrityMonitor(audit_b, shared_registry)

    if ordering == "a_first":
        state_first = run(mon_a.verify_once())   # A: genuinely intact -> HEALTHY, establishes identity
        state_second = run(mon_b.verify_once())  # B: genuinely corrupted, different identity -> vetoed
        assert state_first == IntegrityState.HEALTHY
        assert state_second == IntegrityState.UNHEALTHY
        assert mon_b.identity_conflict_detected is True
    else:
        state_first = run(mon_b.verify_once())   # B: genuinely corrupted -> UNHEALTHY, establishes identity
        state_second = run(mon_a.verify_once())  # A: genuinely intact, different identity -> vetoed
        assert state_first == IntegrityState.UNHEALTHY
        assert state_second == IntegrityState.UNHEALTHY
        assert mon_a.identity_conflict_detected is True

    assert run(shared_registry.is_conflicted()) is True

    # Both workers' current_state() -- including the one whose write was
    # NEVER vetoed -- report UNHEALTHY. This is the global latch's own
    # requirement: the conflict's mere existence poisons the key for
    # EVERY reader, not only the loser of the race.
    assert run(mon_a.current_state()) == IntegrityState.UNHEALTHY
    assert run(mon_b.current_state()) == IntegrityState.UNHEALTHY

    # Both enforcement boundaries, both workers: zero actuator calls.
    coord_a = _bare_coordinator(audit_a, integrity_monitor=mon_a)
    coord_b = _bare_coordinator(audit_b, integrity_monitor=mon_b)
    calls = {"n": 0}

    async def executor():
        calls["n"] += 1
        return {"ok": True}

    result_a = run(coord_a.enforce(
        token=_token(f"global-latch-dispatch-a-{ordering}"), action=ACTION, payload={}, executor=executor,
    ))
    assert result_a.status == ActuationStatus.BLOCKED
    result_b = run(coord_b.enforce(
        token=_token(f"global-latch-dispatch-b-{ordering}"), action=ACTION, payload={}, executor=executor,
    ))
    assert result_b.status == ActuationStatus.BLOCKED
    assert calls["n"] == 0

    mandate_key = SigningKey.generate(f"global-latch-issuer-{ordering}")
    service_a = _governance_service(mandate_key=mandate_key, integrity_monitor=mon_a)
    service_a._test_audit = audit_a
    out_a = run(service_a.execute_with_mandate(
        mandate=_mandate(mandate_key), actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=_raw_context(), idempotency_key=f"global-latch-issuance-a-{ordering}", tenant_id="tenant-1",
    ))
    assert out_a.status == "BLOCKED"
    assert "AUDIT_INTEGRITY_NOT_HEALTHY" in out_a.reason
    assert service_a._test_upstream.calls == 0

    service_b = _governance_service(mandate_key=mandate_key, integrity_monitor=mon_b)
    service_b._test_audit = audit_b
    out_b = run(service_b.execute_with_mandate(
        mandate=_mandate(mandate_key), actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=_raw_context(), idempotency_key=f"global-latch-issuance-b-{ordering}", tenant_id="tenant-1",
    ))
    assert out_b.status == "BLOCKED"
    assert "AUDIT_INTEGRITY_NOT_HEALTHY" in out_b.reason
    assert service_b._test_upstream.calls == 0


def test_global_conflict_latch_never_cleared_by_later_healthy_higher_generation_or_restart():
    """Requirement #3, verbatim: a LATER HEALTHY verification, a HIGHER
    generation, a process restart, or a concurrent write must never clear
    the conflict automatically."""
    audit_a, audit_b = _cloned_genesis_logs(None)
    shared_registry = InMemoryIntegrityStateRegistry()
    mon_a = AuditIntegrityMonitor(audit_a, shared_registry)
    mon_b = AuditIntegrityMonitor(audit_b, shared_registry)
    run(mon_a.verify_once())  # A first -> HEALTHY, establishes identity
    run(mon_b.verify_once())  # B second -> vetoed, latches the global conflict
    assert run(shared_registry.is_conflicted()) is True

    # A LATER verification pass, even a perfectly HEALTHY one, over the
    # SAME (still genuinely intact) log A, at a strictly HIGHER
    # generation than anything seen so far -- must not clear the latch.
    for _ in range(3):
        state = run(mon_a.verify_once())
        assert state == IntegrityState.UNHEALTHY, (
            "a later HEALTHY-worthy pass from the SAME, already-established "
            "identity must still resolve to UNHEALTHY once the global "
            "conflict is latched -- the latch, not this pass's own merit, "
            "is what current_state() (and now verify_once()'s own "
            "short-circuit) must honor"
        )
    assert run(shared_registry.is_conflicted()) is True
    assert run(mon_a.current_state()) == IntegrityState.UNHEALTHY

    # A "process restart" -- a brand-new AuditIntegrityMonitor instance
    # (no local state carried over), still pointed at the SAME registry --
    # sees the SAME latched conflict; it is not a per-process flag.
    mon_a_restarted = AuditIntegrityMonitor(audit_a, shared_registry)
    assert run(mon_a_restarted.current_state()) == IntegrityState.UNHEALTHY
    assert run(mon_a_restarted.verify_once()) == IntegrityState.UNHEALTHY

    # Only the documented, explicit, out-of-band recovery -- a fresh
    # registry/key -- clears it (see
    # test_recovery_after_identity_conflict_requires_explicit_out_of_band_reset
    # above for the full recovery flow).
    fresh_registry = InMemoryIntegrityStateRegistry()
    assert run(fresh_registry.is_conflicted()) is False
    mon_a_recovered = AuditIntegrityMonitor(audit_a, fresh_registry)
    assert run(mon_a_recovered.verify_once()) == IntegrityState.HEALTHY
