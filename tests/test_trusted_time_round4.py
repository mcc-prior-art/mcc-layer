"""PR #122 round 4: completes trusted-time coverage for the paths round 3
left on bare ``time.time()`` -- ``ConsensusVerifier.verify()`` (via
``EnforcementCoordinator.enforce()`` and ``GovernanceService._consensus()``/
``verify_consensus()``), ``ChallengeService.issue()/get()/consume()``, and
``PreExecutionControl.evaluate()``. Reproduces the clock-drift weakness
first (actuator-call-instrumented, real coordinator), then re-confirms it
closed once every component resolves `now` through the hardened
``time_source`` chain instead of a bare local clock.

Each real-actuator test below calls ``coord.enforce()`` WITHOUT an explicit
``now=`` -- exactly the production call shape (``governance_service.py``
never passes one; see tests/test_velocity.py's static guard) -- so it
exercises the coordinator's own ``time_source`` resolution, not the
isolated test-clock override.
"""

from __future__ import annotations

import asyncio
import tempfile
import time
from pathlib import Path

import pytest

from mcc_core import (
    ActuationStatus,
    AuditLog,
    ChallengeService,
    ConsensusPolicy,
    ConsensusVerifier,
    DecisionEngine,
    EnforcementCoordinator,
    ExecutionGate,
    InMemoryChallengeRegistry,
    InMemoryIdempotencyRegistry,
    InMemoryNonceRegistry,
    InMemoryVelocityRegistry,
    ProfileRegistry,
    SigningKey,
    issue_vote,
)
from mcc_core.trusted_time import TimeTrustError, TrustedTimeSource

run = asyncio.run
ACTION = "generic_op"
PAYLOAD = {"value": 1}
ACTOR = "agent/ops"
RESOURCE = "res-1"
POLICY_HASH = "sha256:p"
NONCE = "nonce-fixed-1"


class _FixedTimeSource(TrustedTimeSource):
    """Simulates a gateway instance whose trusted-time resolution reports a
    FIXED value, independent of real wall-clock time -- e.g. a lagging
    local clock, or (for the correctly-resolved side) the true elapsed
    time a correctly-clocked / shared-Redis-backed instance would see."""

    def __init__(self, fixed_now: int) -> None:
        self._now = fixed_now

    async def now(self) -> int:
        return self._now


class _AlwaysUntrusted(TrustedTimeSource):
    async def now(self) -> int:
        raise TimeTrustError("CLOCK_UNTRUSTED", "simulated: time source down for this test")


def _coord(tmp_path, *, time_source, require_consensus=True, require_challenge=False,
           challenges=None):
    Path(tmp_path).mkdir(parents=True, exist_ok=True)
    keys = [SigningKey.generate(f"eval-{i}") for i in range(3)]
    trusted = {k.kid: k.public_key() for k in keys}
    verifier = ConsensusVerifier(trusted_keys=trusted, policy=ConsensusPolicy(threshold=3))
    dk = SigningKey.generate("dk")
    engine = DecisionEngine(signing_key=dk, issuer="mcc/test", audience="gate",
                            policy_id="pilot/v1", policy_hash=POLICY_HASH, token_ttl_seconds=60)
    gate = ExecutionGate(trusted_keys={dk.kid: dk.public_key()}, audience="gate",
                         nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY_HASH,
                         time_source=time_source)
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    coord = EnforcementCoordinator(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(),
        velocity=InMemoryVelocityRegistry(), audit=audit,
        profiles=ProfileRegistry.default_pilot(),
        consensus_verifier=verifier, require_consensus=require_consensus,
        challenges=challenges, require_challenge=require_challenge,
        time_source=time_source,
    )
    return keys, engine, coord


def _token(engine, *, idem="op-1", now=None):
    return engine.issue_token(
        verdict="ALLOW", subject=ACTOR, action=ACTION, payload=PAYLOAD,
        idempotency_key=idem, actor_id=ACTOR, resource_id=RESOURCE, nonce=NONCE,
        tenant_id="tenant-1", now=now,
    )


def _votes(keys, *, not_before, not_after, issued_at):
    return [issue_vote(keys[i], evaluator_id=f"eval-{i}", verdict="ALLOW", action=ACTION,
                       payload=PAYLOAD, actor=ACTOR, not_before=not_before, not_after=not_after,
                       issued_at=issued_at, resource=RESOURCE, policy_hash=POLICY_HASH, nonce=NONCE)
            for i in range(len(keys))]


def _runner(record):
    async def executor():
        record.append("executed")
        return "upstream-ok"
    return executor


# --------------------------------------------------------------------------
# 1. Reproduction: a gateway instance whose trusted-time resolution reports
# a value BEFORE the true deadline accepts an actually-expired consensus
# vote set; one that correctly reports the true elapsed time rejects it.
# Actuator calls independently counted in both cases.
# --------------------------------------------------------------------------

def test_lagging_time_source_accepts_expired_consensus_votes_correct_one_rejects(tmp_path):
    vote_window_start = 1_000_000
    vote_window_end = 1_000_010  # votes valid for 10s
    true_now_at_dispatch = 1_000_020  # 10s PAST the vote deadline

    keys_lag, engine_lag, coord_lag = _coord(tmp_path / "lag", time_source=_FixedTimeSource(vote_window_start + 5))
    votes_lag = _votes(keys_lag, not_before=vote_window_start, not_after=vote_window_end,
                       issued_at=vote_window_start)
    seen_lag: list = []
    res_lag = run(coord_lag.enforce(token=_token(engine_lag, now=vote_window_start + 5), action=ACTION, payload=PAYLOAD,
                                     executor=_runner(seen_lag), consensus_votes=votes_lag))
    assert res_lag.status == ActuationStatus.EXECUTED, (
        "reproduction: a trusted-time source that (wrongly) reports a time "
        "still inside the vote window lets an actually-expired-by-true-time "
        "vote set through -- demonstrates the dependency on an accurate "
        "clock, exactly like the round-2 approval finding, now shown for "
        "consensus votes too"
    )
    assert seen_lag == ["executed"]

    keys_ok, engine_ok, coord_ok = _coord(tmp_path / "correct", time_source=_FixedTimeSource(true_now_at_dispatch))
    votes_ok = _votes(keys_ok, not_before=vote_window_start, not_after=vote_window_end,
                      issued_at=vote_window_start)
    seen_ok: list = []
    res_ok = run(coord_ok.enforce(token=_token(engine_ok, now=true_now_at_dispatch), action=ACTION, payload=PAYLOAD,
                                   executor=_runner(seen_ok), consensus_votes=votes_ok))
    assert res_ok.status == ActuationStatus.BLOCKED, (
        "a correctly-resolved trusted time must reject the expired vote set"
    )
    assert seen_ok == [], "actuator must never be invoked when consensus votes are expired"


def test_shared_time_source_closes_the_lagging_consensus_gap(tmp_path):
    """The fix: when BOTH 'instances' resolve `now` from the SAME shared,
    accurate time source (what MCC_TIME_TRUST_BACKEND=redis gives every
    real gateway instance), there is no lagging clock left to exploit --
    both correctly reject the expired vote set."""
    vote_window_start = 2_000_000
    vote_window_end = 2_000_010
    true_now_at_dispatch = 2_000_020

    shared = _FixedTimeSource(true_now_at_dispatch)  # the ONE shared, accurate clock
    for label in ("a", "b"):
        d = tmp_path / label
        d.mkdir()
        keys, engine, coord = _coord(d, time_source=shared)
        votes = _votes(keys, not_before=vote_window_start, not_after=vote_window_end,
                       issued_at=vote_window_start)
        seen: list = []
        res = run(coord.enforce(token=_token(engine, now=true_now_at_dispatch), action=ACTION, payload=PAYLOAD,
                                executor=_runner(seen), consensus_votes=votes))
        assert res.status == ActuationStatus.BLOCKED
        assert seen == []


# --------------------------------------------------------------------------
# 2. Same reproduction, for the consensus CHALLENGE's single-use expiry.
# --------------------------------------------------------------------------

def test_lagging_time_source_accepts_expired_challenge_correct_one_rejects(tmp_path):
    issued_at = 3_000_000
    ttl_seconds = 10
    true_now_at_dispatch = issued_at + ttl_seconds + 5  # 5s past the challenge deadline

    async def _go():
        lagging_source = _FixedTimeSource(issued_at + 2)  # still "inside" the window per this clock
        challenges_lag = ChallengeService(InMemoryChallengeRegistry(), time_source=lagging_source)
        keys_lag, engine_lag, coord_lag = _coord(
            tmp_path / "lag", time_source=lagging_source, require_consensus=False,
            require_challenge=True, challenges=challenges_lag,
        )
        rec = await challenges_lag.issue(
            action=ACTION, actor=ACTOR, resource=RESOURCE,
            payload_hash=engine_lag.issue_token(  # reuse the engine's own payload hash helper via a throwaway token
                verdict="ALLOW", subject=ACTOR, action=ACTION, payload=PAYLOAD,
                idempotency_key="throwaway", actor_id=ACTOR, resource_id=RESOURCE,
                nonce="throwaway", tenant_id="tenant-1",
            )["payload_hash"],
            policy_hash=POLICY_HASH, ttl_seconds=ttl_seconds, now=issued_at,
        )
        token_lag = engine_lag.issue_token(
            verdict="ALLOW", subject=ACTOR, action=ACTION, payload=PAYLOAD,
            idempotency_key="op-chal-lag", actor_id=ACTOR, resource_id=RESOURCE, nonce=rec.nonce,
            tenant_id="tenant-1", auth_claims={"challenge_id": rec.challenge_id},
            now=issued_at + 2,
        )
        seen_lag: list = []
        res_lag = await coord_lag.enforce(token=token_lag, action=ACTION, payload=PAYLOAD,
                                          executor=_runner(seen_lag))
        assert res_lag.status == ActuationStatus.EXECUTED, (
            "reproduction: a lagging trusted-time source lets an "
            "actually-expired-by-true-time challenge be consumed"
        )
        assert seen_lag == ["executed"]

        correct_source = _FixedTimeSource(true_now_at_dispatch)
        challenges_ok = ChallengeService(InMemoryChallengeRegistry(), time_source=correct_source)
        keys_ok, engine_ok, coord_ok = _coord(
            tmp_path / "correct", time_source=correct_source, require_consensus=False,
            require_challenge=True, challenges=challenges_ok,
        )
        rec2 = await challenges_ok.issue(
            action=ACTION, actor=ACTOR, resource=RESOURCE,
            payload_hash=engine_ok.issue_token(
                verdict="ALLOW", subject=ACTOR, action=ACTION, payload=PAYLOAD,
                idempotency_key="throwaway2", actor_id=ACTOR, resource_id=RESOURCE,
                nonce="throwaway2", tenant_id="tenant-1",
            )["payload_hash"],
            policy_hash=POLICY_HASH, ttl_seconds=ttl_seconds, now=issued_at,
        )
        token_ok = engine_ok.issue_token(
            verdict="ALLOW", subject=ACTOR, action=ACTION, payload=PAYLOAD,
            idempotency_key="op-chal-ok", actor_id=ACTOR, resource_id=RESOURCE, nonce=rec2.nonce,
            tenant_id="tenant-1", auth_claims={"challenge_id": rec2.challenge_id},
            now=true_now_at_dispatch,
        )
        seen_ok: list = []
        res_ok = await coord_ok.enforce(token=token_ok, action=ACTION, payload=PAYLOAD,
                                        executor=_runner(seen_ok))
        assert res_ok.status == ActuationStatus.BLOCKED
        assert seen_ok == [], "actuator must never be invoked when the challenge is expired"

    run(_go())


# --------------------------------------------------------------------------
# 3. Fail-closed wiring: ConsensusVerifier (via GovernanceService),
# ChallengeService, PreExecutionControl all refuse when their time source
# is untrusted -- never silently fall back to an unchecked local clock.
# --------------------------------------------------------------------------

def test_challenge_service_issue_and_consume_fail_closed_when_time_source_untrusted():
    async def _go():
        svc = ChallengeService(InMemoryChallengeRegistry())
        with pytest.raises(TimeTrustError):
            svc.time_source = _AlwaysUntrusted()
            await svc.issue(action=ACTION, actor=ACTOR, resource=RESOURCE,
                            payload_hash="sha256:" + "0" * 64, policy_hash=POLICY_HASH)

        # A challenge issued with a trusted clock, then attacked via an
        # untrusted source at consume() time.
        svc2 = ChallengeService(InMemoryChallengeRegistry())
        rec = await svc2.issue(action=ACTION, actor=ACTOR, resource=RESOURCE,
                               payload_hash="sha256:" + "0" * 64, policy_hash=POLICY_HASH,
                               now=1_000_000)
        svc2.time_source = _AlwaysUntrusted()
        result = await svc2.consume(
            rec.challenge_id, action=ACTION, actor=ACTOR, resource=RESOURCE,
            payload_hash="sha256:" + "0" * 64, policy_hash=POLICY_HASH, nonce=rec.nonce,
        )
        assert result.ok is False
        assert "CLOCK_UNTRUSTED" in result.reason

    run(_go())


def test_pre_execution_control_fails_closed_when_time_source_untrusted():
    """Round 5 fix: the ORIGINAL version of this test (see git history)
    exercised only the NOT_REQUIRED short-circuit, which returns before
    PreExecutionControl.evaluate() ever reaches its own clock resolution --
    the untrusted time source it constructed was never actually consulted.
    This version configures a REAL AttestationRequirement for the action
    under test (so `for_action()` returns non-None and the NOT_REQUIRED
    short-circuit is not taken) and supplies a real-shaped attestation
    payload (so the ATTESTATION_REQUIRED "none supplied" short-circuit is
    not taken either) -- forcing control flow into the clock-resolution
    block at gateway/pre_execution_control.py's `now is not None` branch.
    """
    from gateway.pre_execution_control import (
        AttestationControlReason,
        AttestationRequirement,
        AttestationRequirementRegistry,
        PreExecutionControl,
    )
    from mcc_attestation import AttesterTrustStore

    async def _go():
        requirement = AttestationRequirement(
            action_pattern="payment.*", evidence_type="risk_assessment",
            scope_template="payment:{resource}",
        )
        control = PreExecutionControl(
            requirements=AttestationRequirementRegistry([requirement]),
            trust_store=AttesterTrustStore([]), nonce_registry=InMemoryNonceRegistry(),
            time_source=_AlwaysUntrusted(),
        )
        # A real-shaped (not necessarily cryptographically valid) raw
        # attestation dict -- clock resolution happens BEFORE
        # verify_attestation() is ever called, so an untrusted clock must
        # deny here regardless of whether the attestation itself would
        # otherwise have verified.
        raw_attestation = {
            "evidence_type": "risk_assessment", "attester_id": "attester.payment-risk.v1",
            "claims": {"risk_class": "low"}, "action_hash": "sha256:" + "0" * 64,
            "scope": "payment:res-1", "nonce": "att-nonce-1",
        }
        result = await control.evaluate(
            action="payment.send", forward_context={"amount": 100}, resource="res-1",
            raw_attestation=raw_attestation,
        )
        assert result.ok is False
        assert result.reason_code == AttestationControlReason.CLOCK_UNTRUSTED
        assert "CLOCK_UNTRUSTED" in result.reason
        # Fail-closed also means no evidence_digest and no nonce consumption
        # -- an untrusted clock must never produce anything a caller could
        # mistake for verified evidence or burn the single-use attestation
        # nonce on a check that was never actually performed.
        assert result.evidence_digest is None
        assert result.verification is None

    run(_go())


def test_pre_execution_control_untrusted_clock_blocks_full_execution_with_zero_actuator_calls():
    """Round 5: the SAME untrusted-clock scenario, driven through the real
    production call path (GovernanceService.execute_with_mandate, exactly
    what gateway/governance_api.py's /mandates/execute route calls) with a
    REAL AttestationRequirement configured and a REAL, independently
    counted upstream actuator -- confirming no execution occurs.

    Residual finding (documented, not a defect): GovernanceService always
    resolves its OWN trusted `now` first (`self._now()`, at the top of
    execute_with_mandate) and forwards it explicitly into
    `_attestation_gate()` -> `PreExecutionControl.evaluate(now=now)`.
    `pre_execution_control.evaluate()`'s *own* internal
    `self.time_source.now()` resolution (exercised directly, in isolation,
    by the test above) is therefore never reached via this -- or any other
    -- real caller: `_attestation_gate` is PreExecutionControl.evaluate()'s
    ONLY production call site, and it always supplies `now` explicitly.
    The net security property (no token, no execution, when the clock
    cannot be trusted) still holds -- it is enforced one step earlier, at
    GovernanceService._now(), before _attestation_gate is ever reached --
    but PreExecutionControl's own clock-resolution branch is presently
    unreachable dead code in production. This test proves the END-TO-END
    guarantee the task asks for; the unit test above proves
    PreExecutionControl's branch is correct in isolation, in case a future
    caller ever does omit `now`.
    """
    from gateway.governance_service import GovernanceService
    from gateway.pre_execution_control import (
        AttestationRequirement,
        AttestationRequirementRegistry,
        PreExecutionControl,
    )
    from gateway.trust import TrustSet
    from mcc_attestation import AttesterTrustStore
    from mcc_core import (
        ApprovalService,
        InMemoryApprovalRegistry,
        InMemoryRevocationRegistry,
        issue_mandate,
    )

    async def _go():
        action = "payment.send"
        resource = "vendor-1"
        untrusted = _AlwaysUntrusted()

        requirement = AttestationRequirement(
            action_pattern=action, evidence_type="risk_assessment",
            scope_template="payment:{resource}",
        )
        pre_execution_control = PreExecutionControl(
            requirements=AttestationRequirementRegistry([requirement]),
            trust_store=AttesterTrustStore([]), nonce_registry=InMemoryNonceRegistry(),
            time_source=untrusted,
        )

        mandate_key = SigningKey.generate("issuer-1")
        dk = SigningKey.generate("dk")
        engine = DecisionEngine(signing_key=dk, issuer="mcc/test", audience="gate",
                                policy_id="pilot/v1", policy_hash=POLICY_HASH)
        gate = ExecutionGate(trusted_keys={dk.kid: dk.public_key()}, audience="gate",
                             nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY_HASH)
        audit_dir = tempfile.mkdtemp(prefix="mcc-round5-pec-")
        audit = AuditLog(str(Path(audit_dir) / "audit.jsonl"))
        coordinator = EnforcementCoordinator(
            gate=gate, idempotency=InMemoryIdempotencyRegistry(),
            velocity=InMemoryVelocityRegistry(), audit=audit,
            profiles=ProfileRegistry.default_pilot(),
        )
        trust_set = TrustSet()
        trust_set.add_runtime_issuer("axlogiq/pilot", mandate_key.kid, mandate_key.public_key())
        approver_key = SigningKey.generate("approver-1")

        actuator_calls: list = []

        async def upstream(act, payload):
            actuator_calls.append((act, payload))
            return {"ok": True}

        service = GovernanceService(
            engine=engine, coordinator=coordinator, trust_set=trust_set,
            revocation_registry=InMemoryRevocationRegistry(),
            approvals=ApprovalService(InMemoryApprovalRegistry(), approver_key),
            profiles=ProfileRegistry.default_pilot(), upstream=upstream,
            policy_hash=POLICY_HASH, pre_execution_control=pre_execution_control,
            time_source=untrusted,
        )

        # The mandate's own validity window is independent of the untrusted
        # time_source (issued directly with a real now, not resolved
        # through it) -- isolating the test to the clock-trust failure path
        # alone, not a coincidental mandate-expiry rejection.
        real_now = int(time.time())
        mandate = issue_mandate(
            mandate_key, issuer="axlogiq/pilot", subject="agent/payments-bot",
            action_scope=[action], resource_scope=[resource], constraints={},
            not_before=real_now - 10, not_after=real_now + 3600, issued_at=real_now,
        )

        out = await service.execute_with_mandate(
            mandate=mandate, actor="agent/payments-bot", action=action, resource=resource,
            context={"source": "acct-1", "beneficiary_id": resource, "amount": 100, "currency": "eur"},
            attestation={
                "evidence_type": "risk_assessment", "attester_id": "attester.payment-risk.v1",
                "claims": {"risk_class": "low"}, "nonce": "att-nonce-2",
            },
            idempotency_key="op-round5-pec-untrusted", tenant_id="tenant-round5-pec",
        )

        assert out.status == "BLOCKED"
        assert out.decision == "DENY"
        assert "CLOCK_UNTRUSTED" in out.reason
        assert actuator_calls == [], (
            "the upstream actuator must never be invoked when the shared "
            "trusted-time source cannot vouch for `now`, regardless of "
            "which component's clock check is the one that actually fires"
        )

    run(_go())


def test_governance_service_verify_consensus_fails_closed_when_time_source_untrusted():
    from gateway.governance_service import GovernanceService

    async def _go():
        keys = [SigningKey.generate(f"eval-{i}") for i in range(3)]
        trusted = {k.kid: k.public_key() for k in keys}
        verifier = ConsensusVerifier(trusted_keys=trusted, policy=ConsensusPolicy(threshold=3))
        dk = SigningKey.generate("dk")
        engine = DecisionEngine(signing_key=dk, issuer="mcc", audience="gate",
                                policy_id="p", policy_hash=POLICY_HASH, token_ttl_seconds=60)
        gate = ExecutionGate(trusted_keys={dk.kid: dk.public_key()}, audience="gate",
                             nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY_HASH)
        from mcc_core import InMemoryIdempotencyRegistry as _Idem
        from mcc_core import InMemoryVelocityRegistry as _Vel
        import tempfile
        audit = AuditLog(str(Path(tempfile.mkdtemp()) / "a.jsonl"))
        coord = EnforcementCoordinator(gate=gate, idempotency=_Idem(), velocity=_Vel(), audit=audit,
                                       profiles=ProfileRegistry.default_pilot(),
                                       consensus_verifier=verifier)
        from gateway.trust import TrustSet
        from mcc_core import ApprovalService, InMemoryApprovalRegistry, InMemoryRevocationRegistry
        svc = GovernanceService(
            engine=engine, coordinator=coord, trust_set=TrustSet(),
            revocation_registry=InMemoryRevocationRegistry(),
            approvals=ApprovalService(InMemoryApprovalRegistry(), SigningKey.generate("apr")),
            consensus_verifier=verifier, policy_hash=POLICY_HASH,
            time_source=_AlwaysUntrusted(),
        )
        votes = _votes(keys, not_before=0, not_after=10_000_000_000, issued_at=0)
        result = await svc.verify_consensus(votes=votes, action=ACTION, context=PAYLOAD, actor=ACTOR,
                                            resource=RESOURCE)
        assert result["verdict"] == "DENY"
        assert "CLOCK_UNTRUSTED" in result["reason"]

    run(_go())
