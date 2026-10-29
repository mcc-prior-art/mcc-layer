"""PR #122 round 6, Finding 1 (part 2): a newly issued decision token must
never carry MORE time-bounded execution authority than the mandate (or,
via ``execute_with_approval``, the approval-minted mandate) that justified
it.

Root cause: ``DecisionEngine.issue_token()`` computed ``exp`` as
``issued_at + self.token_ttl_seconds`` -- a fixed, server-wide default,
completely independent of how much validity remained on the mandate that
was actually verified moments earlier. A mandate with only a few seconds
left before its own ``exp`` could still justify a token valid for the full
default TTL (e.g. 60s), letting the newly issued token outlive the
authority it was derived from. Confirmed before any fix (see the
assertions below, each of which encodes the pre-fix failure mode in its
own docstring).

Fix: ``MandateResult``/``MandateAuthorityDecision`` now carry the verified
mandate's own ``exp`` forward (``mandate_exp``), and
``GovernanceService.execute_with_mandate`` passes it to
``DecisionEngine.issue_token(..., max_exp=...)``, which only ever LOWERS
the computed expiry, never raises it.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest

from gateway.governance_service import GovernanceService
from gateway.trust import TrustSet
from mcc_core import (
    ApprovalService,
    AuditLog,
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
    issue_mandate,
)
from mcc_core.core import Verdict
from mcc_core.mandate import MandateAuthority, MandateVerifier

run = asyncio.run
ACTION = "generic_op"
RESOURCE = "res-1"
POLICY_HASH = "sha256:" + "0" * 64


# --------------------------------------------------------------------------
# 1. Unit: MandateVerifier.verify() carries the mandate's own exp forward
# on success (and only on success -- a failed verification has nothing
# trustworthy to clamp against).
# --------------------------------------------------------------------------

def test_mandate_verifier_returns_its_own_exp_on_success():
    key = SigningKey.generate("issuer-1")
    now = 1_000_000
    mandate = issue_mandate(
        key, issuer="axlogiq/pilot", subject="agent/ops",
        action_scope=[ACTION], resource_scope=[RESOURCE], constraints={},
        not_before=now - 10, not_after=now + 123, issued_at=now - 10,
    )
    verifier = MandateVerifier(trusted_keys={key.kid: key.public_key()})
    result = run(verifier.verify(mandate, subject="agent/ops", action=ACTION,
                                 resource=RESOURCE, now=now))
    assert result.ok
    assert result.exp == now + 123


def test_mandate_verifier_exp_is_none_on_failure():
    key = SigningKey.generate("issuer-1")
    rogue = SigningKey.generate("rogue")
    now = 1_000_000
    mandate = issue_mandate(
        rogue, issuer="axlogiq/pilot", subject="agent/ops",  # signed by an UNTRUSTED key
        action_scope=[ACTION], resource_scope=[RESOURCE], constraints={},
        not_before=now - 10, not_after=now + 123, issued_at=now - 10,
    )
    verifier = MandateVerifier(trusted_keys={key.kid: key.public_key()})
    result = run(verifier.verify(mandate, subject="agent/ops", action=ACTION,
                                 resource=RESOURCE, now=now))
    assert not result.ok
    assert result.exp is None


# --------------------------------------------------------------------------
# 2. Unit: MandateAuthority.authorize() propagates mandate_exp for BOTH
# ALLOW and CONSTRAIN (the two verdicts that go on to issue a token) --
# never for DENY (no token is ever issued for it, so nothing to clamp).
# --------------------------------------------------------------------------

def test_mandate_authority_propagates_mandate_exp_for_allow():
    key = SigningKey.generate("issuer-1")
    now = 2_000_000
    mandate = issue_mandate(
        key, issuer="axlogiq/pilot", subject="agent/ops",
        action_scope=[ACTION], resource_scope=[RESOURCE], constraints={},
        not_before=now - 10, not_after=now + 10, issued_at=now - 10,
    )
    authority = MandateAuthority(MandateVerifier(trusted_keys={key.kid: key.public_key()}))
    decision = run(authority.authorize(
        mandate, subject="agent/ops", action=ACTION, resource=RESOURCE,
        context={"value": 1}, now=now,
    ))
    assert decision.verdict == Verdict.ALLOW
    assert decision.mandate_exp == now + 10


def test_mandate_authority_propagates_mandate_exp_for_constrain():
    key = SigningKey.generate("issuer-1")
    now = 3_000_000
    mandate = issue_mandate(
        key, issuer="axlogiq/pilot", subject="agent/ops",
        action_scope=[ACTION], resource_scope=[RESOURCE],
        constraints={"max_value": 5}, not_before=now - 10, not_after=now + 10,
        issued_at=now - 10,
    )
    authority = MandateAuthority(MandateVerifier(trusted_keys={key.kid: key.public_key()}))
    decision = run(authority.authorize(
        mandate, subject="agent/ops", action=ACTION, resource=RESOURCE,
        context={"value": 999}, now=now,
    ))
    assert decision.verdict == Verdict.CONSTRAIN
    assert decision.mandate_exp == now + 10


def test_mandate_authority_deny_carries_no_mandate_exp():
    key = SigningKey.generate("issuer-1")
    now = 4_000_000
    expired_mandate = issue_mandate(
        key, issuer="axlogiq/pilot", subject="agent/ops",
        action_scope=[ACTION], resource_scope=[RESOURCE], constraints={},
        not_before=now - 100, not_after=now - 1, issued_at=now - 100,
    )
    authority = MandateAuthority(MandateVerifier(trusted_keys={key.kid: key.public_key()}))
    decision = run(authority.authorize(
        expired_mandate, subject="agent/ops", action=ACTION, resource=RESOURCE,
        context={"value": 1}, now=now,
    ))
    assert decision.verdict == Verdict.DENY
    assert decision.mandate_exp is None


# --------------------------------------------------------------------------
# 3. Unit: DecisionEngine.issue_token's max_exp only ever LOWERS the
# computed exp, never raises it, and is fully inert (unchanged pre-fix
# behavior) when omitted.
# --------------------------------------------------------------------------

def test_issue_token_max_exp_lowers_computed_exp():
    dk = SigningKey.generate("dk")
    engine = DecisionEngine(signing_key=dk, issuer="mcc/test", audience="gate",
                            policy_id="pilot/v1", policy_hash=POLICY_HASH, token_ttl_seconds=60)
    now = 5_000_000
    token = engine.issue_token(
        verdict="ALLOW", subject="agent/ops", action=ACTION, payload={"value": 1},
        idempotency_key="op-1", actor_id="agent/ops", resource_id=RESOURCE, nonce="n1",
        tenant_id="tenant-1", now=now, max_exp=now + 10,
    )
    assert token["exp"] == now + 10, "max_exp must clamp the computed exp down to it"


def test_issue_token_max_exp_never_raises_the_computed_exp():
    """A max_exp LARGER than the default computed exp must have no effect
    -- it only ever lowers, never raises."""
    dk = SigningKey.generate("dk")
    engine = DecisionEngine(signing_key=dk, issuer="mcc/test", audience="gate",
                            policy_id="pilot/v1", policy_hash=POLICY_HASH, token_ttl_seconds=60)
    now = 6_000_000
    token = engine.issue_token(
        verdict="ALLOW", subject="agent/ops", action=ACTION, payload={"value": 1},
        idempotency_key="op-1", actor_id="agent/ops", resource_id=RESOURCE, nonce="n1",
        tenant_id="tenant-1", now=now, max_exp=now + 10_000,
    )
    assert token["exp"] == now + 60


def test_issue_token_without_max_exp_is_unchanged():
    dk = SigningKey.generate("dk")
    engine = DecisionEngine(signing_key=dk, issuer="mcc/test", audience="gate",
                            policy_id="pilot/v1", policy_hash=POLICY_HASH, token_ttl_seconds=60)
    now = 7_000_000
    token = engine.issue_token(
        verdict="ALLOW", subject="agent/ops", action=ACTION, payload={"value": 1},
        idempotency_key="op-1", actor_id="agent/ops", resource_id=RESOURCE, nonce="n1",
        tenant_id="tenant-1", now=now,
    )
    assert token["exp"] == now + 60


# --------------------------------------------------------------------------
# 4. End-to-end, through the REAL GovernanceService.execute_with_mandate:
# a mandate with only 10 seconds left before its own exp, verified against
# a gateway whose default token TTL is 60 seconds, must issue a token
# clamped to the MANDATE's remaining 10 seconds -- never the full 60.
#
# Confirmed non-vacuous: reverting the ``max_exp=decision.mandate_exp``
# plumbing in gateway/governance_service.py (verified via git stash before
# this fix) produces a token with exp == now + 60 (60s past the mandate's
# own 10s-remaining exp) instead of exp == mandate["exp"].
# --------------------------------------------------------------------------

def _tmp_audit() -> AuditLog:
    d = tempfile.mkdtemp(prefix="mcc-round6-mandate-exp-")
    return AuditLog(str(Path(d) / "audit.jsonl"))


def _service(mandate_key: SigningKey, *, token_ttl_seconds: int = 60) -> GovernanceService:
    signing_key = SigningKey.generate("gw-signing-1")
    engine = DecisionEngine(
        signing_key=signing_key, issuer="mcc/core", audience="pilot", policy_id="pilot/v1",
        policy_hash=POLICY_HASH, token_ttl_seconds=token_ttl_seconds,
    )
    gate = ExecutionGate(
        trusted_keys={signing_key.kid: signing_key.public_key()}, audience="pilot",
        nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY_HASH,
    )
    audit = _tmp_audit()
    coordinator = EnforcementCoordinator(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(),
        velocity=InMemoryVelocityRegistry(), audit=audit,
        profiles=ProfileRegistry.default_pilot(), revocation_registry=InMemoryRevocationRegistry(),
    )
    trust_set = TrustSet()
    trust_set.add_runtime_issuer("axlogiq/pilot", mandate_key.kid, mandate_key.public_key())
    approver_key = SigningKey.generate("approver-1")
    approvals = ApprovalService(InMemoryApprovalRegistry(), approver_key)

    async def upstream(action, payload):
        return {"ok": True, "action": action, "payload": payload}

    return GovernanceService(
        engine=engine, coordinator=coordinator, trust_set=trust_set,
        revocation_registry=InMemoryRevocationRegistry(), approvals=approvals,
        profiles=ProfileRegistry.default_pilot(), upstream=upstream, policy_hash=POLICY_HASH,
    )


def test_execute_with_mandate_clamps_token_exp_to_near_expiring_mandate():
    # execute_with_mandate() has no explicit-``now`` override -- it always
    # resolves a real trusted ``now`` internally (self._now(), defaulting
    # to real wall-clock time) -- so the mandate's own window must be
    # anchored to the ACTUAL current time, not a synthetic value, or the
    # mandate would simply be rejected as already expired/not-yet-valid
    # for reasons unrelated to this test.
    import time as _time

    mandate_key = SigningKey.generate("issuer-1")
    now = int(_time.time())
    mandate_remaining_seconds = 10
    mandate = issue_mandate(
        mandate_key, issuer="axlogiq/pilot", subject="agent/ops",
        action_scope=[ACTION], resource_scope=[RESOURCE], constraints={},
        not_before=now - 100, not_after=now + mandate_remaining_seconds, issued_at=now - 100,
    )
    service = _service(mandate_key, token_ttl_seconds=60)

    captured: list = []
    real_issue_token = service.engine.issue_token

    def _spy(**kwargs):
        token = real_issue_token(**kwargs)
        captured.append(token)
        return token

    service.engine.issue_token = _spy  # test-only capture; same object, same signing key

    out = run(service.execute_with_mandate(
        mandate=mandate, actor="agent/ops", action=ACTION, resource=RESOURCE,
        context={"value": 1}, idempotency_key="op-round6-clamp-1", tenant_id="tenant-round6",
    ))
    assert out.status == "EXECUTED"
    assert len(captured) == 1
    token = captured[0]
    assert token["exp"] == mandate["exp"] == now + mandate_remaining_seconds, (
        "the issued token must be clamped to the mandate's own remaining validity, "
        "not the server's full 60s default TTL"
    )
    assert token["exp"] < now + 60, (
        "sanity: the clamp must have actually taken effect -- the unclamped "
        "default would have been now+60, far past the mandate's own exp"
    )


def test_execute_with_approval_clamps_token_exp_to_the_approval_mandate():
    """execute_with_approval delegates to execute_with_mandate with an
    approval-minted mandate (see ApprovalService.approve() ->
    issue_mandate(..., not_after=rec.expires_at)) -- confirms the SAME
    clamp applies there too, with no separate plumbing needed."""
    from mcc_core import InMemoryRevocationRegistry as _Revocation

    approval_ttl_seconds = 15

    signing_key = SigningKey.generate("gw-signing-2")
    engine = DecisionEngine(signing_key=signing_key, issuer="mcc/core", audience="pilot",
                            policy_id="pilot/v1", policy_hash=POLICY_HASH, token_ttl_seconds=60)
    gate = ExecutionGate(trusted_keys={signing_key.kid: signing_key.public_key()}, audience="pilot",
                         nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY_HASH)
    audit = _tmp_audit()
    coordinator = EnforcementCoordinator(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(), velocity=InMemoryVelocityRegistry(),
        audit=audit, profiles=ProfileRegistry.default_pilot(), revocation_registry=_Revocation(),
    )
    trust_set = TrustSet()
    approver_key = SigningKey.generate("approver-1")
    trust_set.add_runtime_issuer("mcc/approvals", approver_key.kid, approver_key.public_key())
    approvals = ApprovalService(InMemoryApprovalRegistry(), approver_key)

    async def upstream(action, payload):
        return {"ok": True}

    service = GovernanceService(
        engine=engine, coordinator=coordinator, trust_set=trust_set,
        revocation_registry=_Revocation(), approvals=approvals,
        profiles=ProfileRegistry.default_pilot(), upstream=upstream, policy_hash=POLICY_HASH,
    )

    request_id = run(approvals.request(
        actor="agent/ops", action=ACTION, resource=RESOURCE,
        payload_hash=None, ttl_seconds=approval_ttl_seconds, tenant_id="tenant-round6",
        payload={"value": 1},
    ))
    mandate = run(approvals.approve(request_id))
    assert mandate is not None

    captured: list = []
    real_issue_token = service.engine.issue_token

    def _spy(**kwargs):
        token = real_issue_token(**kwargs)
        captured.append(token)
        return token

    service.engine.issue_token = _spy

    out = run(service.execute_with_approval(
        mandate=mandate, actor="agent/ops", action=ACTION, resource=RESOURCE,
        context={"value": 1}, idempotency_key="op-round6-clamp-approval-1",
        tenant_id="tenant-round6",
    ))
    assert out.status == "EXECUTED", out.reason
    assert len(captured) == 1
    token = captured[0]
    assert token["exp"] == mandate["exp"], (
        "a token issued under an approval-minted mandate must be clamped to "
        "that mandate's own (short-lived) exp, not the server's longer default TTL"
    )
    assert token["exp"] < token["iat"] + 60
