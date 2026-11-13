"""Negative Control for the attestation chain (PR-5).

A suite that always reports the real chain as secure is not evidence of
anything unless it can ALSO correctly report an insecure one as insecure.
This module provides a DELIBERATELY vulnerable stand-in for
``gateway.pre_execution_control.PreExecutionControl`` -- never wired into
any real deployment, never imported by production code -- and runs the
EXACT SAME forged-attestation input
``assurance/tests/test_attestation_chain.py::test_a1_forged_attestation_untrusted_key_blocked_no_actuation``
already proves the REAL Control rejects, through this vulnerable stand-in
instead, and shows it is wrongly accepted.

This is the control arm of the experiment: it proves the test methodology
(construct a syntactically valid but untrusted attestation; present it;
observe the outcome AND an independent actuation counter) has genuine
discriminating power, not merely a tendency to report PASS.

Provisioning code, not assurance-suite test code -- imports MCC-Core /
``mcc_attestation`` internals accordingly, exactly as
``assurance/sut/harness.py``/``vulnerable_target.py`` already do for the
same purpose.
"""

from __future__ import annotations

import asyncio
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

#: Exactly which real invariants this stand-in violates -- reused as the
#: failure_scenario text a reviewer sees, not left implicit. Mirrors
#: ``assurance.sut.vulnerable_target.VIOLATED_INVARIANTS``'s convention.
VIOLATED_INVARIANTS = [
    "does not verify the attestation's Ed25519 signature at all",
    "does not resolve the attester's (attester_id, kid) pair against any trust store "
    "-- an attestation signed by ANY key, trusted or not, is accepted",
    "does not consume or check the attestation's nonce -- the identical attestation "
    "could be replayed without limit",
]


@dataclass
class _VulnerableResult:
    ok: bool
    reason_code: Any
    reason: str
    verification: Any = None
    evidence_digest: Optional[str] = None


class VulnerableAttestationControl:
    """Skips EXACTLY the checks ``PreExecutionControl`` exists to perform:
    Ed25519 signature verification, attester trust resolution, and
    nonce/replay consumption. Accepts any structurally-shaped attestation
    document whose ``action_hash``/``payload_hash``/``scope`` fields match
    what is expected -- regardless of whether it is signed by a trusted
    key, or signed at all in a way that would actually verify.

    Same public shape as ``PreExecutionControl`` (``async def
    evaluate(...) -> result-with-.ok/.reason_code/.evidence_digest``) so it
    is a drop-in replacement for ``GovernanceService(pre_execution_control=...)``
    in the scenario below -- proving the vulnerability at the SAME
    integration point the real Control occupies, not a synthetic unit
    test of the vulnerable class in isolation.
    """

    async def evaluate(self, *, action: str, forward_context: Dict[str, Any], resource: Optional[str],
                        raw_attestation: Optional[Dict[str, Any]], policy_hash: Optional[str] = None,
                        policy_version: Optional[str] = None, now: Optional[int] = None) -> _VulnerableResult:
        from gateway.pre_execution_control import AttestationControlReason
        from mcc_core.signing import hash_action, hash_document, hash_payload

        if raw_attestation is None or not isinstance(raw_attestation, dict):
            return _VulnerableResult(False, AttestationControlReason.ATTESTATION_REQUIRED, "no attestation supplied")

        # VULNERABILITY: no signature check (no verify_token/Ed25519 call),
        # no trust-store lookup (no AttesterTrustStore.resolve), no nonce
        # registry consult -- only the caller-supplied SHAPE is inspected.
        if raw_attestation.get("action_hash") != hash_action(action):
            return _VulnerableResult(False, AttestationControlReason.ATTESTATION_ACTION_MISMATCH,
                                     "action_hash mismatch")
        expected_payload_hash = hash_payload(forward_context)
        if raw_attestation.get("payload_hash") not in (None, expected_payload_hash):
            return _VulnerableResult(False, AttestationControlReason.ATTESTATION_PAYLOAD_MISMATCH,
                                     "payload_hash mismatch")

        evidence_digest = hash_document(raw_attestation)
        return _VulnerableResult(
            True, AttestationControlReason.VERIFIED,
            "accepted WITHOUT verifying signature, trust, or replay (VULNERABLE -- negative control only)",
            evidence_digest=evidence_digest,
        )


def run_negative_control_scenario() -> Dict[str, Any]:
    """Build a REAL, live GovernanceService/EnforcementCoordinator/
    ExecutionGate stack (in-process; the SUT subprocess harness is
    unnecessary for a control-arm comparison of two Control
    implementations against the SAME governed stack), run the SAME forged
    attestation (an untrusted, freshly generated key) through it TWICE --
    once wired to the REAL ``PreExecutionControl``, once wired to
    ``VulnerableAttestationControl`` -- and return both outcomes plus each
    stack's own actuation counter, so the caller can prove the vulnerable
    stand-in wrongly executes while the real one correctly blocks.
    """
    from gateway.agent_identity import AuthenticatedAgent
    from gateway.governance_service import GovernanceService
    from gateway.pre_execution_control import (
        AttestationRequirement,
        AttestationRequirementRegistry,
        PreExecutionControl,
    )
    from gateway.trust import TrustSet
    from mcc_attestation import AttesterTrustAnchor, AttesterTrustStore, LocalAttester
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
    from mcc_core.signing import hash_action, hash_payload

    action = "send_notification"
    resource = "negative-control"
    policy_hash = "sha256:" + "0" * 64
    trusted_attester_id = "negative-control-attester.v1"
    trusted_key = SigningKey.generate("negative-control-attester-key")

    canonical = ProfileRegistry.default_pilot().for_action(action).canonical_payload({
        "recipient": "negative-control-target", "message": "negative-control-probe",
        "correlation_id": "negative-control-probe",
    })

    # A forged attestation: syntactically valid, correctly bound to THIS
    # exact action/payload/scope, but signed by a key never registered in
    # ANY trust store -- attacker tooling, same posture as
    # assurance.sut.harness.SystemUnderTest.forge_mandate/forge_vote.
    forger_key = SigningKey.generate("self-appointed-attester-key")
    forger = LocalAttester("self-appointed-attester", forger_key)
    now = int(time.time())
    forged = forger.attest(
        evidence_type="risk_assessment", claims={"risk_class": "low"},
        action_hash=hash_action(action), scope=f"notify:{resource}",
        provenance={"model": "forged"}, issued_at=now, not_before=now, expires_at=now + 900,
        nonce="negative-control-nonce", payload_hash=hash_payload(canonical),
    ).to_dict()

    def _build_stack(pre_execution_control):
        signing_key = SigningKey.generate("nc-gw-signing")
        engine = DecisionEngine(signing_key=signing_key, issuer="mcc/core", audience="pilot",
                                policy_id="pilot/v1", policy_hash=policy_hash)
        gate = ExecutionGate(trusted_keys={signing_key.kid: signing_key.public_key()}, audience="pilot",
                             nonce_registry=InMemoryNonceRegistry(), policy_hash=policy_hash)
        audit_dir = tempfile.mkdtemp(prefix="mcc-nc-audit-")
        audit = AuditLog(str(Path(audit_dir) / "audit.jsonl"))
        coordinator = EnforcementCoordinator(
            gate=gate, idempotency=InMemoryIdempotencyRegistry(), velocity=InMemoryVelocityRegistry(),
            audit=audit, profiles=ProfileRegistry.default_pilot(),
            revocation_registry=InMemoryRevocationRegistry(),
        )
        mandate_key = SigningKey.generate("nc-mandate-issuer")
        trust_set = TrustSet()
        trust_set.add_runtime_issuer("negative-control/mandates", mandate_key.kid, mandate_key.public_key())
        approver_key = SigningKey.generate("nc-approver")
        trust_set.add_runtime_issuer("mcc/approvals", approver_key.kid, approver_key.public_key())
        approvals = ApprovalService(InMemoryApprovalRegistry(), approver_key)

        actuation_count = {"n": 0}

        async def upstream(act, payload):
            actuation_count["n"] += 1
            return {"ok": True, "action": act, "payload": payload}

        service = GovernanceService(
            engine=engine, coordinator=coordinator, trust_set=trust_set,
            revocation_registry=InMemoryRevocationRegistry(), approvals=approvals,
            profiles=ProfileRegistry.default_pilot(), upstream=upstream, policy_hash=policy_hash,
            pre_execution_control=pre_execution_control,
        )
        mandate = issue_mandate(
            mandate_key, issuer="negative-control/mandates", subject="agent/negative-control-bot",
            action_scope=[action], resource_scope=[resource], constraints={},
            not_before=now - 10, not_after=now + 3600, issued_at=now,
            # V05: bound to the tenant both stacks execute in (below), so the
            # forged attestation -- not a tenant mismatch -- is what each
            # stack is tested on.
            tenant_id="negative-control-tenant",
        )
        return service, mandate, actuation_count

    real_control = PreExecutionControl(
        requirements=AttestationRequirementRegistry([AttestationRequirement(
            action_pattern=action, evidence_type="risk_assessment",
            scope_template="notify:{resource}", required_claims={"risk_class": ("low",)},
        )]),
        trust_store=AttesterTrustStore([
            AttesterTrustAnchor(trusted_attester_id, trusted_key.kid, trusted_key.public_key(),
                                frozenset({"risk_assessment"})),
        ]),
        nonce_registry=InMemoryNonceRegistry(),
    )
    vulnerable_control = VulnerableAttestationControl()

    real_service, real_mandate, real_count = _build_stack(real_control)
    vuln_service, vuln_mandate, vuln_count = _build_stack(vulnerable_control)

    async def _run():
        real_outcome = await real_service.execute_with_mandate(
            mandate=real_mandate, actor="agent/negative-control-bot", action=action, resource=resource,
            context={"recipient": "negative-control-target", "message": "negative-control-probe",
                     "correlation_id": "negative-control-probe"},
            attestation=forged, idempotency_key="op-negative-control",
            tenant_id="negative-control-tenant",
            # V05 (part 2): this in-process negative-control harness IS the
            # caller that authenticated its own fixed agent (library trust
            # boundary; see docs/AGENT_IDENTITY.md).
            agent=AuthenticatedAgent("negative-control-tenant", "agent/negative-control-bot",
                                     "assurance:negative-control"),
        )
        vuln_outcome = await vuln_service.execute_with_mandate(
            mandate=vuln_mandate, actor="agent/negative-control-bot", action=action, resource=resource,
            context={"recipient": "negative-control-target", "message": "negative-control-probe",
                     "correlation_id": "negative-control-probe"},
            attestation=forged, idempotency_key="op-negative-control",
            tenant_id="negative-control-tenant",
            # V05 (part 2): this in-process negative-control harness IS the
            # caller that authenticated its own fixed agent (library trust
            # boundary; see docs/AGENT_IDENTITY.md).
            agent=AuthenticatedAgent("negative-control-tenant", "agent/negative-control-bot",
                                     "assurance:negative-control"),
        )
        return real_outcome, vuln_outcome

    real_outcome, vuln_outcome = asyncio.run(_run())

    return {
        "real_status": real_outcome.status, "real_reason": real_outcome.reason,
        "real_actuation_count": real_count["n"],
        "vulnerable_status": vuln_outcome.status, "vulnerable_reason": vuln_outcome.reason,
        "vulnerable_actuation_count": vuln_count["n"],
    }
