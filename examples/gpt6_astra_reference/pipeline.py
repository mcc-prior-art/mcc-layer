"""Orchestrates ONE Astra proposal through the real, unmodified MCC chain.

    ASTRA PROPOSAL
        -> INDEPENDENT ATTESTER  (mcc_attester_service.AttesterService.attest)
        -> CONTROL               (gateway.pre_execution_control.PreExecutionControl.evaluate,
                                   reached via GovernanceService)
        -> SIGNED EXECUTION AUTHORITY (mcc_core.core.DecisionEngine.issue_token)
        -> AUTHORITY VERIFICATION + GATE (mcc_core.gate.ExecutionGate,
                                   via mcc_core.coordinator.EnforcementCoordinator.enforce)
        -> EXECUTION             (the configured upstream -- GitHubIssueActuator
                                   in this demo, but this module never imports it)

Two entry points, both composed ENTIRELY from real, existing, public
MCC-Core/gateway primitives -- no new decision logic, no new token format,
no second Gate:

* :func:`run_positive_path` -- the single supported public path,
  ``GovernanceService.execute_with_mandate``, unchanged and untouched. Used
  for the positive, wrong-scope, and autonomous-expansion scenarios, all of
  which need exactly one governed call per proposal.
* :func:`run_with_explicit_steps` -- the SAME sequence
  ``execute_with_mandate`` performs internally
  (authority -> control -> issue_token -> enforce), exposed as separate
  awaitable steps so the tamper/replay/expiry adversarial scenarios can
  observe or reuse an intermediate artifact (an already-issued token)
  exactly as ``tests/test_compromised_intelligence_adversarial.py`` and
  ``tests/test_evidence_bound_execution_ticket.py`` already do throughout
  this repository. This function calls the identical
  ``MandateAuthority``/``PreExecutionControl``/``DecisionEngine``/
  ``EnforcementCoordinator`` objects the convenience wrapper uses; it does
  not reimplement any of their decision logic.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Dict, Optional

from gateway.agent_identity import AuthenticatedAgent
from gateway.governance_service import ExecOutcome, GovernanceService
from mcc_attester_service import AttesterService
from mcc_core.signing import hash_document

from .issue_contract import (
    GITHUB_ISSUE_ACTION,
    require_coherent_marker_context,
    validate_github_issue_request_payload,
)
from .models import AstraProposal, require_logical_operation_id


def _require_github_issue_context_coherence(*, action: str, payload: Dict[str, Any], logical_operation_id: str) -> None:
    """Round 21 requirement 3: validated independently at EVERY protected
    reference boundary (``run_positive_path``/``issue_authority``/
    ``enforce_authority``), never only inside the preparation helper
    (``governed_call.prepare_marked_call``) -- a direct caller that
    constructs its own proposal/payload and skips that helper cannot bypass
    either check by doing so.

    A no-op for every action other than the one real actuator this
    reference integration ships (``issue_contract.GITHUB_ISSUE_ACTION``):
    the strict schema and marker-context rules are specific to that one
    action's request contract, not a generic property every proposal must
    carry.

    Raises :class:`~.issue_contract.GitHubIssuePayloadError` (unsupported
    field / missing or malformed title / non-string body) or
    :class:`~.issue_contract.MarkerSyntaxError` (missing/duplicate/malformed
    marker) or :class:`~.issue_contract.OperationContextMismatchError` (a
    single well-formed marker present, but naming a DIFFERENT
    logical_operation_id than the one being presented here) -- all BEFORE
    any attestation/authority/actuator call this boundary function is about
    to make."""
    if action != GITHUB_ISSUE_ACTION:
        return
    validate_github_issue_request_payload(payload)
    require_coherent_marker_context(payload, logical_operation_id=logical_operation_id)


@dataclass(frozen=True)
class AttestationOutcome:
    ok: bool
    raw_attestation: Optional[Dict[str, Any]]
    reason: str


async def obtain_attestation(
    attester: AttesterService, *, proposal: AstraProposal, canonical_payload: Dict[str, Any],
) -> AttestationOutcome:
    """The Attester independently assesses the PROPOSED action -- it knows
    nothing about Astra, and nothing here reads a caller-supplied "trusted"
    field off ``proposal`` (there isn't one; see ``models.AstraProposal``).
    A proposal is intentionally allowed to enter the assessment pipeline;
    this does not itself grant authority (see
    ``docs/EXECUTION_AUTHORITY_BOUNDARY.md`` §11)."""
    try:
        raw = await attester.attest(
            action=proposal.action, resource=proposal.resource, payload=canonical_payload,
        )
        return AttestationOutcome(True, raw, "VERIFIED")
    except Exception as exc:  # noqa: BLE001 -- any Attester-side refusal fails closed
        return AttestationOutcome(False, None, f"ATTESTER_REFUSED: {exc!r}")


async def run_positive_path(
    service: GovernanceService, *, mandate: Any, actor: str, proposal: AstraProposal,
    attestation: Optional[Dict[str, Any]], logical_operation_id: str, tenant_id: str,
) -> ExecOutcome:
    """The single supported public path. Used whenever a scenario needs
    exactly one governed call — positive, wrong-scope, and
    autonomous-scope-expansion.

    ``logical_operation_id`` is MANDATORY (Round 18) and becomes the signed
    token's ``idempotency_key`` — the durable logical-operation identity
    ``EnforcementCoordinator`` binds to the exact (action, resource,
    payload_hash) triple (see ``docs/DURABLE_OPERATION_SAFETY.md``). This is
    checked HERE, at the actual protected-execution boundary — not only in
    ``cli.py`` — so no caller of this function (the CLI, ``live_matrix``,
    ``live_redteam``, the adversarial scenarios, or any future caller) can
    reach ``GovernanceService.execute_with_mandate``/the Gate/the actuator
    without one. A missing or empty id raises
    :class:`~.models.MissingLogicalOperationIdError` synchronously, before
    any attestation/authority/gate call is made — the executor is never
    reached.

    ``tenant_id`` is MANDATORY (PR #105) — the trusted, authenticated
    identity that scopes the durable execution identity
    ``(tenant_id, logical_operation_id)``. Forwarded to
    ``GovernanceService.execute_with_mandate`` unchanged; the coordinator
    itself is what fails closed if it is ever missing or empty when the
    signed token actually reaches it.

    Round 21 requirement 3: for the one action this integration's real
    actuator understands, this ALSO independently validates the strict
    request schema and operation-context coherence (the payload's own
    marker must name exactly this ``logical_operation_id``) — before any
    attestation/authority/gate call — regardless of whether the caller
    routed its proposal through ``governed_call.prepare_marked_call`` at
    all."""
    require_logical_operation_id(logical_operation_id)
    _require_github_issue_context_coherence(
        action=proposal.action, payload=proposal.payload, logical_operation_id=logical_operation_id,
    )
    return await service.execute_with_mandate(
        mandate=mandate, actor=actor, action=proposal.action, resource=proposal.resource,
        context=proposal.payload, attestation=attestation, idempotency_key=logical_operation_id,
        tenant_id=tenant_id,
        # V05 (part 2): this in-process reference pipeline embeds
        # GovernanceService and IS the authenticating caller for the one agent
        # it drives (library trust boundary; see docs/AGENT_IDENTITY.md). It
        # binds the authenticated principal to ``actor``, so the governed
        # principal == actor == signed mandate subject checks still apply.
        agent=AuthenticatedAgent(tenant_id, actor, "gpt6-astra-reference:in-process"),
    )


@dataclass(frozen=True)
class IssuedAuthority:
    """An intermediate artifact of the real chain, exposed only so the
    adversarial scenarios can present it more than once (replay) or
    against a mutated action/payload (tamper) -- never a new authority
    format, just the real ``DecisionEngine``-signed token this repository
    already defines."""

    token: Dict[str, Any]
    canonical_payload: Dict[str, Any]
    evidence_digest: Optional[str]


class AuthorityDeniedError(Exception):
    """Raised by ``issue_authority`` when the mandate/control layer denies
    before any token is issued. Carries the real ``ExecOutcome`` so the
    caller can classify it precisely."""

    def __init__(self, outcome: ExecOutcome) -> None:
        super().__init__(outcome.reason)
        self.outcome = outcome


async def issue_authority(
    service: GovernanceService, *, mandate: Any, actor: str, proposal: AstraProposal,
    attestation: Optional[Dict[str, Any]], logical_operation_id: str, tenant_id: str,
) -> IssuedAuthority:
    """Reproduces ``GovernanceService.execute_with_mandate``'s OWN sequence
    up to (and including) token issuance, stopping BEFORE
    ``EnforcementCoordinator.enforce`` — the exact seam the tamper/replay
    scenarios need. Built ENTIRELY from ``GovernanceService``'s own public
    attributes (``engine``/``trust_set``/``revocation_registry``/
    ``pre_execution_control``/``profiles``/``policy_hash``) and public
    classes (``MandateAuthority``/``MandateVerifier``/
    ``PreExecutionControl.evaluate``/``DecisionEngine.issue_token``) — no
    private method of ``GovernanceService`` is called, and no decision
    logic is reimplemented; this only sequences the same real calls
    ``execute_with_mandate`` itself makes. Raises
    :class:`AuthorityDeniedError` if the real mandate-authority or Control
    check denies, exactly as ``execute_with_mandate`` itself would have
    returned BLOCKED at that point.

    ``logical_operation_id`` is MANDATORY (Round 18), checked here — the
    other half of this pipeline's protected-execution boundary, alongside
    :func:`run_positive_path` — before ANY of the trust/authority/Control
    calls below run. A missing or empty id raises
    :class:`~.models.MissingLogicalOperationIdError` immediately; no token
    is ever issued.

    ``tenant_id`` is MANDATORY (PR #105) — the trusted, authenticated
    identity that becomes the signed token's own ``tenant_id`` claim, the
    other half (alongside ``logical_operation_id``) of the durable
    execution identity ``EnforcementCoordinator``/``IdempotencyRegistry``
    scope to. Never accepted from ``proposal``/payload/mandate content —
    this reference integration's trusted boundary is the caller of this
    function (mirroring ``examples/governed_agent/mcc_client.py``'s
    ``self.tenant_id``), not anything the intelligence proposed.

    Round 21 requirement 3: for the one action this integration's real
    actuator understands, this ALSO independently validates the strict
    request schema and operation-context coherence (the payload's own
    marker must name exactly this ``logical_operation_id``) before ANY of
    the trust/authority/Control calls below run, let alone token issuance —
    regardless of whether the caller routed its proposal through
    ``governed_call.prepare_marked_call`` at all. This is precisely what
    closes the Round 20 counterexample where a genuinely signed token could
    be minted with ``idempotency_key`` B for a payload whose marker actually
    names a DIFFERENT operation A."""
    require_logical_operation_id(logical_operation_id)
    _require_github_issue_context_coherence(
        action=proposal.action, payload=proposal.payload, logical_operation_id=logical_operation_id,
    )
    import time

    from mcc_core import MandateAuthority, MandateVerifier, Verdict

    now = int(time.time())
    kid = mandate.get("kid") if isinstance(mandate, dict) else None
    resolution = service.trust_set.resolve(kid, now=now)
    if not resolution.ok:
        raise AuthorityDeniedError(
            ExecOutcome("BLOCKED", f"{resolution.status.value}: {resolution.reason}", decision="DENY")
        )
    authority = MandateAuthority(MandateVerifier(
        trusted_keys={resolution.kid: resolution.public_key},
        revocation_registry=service.revocation_registry,
    ))

    profile = service.profiles.for_action(proposal.action)
    canonical = profile.canonical_payload(proposal.payload)

    decision = await authority.authorize(
        mandate, subject=actor, action=proposal.action, resource=proposal.resource,
        context=canonical, now=now, policy_hash=service.policy_hash,
    )
    if decision.verdict not in (Verdict.ALLOW, Verdict.CONSTRAIN):
        raise AuthorityDeniedError(ExecOutcome("BLOCKED", decision.reason, decision=decision.verdict.value))

    forward_context = decision.forward_context or canonical

    evidence_digest = None
    if service.pre_execution_control is not None:
        result = await service.pre_execution_control.evaluate(
            action=proposal.action, forward_context=forward_context, resource=proposal.resource,
            raw_attestation=attestation, policy_hash=service.policy_hash,
        )
        if not result.ok:
            raise AuthorityDeniedError(
                ExecOutcome("BLOCKED", f"{result.reason_code.value}: {result.reason}", decision="DENY")
            )
        evidence_digest = result.evidence_digest

    auth_claims = dict(profile.auth_claims(forward_context))
    token = service.engine.issue_token(
        verdict=decision.verdict.value, subject=actor, action=proposal.action,
        payload=forward_context, constraints=decision.constraints,
        actor_id=actor, resource_id=proposal.resource,
        auth_claims=auth_claims, mandate_id=decision.mandate_id,
        evidence_digest=evidence_digest, idempotency_key=logical_operation_id,
        tenant_id=tenant_id,
    )
    return IssuedAuthority(token=token, canonical_payload=forward_context, evidence_digest=evidence_digest)


async def enforce_authority(
    service: GovernanceService, *, issued: IssuedAuthority, actor: str, resource: Optional[str],
    action: str, payload: Optional[Dict[str, Any]] = None,
    attestation: Optional[Dict[str, Any]] = None,
) -> ExecOutcome:
    """Presents ``issued.token`` to the real, public
    ``EnforcementCoordinator.enforce`` — the SAME call
    ``GovernanceService`` itself makes to reach the upstream, and the
    identical call ``main.py``'s own consensus ``/evaluate`` path already
    makes directly (this is not a new call shape). ``payload`` defaults to
    the token's own canonical payload; passing a DIFFERENT
    ``payload``/``action`` here is exactly how the tamper scenario is
    honestly reproduced — the Gate's own action_hash/payload_hash binding
    check is what then fires, nothing here decides that outcome.

    Round 18 defense-in-depth: even though ``issued.token`` can only have
    been produced by :func:`issue_authority` (which already refuses to
    issue one without a ``logical_operation_id``), this is the function
    that actually reaches the coordinator/executor, so it independently
    re-verifies the token itself carries a non-empty ``idempotency_key``
    before doing anything else -- a hand-crafted or future alternate caller
    presenting a token without one is refused here too, before the
    coordinator or the actuator is ever reached.

    Round 21 requirement 3/Blocker 2 counterexample B: the effective
    payload about to be enforced (``payload`` if the caller overrode it,
    else ``issued.canonical_payload``) is ALSO independently checked here
    against the REAL, signed token's own ``idempotency_key`` — never a
    caller-supplied id, never derived from the payload itself. This is the
    check that catches a genuinely signed token for operation B being
    presented alongside a payload whose marker actually names a DIFFERENT
    operation A: the Gate's own hash check alone cannot catch this (the
    hash can match perfectly fine), so this must be independent of it.
    Reading the marker establishes no authority by itself; the real Gate
    still verifies the token's signature/binding exactly as before.

    Round 24: ``payload``/``issued.canonical_payload`` is a mutable dict the
    CALLER still holds a live reference to. ``coordinator.enforce`` awaits
    through several admission steps (idempotency reservation, velocity,
    audit) between the point the Gate verifies this payload's hash and the
    point ``executor()`` finally dispatches it -- an event loop can run
    other, concurrently-scheduled code during any of those suspensions. If
    the caller (or anything else holding a reference to the SAME dict
    object) mutated it during that window, the Gate's verification and the
    actual outbound dispatch would silently observe DIFFERENT content, even
    though both reads target the identical object. A deep-copied snapshot
    is taken here, synchronously, before this function's first ``await`` --
    every subsequent read (context coherence, the Gate via
    ``coordinator.enforce``, and ``executor()``'s own dispatch) uses this
    SAME private, frozen-in-effect copy, which no external reference can
    reach or mutate.

    PR #105: ``tenant_id`` is read directly off ``issued.token`` (the
    signed claim :func:`issue_authority` already put there), never as a
    separate parameter here -- this function only ever presents an
    already-issued token to the real coordinator, so there is no second,
    independently-trusted tenant identity for it to accept. Included in
    ``request_binding`` purely as the same free defense-in-depth every
    other production call site in this repository now carries (see
    ``gate.py``'s generic binding-dict mechanism); the coordinator's
    mandatory fail-closed check is already satisfied by the token's own
    claim regardless."""
    require_logical_operation_id(issued.token.get("idempotency_key"))
    effective_payload = copy.deepcopy(payload if payload is not None else issued.canonical_payload)
    _require_github_issue_context_coherence(
        action=action, payload=effective_payload,
        logical_operation_id=issued.token.get("idempotency_key"),
    )

    async def executor():
        if service.upstream is None:
            raise RuntimeError("no upstream configured")
        return await service.upstream(action, effective_payload)

    result = await service.coordinator.enforce(
        token=issued.token, action=action, payload=effective_payload, executor=executor,
        request_binding={
            "actor_id": actor, "resource_id": resource, "transaction_id": None,
            "tenant_id": issued.token.get("tenant_id"),
        },
        evidence=attestation,
    )
    return ExecOutcome(
        status=result.status.value, reason=result.reason,
        decision=result.decision.value if result.decision else None,
        audit_ref=result.audit_ref, execution=result.execution,
    )


def proposal_fingerprint(proposal: AstraProposal) -> str:
    return hash_document({"action": proposal.action, "resource": proposal.resource,
                          "payload": proposal.payload})


def attestation_fingerprint(raw_attestation: Optional[Dict[str, Any]]) -> Optional[str]:
    return hash_document(raw_attestation) if raw_attestation is not None else None


def authority_fingerprint(token: Optional[Dict[str, Any]]) -> Optional[str]:
    return hash_document(token) if token is not None else None


__all__ = [
    "AttestationOutcome", "obtain_attestation", "run_positive_path",
    "IssuedAuthority", "AuthorityDeniedError", "issue_authority", "enforce_authority",
    "proposal_fingerprint", "attestation_fingerprint", "authority_fingerprint",
]
