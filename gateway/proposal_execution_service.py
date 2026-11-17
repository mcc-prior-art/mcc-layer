"""ProposalExecutionService — Phase 2 bridge: tenant-owned proposal -> signed
authority -> the EXISTING, unmodified governed execution path.

    authenticated tenant
    -> ProposalRegistry.get(tenant_id=, logical_operation_id=)   (ownership +
       the proposal's OWN stored action/resource/canonical payload -- the
       ONE source of truth for what is about to be authorized; never an
       independently re-supplied payload)
    -> mcc_core.authority.AuthorityModel.evaluate(identity=tenant_id, ...)
       (trusted, tenant-identity-keyed verdict: ALLOW/DENY/ESCALATE/CONSTRAIN)
    -> mcc_core.core.DecisionEngine.issue_token   (signed authority; carries
       tenant_id + idempotency_key=logical_operation_id, exactly the PR #105
       durable identity pair)
    -> mcc_core.coordinator.EnforcementCoordinator.enforce   (the ONE
       execution path this repository has: ExecutionGate verification, the
       tenant-scoped IdempotencyRegistry, velocity, audit-before-actuation)
    -> the injected upstream actuator

    PROPOSAL != PERMISSION.
    TENANT_ID != AUTHORITY.
    PROPOSAL SERVICE != EXECUTION ENGINE.

This module is deliberately the ONLY new service boundary Phase 2
introduces. It composes exclusively public primitives this repository
already ships and already uses elsewhere for the identical purpose
(``examples/governed_agent/mcc_client.py``, ``gateway/governance_service.py``,
``examples/gpt6_astra_reference/pipeline.py``) -- no new decision logic, no
new token format, no second Gate, no second ``EnforcementCoordinator``, no
second durable execution registry, and no proposal-specific actuator bypass.

Lives in ``gateway/`` (not ``src/mcc_proposal/``) deliberately:
``tests/test_proposal_service_architecture_guards.py`` statically forbids
every file under ``src/mcc_proposal/`` from importing the Gate, the
coordinator, the authority model, or the signing authority at all -- a
future refactor cannot silently smuggle execution authority into what must
stay a transport-neutral, non-actuating ingress/lifecycle boundary. This
bridge is exactly what fills the "MCC INDEPENDENT AUTHORITY BOUNDARY" layer
``mcc_proposal/service.py``'s own module docstring already draws a box for.
"""

from __future__ import annotations

import copy
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional

from mcc_core import (
    ActuationStatus,
    AuthorityModel,
    DecisionEngine,
    EnforcementCoordinator,
    ProfileError,
    ProfileRegistry,
    Verdict,
    hash_document,
    hash_payload,
)

from mcc_proposal.binding import BindingComputationError, compute_proposal_binding
from mcc_proposal.registry import ProposalBackendUnavailable


class ResourceMismatchError(Exception):
    """Raised by :meth:`ResourceBoundUpstream.execute` when asked to
    dispatch to a resource other than its own fixed, trusted configuration.
    Defense in depth (Phase 2 remediation, final Blocker 2 fix):
    ``ProposalExecutionService`` already refuses ``RESOURCE_MISMATCH``
    before ever calling ``execute`` -- this second, independent check
    inside the actuator wrapper itself means there is no path, present or
    future, through which any caller could reach a real dispatch with a
    mismatched resource, even one that bypassed
    ``ProposalExecutionService``'s own pre-check entirely."""


# The low-level I/O implementation an operator plugs in. Unlike Phase 2's
# original ``(action, payload) -> Awaitable[Any]`` shape, ``resource`` is now
# an explicit, first-class argument of the SAME call that performs the real
# side effect -- the authorized resource is part of the actual controlled
# invocation, never a separate piece of metadata checked once and then
# forgotten. A correctly-written dispatcher determines its real I/O
# destination FROM this parameter (e.g. builds its outbound request/lookup
# key directly from it); there is no second, independently-selected
# destination for a competent implementation to diverge to.
ActuatorDispatch = Callable[..., Awaitable[Any]]  # (*, resource, action, payload) -> Awaitable[Any]


class ResourceBoundUpstream:
    """The ONLY actuator contract :class:`ProposalExecutionService` accepts
    (Phase 2 remediation, Blocker 2 -- final fix). ``resource`` is the
    actuator's OWN fixed, trusted configured destination -- set once, at
    construction, by the deployment operator; NEVER derived from proposal
    content, request payload, or any other untrusted input.

    The original remediation round's design verified ``resource`` against
    the authorized resource, but then dispatched via a plain
    ``(action, payload)`` call: the verified resource was metadata,
    disconnected from the actual invocation, so a wrapped callable
    hardcoded to some entirely different, unrelated destination could still
    be wrapped and declared under a truthful-looking (but disconnected)
    ``resource`` string. This final fix closes that gap TWO ways, together:

    1. ``resource`` is now an explicit argument of :meth:`execute` --
       the SAME call that reaches ``dispatch`` -- so the authorized
       resource is structurally part of the real invocation, not a
       separate fact checked once elsewhere and then discarded.
    2. :meth:`execute` independently re-verifies ``resource`` against
       ``self.resource`` immediately before calling ``dispatch``, raising
       :class:`ResourceMismatchError` on any mismatch -- defense in depth
       beyond ``ProposalExecutionService``'s own pre-token-issuance check.

    There is no plain ``__call__``/2-argument entry point left: every
    caller must go through :meth:`execute`, which always carries the
    resource. ``resource=None`` is a legitimate configuration for an
    actuator with no distinguishable destination concept -- it matches only
    a proposal whose OWN authorized ``resource`` is also ``None`` (never a
    real resource string, since ``None != "some-resource"``).
    """

    def __init__(self, resource: Optional[str], dispatch: ActuatorDispatch) -> None:
        self.resource = resource
        self._dispatch = dispatch

    async def execute(self, *, resource: Optional[str], action: str, payload: Dict[str, Any]) -> Any:
        if resource != self.resource:
            raise ResourceMismatchError(
                f"actuator configured for resource {self.resource!r} refuses to "
                f"dispatch to {resource!r}"
            )
        return await self._dispatch(resource=resource, action=action, payload=payload)


class ProposalExecStatus(str, Enum):
    """The stable outcome vocabulary for :meth:`ProposalExecutionService.
    authorize_and_execute`. Distinct from ``OperationStatusValue``
    (``mcc_proposal.models``) -- that vocabulary describes the durable
    execution *state* a status read observes; this one describes what THIS
    ONE authorize-and-execute ATTEMPT did."""

    EXECUTED = "EXECUTED"
    BLOCKED = "BLOCKED"                # refused before/without dispatch; safe, no side effect
    EXECUTION_FAILED = "EXECUTION_FAILED"  # dispatched; outcome durably UNKNOWN
    DENIED = "DENIED"                  # trusted authority verdict was DENY
    ESCALATED = "ESCALATED"            # trusted authority verdict was ESCALATE
    NOT_FOUND = "NOT_FOUND"            # no tenant-owned proposal for this identity (tenant-safe)
    UNAVAILABLE = "UNAVAILABLE"        # backend uncertainty; never "safe to execute"
    REJECTED = "REJECTED"              # malformed/incomplete input or record; zero calls made
    RESOURCE_MISMATCH = "RESOURCE_MISMATCH"  # actuator's configured destination != authorized resource


@dataclass(frozen=True)
class ProposalExecOutcome:
    status: ProposalExecStatus
    reason: str
    decision: Optional[str] = None          # ALLOW / DENY / ESCALATE / CONSTRAIN, when known
    audit_ref: Optional[str] = None
    execution: Any = None
    applied_changes: List[str] = field(default_factory=list)

    @property
    def executed(self) -> bool:
        return self.status == ProposalExecStatus.EXECUTED


def _now() -> int:
    return int(time.time())


class ProposalExecutionService:
    """Bridges :class:`mcc_proposal.registry` (a ``ProposalRegistry`` --
    ``InMemoryProposalRegistry``/``RedisProposalRegistry``) into the real
    authority + execution machinery. Construct ONE instance per deployment,
    wired to the SAME ``ProposalRegistry`` instance
    :class:`mcc_proposal.service.MCCProposalService` uses for status reads,
    and the SAME ``IdempotencyRegistry`` instance passed to it as
    ``durable_execution_state`` -- there is exactly one durable execution
    registry in this deployment, read by the status service and written by
    the coordinator this class drives.
    """

    def __init__(
        self,
        *,
        proposals: Any,
        authority: AuthorityModel,
        engine: DecisionEngine,
        coordinator: EnforcementCoordinator,
        upstream: ResourceBoundUpstream,
        profiles: Optional[ProfileRegistry] = None,
    ) -> None:
        # Phase 2 remediation, Blocker 2 (final fix): a plain (action,
        # payload) -> ... callable is refused at construction time -- there
        # would be no place left to independently verify its real
        # destination against the authorized resource, AND no way to make
        # the authorized resource part of the actual dispatch call.
        # ``upstream`` must expose the fixed, trusted ``.resource``
        # attribute AND the ``execute(resource=, action=, payload=)`` entry
        # point :class:`ResourceBoundUpstream` defines -- there is no
        # remaining unchecked plain-callable path.
        if not hasattr(upstream, "resource") or not callable(getattr(upstream, "execute", None)):
            raise TypeError(
                "upstream must be a ResourceBoundUpstream (or otherwise expose a "
                "fixed, trusted '.resource' attribute and an async "
                "'.execute(resource=, action=, payload=)' method) so "
                "ProposalExecutionService can verify it against the authorized "
                "resource, and pass that same resource into the actual dispatch, "
                "before any external I/O"
            )
        self._proposals = proposals
        self._authority = authority
        self._engine = engine
        self._coordinator = coordinator
        self._upstream = upstream
        self._profiles = profiles or ProfileRegistry.default_pilot()

    async def authorize_and_execute(
        self, *, tenant_id: str, logical_operation_id: str,
        principal_id: Optional[str] = None,
    ) -> ProposalExecOutcome:
        """Authorize and (if authority allows) execute exactly one
        tenant-owned proposal. Takes NO payload/action/resource parameter --
        by construction, this method cannot accept an independently supplied
        execution body that could diverge from the proposal's own stored
        content (Section 2); the only inputs are the two identity
        components, exactly like ``MCCProposalService.get_operation_status``.

        F1b: ``principal_id`` is the individually authenticated caller. When
        given, only the principal the proposal is bound to may execute it --
        another principal's (or a pre-F1b, unbound) proposal is NOT_FOUND,
        before any authority decision, token, reservation, audit or actuator
        call. The token's subject/actor is then that principal; the authority
        policy is still evaluated for the tenant (unchanged semantics).
        """
        if principal_id is not None and (not isinstance(principal_id, str) or not principal_id.strip()):
            return ProposalExecOutcome(
                ProposalExecStatus.REJECTED, "principal_id must be a non-empty authenticated identity",
            )
        # ---- Section 1: tenant ownership first, before anything else ----
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            return ProposalExecOutcome(
                ProposalExecStatus.REJECTED, "tenant_id must be a non-empty authenticated identity",
            )
        if not isinstance(logical_operation_id, str) or not logical_operation_id.strip():
            return ProposalExecOutcome(
                ProposalExecStatus.REJECTED, "logical_operation_id must be a non-empty string",
            )

        try:
            record = await self._proposals.get(tenant_id=tenant_id, logical_operation_id=logical_operation_id)
        except ProposalBackendUnavailable as exc:
            return ProposalExecOutcome(
                ProposalExecStatus.UNAVAILABLE, f"proposal backend unavailable: {exc}",
            )
        if record is None:
            # Tenant-safe: whether this identity was never proposed at all,
            # or was proposed by a DIFFERENT tenant, is indistinguishable
            # here -- exactly mirroring the read-only status boundary.
            return ProposalExecOutcome(ProposalExecStatus.NOT_FOUND, "no proposal for this tenant/identity")
        if principal_id is not None and getattr(record, "principal_id", None) != principal_id:
            # F1b: another principal's operation is indistinguishable from an
            # absent one (no disclosure, nothing consumed or reserved).
            return ProposalExecOutcome(ProposalExecStatus.NOT_FOUND, "no proposal for this tenant/identity")
        actor = principal_id if principal_id is not None else tenant_id

        # ---- Section 2: the proposal record's OWN content is the ONLY
        # source of the governed operation. A record written before this
        # bridge existed (or via the low-level registry API with no content)
        # carries no governable action -- refuse rather than guess. ----
        if not isinstance(record.action, str) or not record.action.strip():
            return ProposalExecOutcome(
                ProposalExecStatus.REJECTED,
                "proposal record carries no stored action/resource/payload content; "
                "cannot authorize an operation with no known shape",
            )
        action = record.action
        resource = record.resource
        payload = dict(record.payload or {})

        # Defense-in-depth internal-consistency check: the binding stored at
        # registration time must still match a fresh recomputation over the
        # SAME stored content, via the SAME reused primitive
        # ``compute_proposal_binding`` -- this should be unreachable by
        # construction (registration always computes both together), but a
        # divergence here can only mean storage corruption, never "this
        # actually belongs to someone else" (the registry is already
        # tenant-scoped). Fail closed rather than execute an unverified body.
        try:
            recomputed_binding = compute_proposal_binding(
                action=action, resource=resource, payload=payload, profiles=self._profiles,
            )
        except BindingComputationError as exc:
            return ProposalExecOutcome(
                ProposalExecStatus.REJECTED, f"stored proposal content no longer profile-valid: {exc}",
            )
        if recomputed_binding != record.binding:
            return ProposalExecOutcome(
                ProposalExecStatus.REJECTED,
                "stored proposal binding does not match its own stored content; "
                "internal consistency error, fail-closed",
            )

        # ---- Section 3: trusted authority issuance. Identity is the
        # AUTHENTICATED tenant_id -- never the proposal's caller-supplied
        # ``actor`` field, which is untrusted transport content. ----
        try:
            profile = self._profiles.for_action(action)
        except ProfileError as exc:
            return ProposalExecOutcome(ProposalExecStatus.REJECTED, f"PROFILE_ERROR: {exc}")

        decision = self._authority.evaluate(identity=tenant_id, action=action, context=payload, now=_now())

        if decision.verdict == Verdict.DENY:
            return ProposalExecOutcome(ProposalExecStatus.DENIED, decision.reason, decision=Verdict.DENY.value)
        if decision.verdict == Verdict.ESCALATE:
            return ProposalExecOutcome(
                ProposalExecStatus.ESCALATED, decision.reason, decision=Verdict.ESCALATE.value,
            )
        if decision.verdict not in (Verdict.ALLOW, Verdict.CONSTRAIN):
            # Unknown/malformed verdict -- never execute.
            return ProposalExecOutcome(
                ProposalExecStatus.REJECTED, f"unknown authority verdict {decision.verdict!r}; fail-closed",
            )

        # ---- Phase 2 remediation, Blocker 2: the actuator's OWN configured
        # destination must equal the authorized resource BEFORE any token is
        # issued or any I/O is attempted. Signing ``resource_id=resource``
        # into the token only proves a string matched inside the token --
        # it proves nothing about where the real side effect is actually
        # sent. This is the independent check that closes that gap: a
        # misconfigured or hardcoded actuator targeting a different
        # resource is refused here, with zero token issuance and zero
        # actuator invocation. ----
        if self._upstream.resource != resource:
            return ProposalExecOutcome(
                ProposalExecStatus.RESOURCE_MISMATCH,
                f"actuator is configured for resource {self._upstream.resource!r}, but this "
                f"operation authorizes resource {resource!r}; refusing before any external call",
                decision=decision.verdict.value,
            )

        forward_context = dict(decision.forward_context or payload)

        auth_claims = dict(profile.auth_claims(forward_context))
        token = self._engine.issue_token(
            verdict=decision.verdict.value,
            subject=actor,
            action=action,
            payload=forward_context,
            constraints=decision.constraints,
            # The proposal's OWN stable identity becomes the idempotency_key
            # -- never regenerated for a retry (Section 3): a second
            # authorize_and_execute call for the SAME (tenant_id,
            # logical_operation_id) presents the SAME idempotency_key, so
            # the coordinator's own duplicate/UNKNOWN semantics (Section 9)
            # apply exactly as they would for any other governed caller.
            idempotency_key=logical_operation_id,
            tenant_id=tenant_id,
            actor_id=actor,
            resource_id=resource,
            auth_claims=auth_claims,
        )

        # Round-24-style hardening (examples/gpt6_astra_reference/pipeline.py
        # ``enforce_authority``): a private, deep-copied snapshot taken here,
        # synchronously, before the first await -- the Gate's verification
        # and the executor's actual dispatch (separated by several awaited
        # admission steps inside ``coordinator.enforce``) observe the
        # IDENTICAL bytes; nothing outside this frame holds a mutable
        # reference to what actually gets dispatched (Section 6).
        effective_payload = copy.deepcopy(forward_context)

        async def executor() -> Any:
            # Phase 2 remediation, Blocker 2 (final fix): ``resource`` here
            # is the SAME authorized value just verified above -- passed
            # directly into the call that performs the real dispatch, not
            # merely compared against separate metadata beforehand. See
            # ResourceBoundUpstream.execute's own defense-in-depth
            # re-verification of this exact value.
            return await self._upstream.execute(resource=resource, action=action, payload=effective_payload)

        result = await self._coordinator.enforce(
            token=token, action=action, payload=effective_payload, executor=executor,
            request_binding={
                "actor_id": actor, "resource_id": resource,
                "transaction_id": None, "tenant_id": tenant_id,
            },
        )

        status_map = {
            ActuationStatus.EXECUTED: ProposalExecStatus.EXECUTED,
            ActuationStatus.BLOCKED: ProposalExecStatus.BLOCKED,
            ActuationStatus.EXECUTION_FAILED: ProposalExecStatus.EXECUTION_FAILED,
        }
        return ProposalExecOutcome(
            status=status_map.get(result.status, ProposalExecStatus.BLOCKED),
            reason=result.reason,
            decision=result.decision.value if result.decision else decision.verdict.value,
            audit_ref=result.audit_ref,
            execution=result.execution,
            applied_changes=list(decision.applied_changes or []),
        )


# --------------------------------------------------------------------------- #
# Reconciliation (Section 8) -- domain-neutral, tenant-scoped, resolves
# durable uncertainty from independently verified positive external
# evidence only. Never executes a new side effect.
# --------------------------------------------------------------------------- #


class ReconcileOutcome(str, Enum):
    RESOLVED = "RESOLVED"              # evidence matched; UNKNOWN/DISPATCH_OWNED -> EXECUTED, by THIS call
    EVIDENCE_MATCHED_NOT_APPLIED = "EVIDENCE_MATCHED_NOT_APPLIED"  # matched, but a racing writer/stale fence beat this call
    NO_EVIDENCE = "NO_EVIDENCE"        # no positive external evidence found; left pending
    EVIDENCE_MISMATCH = "EVIDENCE_MISMATCH"  # evidence WAS returned, but does not bind to this exact operation
    NOT_FOUND = "NOT_FOUND"            # no tenant-owned proposal, or no durable record; tenant-safe
    NOT_RECONCILABLE = "NOT_RECONCILABLE"  # durable state is not UNKNOWN/DISPATCH_OWNED
    REJECTED = "REJECTED"              # malformed input / internal-consistency mismatch
    UNAVAILABLE = "UNAVAILABLE"


@dataclass(frozen=True)
class ProposalReconciliationOutcome:
    outcome: ReconcileOutcome
    reason: str


# Phase 2 remediation, Blocker 1. A verifier looks for independently-
# observed evidence of a specific external side effect, SCOPED by the
# trusted operation context it is called with (never left to guess it),
# and returns either ``None`` ("not found / inconclusive" -- always treated
# identically to a genuine absence, never distinguished for the purpose of
# authorizing anything further) or a dict the verifier itself asserts
# describes what it found:
#
#     {"tenant_id": ..., "logical_operation_id": ..., "action": ...,
#      "resource": ..., "payload": {...}}
#
# This return value is NEVER trusted as-is -- ``reconcile_proposal_operation``
# independently re-checks every one of these fields against the TRUSTED,
# STORED operation context before ever calling ``resolve_unknown`` (mirroring
# ``examples/gpt6_astra_reference/reconciliation.py``'s own
# marker-match-is-not-enough / candidate-content-must-hash-to-payload_hash
# pattern, generalized so the Universal Proposal Service's reconciliation
# stays domain-neutral instead of hardcoded to one actuator).
EvidenceVerifier = Callable[..., Awaitable[Optional[Dict[str, Any]]]]


def _evidence_binding_mismatch(
    evidence: Any, *, tenant_id: str, logical_operation_id: str, action: str,
    resource: Optional[str], authorized_payload_hash: str,
) -> Optional[str]:
    """Returns a human-readable mismatch reason, or ``None`` if ``evidence``
    is a well-formed dict that binds to EVERY one of the trusted, stored
    operation fields. Never raises -- any malformed shape is itself a
    mismatch (fail-closed), never an exception that could skip the caller's
    fail-closed branch."""
    if not isinstance(evidence, dict):
        return "evidence is not a dict"
    required = ("tenant_id", "logical_operation_id", "action", "resource", "payload")
    missing = [k for k in required if k not in evidence]
    if missing:
        return f"evidence is missing required bound field(s): {missing}"
    if evidence["tenant_id"] != tenant_id:
        return "evidence tenant_id does not match the trusted caller tenant_id"
    if evidence["logical_operation_id"] != logical_operation_id:
        return "evidence logical_operation_id does not match the trusted operation identity"
    if evidence["action"] != action:
        return "evidence action does not match the authorized action"
    if evidence["resource"] != resource:
        return "evidence resource does not match the authorized resource"
    if not isinstance(evidence["payload"], dict):
        return "evidence payload is not a dict"
    if hash_payload(evidence["payload"]) != authorized_payload_hash:
        return "evidence payload does not hash to the exact authorized payload_hash"
    return None


async def reconcile_proposal_operation(
    *,
    proposals: Any,
    idempotency: Any,
    authority: AuthorityModel,
    tenant_id: str,
    logical_operation_id: str,
    verify_external_evidence: EvidenceVerifier,
    profiles: Optional[ProfileRegistry] = None,
) -> ProposalReconciliationOutcome:
    """Reconcile ONE proposal-originated operation. Tenant-scoped throughout
    (Section 8): every lookup is keyed by ``(tenant_id, logical_operation_id)``,
    so no tenant may ever resolve another tenant's identical-id record, even
    one sharing every other field byte-for-byte. Never dispatches to an
    actuator -- ``verify_external_evidence`` is a pure, already-scoped LOOK,
    called at most once, and its returned evidence is independently
    re-verified against the trusted stored operation before any durable
    state mutation is attempted (Phase 2 remediation, Blocker 1).

    ``authority`` is the SAME ``AuthorityModel`` :class:`ProposalExecutionService`
    was constructed with. It is evaluated here a second time, over the SAME
    ``(tenant_id, action, record.payload)`` triple that produced the
    original admission -- a pure, deterministic recomputation (no new
    decision logic) that reconstructs the EXACT authorized payload
    (``decision.forward_context``, which for a CONSTRAIN verdict differs
    from the raw proposal payload). This is what lets reconciliation bind
    evidence to the operation's real, final authorized payload_hash rather
    than the pre-authorization proposal content -- a distinction that
    matters exactly for CONSTRAIN operations, where the two differ.
    """
    profiles = profiles or ProfileRegistry.default_pilot()

    if not isinstance(tenant_id, str) or not tenant_id.strip():
        return ProposalReconciliationOutcome(ReconcileOutcome.REJECTED, "tenant_id must be non-empty")
    if not isinstance(logical_operation_id, str) or not logical_operation_id.strip():
        return ProposalReconciliationOutcome(ReconcileOutcome.REJECTED, "logical_operation_id must be non-empty")

    try:
        record = await proposals.get(tenant_id=tenant_id, logical_operation_id=logical_operation_id)
    except ProposalBackendUnavailable as exc:
        return ProposalReconciliationOutcome(ReconcileOutcome.UNAVAILABLE, f"proposal backend unavailable: {exc}")
    if record is None or not isinstance(record.action, str) or not record.action.strip():
        return ProposalReconciliationOutcome(ReconcileOutcome.NOT_FOUND, "no proposal for this tenant/identity")

    from mcc_core.idempotency import IdempotencyBackendUnavailable, IdempotencyState, ReconcileStatus

    try:
        state = await idempotency.get_state(logical_operation_id, tenant_id=tenant_id)
    except IdempotencyBackendUnavailable as exc:
        return ProposalReconciliationOutcome(ReconcileOutcome.UNAVAILABLE, f"durable backend unavailable: {exc}")
    if state is None:
        return ProposalReconciliationOutcome(ReconcileOutcome.NOT_FOUND, "no durable record for this operation")
    if state.state not in (IdempotencyState.UNKNOWN, IdempotencyState.DISPATCH_OWNED):
        return ProposalReconciliationOutcome(
            ReconcileOutcome.NOT_RECONCILABLE, f"durable state is {state.state.value}; nothing to reconcile",
        )

    # Reconstruct the EXACT payload that was actually authorized (and, for
    # CONSTRAIN, dispatched) -- never the raw pre-authorization proposal
    # payload -- via the SAME AuthorityModel evaluated idempotently over
    # the SAME inputs, exactly as ProposalExecutionService did at admission
    # time. This is what the durable record's own ``binding`` was computed
    # from, so this is the correct ground truth to check evidence against
    # and to detect storage/state corruption against.
    try:
        profiles.for_action(record.action)
    except ProfileError as exc:
        return ProposalReconciliationOutcome(ReconcileOutcome.REJECTED, f"PROFILE_ERROR: {exc}")
    decision = authority.evaluate(identity=tenant_id, action=record.action, context=dict(record.payload or {}))
    if decision.verdict not in (Verdict.ALLOW, Verdict.CONSTRAIN):
        return ProposalReconciliationOutcome(
            ReconcileOutcome.REJECTED,
            "authority no longer authorizes this operation; cannot reconstruct the "
            "authorized payload to bind evidence against; fail-closed",
        )
    authorized_payload = dict(decision.forward_context or record.payload or {})
    authorized_payload_hash = hash_payload(authorized_payload)

    try:
        expected_binding = compute_proposal_binding(
            action=record.action, resource=record.resource, payload=authorized_payload, profiles=profiles,
        )
    except BindingComputationError as exc:
        return ProposalReconciliationOutcome(ReconcileOutcome.REJECTED, f"stored proposal content invalid: {exc}")
    if expected_binding != state.binding:
        return ProposalReconciliationOutcome(
            ReconcileOutcome.REJECTED,
            "durable record binding does not match the reconstructed authorized "
            "operation; internal consistency error, fail-closed",
        )

    evidence = await verify_external_evidence(
        tenant_id=tenant_id, logical_operation_id=logical_operation_id,
        action=record.action, resource=record.resource, payload_hash=authorized_payload_hash,
    )
    if evidence is None:
        return ProposalReconciliationOutcome(ReconcileOutcome.NO_EVIDENCE, "no positive external evidence found")

    mismatch = _evidence_binding_mismatch(
        evidence, tenant_id=tenant_id, logical_operation_id=logical_operation_id,
        action=record.action, resource=record.resource, authorized_payload_hash=authorized_payload_hash,
    )
    if mismatch is not None:
        # Evidence WAS returned, but does not prove it corresponds to this
        # exact operation -- fail closed exactly like "no evidence found":
        # zero durable state mutation, UNKNOWN/DISPATCH_OWNED unchanged.
        return ProposalReconciliationOutcome(ReconcileOutcome.EVIDENCE_MISMATCH, mismatch)

    result_ref = hash_document({"evidence": evidence})
    result = await idempotency.resolve_unknown(
        logical_operation_id, tenant_id=tenant_id, expected_generation=state.generation, result_ref=result_ref,
    )
    if result.status == ReconcileStatus.RESOLVED:
        return ProposalReconciliationOutcome(ReconcileOutcome.RESOLVED, result.reason)
    return ProposalReconciliationOutcome(ReconcileOutcome.EVIDENCE_MATCHED_NOT_APPLIED, result.reason)


__all__ = [
    "ProposalExecStatus",
    "ProposalExecOutcome",
    "ProposalExecutionService",
    "ResourceBoundUpstream",
    "ResourceMismatchError",
    "ActuatorDispatch",
    "ReconcileOutcome",
    "ProposalReconciliationOutcome",
    "EvidenceVerifier",
    "reconcile_proposal_operation",
]
