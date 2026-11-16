"""MCCProposalService — the ONE transport-neutral proposal/status boundary.

    ANY INTELLIGENCE / ANY FRAMEWORK / ANY TRANSPORT
                    |
                    v
            MCCProposalService            <-- Phase 1 stops here
                    |
                    v
       MCC INDEPENDENT AUTHORITY BOUNDARY   (future phase)
                    |
                    v
             EnforcementCoordinator
                    |
                    v
              SERVER-OWNED ACTUATOR

This module is deliberately, verifiably non-actuating. It imports NOTHING
from ``mcc_core.gate``, ``mcc_core.coordinator``, ``mcc_core.authority``,
``mcc_core.signing.SigningKey``/``sign_token``, ``mcc_core.mandate``,
``mcc_core.approvals``, or ``gateway.governance_service`` -- see
``tests/test_proposal_service_architecture_guards.py``. It knows nothing
about HTTP, MCP, LangGraph, CrewAI, AutoGen, VoltAgent, gRPC, or any other
transport: every adapter converges on ``submit_proposal``/
``get_operation_status`` and nothing else.

    PROPOSAL != PERMISSION.
    STATUS != AUTHORITY.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from mcc_core.profiles import ProfileError, ProfileRegistry

from .binding import BindingComputationError, compute_proposal_binding
from .models import (
    OperationStatusV1,
    OperationStatusValue,
    ProposalReceiptV1,
    ProposalRequestV1,
    ProposalValidationError,
)
from .registry import ProposalBackendUnavailable, ProposalRegisterStatus

# The read-only durable-execution status view this service is permitted to
# consult. Only ``get_state`` is ever called on it -- see the architecture
# guard test, which asserts this module contains no reference to ``reserve``,
# ``commit_dispatch``, ``mark_executed``, ``mark_unknown``, or
# ``resolve_unknown``.
try:  # pragma: no cover - import-shape only
    from mcc_core.idempotency import IdempotencyBackendUnavailable, IdempotencyState
except ImportError:  # pragma: no cover
    IdempotencyBackendUnavailable = None  # type: ignore[assignment,misc]
    IdempotencyState = None  # type: ignore[assignment,misc]


_DURABLE_STATE_MAP = {}
if IdempotencyState is not None:
    _DURABLE_STATE_MAP = {
        IdempotencyState.RESERVED: OperationStatusValue.RESERVED,
        IdempotencyState.DISPATCH_OWNED: OperationStatusValue.DISPATCH_OWNED,
        IdempotencyState.UNKNOWN: OperationStatusValue.UNKNOWN,
        IdempotencyState.EXECUTED: OperationStatusValue.EXECUTED,
    }


class MCCProposalService:
    """Transport-neutral. Construct one instance per deployment and hand it
    to every adapter (HTTP router, MCP handler, framework facade, SDK
    server-side counterpart) -- never let an adapter construct its own
    registry or recompute its own binding."""

    def __init__(
        self,
        *,
        proposals: Any,
        profiles: Optional[ProfileRegistry] = None,
        durable_execution_state: Optional[Any] = None,
    ) -> None:
        self._proposals = proposals
        self._profiles = profiles or ProfileRegistry.default_pilot()
        # Optional read-only durable-execution registry (an
        # ``InMemoryIdempotencyRegistry``/``RedisIdempotencyRegistry`` or
        # anything exposing an async ``get_state(key, *, tenant_id) ->
        # StateRecord|None`` -- PR #105: tenant-scoped, matching the real
        # registry's mandatory ``tenant_id`` keyword). ``None`` means this
        # deployment of the proposal service is not wired to a real
        # execution backend yet -- status composition then never reports
        # RESERVED/DISPATCH_OWNED/UNKNOWN/EXECUTED, only PROPOSED/NOT_FOUND,
        # which is the honest answer for that configuration (documented in
        # docs/MCC_UNIVERSAL_PROPOSAL_SERVICE_PHASE1.md).
        self._durable = durable_execution_state

    # -- submission ---------------------------------------------------- #

    async def submit_proposal(self, *, tenant_id: str, request: Dict[str, Any],
                              principal_id: Optional[str] = None) -> ProposalReceiptV1:
        """Register a proposal. Never calls the Gate, the coordinator, the
        signing key, or any actuator/upstream -- this either writes one
        PROPOSED record or reports why it did not.

        F1b: ``principal_id`` is the individually authenticated submitter
        (server-resolved from its credential). When given, the request's
        ``actor`` must equal it (never proof by itself) and the record is
        bound to it; only that principal may later execute or read it."""
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            raise ValueError("tenant_id must be a non-empty authenticated identity")
        if principal_id is not None and (not isinstance(principal_id, str) or not principal_id.strip()):
            raise ValueError("principal_id must be a non-empty authenticated identity")
        if principal_id is not None and isinstance(request, dict) and request.get("actor") != principal_id:
            return ProposalReceiptV1.rejected(
                logical_operation_id=(request.get("logical_operation_id")
                                      if isinstance(request.get("logical_operation_id"), str) else "") or "",
                reason="AGENT_PRINCIPAL_MISMATCH: actor is not the authenticated principal",
            )

        try:
            proposal = ProposalRequestV1.from_dict(request)
        except ProposalValidationError as exc:
            return ProposalReceiptV1.rejected(
                logical_operation_id=(request.get("logical_operation_id")
                                      if isinstance(request, dict) and isinstance(
                                          request.get("logical_operation_id"), str) else "") or "",
                reason=f"{exc.code}: {exc.reason}",
            )

        try:
            binding = compute_proposal_binding(
                action=proposal.action, resource=proposal.resource,
                payload=proposal.payload, profiles=self._profiles,
            )
            # Phase 2 (MCC_UNIVERSAL_PROPOSAL_SERVICE_PHASE2): the SAME
            # canonical payload just hashed into ``binding`` is durably
            # stored alongside it -- a pure, deterministic, side-effect-free
            # recomputation via the identical profile, never a second
            # canonicalization rule. This is what lets a later authorization
            # decision execute the proposal's OWN stored content instead of
            # accepting an independently supplied payload (Section 2).
            canonical_payload = self._profiles.for_action(proposal.action).canonical_payload(
                dict(proposal.payload)
            )
        except (BindingComputationError, ProfileError) as exc:
            return ProposalReceiptV1.rejected(
                logical_operation_id=proposal.logical_operation_id, reason=str(exc),
            )

        try:
            result = await self._proposals.register(
                tenant_id=tenant_id, logical_operation_id=proposal.logical_operation_id,
                binding=binding, action=proposal.action, resource=proposal.resource,
                payload=canonical_payload, principal_id=principal_id,
            )
        except ProposalBackendUnavailable as exc:
            return ProposalReceiptV1.unavailable(
                logical_operation_id=proposal.logical_operation_id,
                reason=f"proposal backend unavailable: {exc}",
            )

        if result.status == ProposalRegisterStatus.ERROR:
            return ProposalReceiptV1.unavailable(
                logical_operation_id=proposal.logical_operation_id, reason=result.reason,
            )
        if result.status == ProposalRegisterStatus.BINDING_CONFLICT:
            return ProposalReceiptV1.conflict(logical_operation_id=proposal.logical_operation_id)
        # REGISTERED or IDEMPOTENT_DUPLICATE both surface as an accepted,
        # idempotent PROPOSED receipt carrying the one true binding.
        return ProposalReceiptV1.proposed(
            logical_operation_id=proposal.logical_operation_id, proposal_binding=result.binding or binding,
        )

    # -- status ---------------------------------------------------------- #

    async def get_operation_status(self, *, tenant_id: str, logical_operation_id: str,
                                   principal_id: Optional[str] = None) -> OperationStatusV1:
        """Read-only. Performs zero state writes and calls no actuator.

        Ownership-gated, tenant-scoped precedence (PR #105 -- durable
        identity itself is now tenant-scoped at the registry level, not
        merely disambiguated after the fact by binding comparison):

          1. tenant-scoped proposal ownership lookup uncertain -> UNAVAILABLE
             (cannot prove ownership; never disclose)
          2. no tenant-scoped proposal record for this identity -> NOT_FOUND,
             WITHOUT ever consulting the durable execution registry. A
             tenant that never proposed this identity can neither observe
             another tenant's durable state nor infer that it exists.
          3. ownership established; durable execution backend uncertain ->
             UNAVAILABLE
          4. ownership established; a TENANT-SCOPED durable execution record
             exists (``self._durable.get_state(key, tenant_id=tenant_id)`` --
             the registry itself, not a binding comparison, is what
             establishes this is THIS tenant's record; see Section 6) ->
             its exact state, verbatim
          5. ownership established; no durable record for this tenant ->
             PROPOSED

        The proposal binding vs. durable binding comparison is retained as
        defense-in-depth / internal-consistency checking ONLY -- it is no
        longer the mechanism that establishes tenant ownership (the
        tenant-scoped registry lookup itself is). A mismatch WITHIN this
        tenant's own scoped record can only mean an internal corruption
        (this tenant's proposal and its own durable dispatch record
        disagree about what operation this id names) -- it is never
        silently reinterpreted as "must be another tenant's record" (the
        registry is tenant-scoped; it structurally cannot return another
        tenant's record here). Fail closed.
        """
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            raise ValueError("tenant_id must be a non-empty authenticated identity")
        if not isinstance(logical_operation_id, str) or not logical_operation_id.strip():
            return OperationStatusV1.of(
                logical_operation_id=str(logical_operation_id),
                status=OperationStatusValue.NOT_FOUND,
                detail="invalid logical_operation_id",
            )

        # 1-2. Ownership gate: only a tenant that has itself registered a
        # proposal for this exact logical_operation_id may have durable
        # execution state composed into its response.
        try:
            record = await self._proposals.get(tenant_id=tenant_id, logical_operation_id=logical_operation_id)
        except ProposalBackendUnavailable as exc:
            return OperationStatusV1.of(
                logical_operation_id=logical_operation_id, status=OperationStatusValue.UNAVAILABLE,
                detail=f"proposal backend unavailable: {exc}",
            )
        if record is None:
            return OperationStatusV1.of(logical_operation_id=logical_operation_id, status=OperationStatusValue.NOT_FOUND)
        if principal_id is not None and getattr(record, "principal_id", None) != principal_id:
            # F1b: another principal's (or a pre-F1b) operation is
            # indistinguishable from an absent one -- never disclosed.
            return OperationStatusV1.of(logical_operation_id=logical_operation_id, status=OperationStatusValue.NOT_FOUND)

        # 3-5. Ownership established -- the durable execution registry (if
        # configured) is queried DIRECTLY for THIS tenant's own scoped
        # record (Section 6: never the globally-keyed lookup).
        if self._durable is not None:
            try:
                state = await self._durable.get_state(logical_operation_id, tenant_id=tenant_id)
            except IdempotencyBackendUnavailable as exc:  # type: ignore[misc]
                return OperationStatusV1.of(
                    logical_operation_id=logical_operation_id, status=OperationStatusValue.UNAVAILABLE,
                    detail=f"durable execution backend unavailable: {exc}",
                )
            if state is not None:
                if state.binding != record.binding:
                    # Internal consistency error (Section 6): the registry is
                    # tenant-scoped, so this record is structurally already
                    # proven to belong to THIS tenant -- a binding mismatch
                    # here cannot be "someone else's record" and must never
                    # be reinterpreted as one. Fail closed rather than guess.
                    return OperationStatusV1.of(
                        logical_operation_id=logical_operation_id, status=OperationStatusValue.UNAVAILABLE,
                        detail="durable record binding does not match this tenant's own registered "
                               "proposal binding; internal consistency error, fail-closed",
                    )
                mapped = _DURABLE_STATE_MAP.get(state.state)
                if mapped is None:  # pragma: no cover - defensive; never mask as NOT_FOUND/PROPOSED
                    return OperationStatusV1.of(
                        logical_operation_id=logical_operation_id, status=OperationStatusValue.UNAVAILABLE,
                        detail="durable execution backend returned an unrecognized state",
                    )
                return OperationStatusV1.of(
                    logical_operation_id=logical_operation_id, status=mapped, proposal_binding=state.binding,
                )

        return OperationStatusV1.of(
            logical_operation_id=logical_operation_id, status=OperationStatusValue.PROPOSED,
            proposal_binding=record.binding,
        )


__all__ = ["MCCProposalService"]
