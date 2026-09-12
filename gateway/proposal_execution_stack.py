"""Proposal Execution Stack — domain-neutral builder for the Phase 2
governed execution bridge, generalized from
``examples/phase2_live_sandbox/stack.py`` (which is GitHub-sandbox-
specific) for the Pilot Execution API (PR #111).

Builds the SAME components every other production/reference call site in
this repository uses (``mcc_core.core.DecisionEngine``,
``mcc_core.gate.ExecutionGate``, ``mcc_core.coordinator.EnforcementCoordinator``,
``mcc_core.authority.AuthorityModel``,
``gateway.proposal_execution_service.ProposalExecutionService``) — no new
decision logic, no second Gate, no second ``EnforcementCoordinator``, no
second durable execution registry, no new actuator architecture.

Deliberately takes ``proposals``/``idempotency``/``nonces`` as REQUIRED,
already-constructed arguments rather than selecting a backend from the
environment itself: ``ProposalExecutionService`` and
``mcc_proposal.MCCProposalService`` (Phase 1's proposal/status boundary)
MUST share the exact same registry instances (there is exactly one durable
execution registry, and one proposal registry, per deployment) — if this
module called ``mcc_proposal.registry.proposal_registry_from_env()`` or
``mcc_core.idempotency.idempotency_registry_from_env()`` a second time
itself, an in-memory-backed deployment would silently construct a SECOND,
divergent registry instance invisible to the Phase 1 routes, and a proposal
submitted through ``POST /v1/proposals`` would never be found by
``POST /v1/operations/{id}/execute``. Making the shared instance an
explicit, required constructor argument (exactly like
``ProposalExecutionService.__init__`` already requires for ``proposals``)
makes that correctness requirement impossible to get wrong by omission.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from mcc_core import (
    ActionPolicy,
    AuditLog,
    AuthorityModel,
    DecisionEngine,
    EnforcementCoordinator,
    ExecutionGate,
    InMemoryVelocityRegistry,
    MandateRegistry,
    ProfileRegistry,
    SigningKey,
    Verdict,
)

from gateway.proposal_execution_service import ProposalExecutionService, ResourceBoundUpstream


@dataclass(frozen=True)
class ProposalExecutionStack:
    proposals: Any
    idempotency: Any
    nonces: Any
    authority: AuthorityModel
    engine: DecisionEngine
    audit: AuditLog
    coordinator: EnforcementCoordinator
    service: ProposalExecutionService


def build_proposal_execution_stack(
    *,
    proposals: Any,
    idempotency: Any,
    nonces: Any,
    tenants: Dict[str, Dict[str, Any]],
    action: str,
    upstream: ResourceBoundUpstream,
    audit_log_path: str,
    signing_key: Optional[SigningKey] = None,
    profiles: Optional[ProfileRegistry] = None,
    key_id: str = "pilot-execution-api-key",
    gate_audience: str = "pilot-execution-api-gate",
    token_ttl_seconds: int = 60,
    without_mandate: Verdict = Verdict.DENY,
) -> ProposalExecutionStack:
    """Assemble ONE ``ProposalExecutionService`` from explicitly-provided,
    already-constructed durable registries plus a caller-provided
    ``ResourceBoundUpstream`` actuator.

    ``tenants`` maps ``tenant_id -> constraints`` (``{}`` for none) — each
    listed tenant is granted the ``execute`` authority for ``action`` via
    the SAME declarative ``AuthorityModel`` every other Phase 2 reference
    call site in this repository uses (``examples/phase2_live_sandbox``,
    ``tests/test_proposal_execution_bridge.py``); an unlisted tenant_id has
    no authority (``DENY`` by default — no authority, zero external
    requests). This is the SAME multi-tenant authority shape the pilot's
    HTTP credential map (``MCC_PROPOSAL_TENANTS``) resolves *identity*
    into — the credential map answers "who is this caller", this answers
    "what may that identity do", and the two are deliberately independent
    layers, exactly as this repository's existing gateway keeps
    authentication (``get_caller``/``get_tenant``) and authority
    (``AuthorityModel.evaluate``) separate.
    """
    signing_key = signing_key or SigningKey.generate(key_id)
    engine = DecisionEngine(
        signing_key=signing_key,
        issuer="mcc/pilot-execution-api",
        audience=gate_audience,
        policy_id="pilot-execution-api/v1",
        policy_hash="sha256:pilot-execution-api",
        token_ttl_seconds=token_ttl_seconds,
    )
    gate = ExecutionGate(
        trusted_keys={signing_key.kid: signing_key.public_key()},
        audience=gate_audience,
        nonce_registry=nonces,
        policy_hash="sha256:pilot-execution-api",
    )
    audit = AuditLog(audit_log_path)
    coordinator = EnforcementCoordinator(
        gate=gate, idempotency=idempotency, velocity=InMemoryVelocityRegistry(),
        audit=audit, profiles=profiles or ProfileRegistry(),
    )

    grants = {t: [{"authority": "execute", "constraints": constraints or {}}] for t, constraints in tenants.items()}
    authority = AuthorityModel(
        registry=MandateRegistry.from_config(grants),
        policies=[ActionPolicy(action=action, requires="execute", on_mandate=Verdict.ALLOW,
                               without_mandate=without_mandate)],
        default=Verdict.DENY,
    )

    service = ProposalExecutionService(
        proposals=proposals, authority=authority, engine=engine,
        coordinator=coordinator, upstream=upstream, profiles=profiles,
    )

    return ProposalExecutionStack(
        proposals=proposals, idempotency=idempotency, nonces=nonces, authority=authority,
        engine=engine, audit=audit, coordinator=coordinator, service=service,
    )


__all__ = ["ProposalExecutionStack", "build_proposal_execution_stack"]
