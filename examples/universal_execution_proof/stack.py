"""Builds the REAL HTTP app this proof runs its traffic through.

Composes, unchanged:

* ``gateway.proposal_execution_stack.build_proposal_execution_stack`` (PR
  #111) -- the domain-neutral AuthorityModel/DecisionEngine/ExecutionGate/
  EnforcementCoordinator/ProposalExecutionService builder.
* ``gateway.proposal_api.mount_proposal_routes`` and
  ``gateway.proposal_execution_api.mount_proposal_execution_routes`` --
  the REAL HTTP surface (``POST /v1/proposals``,
  ``POST /v1/operations/{id}/execute``). There is no reconciliation route
  to mount: PR #111's router no longer exposes one at all, and this
  package adds none either (see docs §"no reconciliation expansion").

``upstream`` is the ONLY domain-specific piece, injected by the caller --
this module never constructs a GitHub-specific (or any other
domain-specific) actuator itself; see ``examples/universal_execution_proof/run_live_proof.py``
for the GitHub wiring and ``generic_ledger_actuator.py`` for the
non-GitHub actuator-neutrality proof.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from fastapi import FastAPI

from mcc_core import Verdict
from mcc_proposal import MCCProposalService

from gateway.proposal_api import mount_proposal_routes
from gateway.proposal_execution_api import mount_proposal_execution_routes
from gateway.proposal_execution_service import ResourceBoundUpstream
from gateway.proposal_execution_stack import ProposalExecutionStack, build_proposal_execution_stack


@dataclass(frozen=True)
class UniversalProofStack:
    exec_stack: ProposalExecutionStack
    proposal_service: MCCProposalService
    app: FastAPI


def build_universal_proof_stack(
    *,
    proposals: Any,
    idempotency: Any,
    nonces: Any,
    tenants_credentials: Dict[str, str],
    tenants_authority: Dict[str, Dict[str, Any]],
    upstream: ResourceBoundUpstream,
    action: str,
    audit_log_path: str,
    without_mandate: Verdict = Verdict.DENY,
) -> UniversalProofStack:
    """One shared set of durable registries feeds BOTH the Phase 1
    proposal/status service and the Phase 2 execution bridge -- there is
    exactly one proposal registry and one durable execution registry in
    this deployment (docs/PILOT_EXECUTION_API.md §11's shared-instance
    requirement, unchanged from PR #111)."""
    exec_stack = build_proposal_execution_stack(
        proposals=proposals, idempotency=idempotency, nonces=nonces,
        tenants=tenants_authority, action=action, upstream=upstream,
        audit_log_path=audit_log_path, without_mandate=without_mandate,
    )
    proposal_service = MCCProposalService(proposals=proposals, durable_execution_state=idempotency)

    app = FastAPI(title="MCC Universal Execution Authority Proof")
    mount_proposal_routes(app, proposal_service, tenants=tenants_credentials)
    mount_proposal_execution_routes(app, exec_stack.service, tenants=tenants_credentials)

    @app.get("/health")
    async def health() -> Dict[str, str]:
        return {"status": "ok"}

    return UniversalProofStack(exec_stack=exec_stack, proposal_service=proposal_service, app=app)


def build_universal_proof_app(**kwargs: Any) -> FastAPI:
    return build_universal_proof_stack(**kwargs).app


__all__ = ["UniversalProofStack", "build_universal_proof_stack", "build_universal_proof_app"]
