"""Reference composition: Phase 1 (proposal submission/status) + PR #111's
Pilot Execution API, correctly sharing ONE ``proposals``/``idempotency``
pair (docs/PILOT_EXECUTION_API.md §11) -- the pattern a real deployment
must follow, demonstrated runnably.

Not wired into ``gateway/app.py``'s default startup (see
docs/PILOT_EXECUTION_API.md §12: no production actuator decision has been
made for this repository).

This module deliberately separates two, non-interchangeable compositions
(PR #111 remediation, Blocker 1):

``build_app(...)`` -- the DEPLOYABLE composition. Fail-closed: every one
of ``tenants_credentials``/``tenants_authority``/``upstream`` is REQUIRED
(``None`` -> raises ``PilotExecutionAPIConfigError`` rather than silently
substituting a demo default), and an explicitly-supplied ``{}`` is
accepted and stays exactly ``{}`` -- never replaced, enriched, or expanded
by a truthiness check (``x or default`` treats ``{}`` and ``None``
identically, which is exactly the defect this fixes: an operator who
deliberately configures zero clients or zero authority grants must get
zero clients/zero authority, not a silently-substituted, more permissive
configuration). There is no code path in ``build_app`` that can produce
the demo credential (``demo-key``/``demo-tenant``) or an auto-generated
authority grant -- those literals do not appear in this function at all.

``build_demo_app(...)`` -- the DEMO-ONLY composition. May deliberately use
``demo-key -> demo-tenant``, a demo authority grant, and the echo/no-
external-I/O actuator -- but it accepts no ``upstream`` parameter at all,
so there is no way to hand it a real actuator and have it silently retain
the demo credentials/authority alongside a genuine external side effect;
``build_demo_app`` calls `build_app` with a hardcoded, literal, hardcoded
echo upstream every time.

    PYTHONPATH=src:.:sdk/python/src uvicorn examples.pilot_execution_api.app:app --port 8000

runs the demo composition. A real deployment calls ``build_app`` directly
with its own real credential map, real authority grants, and a genuine
``ResourceBoundUpstream`` (e.g. adapting
``examples/phase2_live_sandbox/actuator.py``'s ``GitHubSandboxUpstream``
pattern, or any other controlled actuator), plus real Redis-backed
registries via ``mcc_proposal.registry.proposal_registry_from_env()`` /
``mcc_core.idempotency.idempotency_registry_from_env()`` /
``mcc_core.nonce.nonce_registry_from_env()``.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI

from mcc_core import InMemoryIdempotencyRegistry, InMemoryNonceRegistry
from mcc_proposal import InMemoryProposalRegistry, MCCProposalService

from gateway.proposal_api import mount_proposal_routes
from gateway.proposal_execution_api import mount_proposal_execution_routes
from gateway.proposal_execution_service import ResourceBoundUpstream
from gateway.proposal_execution_stack import build_proposal_execution_stack

ACTION = "send_notification"


class PilotExecutionAPIConfigError(Exception):
    """Raised by ``build_app`` when required deployable configuration was
    not supplied at all (``None``). Fail-closed: this is deliberately a
    hard construction-time error, never a silent substitution of demo
    defaults -- see this module's docstring."""


async def echo_upstream(*, resource: Optional[str], action: str, payload: Dict[str, Any]) -> Any:
    """The demo-only actuator: records nothing external, returns a
    deterministic acknowledgement. Used ONLY by ``build_demo_app`` --
    ``build_app`` never references this function."""
    return {"acknowledged": True, "resource": resource, "action": action}


def build_app(
    *,
    tenants_credentials: Optional[Dict[str, str]],
    tenants_authority: Optional[Dict[str, Dict[str, Any]]],
    upstream: Optional[ResourceBoundUpstream],
    action: str = ACTION,
) -> FastAPI:
    """The DEPLOYABLE composition. All three of ``tenants_credentials``,
    ``tenants_authority``, and ``upstream`` are REQUIRED:

    * ``None`` -> ``PilotExecutionAPIConfigError`` (fail closed -- required
      configuration was not supplied at all).
    * ``{}`` (for the two mappings) -> accepted, and used EXACTLY as given
      (zero configured clients / zero authority grants) -- never replaced
      by a demo default, never enriched, never auto-populated.

    No truthiness-based fallback (``x or default``) appears anywhere in
    this function -- that pattern is exactly what previously let an
    explicit ``{}`` be silently treated as "missing" and replaced by a
    permissive default. Supplying a real/custom ``upstream`` here NEVER
    activates or preserves any demo credential/authority: this function
    contains no demo literals to activate in the first place.
    """
    if tenants_credentials is None:
        raise PilotExecutionAPIConfigError(
            "tenants_credentials is required and was not supplied (None); pass an "
            "explicit {} for a deployment with zero authenticated clients -- fail closed"
        )
    if tenants_authority is None:
        raise PilotExecutionAPIConfigError(
            "tenants_authority is required and was not supplied (None); pass an "
            "explicit {} for a deployment granting zero execution authority -- fail closed"
        )
    if upstream is None:
        raise PilotExecutionAPIConfigError(
            "upstream is required and was not supplied (None); no actuator may be "
            "silently constructed -- fail closed"
        )

    proposals = InMemoryProposalRegistry()
    idempotency = InMemoryIdempotencyRegistry()
    nonces = InMemoryNonceRegistry()

    audit_log_path = str(Path(tempfile.mkdtemp(prefix="mcc-pilot-execution-api-")) / "audit.jsonl")

    stack = build_proposal_execution_stack(
        proposals=proposals, idempotency=idempotency, nonces=nonces,
        tenants=tenants_authority, action=action, upstream=upstream,
        audit_log_path=audit_log_path,
    )

    # The SAME proposals/idempotency instances flow into Phase 1's status
    # service -- the shared-instance requirement docs/PILOT_EXECUTION_API.md
    # §11 documents.
    proposal_service = MCCProposalService(proposals=proposals, durable_execution_state=idempotency)

    app = FastAPI(title="MCC Pilot Execution API")
    mount_proposal_routes(app, proposal_service, tenants=tenants_credentials)
    mount_proposal_execution_routes(app, stack.service, tenants=tenants_credentials)

    @app.get("/health")
    async def health() -> Dict[str, str]:
        return {"status": "ok"}

    return app


def build_demo_app(*, action: str = ACTION) -> FastAPI:
    """The DEMO-ONLY composition: a hardcoded demo credential, a hardcoded
    demo authority grant, and the echo/no-external-I/O actuator --
    deliberately with NO ``upstream`` parameter, so there is no way to
    combine a real actuator with these demo security defaults through
    this function. Safe to run with zero configuration and makes no real
    external I/O."""
    return build_app(
        tenants_credentials={"demo-key": "demo-tenant"},
        tenants_authority={"demo-tenant": {}},
        upstream=ResourceBoundUpstream(resource=None, dispatch=echo_upstream),
        action=action,
    )


app = build_demo_app()


__all__ = [
    "build_app", "build_demo_app", "app", "echo_upstream", "ACTION",
    "PilotExecutionAPIConfigError",
]
