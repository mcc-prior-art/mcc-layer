"""External Pilot Integration Pack -- server composition (PR #113).

Mirrors the SAME deployable/demo split
``examples/pilot_execution_api/app.py`` (PR #111) already established,
composed from the SAME underlying primitives every governed HTTP surface
in this repository uses:

    gateway.proposal_execution_stack.build_proposal_execution_stack
    gateway.proposal_api.mount_proposal_routes
    gateway.proposal_execution_api.mount_proposal_execution_routes

No new decision logic, no second Gate, no second EnforcementCoordinator,
no second durable execution registry, no new actuator-dispatch
architecture. The one difference from ``examples/pilot_execution_api/app.py``
is that ``build_external_pilot_app`` accepts already-constructed
``proposals``/``idempotency``/``nonces`` registries (in-memory OR real
Redis-backed) rather than hardcoding in-memory ones -- needed so this
pack's replay/tenant-isolation scenarios can optionally run against real
durable Redis state, exactly like
``tests/test_proposal_execution_api.py``'s own established
"additionally run against real Redis, skip if unreachable" convention.

``build_app``/``build_demo_app`` (PR #111) is not merely mimicked in
spirit here for effort's sake: every governed decision this module's
composition makes is still made by the exact same
``ProposalExecutionService``/``AuthorityModel``/``DecisionEngine``/
``ExecutionGate``/``EnforcementCoordinator`` classes that module's own
composition uses -- ``build_proposal_execution_stack`` is the single
place those are actually constructed, and this module calls it, never
reimplements it.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from fastapi import FastAPI

from mcc_core import InMemoryIdempotencyRegistry, InMemoryNonceRegistry
from mcc_proposal import InMemoryProposalRegistry, MCCProposalService

from gateway.proposal_api import mount_proposal_routes, tenants_from_env
from gateway.proposal_execution_api import mount_proposal_execution_routes
from gateway.proposal_execution_service import ResourceBoundUpstream
from gateway.proposal_execution_stack import build_proposal_execution_stack

from examples.external_pilot.actuator.demo_actuator import build_demo_actuator

ACTION = "external_pilot_demo_action"


def authority_from_env(env: Optional[Mapping[str, str]] = None) -> Dict[str, Dict[str, Any]]:
    """``tenant_id -> constraints`` map, from ``MCC_EXTERNAL_PILOT_AUTHORITY``
    (a JSON object) -- the authority-grant counterpart to
    ``gateway.proposal_api.tenants_from_env``'s existing credential-map
    loader (reused directly for credentials in ``build_app_from_env``
    below; there is no separate ``tenants_authority_from_env`` anywhere
    else in this repository to reuse for THIS shape, so this is new, but
    mirrors that function's exact fail-closed contract). Unset/empty ->
    ``{}`` -- zero execution authority for every tenant, DENY by default;
    never a silent, more-permissive substitute."""
    env = os.environ if env is None else env
    raw = (env.get("MCC_EXTERNAL_PILOT_AUTHORITY") or "").strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ExternalPilotConfigError(f"MCC_EXTERNAL_PILOT_AUTHORITY is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or not all(
        isinstance(k, str) and k.strip() and isinstance(v, dict) for k, v in data.items()
    ):
        raise ExternalPilotConfigError(
            "MCC_EXTERNAL_PILOT_AUTHORITY must be a JSON object of {tenant_id: {constraints}}"
        )
    return dict(data)


class ExternalPilotConfigError(Exception):
    """Raised by ``build_external_pilot_app`` when required deployable
    configuration was not supplied at all (``None``). Fail-closed:
    missing mandatory authority/security configuration never silently
    enables demo authority -- mirrors
    ``examples.pilot_execution_api.app.PilotExecutionAPIConfigError``'s
    own contract exactly."""


def build_external_pilot_app(
    *,
    proposals: Any,
    idempotency: Any,
    nonces: Any,
    tenants_credentials: Optional[Dict[str, str]],
    tenants_authority: Optional[Dict[str, Dict[str, Any]]],
    upstream: Optional[ResourceBoundUpstream],
    audit_log_path: str,
    action: str = ACTION,
) -> FastAPI:
    """The DEPLOYABLE composition. ``tenants_credentials``,
    ``tenants_authority``, and ``upstream`` are all REQUIRED: ``None`` ->
    ``ExternalPilotConfigError`` (fail closed); an explicit ``{}`` is
    accepted and used EXACTLY as given (zero clients / zero authority
    grants), never silently replaced by a more permissive default --
    identical contract to ``examples.pilot_execution_api.app.build_app``.
    """
    if tenants_credentials is None:
        raise ExternalPilotConfigError(
            "tenants_credentials is required and was not supplied (None); pass an "
            "explicit {} for zero authenticated clients -- fail closed"
        )
    if tenants_authority is None:
        raise ExternalPilotConfigError(
            "tenants_authority is required and was not supplied (None); pass an "
            "explicit {} for zero execution authority -- fail closed"
        )
    if upstream is None:
        raise ExternalPilotConfigError(
            "upstream is required and was not supplied (None); no actuator may be "
            "silently constructed -- fail closed"
        )

    stack = build_proposal_execution_stack(
        proposals=proposals, idempotency=idempotency, nonces=nonces,
        tenants=tenants_authority, action=action, upstream=upstream,
        audit_log_path=audit_log_path,
    )
    # The SAME proposals/idempotency instances flow into Phase 1's status
    # service -- exactly the shared-instance requirement
    # docs/PILOT_EXECUTION_API.md §11 documents, and the same pattern
    # every other stack builder in this repository (build_app,
    # build_universal_proof_stack) follows.
    proposal_service = MCCProposalService(proposals=proposals, durable_execution_state=idempotency)

    app = FastAPI(title="MCC External Pilot Integration Pack")
    mount_proposal_routes(app, proposal_service, tenants=tenants_credentials)
    mount_proposal_execution_routes(app, stack.service, tenants=tenants_credentials)

    @app.get("/health")
    async def health() -> Dict[str, str]:
        return {"status": "ok"}

    return app


def build_demo_app(*, action: str = ACTION) -> FastAPI:
    """The DEMO-ONLY composition for the fresh-clone quick-start and
    self-check: in-memory registries, a hardcoded demo credential/
    authority grant, and the isolated, obviously non-production
    ``DemoLedgerActuator`` (never a real actuator). Makes zero external
    I/O and requires zero external services (no Redis, no real
    credentials) -- safe to run immediately after cloning."""
    upstream, _ledger = build_demo_actuator()
    audit_log_path = str(Path(tempfile.mkdtemp(prefix="mcc-external-pilot-demo-")) / "audit.jsonl")
    return build_external_pilot_app(
        proposals=InMemoryProposalRegistry(),
        idempotency=InMemoryIdempotencyRegistry(),
        nonces=InMemoryNonceRegistry(),
        tenants_credentials={"demo-key": "demo-tenant"},
        tenants_authority={"demo-tenant": {}},
        upstream=upstream,
        audit_log_path=audit_log_path,
        action=action,
    )


def build_app_from_env(*, upstream: Optional[ResourceBoundUpstream], action: str = ACTION,
                        env: Optional[Mapping[str, str]] = None) -> FastAPI:
    """Real-deployment entry point: reads credentials
    (``MCC_PROPOSAL_TENANTS`` -- reused, unchanged, from
    ``gateway.proposal_api.tenants_from_env``) and authority grants
    (``MCC_EXTERNAL_PILOT_AUTHORITY``, see ``authority_from_env`` above)
    from the environment; selects an in-memory or real Redis-backed
    durable-state backend via ``MCC_EXTERNAL_PILOT_BACKEND``
    (``memory`` default, or ``redis`` + ``MCC_REDIS_URL``). ``upstream``
    is deliberately NEVER read from the environment -- a real actuator is
    always a Python object the deployment constructs and passes in
    explicitly (see ``docs/EXTERNAL_PILOT_INTEGRATION.md`` "How to
    connect your actuator"); this function still fails closed
    (``ExternalPilotConfigError``) if it is not supplied.

    Missing/empty ``MCC_PROPOSAL_TENANTS`` or ``MCC_EXTERNAL_PILOT_AUTHORITY``
    are valid, explicit "zero clients"/"zero authority" configurations
    (empty dicts) -- never silently replaced by the demo credential/
    authority pair ``build_demo_app`` uses.
    """
    env = os.environ if env is None else env
    tenants_credentials = tenants_from_env(env)
    tenants_authority = authority_from_env(env)
    backend = (env.get("MCC_EXTERNAL_PILOT_BACKEND") or "memory").strip().lower()

    if backend == "redis":
        redis_url = (env.get("MCC_REDIS_URL") or "").strip()
        if not redis_url:
            raise ExternalPilotConfigError(
                "MCC_EXTERNAL_PILOT_BACKEND=redis requires MCC_REDIS_URL to be set -- fail closed"
            )
        import redis.asyncio as redis

        from mcc_core import RedisIdempotencyRegistry, RedisNonceRegistry
        from mcc_proposal import RedisProposalRegistry

        client_redis = redis.from_url(redis_url, decode_responses=True)
        proposals: Any = RedisProposalRegistry(client_redis, namespace="mcc:v1:external-pilot:proposal:")
        idempotency: Any = RedisIdempotencyRegistry(client_redis, namespace="mcc:idem:external-pilot:")
        nonces: Any = RedisNonceRegistry(client_redis, namespace="mcc:nonce:external-pilot:")
    elif backend == "memory":
        proposals = InMemoryProposalRegistry()
        idempotency = InMemoryIdempotencyRegistry()
        nonces = InMemoryNonceRegistry()
    else:
        raise ExternalPilotConfigError(
            f"MCC_EXTERNAL_PILOT_BACKEND must be 'memory' or 'redis', got {backend!r} -- fail closed"
        )

    audit_log_path = str(Path(tempfile.mkdtemp(prefix="mcc-external-pilot-")) / "audit.jsonl")
    return build_external_pilot_app(
        proposals=proposals, idempotency=idempotency, nonces=nonces,
        tenants_credentials=tenants_credentials, tenants_authority=tenants_authority,
        upstream=upstream, audit_log_path=audit_log_path, action=action,
    )


app = build_demo_app()


__all__ = [
    "ACTION", "ExternalPilotConfigError", "authority_from_env",
    "build_external_pilot_app", "build_demo_app", "build_app_from_env", "app",
]
