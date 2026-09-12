"""HTTP transport for the MCC Universal Proposal Service (Phase 1).

Additive endpoints only — ``/evaluate`` and its existing semantics are
untouched (Section 11). This module performs authentication, deserialization,
transport-level shape validation, and response serialization ONLY: every
decision (accepted / idempotent duplicate / conflict / rejected /
unavailable) is made by :class:`mcc_proposal.MCCProposalService`, never here.

    POST /v1/proposals                        -> ProposalReceiptV1
    GET  /v1/operations/{logical_operation_id} -> OperationStatusV1

Both endpoints are informational/non-actuating: this router never calls the
Gate, the coordinator, a signing key, or any actuator.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Mapping, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from mcc_proposal import MCCProposalService
from mcc_proposal.models import MAX_PAYLOAD_BYTES

# Generous upper bound on the whole request body (payload bound + protocol
# overhead + headroom for the other fields) — Section 21 remote-ingress
# safety. Not a business limit; a deterministic rejection for a pathological
# caller.
MAX_REQUEST_BODY_BYTES = MAX_PAYLOAD_BYTES + 65_536


class ProposalTenantConfigError(Exception):
    """Raised when ``MCC_PROPOSAL_TENANTS`` is present but malformed
    (fail-closed: a misconfigured tenant map must refuse startup, never
    silently grant/deny access)."""


def tenants_from_env(env: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
    """``api_key -> tenant_id`` map, from ``MCC_PROPOSAL_TENANTS`` (a JSON
    object). Unset/empty -> no tenants configured -> every request is
    rejected (fail-closed default; no anonymous/default writer)."""
    env = os.environ if env is None else env
    raw = (env.get("MCC_PROPOSAL_TENANTS") or "").strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProposalTenantConfigError(f"MCC_PROPOSAL_TENANTS is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or not all(
        isinstance(k, str) and k.strip() and isinstance(v, str) and v.strip() for k, v in data.items()
    ):
        raise ProposalTenantConfigError(
            "MCC_PROPOSAL_TENANTS must be a JSON object of {api_key: tenant_id}, "
            "all non-empty strings"
        )
    return dict(data)


class ProposalRequestBody(BaseModel):
    # Strict at the top level, mirroring EvaluateRequest (gateway/app.py):
    # an unrecognized field is a rejection (422), not a silent no-op — the
    # HTTP-layer defense-in-depth half of the authority-bearing-field
    # rejection Section 10 requires (the service layer enforces it too, for
    # every adapter that does not have a strict schema of its own).
    model_config = ConfigDict(extra="forbid")

    logical_operation_id: str = Field(..., min_length=1)
    actor: str = Field(..., min_length=1)
    action: str = Field(..., min_length=1)
    resource: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)


async def _check_body_size(request: Request) -> None:
    """Best-effort remote-ingress bound (Section 21). Runs after FastAPI has
    already parsed the JSON body into ``ProposalRequestBody`` (a
    ``Content-Length``-based pre-parse rejection would need a custom ASGI
    middleware, which is more than this "thinnest sufficient" Phase-1
    transport needs at these bounds) -- it still deterministically rejects
    an oversized request with 413 rather than accepting it."""
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_REQUEST_BODY_BYTES:
                raise HTTPException(status_code=413, detail="REQUEST_TOO_LARGE")
        except ValueError:
            pass


def get_tenant_dependency(tenants: Dict[str, str]):
    """Build a FastAPI dependency resolving ``X-Api-Key`` to the ONE
    server-side-trusted tenant identity it maps to, via ``tenants``
    (``api_key -> tenant_id``). Tenant identity is never taken from the
    request body, a query parameter, or any other caller-supplied field —
    reused, unchanged, by every HTTP surface in this repository that needs
    the SAME trusted-credential-to-tenant resolution (``mount_proposal_routes``
    below, and ``gateway.proposal_execution_api.mount_proposal_execution_routes``).

    Missing, blank, and invalid credentials are ALL authentication failures
    and MUST all produce the SAME HTTP 401 — never 422. ``x_api_key`` is
    declared ``Optional[str] = Header(default=None)`` (not FastAPI's
    ``Header(...)``, required) precisely so an absent header never reaches
    FastAPI's own request-validation layer (which would otherwise reject it
    with 422 before this authentication boundary ever runs) — absence is
    handled explicitly, inside the authentication check itself, exactly
    like a blank or wrong value."""

    def get_tenant(x_api_key: Optional[str] = Header(default=None)) -> str:
        if not x_api_key:
            raise HTTPException(status_code=401, detail="INVALID_API_KEY")
        tenant = tenants.get(x_api_key)
        if not tenant:
            raise HTTPException(status_code=401, detail="INVALID_API_KEY")
        return tenant

    return get_tenant


def mount_proposal_routes(
    app: FastAPI, service: MCCProposalService, *, tenants: Dict[str, str],
) -> None:
    """Mount the two Phase-1 proposal endpoints onto an existing FastAPI app.
    ``tenants`` maps an authenticated API key to the tenant/security-domain
    identity that scopes every proposal — this identity is never taken from
    the request body."""

    get_tenant = get_tenant_dependency(tenants)

    @app.post("/v1/proposals")
    async def submit_proposal(
        body: ProposalRequestBody,
        request: Request,
        tenant: str = Depends(get_tenant),
    ) -> Dict[str, Any]:
        await _check_body_size(request)
        receipt = await service.submit_proposal(
            tenant_id=tenant,
            request={
                "logical_operation_id": body.logical_operation_id,
                "actor": body.actor,
                "action": body.action,
                "resource": body.resource,
                "payload": body.payload,
            },
        )
        return receipt.to_dict()

    @app.get("/v1/operations/{logical_operation_id}")
    async def get_operation_status(
        logical_operation_id: str, tenant: str = Depends(get_tenant),
    ) -> Dict[str, Any]:
        status = await service.get_operation_status(
            tenant_id=tenant, logical_operation_id=logical_operation_id,
        )
        return status.to_dict()


__all__ = [
    "mount_proposal_routes", "tenants_from_env", "ProposalTenantConfigError",
    "ProposalRequestBody", "get_tenant_dependency",
]
