"""Shared, transport-agnostic backend abstraction every non-HTTP-native
adapter (MCP, LangGraph, CrewAI, AutoGen) reuses to reach
``MCCProposalService`` (Sections 12-13).

Two interchangeable backends, both pure translation — neither computes a
binding, evaluates a policy, infers a status, or executes anything:

* :class:`HttpProposalBackend` — the realistic deployment shape. The adapter
  runs as (or reaches) a separate process; it forwards the caller's
  credential to a real Gateway's ``/v1/proposals`` / ``/v1/operations/{id}``
  over HTTP (using the stdlib's ``urllib`` — no new dependency). This mirrors
  the Forward Architecture Rule already written for a future MCP adapter
  (CLAUDE.md §"MCP Adapter Boundary"): an ingress adapter reaches the
  platform only through the governed HTTP boundary, never by importing
  governance internals — and the same discipline applies to every other
  transport adapter here.

* :class:`InProcessProposalBackend` — for local development and the
  conformance suite: wraps an in-process ``MCCProposalService`` instance
  directly, with a small tenant map exactly like ``gateway.proposal_api``'s.
  Still zero business logic here: it calls the identical service methods
  every other adapter calls.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Protocol


class ProposalBackendError(Exception):
    """Raised when the backend cannot reach/parse a response from the
    underlying service. Callers must treat this as UNAVAILABLE, never as a
    successful or "not found" outcome."""


class ProposalBackend(Protocol):
    async def submit_proposal(self, *, credential: str, request: Dict[str, Any]) -> Dict[str, Any]: ...

    async def get_operation_status(self, *, credential: str, logical_operation_id: str) -> Dict[str, Any]: ...


class HttpProposalBackend:
    """Forwards to a real Gateway's Phase-1 HTTP endpoints. ``credential`` is
    whatever the MCP client supplied (an API key) — forwarded verbatim as
    ``x-api-key``; this module never inspects, maps, or resolves it to a
    tenant itself. The Gateway remains the sole authenticator."""

    def __init__(self, *, base_url: str, timeout_seconds: float = 10.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_seconds

    def _request(self, method: str, path: str, *, credential: str,
                body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = f"{self._base_url}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("x-api-key", credential)
        if data is not None:
            req.add_header("content-type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310 - trusted local gateway URL
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                detail = json.loads(exc.read().decode("utf-8"))
            except Exception:  # noqa: BLE001
                detail = {"detail": exc.reason}
            raise ProposalBackendError(f"gateway returned HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ProposalBackendError(f"gateway unreachable: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ProposalBackendError(f"gateway returned malformed JSON: {exc}") from exc

    async def submit_proposal(self, *, credential: str, request: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("POST", "/v1/proposals", credential=credential, body=request)

    async def get_operation_status(self, *, credential: str, logical_operation_id: str) -> Dict[str, Any]:
        from urllib.parse import quote

        path = f"/v1/operations/{quote(logical_operation_id, safe='')}"
        return self._request("GET", path, credential=credential)


class InProcessProposalBackend:
    """Local-development / conformance-suite backend: calls an in-process
    ``MCCProposalService`` directly. F1b: ``credential`` resolves through
    the hash-only per-agent registry (``agent_credentials``) to (tenant,
    principal), exactly as ``gateway.proposal_api.get_principal_dependency``
    does; the proposal is bound to that principal and its ``actor`` must
    equal it. A key only in the legacy ``tenants`` map (a shared tenant
    key) is refused unless ``identity_mode`` is explicitly
    ``legacy-shared-key``."""

    def __init__(self, *, service: Any, tenants: Optional[Dict[str, str]] = None,
                 agent_credentials: Any = None, identity_mode: Optional[str] = None) -> None:
        import os

        from mcc_core.agent_identity import agent_identity_mode_from_env
        self._service = service
        self._tenants = dict(tenants or {})
        self._registry = agent_credentials
        self._mode = identity_mode or agent_identity_mode_from_env(os.environ)

    def _identity(self, credential: str):
        from mcc_core.agent_identity import AGENT_IDENTITY_LEGACY
        if self._registry is not None and credential:
            res = self._registry.authenticate(credential)
            if res.agent is not None:
                return res.agent.tenant_id, res.agent.principal_id
            if res.error == "AGENT_CREDENTIAL_REVOKED":
                raise ProposalBackendError(res.error)
        tenant = self._tenants.get(credential)
        if not tenant:
            raise ProposalBackendError("INVALID_API_KEY")
        if self._mode != AGENT_IDENTITY_LEGACY:
            raise ProposalBackendError("AGENT_IDENTITY_REQUIRED")
        return tenant, None

    async def submit_proposal(self, *, credential: str, request: Dict[str, Any]) -> Dict[str, Any]:
        tenant, principal = self._identity(credential)
        if principal is not None and isinstance(request, dict) and request.get("actor") != principal:
            raise ProposalBackendError("AGENT_PRINCIPAL_MISMATCH")
        receipt = await self._service.submit_proposal(tenant_id=tenant, request=request,
                                                      principal_id=principal)
        return receipt.to_dict()

    async def get_operation_status(self, *, credential: str, logical_operation_id: str) -> Dict[str, Any]:
        tenant, principal = self._identity(credential)
        status = await self._service.get_operation_status(
            tenant_id=tenant, logical_operation_id=logical_operation_id, principal_id=principal,
        )
        return status.to_dict()


__all__ = ["ProposalBackendError", "ProposalBackend", "HttpProposalBackend", "InProcessProposalBackend"]
