"""Reference HTTP client for the EXISTING PR #111 Pilot Execution API
(PR #113 -- External Pilot Integration Pack).

This is what ANY external integrator's code looks like from MCC's point
of view: an authenticated HTTP caller submitting a generic proposal, then
asking MCC to execute it. It is deliberately the ONLY way this package's
own scenarios/self-check reach execution -- there is no shortcut, no
direct import of ``ProposalExecutionService``, no direct import of
``EnforcementCoordinator``, no signing key, and no reference to any
actuator anywhere in this file (verified statically by
``tests/test_external_pilot_architecture_guards.py``).

Depends on ``httpx`` only -- a plain HTTP client library, not an agent
framework or model-provider SDK. Does NOT import or require:
OpenAI SDK, Anthropic SDK, LangGraph, CrewAI, AutoGen, VoltAgent, MCP, or
any GitHub-specific library. An integrator may use any HTTP client in any
language; this module is a convenience reference, not a required
dependency of the protocol itself.

Trusted vs. untrusted, from this client's own point of view:

* ``api_key`` -- what authenticates THIS caller to MCC; MCC resolves it,
  server-side, to a trusted tenant identity (``X-Api-Key`` header). This
  client never sees, computes, or needs to know that tenant_id.
* Everything this client sends (``actor``, ``action``, ``resource``,
  ``payload``) is UNTRUSTED input from MCC's point of view -- it is a
  proposal, not a permission (``PROPOSAL != PERMISSION``). MCC's own
  trusted authority evaluation, signed token issuance, and controlled
  actuator dispatch happen entirely server-side, after this client's HTTP
  call has already returned.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx


@dataclass(frozen=True)
class ProposalSubmission:
    logical_operation_id: str
    actor: str
    action: str
    resource: Optional[str]
    payload: Dict[str, Any]


class MCCPilotClientError(Exception):
    """Raised for a transport-level failure (connection error, timeout) --
    never raised for a governed HTTP response (DENIED/BLOCKED/etc.), which
    this client returns as a plain, inspectable dict; only MCC's trusted
    server-side authority evaluation decides ALLOW/DENY/execute, never
    this client."""


class MCCPilotClient:
    """Thin, real-HTTP client for ``POST /v1/proposals``,
    ``GET /v1/operations/{id}``, and ``POST /v1/operations/{id}/execute``
    -- the EXISTING, unmodified PR #111 routes. Every call in this class
    is a genuine HTTP request/response cycle; nothing here calls into
    MCC-Core, ``gateway.proposal_execution_service``, or any actuator.

    ``transport`` is accepted so the SAME client class can be pointed at
    either a real TCP socket (``httpx.AsyncClient(base_url=...)``, the
    fresh-clone quick-start / self-check) or an in-process ASGI transport
    (``httpx.AsyncClient(transport=httpx.ASGITransport(app=app), ...)``,
    used by this pack's own pytest scenarios) -- both are genuine HTTP
    request/response cycles through FastAPI's real routing/dependency/
    validation layer; neither is a direct Python call into the governed
    service.
    """

    def __init__(self, *, base_url: str = "", client: Optional[httpx.AsyncClient] = None,
                 api_key: str, timeout: float = 15.0) -> None:
        if client is not None and base_url:
            raise ValueError("pass either base_url or an already-configured client, not both")
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(base_url=base_url, timeout=timeout)
        self._api_key = api_key

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    def _headers(self) -> Dict[str, str]:
        # The api_key is the ONLY credential this client ever presents --
        # never a signing key, never a bearer token minted by this client
        # itself.
        return {"x-api-key": self._api_key}

    async def submit_proposal(self, submission: ProposalSubmission) -> Dict[str, Any]:
        """``POST /v1/proposals``. Returns the raw response as
        ``{"status_code": int, "body": <parsed JSON or raw text>}`` --
        never raises for a governed rejection (422 REJECTED, 401
        unauthenticated, etc.); only for a transport failure."""
        try:
            r = await self._client.post(
                "/v1/proposals", headers=self._headers(),
                json={
                    "logical_operation_id": submission.logical_operation_id,
                    "actor": submission.actor,
                    "action": submission.action,
                    "resource": submission.resource,
                    "payload": submission.payload,
                },
            )
        except httpx.HTTPError as exc:
            raise MCCPilotClientError(f"transport failure submitting proposal: {exc!r}") from exc
        return {"status_code": r.status_code, "body": _safe_json(r)}

    async def execute(self, logical_operation_id: str) -> Dict[str, Any]:
        """``POST /v1/operations/{id}/execute``. This is the ONLY call in
        this client that can cause a real side effect -- and it causes
        one only if MCC's own trusted authority evaluation allows it;
        this client supplies no body, no action, no resource, no
        payload, and no authority of its own on this call at all."""
        try:
            r = await self._client.post(
                f"/v1/operations/{logical_operation_id}/execute", headers=self._headers(),
            )
        except httpx.HTTPError as exc:
            raise MCCPilotClientError(f"transport failure executing operation: {exc!r}") from exc
        return {"status_code": r.status_code, "body": _safe_json(r)}

    async def adversarial_execute_with_body(self, logical_operation_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
        """NOT part of the real integration surface -- ``execute`` above
        is the only method a well-behaved integrator ever needs, and it
        takes no body for exactly this reason. This method exists solely
        for scenario F (payload/action binding): it proves that even a
        caller who DOES attempt to smuggle a body onto the execute
        request (a different action, resource, payload, or a forged
        authority/decision/tenant_id field) has it silently ignored
        server-side -- the server's route handler has no body parameter
        to receive it at all, so this is a genuine adversarial probe, not
        a capability this client normally exposes."""
        try:
            r = await self._client.post(
                f"/v1/operations/{logical_operation_id}/execute", headers=self._headers(), json=body,
            )
        except httpx.HTTPError as exc:
            raise MCCPilotClientError(f"transport failure on adversarial execute probe: {exc!r}") from exc
        return {"status_code": r.status_code, "body": _safe_json(r)}

    async def get_status(self, logical_operation_id: str) -> Dict[str, Any]:
        """``GET /v1/operations/{id}``. Read-only; never causes a side
        effect."""
        try:
            r = await self._client.get(f"/v1/operations/{logical_operation_id}", headers=self._headers())
        except httpx.HTTPError as exc:
            raise MCCPilotClientError(f"transport failure reading operation status: {exc!r}") from exc
        return {"status_code": r.status_code, "body": _safe_json(r)}


def _safe_json(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return response.text


__all__ = ["MCCPilotClient", "MCCPilotClientError", "ProposalSubmission"]
