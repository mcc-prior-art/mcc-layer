"""Shared harness: one ``MCCProposalService``, one tenant, one credential —
wrapped behind every adapter this repository supports, so cross-adapter
identity/parity tests submit through one adapter and observe through
another with no possibility of talking to two different backing stores.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Protocol

from fastapi import FastAPI
from fastapi.testclient import TestClient

from gateway.proposal_api import mount_proposal_routes
from integrations.mcp import InProcessProposalBackend, McpProposalServer
from integrations.mcp.http_app import build_mcp_http_app
from mcc_client import MCCClient
from mcc_client.transport import Transport
from mcc_proposal import MCCProposalService
from mcc_proposal.adapters import autogen, crewai, generic_http, langgraph

CREDENTIAL = "shared-key"
TENANT = "shared-tenant"
PRINCIPAL = "a"

run = asyncio.run


class ProposalAdapter(Protocol):
    """The one protocol every conformance-tested adapter implements."""

    name: str

    def submit(self, request: Dict[str, Any]) -> Dict[str, Any]: ...

    def status(self, logical_operation_id: str) -> Dict[str, Any]: ...


@dataclass
class SharedStack:
    service: MCCProposalService
    http_app: FastAPI
    http_client: TestClient
    mcp_app: FastAPI
    mcp_client: TestClient
    backend: InProcessProposalBackend


def build_shared_stack(*, durable_execution_state: Optional[Any] = None) -> SharedStack:
    from mcc_proposal import InMemoryProposalRegistry

    service = MCCProposalService(
        proposals=InMemoryProposalRegistry(), durable_execution_state=durable_execution_state,
    )
    # F1b: CREDENTIAL is ONE registered principal's own key (PRINCIPAL, the
    # actor every conformance request submits as) -- not a shared tenant key.
    from tests._agent_credentials import tenant_key_registry
    creds = tenant_key_registry({CREDENTIAL: TENANT}, PRINCIPAL)

    http_app = FastAPI()
    mount_proposal_routes(http_app, service, agent_credentials=creds)
    http_client = TestClient(http_app)

    backend = InProcessProposalBackend(service=service, agent_credentials=creds)
    mcp_app = build_mcp_http_app(backend)
    mcp_client = TestClient(mcp_app)

    return SharedStack(
        service=service, http_app=http_app, http_client=http_client,
        mcp_app=mcp_app, mcp_client=mcp_client, backend=backend,
    )


class _GenericHttpAdapter:
    name = "generic_http"

    def __init__(self, stack: SharedStack) -> None:
        self._client = stack.http_client

    def submit(self, request: Dict[str, Any]) -> Dict[str, Any]:
        r = self._client.post("/v1/proposals", json=request, headers={"x-api-key": CREDENTIAL})
        return r.json()

    def status(self, logical_operation_id: str) -> Dict[str, Any]:
        r = self._client.get(f"/v1/operations/{logical_operation_id}", headers={"x-api-key": CREDENTIAL})
        return r.json()


class _McpAdapter:
    name = "mcp"

    def __init__(self, stack: SharedStack) -> None:
        self._client = stack.mcp_client
        self._next_id = 0

    def _call(self, tool: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        import json

        self._next_id += 1
        msg = {"jsonrpc": "2.0", "id": self._next_id, "method": "tools/call",
               "params": {"name": tool, "arguments": arguments}}
        r = self._client.post("/mcp", json=msg, headers={"x-api-key": CREDENTIAL})
        data = r.json()
        assert "error" not in data, data
        text = data["result"]["content"][0]["text"]
        return json.loads(text)

    def submit(self, request: Dict[str, Any]) -> Dict[str, Any]:
        return self._call("mcc_submit_proposal", request)

    def status(self, logical_operation_id: str) -> Dict[str, Any]:
        return self._call("mcc_get_operation_status", {"logical_operation_id": logical_operation_id})


class _FacadeAdapter:
    """Wraps one of the framework-neutral facade modules
    (``mcc_proposal.adapters.{langgraph,crewai,autogen,generic_http}``)."""

    def __init__(self, name: str, module: Any, stack: SharedStack) -> None:
        self.name = name
        self._module = module
        self._backend = stack.backend

    def submit(self, request: Dict[str, Any]) -> Dict[str, Any]:
        return run(self._module.submit_proposal(
            self._backend, CREDENTIAL,
            logical_operation_id=request["logical_operation_id"], actor=request["actor"],
            action=request["action"], resource=request.get("resource"),
            payload=request.get("payload"),
        ))

    def status(self, logical_operation_id: str) -> Dict[str, Any]:
        return run(self._module.get_operation_status(
            self._backend, CREDENTIAL, logical_operation_id=logical_operation_id,
        ))


class _PythonSdkAdapter:
    name = "python_sdk"

    def __init__(self, stack: SharedStack) -> None:
        http_client = stack.http_client

        class _TestClientTransport(Transport):
            def __init__(self) -> None:  # noqa: D401 - deliberately skip the real Transport.__init__
                pass

            def post(self, path, body, *, operator=False, correlation_id=None, retry_safe=False):
                r = http_client.post(path, json=body, headers={"x-api-key": CREDENTIAL})
                return r.json()

            def get(self, path, *, params=None, correlation_id=None):
                r = http_client.get(path, headers={"x-api-key": CREDENTIAL})
                return r.json()

            def close(self) -> None:
                pass

        self._client = MCCClient("unused", transport=_TestClientTransport())

    def submit(self, request: Dict[str, Any]) -> Dict[str, Any]:
        return self._client.submit_proposal(
            logical_operation_id=request["logical_operation_id"], actor=request["actor"],
            action=request["action"], resource=request.get("resource"), payload=request.get("payload"),
        )

    def status(self, logical_operation_id: str) -> Dict[str, Any]:
        return self._client.get_operation_status(logical_operation_id)


def build_all_adapters(stack: SharedStack) -> Dict[str, ProposalAdapter]:
    """Every in-repo-testable adapter, all pointed at the SAME shared stack.
    (VoltAgent/TypeScript is verified separately — see
    ``test_voltagent_wire_contract_matches_python.py``.)"""
    return {
        "generic_http": _GenericHttpAdapter(stack),
        "mcp": _McpAdapter(stack),
        "langgraph": _FacadeAdapter("langgraph", langgraph, stack),
        "crewai": _FacadeAdapter("crewai", crewai, stack),
        "autogen": _FacadeAdapter("autogen", autogen, stack),
        "python_sdk": _PythonSdkAdapter(stack),
    }


__all__ = ["CREDENTIAL", "TENANT", "SharedStack", "build_shared_stack", "build_all_adapters", "ProposalAdapter"]
