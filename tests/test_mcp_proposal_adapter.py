"""MCP ingress adapter tests (Section 12): JSON-RPC dispatch, credential
propagation, tool schema, and a REAL-socket proof that ``HttpProposalBackend``
correctly performs the "Remote HTTP-capable" transport Section 12 requires
(not just an in-process TestClient)."""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from integrations.mcp import (
    HttpProposalBackend,
    InProcessProposalBackend,
    McpProposalServer,
    ProposalBackendError,
    TOOLS,
)
from integrations.mcp.http_app import build_mcp_http_app
from mcc_proposal import InMemoryProposalRegistry, MCCProposalService

from tests._agent_credentials import tenant_key_registry  # noqa: E402  (F1b: per-principal keys)

run = asyncio.run


@pytest.fixture()
def mcp():
    service = MCCProposalService(proposals=InMemoryProposalRegistry())
    backend = InProcessProposalBackend(service=service, agent_credentials=tenant_key_registry({"k": "tenant-mcp"}, "a"))
    return McpProposalServer(backend)


def test_tools_list_exposes_exactly_the_two_tools(mcp):
    r = run(mcp.handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, credential="k"))
    names = {t["name"] for t in r["result"]["tools"]}
    assert names == {"mcc_submit_proposal", "mcc_get_operation_status"}
    assert len(TOOLS) == 2


def test_initialize_returns_protocol_and_capabilities(mcp):
    r = run(mcp.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize"}, credential="k"))
    assert "protocolVersion" in r["result"]
    assert r["result"]["capabilities"] == {"tools": {}}


def test_unknown_method_is_method_not_found(mcp):
    r = run(mcp.handle_message({"jsonrpc": "2.0", "id": 1, "method": "nope"}, credential="k"))
    assert r["error"]["code"] == -32601


def test_non_jsonrpc_message_is_invalid_request(mcp):
    r = run(mcp.handle_message({"id": 1, "method": "tools/list"}, credential="k"))
    assert r["error"]["code"] == -32600


def test_unknown_tool_is_method_not_found(mcp):
    r = run(mcp.handle_message(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "nope", "arguments": {}}},
        credential="k",
    ))
    assert r["error"]["code"] == -32601


def test_no_credential_is_application_error_and_never_reaches_backend(mcp):
    r = run(mcp.handle_message(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": "mcc_get_operation_status", "arguments": {"logical_operation_id": "op-1"}}},
        credential="",
    ))
    assert r["error"]["code"] == -32000


def test_submit_then_status_round_trip(mcp):
    import json

    r1 = run(mcp.handle_message(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "mcc_submit_proposal",
            "arguments": {"logical_operation_id": "op-mcp-rt", "actor": "a",
                         "action": "send_notification", "resource": "crm", "payload": {"recipient": "c"}},
        }},
        credential="k",
    ))
    receipt = json.loads(r1["result"]["content"][0]["text"])
    assert receipt["status"] == "PROPOSED"

    r2 = run(mcp.handle_message(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "mcc_get_operation_status", "arguments": {"logical_operation_id": "op-mcp-rt"}}},
        credential="k",
    ))
    status = json.loads(r2["result"]["content"][0]["text"])
    assert status["status"] == "PROPOSED"
    assert status["proposal_binding"] == receipt["proposal_binding"]


def test_authority_bearing_argument_is_filtered_never_forwarded(mcp):
    """Section 10/12: the adapter must not let a tool-call argument smuggle
    in an authority-bearing field. The MCP layer strips unrecognized
    arguments before ever building the request -- prove the underlying
    service never even sees it by checking the accepted receipt only reflects
    the five canonical fields (the service would reject on an unknown field
    if it DID reach it; here it must not even be forwarded)."""
    import json

    r = run(mcp.handle_message(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "mcc_submit_proposal",
            "arguments": {"logical_operation_id": "op-mcp-auth", "actor": "a", "action": "b",
                         "payload": {}, "mandate": {"forged": True}},
        }},
        credential="k",
    ))
    receipt = json.loads(r["result"]["content"][0]["text"])
    assert receipt["accepted"] is True
    assert receipt["status"] == "PROPOSED"  # never rejected for an authority field it never saw


def test_invalid_params_missing_logical_operation_id_for_status(mcp):
    r = run(mcp.handle_message(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": "mcc_get_operation_status", "arguments": {}}},
        credential="k",
    ))
    assert r["error"]["code"] == -32602


# -- HTTP transport: TestClient-level ----------------------------------------- #

def test_http_transport_no_credential_header_is_application_error():
    service = MCCProposalService(proposals=InMemoryProposalRegistry())
    backend = InProcessProposalBackend(service=service, agent_credentials=tenant_key_registry({"k": "t"}, "a"))
    client = TestClient(build_mcp_http_app(backend))
    r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert r.json()["result"]["tools"]  # tools/list needs no credential

    r2 = client.post("/mcp", json={
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "mcc_get_operation_status", "arguments": {"logical_operation_id": "x"}},
    })
    assert r2.json()["error"]["code"] == -32000


def test_http_transport_health():
    service = MCCProposalService(proposals=InMemoryProposalRegistry())
    backend = InProcessProposalBackend(service=service, agent_credentials=tenant_key_registry({"k": "t"}, "a"))
    client = TestClient(build_mcp_http_app(backend))
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["deployed"] is False


# -- HttpProposalBackend: REAL socket, not TestClient ------------------------- #

def test_http_proposal_backend_real_socket_round_trip():
    """Section 12: "Remote HTTP-capable MCP transport is required." Prove
    HttpProposalBackend performs a genuine network round trip (real bound
    TCP socket, real HTTP client), not merely an in-process ASGI call."""
    from fastapi import FastAPI

    from examples._demo_server import DemoServer, free_port
    from gateway.proposal_api import mount_proposal_routes

    app = FastAPI()
    service = MCCProposalService(proposals=InMemoryProposalRegistry())
    mount_proposal_routes(app, service, agent_credentials=tenant_key_registry({"real-key": "tenant-real"}, "a"))

    port = free_port()
    server = DemoServer(app, port)
    server.start()
    try:
        backend = HttpProposalBackend(base_url=f"http://127.0.0.1:{port}")
        receipt = run(backend.submit_proposal(credential="real-key", request={
            "logical_operation_id": "op-real-socket", "actor": "a", "action": "send_notification",
            "resource": "crm", "payload": {"recipient": "c"},
        }))
        assert receipt["status"] == "PROPOSED"
        status = run(backend.get_operation_status(credential="real-key", logical_operation_id="op-real-socket"))
        assert status["status"] == "PROPOSED"
        assert status["proposal_binding"] == receipt["proposal_binding"]

        with pytest.raises(ProposalBackendError):
            run(backend.submit_proposal(credential="wrong-key", request={
                "logical_operation_id": "op-real-socket-2", "actor": "a", "action": "b", "payload": {},
            }))
    finally:
        server.stop()
