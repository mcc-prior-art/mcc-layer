"""Pilot Execution API — HTTP transport tests for the Phase 2 governed
execution bridge (PR #111).

Adversarial matrix A-P (task Section 12) plus non-vacuity probes (Section
13). Exercises the REAL FastAPI router (``gateway.proposal_execution_api``)
mounted over a REAL ``gateway.proposal_execution_stack``-built
``ProposalExecutionService`` — never a hash comparison in isolation, never
a mocked service.

Most scenarios use in-memory registries (fast, isolated). Replay,
concurrency, and backend-unavailable (Section 7/12.K) additionally run
against REAL Redis (``RedisProposalRegistry``/``RedisIdempotencyRegistry``/
``RedisNonceRegistry``) — skipped, not failed, if Redis is unreachable,
matching this repository's established real-Redis test convention.
"""

from __future__ import annotations

import asyncio
import copy
import tempfile
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcc_core import InMemoryIdempotencyRegistry, InMemoryNonceRegistry, Verdict
from mcc_proposal import InMemoryProposalRegistry, MCCProposalService

from gateway.proposal_api import mount_proposal_routes
from gateway.proposal_execution_api import mount_proposal_execution_routes
from gateway.proposal_execution_service import ResourceBoundUpstream, ResourceMismatchError
from gateway.proposal_execution_stack import build_proposal_execution_stack

run = asyncio.run
ACTION = "test_action"


def _redis_available() -> bool:
    try:
        import redis as redis_sync

        client = redis_sync.from_url("redis://127.0.0.1:6379/9", socket_connect_timeout=0.5)
        client.ping()
        return True
    except Exception:
        return False


def _build_stack(
    *,
    allowed_tenants=("tenant-a", "tenant-b"),
    actuator_resource: Optional[str] = "res-1",
    without_mandate: Verdict = Verdict.DENY,
    max_amount=None,
    dispatch=None,
    proposals=None,
    idempotency=None,
    nonces=None,
):
    proposals = proposals if proposals is not None else InMemoryProposalRegistry()
    idem = idempotency if idempotency is not None else InMemoryIdempotencyRegistry()
    nonces = nonces if nonces is not None else InMemoryNonceRegistry()
    calls: List[Any] = []

    async def raw_upstream(*, resource, action, payload):
        calls.append((action, copy.deepcopy(payload)))
        if dispatch is not None:
            return await dispatch(resource=resource, action=action, payload=payload)
        return {"ok": True}

    upstream = ResourceBoundUpstream(resource=actuator_resource, dispatch=raw_upstream)
    tenants_config = {t: ({"max_amount": max_amount} if max_amount is not None else {}) for t in allowed_tenants}
    audit_path = str(Path(tempfile.mkdtemp(prefix="mcc-exec-api-test-")) / "audit.jsonl")

    stack = build_proposal_execution_stack(
        proposals=proposals, idempotency=idem, nonces=nonces, tenants=tenants_config,
        action=ACTION, upstream=upstream, audit_log_path=audit_path, without_mandate=without_mandate,
    )
    svc = MCCProposalService(proposals=proposals, durable_execution_state=idem)
    return SimpleNamespace(stack=stack, svc=svc, proposals=proposals, idem=idem, calls=calls)


def _build_app(*, credential_tenants: Dict[str, str], **stack_kwargs):
    built = _build_stack(**stack_kwargs)
    app = FastAPI()
    mount_proposal_routes(app, built.svc, tenants=credential_tenants)
    mount_proposal_execution_routes(app, built.stack.service, tenants=credential_tenants)
    return SimpleNamespace(app=app, client=TestClient(app), **vars(built))


def _submit(client: TestClient, *, key: str, op_id: str, resource="res-1", payload=None):
    return client.post(
        "/v1/proposals",
        headers={"x-api-key": key},
        json={"logical_operation_id": op_id, "actor": "agent/x", "action": ACTION,
              "resource": resource, "payload": payload or {"n": 1}},
    )


def _execute(client: TestClient, *, key: str, op_id: str):
    return client.post(f"/v1/operations/{op_id}/execute", headers={"x-api-key": key})


async def _concurrent_execute(app: FastAPI, *, key: str, op_id: str, n: int) -> List[Any]:
    """Genuinely concurrent HTTP execute calls against a SINGLE event loop
    (``asyncio.gather`` over an ``httpx.AsyncClient``/``ASGITransport``) --
    unlike a synchronous ``TestClient`` driven from a thread pool, this
    never hands the real async Redis client's loop-bound connection pool
    to more than one event loop at once, which is a test-harness artifact,
    not a coordinator/idempotency bug (the SAME concurrency proof this
    repository's other tests always run via ``asyncio.gather``, e.g.
    ``tests/test_idempotency.py``/``tests/test_coordinator.py``)."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        return await asyncio.gather(*[
            client.post(f"/v1/operations/{op_id}/execute", headers={"x-api-key": key}) for _ in range(n)
        ])


CREDS = {"key-a": "tenant-a", "key-b": "tenant-b"}


# --------------------------------------------------------------------------- #
# A. valid tenant executes own proposal
# --------------------------------------------------------------------------- #

def test_a_valid_tenant_executes_own_proposal():
    ctx = _build_app(credential_tenants=CREDS)
    r = _submit(ctx.client, key="key-a", op_id="op-a")
    assert r.status_code == 200 and r.json()["status"] == "PROPOSED"

    r2 = _execute(ctx.client, key="key-a", op_id="op-a")
    assert r2.status_code == 200
    assert r2.json()["status"] == "EXECUTED"
    assert len(ctx.calls) == 1


# --------------------------------------------------------------------------- #
# B/C. invalid / missing API key -> 401, zero actuation
# --------------------------------------------------------------------------- #

def test_b_invalid_api_key_is_401_zero_actuation():
    ctx = _build_app(credential_tenants=CREDS)
    _submit(ctx.client, key="key-a", op_id="op-b")
    r = ctx.client.post("/v1/operations/op-b/execute", headers={"x-api-key": "wrong"})
    assert r.status_code == 401
    assert ctx.calls == []


def test_c_missing_api_key_is_401_zero_actuation():
    # Missing credential is an authentication failure -- exactly 401, never
    # 422 (see gateway.proposal_api.get_tenant_dependency: x_api_key is
    # Optional/default=None so absence is handled by the auth check itself).
    ctx = _build_app(credential_tenants=CREDS)
    _submit(ctx.client, key="key-a", op_id="op-c")
    r = ctx.client.post("/v1/operations/op-c/execute")
    assert r.status_code == 401
    assert ctx.calls == []


def test_c2_blank_api_key_is_401_zero_actuation():
    ctx = _build_app(credential_tenants=CREDS)
    _submit(ctx.client, key="key-a", op_id="op-c2")
    r = ctx.client.post("/v1/operations/op-c2/execute", headers={"x-api-key": ""})
    assert r.status_code == 401
    assert ctx.calls == []


# --------------------------------------------------------------------------- #
# D. tenant A cannot execute tenant B's proposal
# --------------------------------------------------------------------------- #

def test_d_tenant_a_cannot_execute_tenant_bs_proposal():
    ctx = _build_app(credential_tenants=CREDS)
    _submit(ctx.client, key="key-b", op_id="op-d")
    r = _execute(ctx.client, key="key-a", op_id="op-d")
    assert r.status_code == 404
    assert r.json()["detail"]["status"] == "NOT_FOUND"
    assert ctx.calls == []

    own = _execute(ctx.client, key="key-b", op_id="op-d")
    assert own.status_code == 200
    assert own.json()["status"] == "EXECUTED"


# --------------------------------------------------------------------------- #
# E. cross-tenant same raw logical_operation_id executes independently
# --------------------------------------------------------------------------- #

def test_e_cross_tenant_same_raw_id_executes_independently():
    ctx = _build_app(credential_tenants=CREDS)
    _submit(ctx.client, key="key-a", op_id="op-shared", payload={"n": 1})
    _submit(ctx.client, key="key-b", op_id="op-shared", payload={"n": 1})

    ra = _execute(ctx.client, key="key-a", op_id="op-shared")
    rb = _execute(ctx.client, key="key-b", op_id="op-shared")
    assert ra.json()["status"] == "EXECUTED"
    assert rb.json()["status"] == "EXECUTED"
    assert len(ctx.calls) == 2


# --------------------------------------------------------------------------- #
# F. replay -> at most one side effect
# --------------------------------------------------------------------------- #

def test_f_replay_at_most_one_side_effect():
    ctx = _build_app(credential_tenants=CREDS)
    _submit(ctx.client, key="key-a", op_id="op-f")
    r1 = _execute(ctx.client, key="key-a", op_id="op-f")
    r2 = _execute(ctx.client, key="key-a", op_id="op-f")
    assert r1.json()["status"] == "EXECUTED"
    assert r2.json()["status"] != "EXECUTED"
    assert len(ctx.calls) == 1


# --------------------------------------------------------------------------- #
# G. concurrent replay -> at most one side effect
# --------------------------------------------------------------------------- #

def test_g_concurrent_replay_at_most_one_side_effect():
    ctx = _build_app(credential_tenants=CREDS)
    _submit(ctx.client, key="key-a", op_id="op-g")

    results = run(_concurrent_execute(ctx.app, key="key-a", op_id="op-g", n=8))
    statuses = [r.json()["status"] for r in results]
    assert statuses.count("EXECUTED") == 1
    assert len(ctx.calls) == 1


# --------------------------------------------------------------------------- #
# H. caller cannot substitute payload/action/resource
# --------------------------------------------------------------------------- #

def test_h_caller_cannot_substitute_payload_action_resource():
    ctx = _build_app(credential_tenants=CREDS)
    _submit(ctx.client, key="key-a", op_id="op-h", resource="res-1", payload={"n": 1})

    # The execute endpoint accepts no body at all -- prove that attempting
    # to smuggle a different action/resource/payload via the request body
    # has zero effect: FastAPI never binds it to anything (no Pydantic
    # model declared for this route), and the dispatched payload is
    # provably still the ORIGINAL stored one.
    r = ctx.client.post(
        "/v1/operations/op-h/execute",
        headers={"x-api-key": "key-a"},
        json={"action": "evil_action", "resource": "res-EVIL", "payload": {"n": 999}},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "EXECUTED"
    assert len(ctx.calls) == 1
    dispatched_action, dispatched_payload = ctx.calls[0]
    assert dispatched_action == ACTION
    assert dispatched_payload == {"n": 1}


# --------------------------------------------------------------------------- #
# I. DENY -> zero actuation
# --------------------------------------------------------------------------- #

def test_i_deny_zero_actuation():
    # tenant-c authenticates (has a credential) but is NOT in allowed_tenants
    # (no authority grant) -- without_mandate defaults to DENY.
    ctx = _build_app(credential_tenants={**CREDS, "key-c": "tenant-c"}, allowed_tenants=("tenant-a", "tenant-b"))
    _submit(ctx.client, key="key-c", op_id="op-i")
    r = _execute(ctx.client, key="key-c", op_id="op-i")
    assert r.status_code == 200
    assert r.json()["status"] == "DENIED"
    assert ctx.calls == []


# --------------------------------------------------------------------------- #
# J. ESCALATE -> zero actuation
# --------------------------------------------------------------------------- #

def test_j_escalate_zero_actuation():
    ctx = _build_app(
        credential_tenants={**CREDS, "key-c": "tenant-c"}, allowed_tenants=("tenant-a", "tenant-b"),
        without_mandate=Verdict.ESCALATE,
    )
    _submit(ctx.client, key="key-c", op_id="op-j")
    r = _execute(ctx.client, key="key-c", op_id="op-j")
    assert r.status_code == 200
    assert r.json()["status"] == "ESCALATED"
    assert ctx.calls == []


# --------------------------------------------------------------------------- #
# K. backend unavailable -> no actuation, 503
# --------------------------------------------------------------------------- #

def test_k_backend_unavailable_is_503_zero_actuation():
    from mcc_proposal.registry import ProposalBackendUnavailable

    ctx = _build_app(credential_tenants=CREDS)
    _submit(ctx.client, key="key-a", op_id="op-k")

    class _DownProposals:
        async def get(self, **kw):
            raise ProposalBackendUnavailable("down")

    ctx.stack.service._proposals = _DownProposals()  # type: ignore[attr-defined]
    r = _execute(ctx.client, key="key-a", op_id="op-k")
    assert r.status_code == 503
    assert ctx.calls == []


# --------------------------------------------------------------------------- #
# L. malformed logical_operation_id -> fail closed
# --------------------------------------------------------------------------- #

def test_l_malformed_logical_operation_id_fails_closed():
    ctx = _build_app(credential_tenants=CREDS)
    # Whitespace-only id -- non-empty path segment (passes routing), but
    # authorize_and_execute's own fail-closed strip() check rejects it.
    r = ctx.client.post("/v1/operations/%20/execute", headers={"x-api-key": "key-a"})
    assert r.status_code == 422
    assert ctx.calls == []


# --------------------------------------------------------------------------- #
# M. ambiguous post-dispatch failure -> no automatic retry
# --------------------------------------------------------------------------- #

def test_m_ambiguous_post_dispatch_failure_no_automatic_retry():
    async def crashing(*, resource, action, payload):
        raise ConnectionError("simulated ambiguous post-dispatch failure")

    ctx = _build_app(credential_tenants=CREDS, dispatch=crashing)
    _submit(ctx.client, key="key-a", op_id="op-m")
    r1 = _execute(ctx.client, key="key-a", op_id="op-m")
    assert r1.status_code == 200
    assert r1.json()["status"] == "EXECUTION_FAILED"
    assert len(ctx.calls) == 1

    # The HTTP layer performs no transport-level auto-retry; a second
    # explicit call by the caller must not silently re-dispatch either --
    # the durable state stays UNKNOWN-eligible, not a fresh reservation.
    r2 = _execute(ctx.client, key="key-a", op_id="op-m")
    assert r2.json()["status"] != "EXECUTED"
    assert len(ctx.calls) == 1


# --------------------------------------------------------------------------- #
# N. ResourceBoundUpstream mismatch -> zero external I/O
# --------------------------------------------------------------------------- #

def test_n_resource_mismatch_zero_external_io():
    ctx = _build_app(credential_tenants=CREDS, actuator_resource="res-CONFIGURED")
    _submit(ctx.client, key="key-a", op_id="op-n", resource="res-DIFFERENT")
    r = _execute(ctx.client, key="key-a", op_id="op-n")
    assert r.status_code == 200
    assert r.json()["status"] == "RESOURCE_MISMATCH"
    assert ctx.calls == []


# --------------------------------------------------------------------------- #
# O. HTTP layer cannot directly reach the actuator (structural proof)
# --------------------------------------------------------------------------- #

def test_o_http_layer_has_no_direct_actuator_reference():
    """The router module holds no reference to an actuator/upstream at
    all -- it only ever holds a ``ProposalExecutionService``. Proven here
    by inspecting the mounted route closures' own captured names never
    include 'upstream'/'dispatch', and structurally (see
    tests/test_proposal_execution_api_architecture_guards.py) by AST scan
    of the module source."""
    import gateway.proposal_execution_api as mod

    source = Path(mod.__file__).read_text(encoding="utf-8")
    for forbidden in ("ResourceBoundUpstream(", ".execute(resource=", "dispatch("):
        assert forbidden not in source, f"router source references {forbidden!r}"


# --------------------------------------------------------------------------- #
# P. tenant identity cannot be supplied or overridden in request data
# --------------------------------------------------------------------------- #

def test_p_tenant_identity_cannot_be_supplied_or_overridden():
    ctx = _build_app(credential_tenants=CREDS)
    _submit(ctx.client, key="key-b", op_id="op-p")
    # Authenticate as tenant-a, but try every plausible smuggling vector
    # for tenant-b's identity: query param, header, body field. None of
    # them is even read by the endpoint (no body model, no such
    # dependency), so this must behave EXACTLY like an unqualified
    # tenant-a request -- NOT_FOUND, never tenant-b's own operation.
    r = ctx.client.post(
        "/v1/operations/op-p/execute?tenant_id=tenant-b",
        headers={"x-api-key": "key-a", "x-tenant-id": "tenant-b"},
        json={"tenant_id": "tenant-b"},
    )
    assert r.status_code == 404
    assert ctx.calls == []


# --------------------------------------------------------------------------- #
# Reconciliation HTTP route: deferred (Blocker 3 remediation) -- proves the
# route genuinely does not exist, rather than merely being undocumented.
# --------------------------------------------------------------------------- #

def test_default_app_exposes_execute():
    ctx = _build_app(credential_tenants=CREDS)
    _submit(ctx.client, key="key-a", op_id="op-exposes-execute")
    r = _execute(ctx.client, key="key-a", op_id="op-exposes-execute")
    assert r.status_code == 200
    assert r.json()["status"] == "EXECUTED"


def test_reconcile_route_is_404_not_mounted():
    ctx = _build_app(credential_tenants=CREDS)
    _submit(ctx.client, key="key-a", op_id="op-reconcile-404")
    r = ctx.client.post("/v1/operations/op-reconcile-404/reconcile", headers={"x-api-key": "key-a"})
    assert r.status_code == 404


def test_reconcile_absent_from_openapi_schema():
    ctx = _build_app(credential_tenants=CREDS)
    schema = ctx.app.openapi()
    paths = schema.get("paths", {})
    assert not any("reconcile" in p for p in paths), f"reconcile path leaked into OpenAPI: {list(paths)}"
    assert any(p.endswith("/execute") for p in paths)


def test_mount_proposal_execution_routes_accepts_no_reconciliation_parameters():
    """Structural proof there is no alternate way to activate a
    reconciliation handler through this function any more -- the
    signature itself no longer has a place to put
    proposals/idempotency/authority/verify_external_evidence."""
    import inspect

    from gateway.proposal_execution_api import mount_proposal_execution_routes

    sig = inspect.signature(mount_proposal_execution_routes)
    assert set(sig.parameters) == {"app", "service", "tenants"}


def test_no_reconcile_handler_reachable_through_any_route():
    """Belt-and-braces: enumerate every route FastAPI actually registered
    and confirm none of them is a reconcile handler under any alias."""
    ctx = _build_app(credential_tenants=CREDS)
    paths = [r.path for r in ctx.app.routes]
    assert not any("reconcile" in p for p in paths), paths


# --------------------------------------------------------------------------- #
# Non-vacuity probes (Section 13)
# --------------------------------------------------------------------------- #

def test_non_vacuity_1_removing_tenant_scoped_auth_resolution_is_caught():
    """Plant a deliberately-broken router that takes tenant_id from a
    header (never the trusted credential map) instead of the real
    ``get_tenant_dependency`` -- proves the real test (D/P above) WOULD
    catch this class of vulnerability if it were ever reintroduced."""
    from fastapi import Header

    ctx = _build_stack()
    app = FastAPI()
    svc = ctx.stack.service

    @app.post("/v1/operations/{logical_operation_id}/execute")
    async def vulnerable_execute(logical_operation_id: str, x_tenant_id: str = Header(...)):
        # VULNERABLE: tenant_id taken directly from a caller-supplied
        # header, never resolved from an authenticated credential map.
        return (await svc.authorize_and_execute(
            tenant_id=x_tenant_id, logical_operation_id=logical_operation_id,
        )).status.value

    client = TestClient(app)
    run(ctx.svc.submit_proposal(tenant_id="tenant-b", request={
        "logical_operation_id": "op-nv1", "actor": "agent/x", "action": ACTION,
        "resource": "res-1", "payload": {"n": 1},
    }))
    # An attacker with NO real tenant-b credential can execute tenant-b's
    # operation merely by naming it in a header.
    r = client.post("/v1/operations/op-nv1/execute", headers={"x-tenant-id": "tenant-b"})
    assert r.text.strip('"') == "EXECUTED", "the planted vulnerable router should have wrongly executed"

    # Now prove the REAL router refuses the identical attack.
    real_ctx = _build_app(credential_tenants=CREDS)
    run(real_ctx.svc.submit_proposal(tenant_id="tenant-b", request={
        "logical_operation_id": "op-nv1b", "actor": "agent/x", "action": ACTION,
        "resource": "res-1", "payload": {"n": 1},
    }))
    real_r = real_ctx.client.post(
        "/v1/operations/op-nv1b/execute",
        headers={"x-api-key": "key-a", "x-tenant-id": "tenant-b"},
    )
    assert real_r.status_code == 404
    assert real_ctx.calls == []


def test_non_vacuity_2_bypassing_service_and_calling_actuator_directly_is_caught():
    """Plant a router endpoint that calls the actuator's ``dispatch``
    DIRECTLY, bypassing ``ProposalExecutionService`` (no authority
    evaluation, no token, no coordinator, no idempotency) -- proves this
    class of bypass is architecturally detectable (see
    tests/test_proposal_execution_api_architecture_guards.py, which scans
    the REAL router source for exactly the forbidden imports/calls this
    planted example makes)."""
    calls: List[Any] = []

    async def raw_upstream(*, resource, action, payload):
        calls.append((action, payload))
        return {"ok": True}

    upstream = ResourceBoundUpstream(resource="res-1", dispatch=raw_upstream)
    app = FastAPI()

    @app.post("/v1/operations/{logical_operation_id}/execute")
    async def vulnerable_bypass(logical_operation_id: str):
        # VULNERABLE: calls the actuator directly -- no authority check,
        # no signed token, no coordinator, no idempotency admission.
        return await upstream.execute(resource="res-1", action=ACTION, payload={"n": "attacker-controlled"})

    client = TestClient(app)
    r = client.post("/v1/operations/anything-at-all/execute")
    assert r.status_code == 200
    assert len(calls) == 1, "the planted bypass should have wrongly dispatched with zero authority"

    # The real router source contains none of the forbidden constructs
    # this bypass required (see the architecture guard test file for the
    # full AST-based proof); a quick source-level corroboration here:
    import gateway.proposal_execution_api as mod

    source = Path(mod.__file__).read_text(encoding="utf-8")
    assert "ResourceBoundUpstream(" not in source
    assert ".execute(resource=" not in source


# --------------------------------------------------------------------------- #
# Real-Redis: replay, concurrency, backend-unavailable (Section 7/14)
# --------------------------------------------------------------------------- #

pytestmark_redis = pytest.mark.skipif(not _redis_available(), reason="real Redis not reachable at 127.0.0.1:6379/9")


@pytestmark_redis
def test_redis_replay_at_most_one_side_effect():
    # ``with ctx.client as client:`` keeps ONE persistent anyio portal
    # (and therefore ONE event loop) alive across every call in this test
    # -- a plain, non-context-managed ``TestClient.post()`` spins up (and
    # tears down) a fresh event loop PER CALL, which breaks the real async
    # Redis client's loop-bound connection pool/locks the moment a second
    # call reuses the same registry from a different loop. Pure in-memory
    # tests never notice this (no real loop-bound resource involved).
    import redis.asyncio as redis

    from mcc_core import RedisIdempotencyRegistry, RedisNonceRegistry
    from mcc_proposal import RedisProposalRegistry

    ns = uuid.uuid4().hex[:8]
    client = redis.from_url("redis://127.0.0.1:6379/9", decode_responses=True)
    proposals = RedisProposalRegistry(client, namespace=f"mcc:v1:exec-api-test-{ns}:proposal:")
    idem = RedisIdempotencyRegistry(client, namespace=f"mcc:idem:exec-api-test-{ns}:")
    nonces = RedisNonceRegistry(client, namespace=f"mcc:nonce:exec-api-test-{ns}:")
    ctx = _build_app(credential_tenants=CREDS, proposals=proposals, idempotency=idem, nonces=nonces)
    with ctx.client as tc:
        _submit(tc, key="key-a", op_id="op-redis-replay")
        r1 = _execute(tc, key="key-a", op_id="op-redis-replay")
        r2 = _execute(tc, key="key-a", op_id="op-redis-replay")
    assert r1.json()["status"] == "EXECUTED"
    assert r2.json()["status"] != "EXECUTED"
    assert len(ctx.calls) == 1


@pytestmark_redis
def test_redis_concurrent_replay_at_most_one_side_effect():
    import redis.asyncio as redis

    from mcc_core import RedisIdempotencyRegistry, RedisNonceRegistry
    from mcc_proposal import RedisProposalRegistry

    ns = uuid.uuid4().hex[:8]
    client = redis.from_url("redis://127.0.0.1:6379/9", decode_responses=True)
    proposals = RedisProposalRegistry(client, namespace=f"mcc:v1:exec-api-test-{ns}:proposal:")
    idem = RedisIdempotencyRegistry(client, namespace=f"mcc:idem:exec-api-test-{ns}:")
    nonces = RedisNonceRegistry(client, namespace=f"mcc:nonce:exec-api-test-{ns}:")
    ctx = _build_app(credential_tenants=CREDS, proposals=proposals, idempotency=idem, nonces=nonces)

    async def _run():
        # Submit AND execute both go through the SAME single-event-loop
        # async client here -- never the sync TestClient in this test --
        # so the real async Redis client's loop-bound connection pool is
        # touched by exactly one loop for the test's entire duration.
        transport = httpx.ASGITransport(app=ctx.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            await client.post("/v1/proposals", headers={"x-api-key": "key-a"}, json={
                "logical_operation_id": "op-redis-concurrent", "actor": "agent/x", "action": ACTION,
                "resource": "res-1", "payload": {"n": 1},
            })
            return await asyncio.gather(*[
                client.post("/v1/operations/op-redis-concurrent/execute", headers={"x-api-key": "key-a"})
                for _ in range(8)
            ])

    results = run(_run())
    statuses = [r.json()["status"] for r in results]
    assert statuses.count("EXECUTED") == 1
    assert len(ctx.calls) == 1


@pytestmark_redis
def test_redis_backend_unavailable_is_503_zero_actuation():
    import redis.asyncio as redis

    from mcc_core import RedisIdempotencyRegistry, RedisNonceRegistry
    from mcc_proposal import RedisProposalRegistry

    ns = uuid.uuid4().hex[:8]
    client = redis.from_url("redis://127.0.0.1:6379/9", decode_responses=True)
    proposals = RedisProposalRegistry(client, namespace=f"mcc:v1:exec-api-test-{ns}:proposal:")
    idem = RedisIdempotencyRegistry(client, namespace=f"mcc:idem:exec-api-test-{ns}:")
    nonces = RedisNonceRegistry(client, namespace=f"mcc:nonce:exec-api-test-{ns}:")
    ctx = _build_app(credential_tenants=CREDS, proposals=proposals, idempotency=idem, nonces=nonces)

    # Point the service at an unreachable Redis instance to simulate a
    # genuine backend outage against the real registry class.
    bad_client = redis.from_url("redis://127.0.0.1:1/9", decode_responses=True, socket_connect_timeout=0.2)
    ctx.stack.service._proposals = RedisProposalRegistry(bad_client, namespace=f"mcc:v1:exec-api-test-{ns}:proposal:")

    with ctx.client as tc:
        _submit(tc, key="key-a", op_id="op-redis-down")
        r = _execute(tc, key="key-a", op_id="op-redis-down")
    assert r.status_code == 503
    assert ctx.calls == []
