"""R1 remediation regression suite -- Human Approval Authorization Bypass.

R1 (internal red-team assessment, redteam/ at cb5bd33, cases V05 x1 + V16 x3):
an approval-minted mandate presented on ``POST /mandates/execute`` executed as
a standing grant. ``approval_id`` never reached the decision token, so the
coordinator never consumed the approval, and payload binding, single-use, and
operator invalidation were all skipped.

Invariant under test: an approval-minted mandate authorizes ONLY the exact
operation the human approved -- on EVERY execution route
(``/mandates/execute`` and ``/approvals/{id}/execute``).

Every negative test asserts on the actuator itself (``calls``): a bypass is
counted only when the upstream was actually invoked. Tests drive the real
FastAPI routes (``mount_mandate_routes`` / ``mount_approval_routes``) over the
real GovernanceService -> MandateAuthority -> DecisionEngine ->
EnforcementCoordinator -> ExecutionGate stack. One test additionally runs over
a real loopback TCP socket (embedded uvicorn), and the Redis tests use a real
Redis server (skipped -- never silently passed -- when none is reachable).
"""
from __future__ import annotations

import asyncio
import os
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcc_core import (
    ApprovalService,
    AuditLog,
    DecisionEngine,
    EnforcementCoordinator,
    ExecutionGate,
    InMemoryApprovalRegistry,
    InMemoryIdempotencyRegistry,
    InMemoryNonceRegistry,
    InMemoryRevocationRegistry,
    InMemoryVelocityRegistry,
    ProfileRegistry,
    SigningKey,
)
from mcc_core.approvals import RedisApprovalRegistry
from mcc_core.mandate import issue_mandate

from gateway.governance_api import mount_approval_routes, mount_mandate_routes
from gateway.governance_service import GovernanceService
from gateway.trust import TrustSet

POLICY = "sha256:" + "0" * 64
AGENT = {"x-api-key": "agent-key"}
OP = {"x-operator-key": "op-key"}
ACTOR = "agent/payments-bot"
ACTION = "send_payment"
RESOURCE = "acct-1"
TX = "tx-1"
REDIS_URL = os.environ.get("MCC_REDIS_URL", "redis://127.0.0.1:6379/0")


def payment(**overrides):
    # Canonical PaymentProfile form (float amount, upper-case currency) so the
    # approval's server-computed payload_hash matches the executed payload.
    ctx = {"source": RESOURCE, "beneficiary_id": "vendor-42", "amount": 100.0, "currency": "EUR"}
    ctx.update(overrides)
    return ctx


class Gateway:
    """One fully wired gateway exposed through the real HTTP routes."""

    def __init__(self, *, approval_registry=None, approver_key=None, coordinator_approvals=True):
        self.approver = approver_key or SigningKey.generate("mcc-approver-1")
        self.issuer = SigningKey.generate("treasury-1")
        self.trust = TrustSet()
        # Exactly the production wiring (governance_api.build_governance_service):
        # the approver key sits in the SAME trust set as ordinary mandate issuers.
        self.trust.add_runtime_issuer("mcc/approvals", self.approver.kid, self.approver.public_key())
        self.trust.add_runtime_issuer("issuer/treasury", self.issuer.kid, self.issuer.public_key())
        dk = SigningKey.generate("gw-1")
        engine = DecisionEngine(signing_key=dk, issuer="mcc/core", audience="gate",
                                policy_id="pilot/v1", policy_hash=POLICY, token_ttl_seconds=60)
        gate = ExecutionGate(trusted_keys={dk.kid: dk.public_key()}, audience="gate",
                             nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY)
        self.revocation = InMemoryRevocationRegistry()
        self.approvals = ApprovalService(approval_registry or InMemoryApprovalRegistry(), self.approver)
        self.audit_path = str(Path(tempfile.mkdtemp(prefix="mcc-r1-")) / "audit.jsonl")
        self.coordinator = EnforcementCoordinator(
            gate=gate, idempotency=InMemoryIdempotencyRegistry(),
            velocity=InMemoryVelocityRegistry(), audit=AuditLog(self.audit_path),
            profiles=ProfileRegistry.default_pilot(), revocation_registry=self.revocation,
            approvals=self.approvals if coordinator_approvals else None)
        self.calls: list = []
        self._lock = threading.Lock()

        async def upstream(action, payload):
            with self._lock:
                self.calls.append((action, dict(payload)))
            return {"ok": True}

        self.service = GovernanceService(
            engine=engine, coordinator=self.coordinator, trust_set=self.trust,
            revocation_registry=self.revocation, approvals=self.approvals,
            upstream=upstream, policy_hash=POLICY)
        self.app = FastAPI()
        mount_mandate_routes(self.app, self.service, api_key="agent-key", operator_key="op-key",
                             tenant_id="tenant-1")
        mount_approval_routes(self.app, self.service, api_key="agent-key", operator_key="op-key",
                              tenant_id="tenant-1")
        self.client = TestClient(self.app)

    # ---- HTTP helpers ----

    def request_approval(self, *, payload=None, transaction_id=TX, ttl_seconds=None, **kw):
        body = {"actor": ACTOR, "action": ACTION, "resource": RESOURCE,
                "transaction_id": transaction_id, "policy_hash": POLICY,
                "payload": payload or payment()}
        if ttl_seconds is not None:
            body["ttl_seconds"] = ttl_seconds
        body.update(kw)
        r = self.client.post("/approvals", headers=AGENT, json=body)
        assert r.status_code == 200, r.text
        return r.json()["request_id"]

    def approve(self, rid):
        r = self.client.post(f"/approvals/{rid}/approve", headers=OP)
        assert r.status_code == 200, r.text
        return r.json()["mandate"]

    def approved(self, **kw):
        rid = self.request_approval(**kw)
        return rid, self.approve(rid)

    def state(self, rid):
        return self.client.get(f"/approvals/{rid}", headers=AGENT).json()["state"]

    def body(self, mandate, *, context=None, transaction_id=TX, idem=None,
             actor=ACTOR, action=ACTION, resource=RESOURCE):
        return {"mandate": mandate, "actor": actor, "action": action, "resource": resource,
                "context": payment() if context is None else context,
                "transaction_id": transaction_id,
                "idempotency_key": idem or f"op-{uuid.uuid4().hex}"}

    def mandate_execute(self, mandate, **kw):
        r = self.client.post("/mandates/execute", headers=AGENT, json=self.body(mandate, **kw))
        assert r.status_code == 200, r.text
        return r.json()

    def approval_execute(self, rid, mandate, **kw):
        r = self.client.post(f"/approvals/{rid}/execute", headers=AGENT, json=self.body(mandate, **kw))
        assert r.status_code == 200, r.text
        return r.json()

    def standing_mandate(self, **overrides):
        now = int(time.time())
        kw = dict(issuer="issuer/treasury", subject=ACTOR, action_scope=[ACTION],
                  resource_scope=[RESOURCE], constraints={"max_amount": 5000},
                  not_before=now - 10, not_after=now + 3600, issued_at=now - 10,
                  policy_hash=POLICY,
                  # V05: bound to this gateway's mounted tenant (strict tenant mode).
                  tenant_id="tenant-1")
        kw.update(overrides)
        return issue_mandate(self.issuer, **kw)


ROUTES = ("mandate", "approval")


def run_route(gw, route, rid, mandate, **kw):
    if route == "mandate":
        return gw.mandate_execute(mandate, **kw)
    return gw.approval_execute(rid, mandate, **kw)


# ===========================================================================
# The four original R1 red-team cases, reproduced over HTTP
# ===========================================================================

def test_r1_v05_approval_obtained_by_a_executed_by_b_with_other_payload():
    """V05: A obtains human approval for 100 EUR -> vendor-42; a colluding
    agent presents that mandate on /mandates/execute for 1,000,000 EUR to
    attacker-acct under a different transaction."""
    gw = Gateway()
    rid, mandate = gw.approved()
    out = gw.mandate_execute(mandate, context=payment(amount=1_000_000.0, beneficiary_id="attacker-acct"),
                             transaction_id="tx-evil", idem="evil-1")
    assert out["status"] == "BLOCKED" and out["decision"] == "DENY", out
    assert gw.calls == []
    # The failed attack does not burn the legitimate approval.
    assert gw.state(rid) == "APPROVED"


def test_r1_v16_approval_mandate_on_mandate_route_other_payload():
    gw = Gateway()
    rid, mandate = gw.approved()
    out = gw.mandate_execute(mandate, context=payment(amount=1_000_000.0, beneficiary_id="attacker-acct"),
                             transaction_id="tx-x", idem="evil")
    assert out["status"] == "BLOCKED", out
    assert gw.calls == []


def test_r1_v16_approval_mandate_on_mandate_route_is_not_reusable():
    """Original attack varied transaction_id per attempt; here the
    transaction is held CORRECT so only single-use stands in the way."""
    gw = Gateway()
    rid, mandate = gw.approved()
    outs = [gw.mandate_execute(mandate, idem=f"again-{i}") for i in range(5)]
    assert [o["status"] for o in outs] == ["EXECUTED"] + ["BLOCKED"] * 4, outs
    assert len(gw.calls) == 1
    assert gw.state(rid) == "CONSUMED"
    # The original attack's exact shape (a new transaction_id each time).
    gw2 = Gateway()
    rid2, m2 = gw2.approved()
    for i in range(5):
        gw2.mandate_execute(m2, transaction_id=f"tx-other-{i}", idem=f"again-{i}")
    assert gw2.calls == []


def test_r1_v16_invalidated_approval_on_mandate_route():
    gw = Gateway()
    rid, mandate = gw.approved()
    assert gw.client.post(f"/approvals/{rid}/invalidate", headers=OP).status_code == 200
    out = gw.mandate_execute(mandate)
    assert out["status"] == "BLOCKED", out
    assert "INVALIDATED" in out["reason"]
    assert gw.calls == []


# ===========================================================================
# Post-approval modification, on BOTH routes
# ===========================================================================

@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("change", [
    {"amount": 1_000_000.0},
    {"amount": 100.01},
    {"amount": -100.0},
    {"beneficiary_id": "attacker-acct"},
    {"currency": "USD"},
    {"source": "acct-other"},
    {"memo": "extra field smuggled after approval"},
], ids=["amount-up", "amount-cent", "amount-negative", "recipient", "currency", "source", "extra-field"])
def test_modified_payload_after_approval_blocked(route, change):
    gw = Gateway()
    rid, mandate = gw.approved()
    out = run_route(gw, route, rid, mandate, context=payment(**change))
    assert out["status"] == "BLOCKED", out
    assert gw.calls == []
    assert gw.state(rid) == "APPROVED"   # untouched: still usable for the approved operation
    ok = run_route(gw, route, rid, mandate)
    assert ok["status"] == "EXECUTED" and gw.calls == [(ACTION, payment())]


@pytest.mark.parametrize("route", ROUTES)
def test_changed_action_blocked(route):
    gw = Gateway()
    rid, mandate = gw.approved()
    out = run_route(gw, route, rid, mandate, action="pay_vendor")
    assert out["status"] == "BLOCKED", out
    assert gw.calls == []


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("field,value", [("transaction_id", "tx-other"), ("transaction_id", None),
                                         ("actor", "agent/intern"), ("resource", "acct-2")])
def test_changed_binding_field_blocked(route, field, value):
    gw = Gateway()
    rid, mandate = gw.approved()
    out = run_route(gw, route, rid, mandate, **{field: value})
    assert out["status"] == "BLOCKED", out
    assert gw.calls == []


@pytest.mark.parametrize("route", ROUTES)
def test_constraints_on_approval_never_execute_unapproved_clamped_payload(route):
    """An approval request whose (agent-supplied) constraints would CONSTRAIN
    the approved payload: the clamped payload was not what the human approved,
    so it must not execute either."""
    gw = Gateway()
    rid, mandate = gw.approved(constraints={"max_amount": 50})
    out = run_route(gw, route, rid, mandate)
    assert out["status"] == "BLOCKED", out
    assert gw.calls == []


# ===========================================================================
# Invalid or substituted approval evidence
# ===========================================================================

def test_approval_route_path_must_match_mandate_approval_id():
    gw = Gateway()
    rid_a, m_a = gw.approved(transaction_id="tx-a")
    rid_b, _ = gw.approved(transaction_id="tx-b")
    out = gw.approval_execute(rid_b, m_a, transaction_id="tx-a")
    assert out["status"] == "BLOCKED" and "APPROVAL_ID_MISMATCH" in out["reason"], out
    assert gw.calls == []
    assert gw.state(rid_a) == "APPROVED" and gw.state(rid_b) == "APPROVED"


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("tamper", [
    lambda m: m.pop("approval_id"),
    lambda m: m.pop("single_use"),
    lambda m: m.update(single_use=False),
    lambda m: m.update(payload_hash="sha256:" + "f" * 64),
    lambda m: m.update(approval_id="req-someone-else"),
], ids=["strip-approval-id", "strip-single-use", "single-use-false", "swap-payload-hash", "swap-approval-id"])
def test_tampered_approval_mandate_blocked(route, tamper):
    gw = Gateway()
    rid, mandate = gw.approved()
    forged = dict(mandate)
    tamper(forged)
    out = run_route(gw, route, rid, forged)
    assert out["status"] == "BLOCKED", out
    assert gw.calls == []


@pytest.mark.parametrize("route", ROUTES)
def test_approval_mandate_signed_by_untrusted_key_blocked(route):
    gw = Gateway()
    rid, mandate = gw.approved()
    rogue = SigningKey.generate(gw.approver.kid)   # same kid, different key
    claims = {k: v for k, v in mandate.items() if k not in ("kid", "sig")}
    forged = rogue.sign_token({**claims, "payload_hash": "sha256:" + "a" * 64})
    out = run_route(gw, route, rid, forged)
    assert out["status"] == "BLOCKED", out
    assert gw.calls == []


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("drop", ["approval_id", "single_use", "payload_hash", "action_hash", "transaction_id"])
def test_partially_bound_mandate_from_trusted_key_fails_closed(route, drop):
    """Defense against a minting defect: a mandate validly signed by the
    trusted approver key but carrying an INCOMPLETE approval binding is a
    denial -- never downgraded to a standing grant."""
    gw = Gateway()
    rid, real = gw.approved()
    extra = {k: real[k] for k in ("approval_id", "single_use", "payload_hash",
                                  "action_hash", "transaction_id") if k != drop}
    m = issue_mandate(gw.approver, issuer="mcc/approvals", subject=ACTOR, action_scope=[ACTION],
                      resource_scope=[RESOURCE], not_before=real["nbf"], not_after=real["exp"],
                      issued_at=real["iat"], policy_hash=POLICY, mandate_id=real["mandate_id"],
                      extra=extra, tenant_id=real["tenant_id"])  # V05: same tenant as the real one
    out = run_route(gw, route, rid, m)
    assert out["status"] == "BLOCKED", out
    assert gw.calls == []
    if route == "mandate":
        assert "MALFORMED_APPROVAL_MANDATE" in out["reason"]


def test_mandate_verify_reports_malformed_approval_binding():
    gw = Gateway()
    rid, real = gw.approved()
    forged_extra = {k: real[k] for k in ("approval_id", "payload_hash", "action_hash", "transaction_id")}
    m = issue_mandate(gw.approver, issuer="mcc/approvals", subject=ACTOR, action_scope=[ACTION],
                      resource_scope=[RESOURCE], not_before=real["nbf"], not_after=real["exp"],
                      policy_hash=POLICY, extra=forged_extra,
                      tenant_id=real["tenant_id"])  # V05: same tenant as the real one
    r = gw.client.post("/mandates/verify", headers=AGENT, json={
        "mandate": m, "subject": ACTOR, "action": ACTION, "resource": RESOURCE})
    assert r.status_code == 200 and r.json()["verified"] is False
    assert "MALFORMED_APPROVAL_MANDATE" in r.json()["reason"]


# ===========================================================================
# Validity: expired / revoked / invalidated / denied
# ===========================================================================

@pytest.mark.parametrize("route", ROUTES)
def test_expired_approval_blocked(route):
    gw = Gateway()
    rid, mandate = gw.approved(ttl_seconds=1)
    time.sleep(1.3)
    out = run_route(gw, route, rid, mandate)
    assert out["status"] == "BLOCKED" and "EXPIRED" in out["reason"], out
    assert gw.calls == []


@pytest.mark.parametrize("route", ROUTES)
def test_revoked_approval_mandate_blocked(route):
    gw = Gateway()
    rid, mandate = gw.approved()
    r = gw.client.post(f"/mandates/{mandate['mandate_id']}/revoke", headers=OP)
    assert r.status_code == 200 and r.json()["ok"] is True
    out = run_route(gw, route, rid, mandate)
    assert out["status"] == "BLOCKED" and "revoked" in out["reason"].lower(), out
    assert gw.calls == []


@pytest.mark.parametrize("route", ROUTES)
def test_invalidated_approval_blocked(route):
    gw = Gateway()
    rid, mandate = gw.approved()
    assert gw.client.post(f"/approvals/{rid}/invalidate", headers=OP).status_code == 200
    out = run_route(gw, route, rid, mandate)
    assert out["status"] == "BLOCKED", out
    assert gw.calls == []


def test_denied_request_mints_nothing_executable():
    gw = Gateway()
    rid = gw.request_approval()
    assert gw.client.post(f"/approvals/{rid}/deny", headers=OP).status_code == 200
    assert gw.client.post(f"/approvals/{rid}/approve", headers=OP).status_code == 409
    assert gw.calls == []


# ===========================================================================
# Duplicate execution / replay, including CROSS-ROUTE
# ===========================================================================

@pytest.mark.parametrize("first,second", [("approval", "mandate"), ("mandate", "approval"),
                                          ("mandate", "mandate"), ("approval", "approval")])
def test_single_use_across_routes(first, second):
    gw = Gateway()
    rid, mandate = gw.approved()
    a = run_route(gw, first, rid, mandate, idem="op-1")
    b = run_route(gw, second, rid, mandate, idem="op-2")
    assert a["status"] == "EXECUTED", a
    assert b["status"] == "BLOCKED", b
    assert len(gw.calls) == 1
    assert gw.state(rid) == "CONSUMED"


@pytest.mark.parametrize("route", ROUTES)
def test_replay_with_same_idempotency_key_executes_once(route):
    gw = Gateway()
    rid, mandate = gw.approved()
    a = run_route(gw, route, rid, mandate, idem="same")
    b = run_route(gw, route, rid, mandate, idem="same")
    assert a["status"] == "EXECUTED" and b["status"] == "BLOCKED"
    assert len(gw.calls) == 1


def test_concurrent_http_consumption_single_winner_in_memory():
    gw = Gateway()
    rid, mandate = gw.approved()
    with gw.client:   # one shared event loop: requests interleave truly concurrently
        with ThreadPoolExecutor(max_workers=16) as pool:
            futs = [pool.submit(run_route, gw, ROUTES[i % 2], rid, mandate, idem=f"c-{i}")
                    for i in range(24)]
            outs = [f.result() for f in futs]
    assert sum(o["status"] == "EXECUTED" for o in outs) == 1, outs
    assert len(gw.calls) == 1


# ===========================================================================
# Fail-closed when approval consumption is unavailable
# ===========================================================================

@pytest.mark.parametrize("route", ROUTES)
def test_coordinator_without_approval_service_fails_closed(route):
    gw = Gateway(coordinator_approvals=False)
    rid, mandate = gw.approved()
    out = run_route(gw, route, rid, mandate)
    assert out["status"] == "BLOCKED", out
    assert gw.calls == []


def test_coordinator_blocks_approval_token_without_approval_service():
    """Unit-level: the coordinator itself never actuates a token naming an
    approval it cannot consume (no reliance on the service-layer check)."""
    gw = Gateway(coordinator_approvals=False)
    token = gw.service.engine.issue_token(
        verdict="ALLOW", subject=ACTOR, action=ACTION, payload=payment(),
        idempotency_key="k", tenant_id="tenant-1", actor_id=ACTOR, resource_id=RESOURCE,
        auth_claims={"approval_id": "req-x"})

    async def ex():
        gw.calls.append(("direct", {}))
    res = asyncio.run(gw.coordinator.enforce(
        token=token, action=ACTION, payload=payment(), executor=ex,
        request_binding={"actor_id": ACTOR, "resource_id": RESOURCE, "tenant_id": "tenant-1"}))
    assert res.status.value == "BLOCKED" and "no approval service" in res.reason
    assert gw.calls == []


# ===========================================================================
# Legitimate execution remains functional
# ===========================================================================

@pytest.mark.parametrize("route", ROUTES)
def test_legitimate_approved_execution(route):
    gw = Gateway()
    rid, mandate = gw.approved()
    out = run_route(gw, route, rid, mandate)
    assert out["status"] == "EXECUTED" and out["decision"] == "ALLOW", out
    assert gw.calls == [(ACTION, payment())]
    assert gw.state(rid) == "CONSUMED"


def test_legitimate_approval_without_transaction_id():
    gw = Gateway()
    rid, mandate = gw.approved(transaction_id=None)
    out = gw.approval_execute(rid, mandate, transaction_id=None)
    assert out["status"] == "EXECUTED", out
    assert len(gw.calls) == 1


def test_standing_mandate_unaffected():
    """Backward compatibility: an ordinary (non-approval) mandate keeps its
    standing-grant semantics on /mandates/execute -- reusable for distinct
    operations, CONSTRAIN still clamps."""
    gw = Gateway()
    m = gw.standing_mandate()
    a = gw.mandate_execute(m, idem="s-1")
    b = gw.mandate_execute(m, idem="s-2", context=payment(amount=7500.0))
    assert a["status"] == "EXECUTED" and a["decision"] == "ALLOW", a
    assert b["status"] == "EXECUTED" and b["decision"] == "CONSTRAIN", b
    assert [p["amount"] for _, p in gw.calls] == [100.0, 5000.0]


def test_standing_mandate_on_approval_route_rejected():
    """A non-approval mandate is not approval evidence for a request id."""
    gw = Gateway()
    rid = gw.request_approval()
    out = gw.approval_execute(rid, gw.standing_mandate())
    assert out["status"] == "BLOCKED" and "APPROVAL_ID_MISMATCH" in out["reason"], out
    assert gw.calls == []


# ===========================================================================
# Real network socket (embedded uvicorn) -- the V05 attack end to end
# ===========================================================================

def test_r1_over_real_http_socket():
    from examples._demo_server import DemoServer, free_port

    gw = Gateway()
    port = free_port()
    with DemoServer(gw.app, port):
        base = f"http://127.0.0.1:{port}"
        with httpx.Client(base_url=base, timeout=10) as c:
            rid = c.post("/approvals", headers=AGENT, json={
                "actor": ACTOR, "action": ACTION, "resource": RESOURCE, "transaction_id": TX,
                "policy_hash": POLICY, "payload": payment()}).json()["request_id"]
            mandate = c.post(f"/approvals/{rid}/approve", headers=OP).json()["mandate"]
            evil = c.post("/mandates/execute", headers=AGENT, json=gw.body(
                mandate, context=payment(amount=1_000_000.0, beneficiary_id="attacker-acct"),
                transaction_id="tx-evil")).json()
            ok = c.post("/mandates/execute", headers=AGENT, json=gw.body(mandate)).json()
            again = c.post(f"/approvals/{rid}/execute", headers=AGENT, json=gw.body(mandate)).json()
    assert evil["status"] == "BLOCKED", evil
    assert ok["status"] == "EXECUTED", ok
    assert again["status"] == "BLOCKED", again
    assert gw.calls == [(ACTION, payment())]


# ===========================================================================
# Real Redis: cross-instance + concurrent single-use consumption
# ===========================================================================

def _redis_reachable() -> bool:
    async def ping():
        import redis.asyncio as aioredis
        client = aioredis.from_url(REDIS_URL, decode_responses=True)
        try:
            await asyncio.wait_for(client.ping(), timeout=1.0)
            return True
        finally:
            await client.aclose()
    try:
        return asyncio.run(ping())
    except Exception:
        return False


requires_redis = pytest.mark.skipif(
    not _redis_reachable(),
    reason=f"NOT TESTED: no Redis reachable at {REDIS_URL} (set MCC_REDIS_URL)")


def _redis_gateways(n):
    import redis.asyncio as aioredis
    ns = f"mcc-r1-test-{uuid.uuid4().hex}:"
    approver = SigningKey.generate("mcc-approver-1")
    # Each instance gets its own Redis client (bound to its own TestClient loop)
    # over the SAME approval namespace -- i.e. N gateway replicas, one Redis.
    return [Gateway(approval_registry=RedisApprovalRegistry(
                        aioredis.from_url(REDIS_URL, decode_responses=True), namespace=ns),
                    approver_key=approver)
            for _ in range(n)]


@requires_redis
def test_redis_cross_instance_concurrent_single_winner_across_routes():
    gws = _redis_gateways(3)
    with gws[0].client, gws[1].client, gws[2].client:
        rid, mandate = gws[0].approved()
        with ThreadPoolExecutor(max_workers=18) as pool:
            futs = [pool.submit(run_route, gws[i % 3], ROUTES[i % 2], rid, mandate, idem=f"r-{i}")
                    for i in range(30)]
            outs = [f.result() for f in futs]
        state = gws[1].state(rid)
    total_calls = sum(len(g.calls) for g in gws)
    assert sum(o["status"] == "EXECUTED" for o in outs) == 1, outs
    assert total_calls == 1
    assert state == "CONSUMED"


@requires_redis
def test_redis_cross_instance_v05_attack_and_invalidation():
    gws = _redis_gateways(2)
    with gws[0].client, gws[1].client:
        rid, mandate = gws[0].approved()
        evil = gws[1].mandate_execute(mandate, context=payment(amount=1_000_000.0,
                                                              beneficiary_id="attacker-acct"),
                                      transaction_id="tx-evil")
        assert gws[0].client.post(f"/approvals/{rid}/invalidate", headers=OP).status_code == 200
        after = gws[1].mandate_execute(mandate)
    assert evil["status"] == "BLOCKED" and after["status"] == "BLOCKED"
    assert gws[0].calls == [] and gws[1].calls == []
