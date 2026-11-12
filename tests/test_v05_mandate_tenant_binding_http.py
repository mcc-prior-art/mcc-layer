"""V05 remediation: signed mandates are bound to the executing tenant.

Internal red-team assessment (redteam/ at cb5bd33), V05. Reproduced on main @
41b2c9a at the real HTTP boundary:

* The gateway authenticates a TENANT (one agent X-API-Key per mount, mapped to
  a server-side tenant_id), not an individual agent. ``actor`` is a request
  field. Within a tenant, a copied mandate executes if the caller names its
  subject as ``actor``. This is the bearer property the original V05 test
  asserts against. Closing it needs a per-agent identity or a
  proof-of-possession contract the system does not have; it is NOT closed
  here and is documented as a design gap.
* A mandate carried no tenant claim, so a mandate from an issuer trusted by
  two tenant gateways EXECUTED in both (cross-tenant).
* With two tenant gateways sharing an approval store and approver key (the HA
  wiring), tenant-B EXECUTED tenant-A's human approval and burned it.

Contract (strict tenant mode, the default):

* A mandate carries a SIGNED ``tenant_id`` claim. After the signature is
  verified, it must be a non-empty, unpadded string equal to the gateway's
  trusted, server-side tenant (the authenticated mount, never a request
  field).
* Missing, empty, malformed or mismatched -> BLOCKED before any token, idem-
  potency reservation, audit pre_actuation record or actuator call.
* Approval-minted mandates carry the request's tenant. ApprovalService.consume
  also refuses another tenant's approval without consuming it.
* ``legacy-unscoped`` is an explicit server-side setting only. It accepts a
  claimless mandate in any tenant (NO tenant isolation for it) but still
  enforces a claim that is present.
"""
from __future__ import annotations

import gc
import json
import tempfile
import time
from pathlib import Path

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
from mcc_core.mandate import (
    MANDATE_TENANT_LEGACY,
    MANDATE_TENANT_STRICT,
    issue_mandate,
    mandate_tenant_error,
)

from gateway.governance_api import mount_approval_routes, mount_mandate_routes
from gateway.governance_service import GovernanceService
from gateway.trust import TrustSet


@pytest.fixture(autouse=True, scope="module")
def _release_this_modules_garbage():
    """Collect this module's cyclic garbage at its own teardown (same hygiene
    as the R3/R4 modules)."""
    yield
    gc.collect()


POLICY = "sha256:" + "0" * 64
ACTOR = "agent/payments-bot"
ACTION = "send_payment"
RESOURCE = "acct-1"
TX = "tx-1"


def payment(beneficiary="vendor-42", amount=100.0):
    return {"source": RESOURCE, "beneficiary_id": beneficiary, "amount": amount, "currency": "EUR"}


class Deployment:
    """One trusted mandate issuer shared by any number of tenant gateways.
    Each gateway is a real FastAPI app with the real mandate + approval routes
    and the real per-mount agent/operator auth dependencies."""

    def __init__(self):
        self.issuer = SigningKey.generate("treasury-1")

    def mandate(self, *, tenant_id=..., subject=ACTOR, action=ACTION, resource=RESOURCE, **kw):
        now = int(time.time())
        args = dict(issuer="issuer/treasury", subject=subject, action_scope=[action],
                    resource_scope=[resource], constraints={"max_amount": 5000},
                    not_before=now - 10, not_after=now + 3600, issued_at=now - 10,
                    policy_hash=POLICY)
        args.update(kw)
        if tenant_id is not ...:
            args["tenant_id"] = tenant_id
        return issue_mandate(self.issuer, **args)

    def raw_mandate(self, **claims):
        """Sign arbitrary claims with the TRUSTED issuer key -- e.g. a
        malformed tenant_id that issue_mandate's typed API would never emit,
        but that a buggy or compromised issuer could."""
        now = int(time.time())
        base = {"mandate_id": f"mdt-raw-{time.monotonic_ns()}", "issuer": "issuer/treasury",
                "subject": ACTOR, "action_scope": [ACTION], "resource_scope": [RESOURCE],
                "constraints": {"max_amount": 5000}, "iat": now - 10, "nbf": now - 10,
                "exp": now + 3600, "revocation_required": False, "policy_hash": POLICY}
        base.update(claims)
        return self.issuer.sign_token(base)

    def gateway(self, tenant, *, approver=None, approval_registry=None, mode=MANDATE_TENANT_STRICT):
        return Gateway(self, tenant, approver=approver or SigningKey.generate(f"apr-{tenant}"),
                       approval_registry=approval_registry or InMemoryApprovalRegistry(), mode=mode)


class Gateway:
    def __init__(self, deployment, tenant, *, approver, approval_registry, mode):
        self.tenant = tenant
        self.key = f"agent-key-{tenant}"
        self.op = {"x-operator-key": f"op-key-{tenant}"}
        trust = TrustSet()
        trust.add_runtime_issuer("issuer/treasury", deployment.issuer.kid, deployment.issuer.public_key())
        trust.add_runtime_issuer("mcc/approvals", approver.kid, approver.public_key())
        dk = SigningKey.generate(f"gw-{tenant}")
        engine = DecisionEngine(signing_key=dk, issuer="mcc/core", audience="gate",
                                policy_id="pilot/v1", policy_hash=POLICY, token_ttl_seconds=60)
        gate = ExecutionGate(trusted_keys={dk.kid: dk.public_key()}, audience="gate",
                             nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY)
        self.approvals = ApprovalService(approval_registry, approver)
        self.audit_path = str(Path(tempfile.mkdtemp(prefix="mcc-v05-")) / "audit.jsonl")
        self.idempotency = InMemoryIdempotencyRegistry()
        coordinator = EnforcementCoordinator(
            gate=gate, idempotency=self.idempotency, velocity=InMemoryVelocityRegistry(),
            audit=AuditLog(self.audit_path), profiles=ProfileRegistry.default_pilot(),
            revocation_registry=InMemoryRevocationRegistry(), approvals=self.approvals)
        self.calls: list = []

        async def upstream(action, payload):
            self.calls.append((action, dict(payload)))
            return {"ok": True}

        self.service = GovernanceService(
            engine=engine, coordinator=coordinator, trust_set=trust,
            revocation_registry=InMemoryRevocationRegistry(), approvals=self.approvals,
            upstream=upstream, policy_hash=POLICY, mandate_tenant_mode=mode)
        app = FastAPI()
        for mount in (mount_mandate_routes, mount_approval_routes):
            mount(app, self.service, api_key=self.key, operator_key=self.op["x-operator-key"],
                  tenant_id=tenant)
        self.client = TestClient(app, raise_server_exceptions=False)

    # ---- HTTP ----
    def post(self, url, body, *, headers=None):
        h = {"x-api-key": self.key, "content-type": "application/json", **(headers or {})}
        return self.client.post(url, headers=h, content=json.dumps(body))

    def execute(self, mandate, *, route="mandate", rid=None, actor=ACTOR, action=ACTION,
                resource=RESOURCE, context=None, transaction_id=TX, key="k-1"):
        url = "/mandates/execute" if route == "mandate" else f"/approvals/{rid}/execute"
        r = self.post(url, {"mandate": mandate, "actor": actor, "action": action, "resource": resource,
                            "context": payment() if context is None else context,
                            "transaction_id": transaction_id, "idempotency_key": key})
        assert r.status_code == 200, (r.status_code, r.text)     # controlled outcome, never a 500
        return r.json()

    def approval(self, *, payload=None, transaction_id=TX):
        r = self.post("/approvals", {"actor": ACTOR, "action": ACTION, "resource": RESOURCE,
                                     "transaction_id": transaction_id, "policy_hash": POLICY,
                                     "payload": payload or payment()})
        assert r.status_code == 200, r.text
        rid = r.json()["request_id"]
        a = self.client.post(f"/approvals/{rid}/approve", headers=self.op)
        assert a.status_code == 200, a.text
        return rid, a.json()["mandate"]

    def state(self, rid):
        return self.client.get(f"/approvals/{rid}", headers={"x-api-key": self.key}).json()["state"]

    def audit_kinds(self):
        p = Path(self.audit_path)
        if not p.exists():
            return []
        return [json.loads(line).get("kind") for line in p.read_text().splitlines() if line.strip()]

    def assert_nothing_happened(self):
        """Rejected before execution: no actuator call, no pre_actuation /
        actuation record, no idempotency reservation."""
        assert self.calls == []
        kinds = self.audit_kinds()
        assert not [k for k in kinds if k == "pre_actuation" or str(k).startswith("actuation_")
                    and k != "actuation_rejected"], kinds


@pytest.fixture
def dep():
    return Deployment()


def _blocked(out, code):
    assert out["status"] == "BLOCKED" and out["decision"] == "DENY", out
    assert out["reason"].startswith(code), out


# ===========================================================================
# 1. The contract itself (pure checker)
# ===========================================================================

@pytest.mark.parametrize("claims,mode,expected", [
    ({"tenant_id": "tenant-A"}, MANDATE_TENANT_STRICT, None),
    ({}, MANDATE_TENANT_STRICT, "MANDATE_TENANT_MISSING"),
    ({"tenant_id": "tenant-B"}, MANDATE_TENANT_STRICT, "MANDATE_TENANT_MISMATCH"),
    ({"tenant_id": ""}, MANDATE_TENANT_STRICT, "MANDATE_TENANT_MALFORMED"),
    ({"tenant_id": None}, MANDATE_TENANT_STRICT, "MANDATE_TENANT_MALFORMED"),
    ({}, MANDATE_TENANT_LEGACY, None),
    ({"tenant_id": "tenant-B"}, MANDATE_TENANT_LEGACY, "MANDATE_TENANT_MISMATCH"),
    ({"tenant_id": None}, MANDATE_TENANT_LEGACY, "MANDATE_TENANT_MALFORMED"),
    ({"tenant_id": "tenant-A"}, "permissive", "MANDATE_TENANT_MODE_INVALID"),
], ids=["match", "missing", "mismatch", "empty", "null", "legacy-missing", "legacy-mismatch",
        "legacy-null", "unknown-mode"])
def test_checker(claims, mode, expected):
    err = mandate_tenant_error(claims, tenant_id="tenant-A", mode=mode)
    assert (err is None) if expected is None else err.startswith(expected), err


@pytest.mark.parametrize("server_tenant", [None, "", "   ", 7], ids=["none", "empty", "blank", "int"])
def test_checker_requires_a_trusted_server_tenant(server_tenant):
    err = mandate_tenant_error({"tenant_id": "tenant-A"}, tenant_id=server_tenant, mode=MANDATE_TENANT_STRICT)
    assert err and err.startswith("MISSING_TENANT_IDENTITY")


def test_unknown_mode_refuses_to_construct(dep):
    with pytest.raises(ValueError):
        dep.gateway("tenant-A", mode="off")


# ===========================================================================
# 2. Standing mandates on POST /mandates/execute
# ===========================================================================

def test_matching_tenant_executes_exactly_once(dep):
    a = dep.gateway("tenant-A")
    out = a.execute(dep.mandate(tenant_id="tenant-A"))
    assert out["status"] == "EXECUTED", out
    assert a.calls == [(ACTION, payment())]


def test_cross_tenant_same_trusted_issuer_is_blocked(dep):
    """Reproduced on main: a tenant-A mandate EXECUTED at tenant-B's gateway
    (same trusted issuer). Now refused, and it still executes in tenant-A."""
    a, b = dep.gateway("tenant-A"), dep.gateway("tenant-B")
    m = dep.mandate(tenant_id="tenant-A")
    _blocked(b.execute(m), "MANDATE_TENANT_MISMATCH")
    b.assert_nothing_happened()
    assert a.execute(m)["status"] == "EXECUTED" and len(a.calls) == 1


def test_missing_tenant_is_blocked_in_every_tenant(dep):
    m = dep.mandate()                                       # no tenant_id claim at all
    for g in (dep.gateway("tenant-A"), dep.gateway("tenant-B")):
        _blocked(g.execute(m), "MANDATE_TENANT_MISSING")
        g.assert_nothing_happened()


@pytest.mark.parametrize("bad", ["", " ", " tenant-A", "tenant-A ", "TENANT-A", "tenant-A\n",
                                 None, 0, 1, True, ["tenant-A"], {"id": "tenant-A"}],
                         ids=["empty", "blank", "lead-space", "trail-space", "case", "newline",
                              "null", "zero", "int", "bool", "list", "object"])
def test_malformed_or_mismatched_signed_tenant_is_blocked(dep, bad):
    """Signed by the TRUSTED issuer, so only the tenant claim is wrong."""
    a = dep.gateway("tenant-A")
    _blocked(a.execute(dep.raw_mandate(tenant_id=bad)), "MANDATE_TENANT_")
    a.assert_nothing_happened()


@pytest.mark.parametrize("tamper", ["rewrite", "add-to-claimless", "remove"])
def test_tampering_with_the_signed_tenant_is_rejected_by_the_signature(dep, tamper):
    a = dep.gateway("tenant-A")
    if tamper == "rewrite":
        m = dict(dep.mandate(tenant_id="tenant-B")); m["tenant_id"] = "tenant-A"
    elif tamper == "add-to-claimless":
        m = dict(dep.mandate()); m["tenant_id"] = "tenant-A"
    else:
        m = dict(dep.mandate(tenant_id="tenant-A")); del m["tenant_id"]
    out = a.execute(m)
    assert out["status"] == "BLOCKED", out
    assert "SIGNATURE" in out["reason"], out
    a.assert_nothing_happened()


def test_request_fields_cannot_supply_the_tenant(dep):
    """The tenant comes only from the authenticated mount. A body field is
    refused by the strict request schema, and another tenant's API key is
    refused at authentication -- neither ever reaches execution."""
    a = dep.gateway("tenant-A")
    m = dep.mandate(tenant_id="tenant-B")
    r = a.post("/mandates/execute", {"mandate": m, "actor": ACTOR, "action": ACTION, "resource": RESOURCE,
                                     "context": payment(), "idempotency_key": "k", "tenant_id": "tenant-B"})
    assert r.status_code == 422, r.text
    r = a.client.post("/mandates/execute", headers={"x-api-key": "agent-key-tenant-B",
                                                    "content-type": "application/json"},
                      content=json.dumps({"mandate": m, "actor": ACTOR, "action": ACTION,
                                          "resource": RESOURCE, "context": payment(),
                                          "idempotency_key": "k"}))
    assert r.status_code == 401, r.text
    a.assert_nothing_happened()


def test_rejected_attempt_reserves_nothing(dep):
    """The same idempotency key stays free for the legitimate operation."""
    a = dep.gateway("tenant-A")
    _blocked(a.execute(dep.mandate(tenant_id="tenant-B"), key="shared"), "MANDATE_TENANT_MISMATCH")
    assert a.execute(dep.mandate(tenant_id="tenant-A"), key="shared")["status"] == "EXECUTED"
    assert len(a.calls) == 1


# ---- tenant binding does not replace authorization (substitution) ----

@pytest.mark.parametrize("field,value,code", [
    ("actor", "agent/intern", "SUBJECT_MISMATCH"),
    ("action", "pay_vendor", "ACTION_SCOPE"),
    ("resource", "acct-2", "RESOURCE_SCOPE"),
], ids=["spoofed-actor", "action", "resource"])
def test_matching_tenant_does_not_override_mandate_scope(dep, field, value, code):
    a = dep.gateway("tenant-A")
    out = a.execute(dep.mandate(tenant_id="tenant-A"), **{field: value})
    assert out["status"] == "BLOCKED" and code in out["reason"], out
    a.assert_nothing_happened()


def test_matching_tenant_does_not_override_constraints(dep):
    a = dep.gateway("tenant-A")
    out = a.execute(dep.mandate(tenant_id="tenant-A", constraints={"allowed_currency": ["USD"]}))
    assert out["status"] == "BLOCKED", out
    a.assert_nothing_happened()


# ===========================================================================
# 3. Approval-minted mandates (both execution routes)
# ===========================================================================

def test_approval_mandate_carries_the_request_tenant(dep):
    a = dep.gateway("tenant-A")
    _, m = a.approval()
    assert m["tenant_id"] == "tenant-A"


@pytest.mark.parametrize("route", ["approval", "mandate"])
def test_approval_executes_exactly_once_in_its_own_tenant(dep, route):
    a = dep.gateway("tenant-A")
    rid, m = a.approval()
    assert a.execute(m, route=route, rid=rid)["status"] == "EXECUTED"
    assert a.calls == [(ACTION, payment())]
    again = a.execute(m, route=route, rid=rid, key="k-2")           # single use (R1)
    assert again["status"] == "BLOCKED" and len(a.calls) == 1


@pytest.mark.parametrize("route", ["approval", "mandate"])
def test_cross_tenant_approval_with_shared_store_and_approver_is_blocked(dep, route):
    """Reproduced on main: with a shared approval store and approver key,
    tenant-B EXECUTED tenant-A's approval and burned it. Now refused at both
    layers, and the approval stays usable by tenant-A."""
    approver, store = SigningKey.generate("mcc-approver-shared"), InMemoryApprovalRegistry()
    a = dep.gateway("tenant-A", approver=approver, approval_registry=store)
    b = dep.gateway("tenant-B", approver=approver, approval_registry=store)
    rid, m = a.approval()
    _blocked(b.execute(m, route=route, rid=rid), "MANDATE_TENANT_MISMATCH")
    b.assert_nothing_happened()
    assert a.state(rid) == "APPROVED"
    assert a.execute(m, route=route, rid=rid)["status"] == "EXECUTED"
    assert len(a.calls) == 1


def test_consume_refuses_another_tenants_approval_without_consuming_it(dep):
    """Defense in depth below the mandate check: even a token for tenant-B
    that names tenant-A's approval cannot consume it."""
    import asyncio
    from mcc_core.signing import hash_action, hash_payload
    a = dep.gateway("tenant-A")
    rid, _ = a.approval()
    res = asyncio.run(a.approvals.consume(rid, action_hash=hash_action(ACTION), transaction_id=TX,
                                          payload_hash=hash_payload(payment()), tenant_id="tenant-B"))
    assert not res.ok and res.reason.startswith("TENANT_MISMATCH")
    assert a.state(rid) == "APPROVED"


@pytest.mark.parametrize("route", ["approval", "mandate"])
@pytest.mark.parametrize("field,value", [("context", payment(beneficiary="attacker", amount=1_000_000.0)),
                                         ("transaction_id", "tx-evil"),
                                         ("action", "pay_vendor"),
                                         ("resource", "acct-2")],
                         ids=["payload", "transaction", "action", "resource"])
def test_approval_substitution_still_blocked_in_the_right_tenant(dep, route, field, value):
    a = dep.gateway("tenant-A")
    rid, m = a.approval()
    out = a.execute(m, route=route, rid=rid, **{field: value})
    assert out["status"] == "BLOCKED", out
    a.assert_nothing_happened()
    assert a.state(rid) == "APPROVED"


@pytest.mark.parametrize("route", ["approval", "mandate"])
def test_tampered_tenant_on_an_approval_mandate_is_rejected(dep, route):
    approver, store = SigningKey.generate("mcc-approver-shared"), InMemoryApprovalRegistry()
    a = dep.gateway("tenant-A", approver=approver, approval_registry=store)
    b = dep.gateway("tenant-B", approver=approver, approval_registry=store)
    rid, m = a.approval()
    forged = dict(m); forged["tenant_id"] = "tenant-B"
    out = b.execute(forged, route=route, rid=rid)
    assert out["status"] == "BLOCKED" and "SIGNATURE" in out["reason"], out
    b.assert_nothing_happened()
    assert a.state(rid) == "APPROVED"


# ===========================================================================
# 4. Explicit legacy mode (server-side only) -- documents what it does NOT give
# ===========================================================================

def test_legacy_mode_accepts_a_claimless_mandate_without_tenant_isolation(dep):
    """Documented, not endorsed: in legacy-unscoped mode a claimless mandate
    executes in ANY tenant -- the cross-tenant exposure strict mode closes."""
    a = dep.gateway("tenant-A", mode=MANDATE_TENANT_LEGACY)
    b = dep.gateway("tenant-B", mode=MANDATE_TENANT_LEGACY)
    m = dep.mandate()
    assert a.execute(m)["status"] == "EXECUTED"
    assert b.execute(m)["status"] == "EXECUTED"


def test_legacy_mode_still_enforces_a_present_claim(dep):
    b = dep.gateway("tenant-B", mode=MANDATE_TENANT_LEGACY)
    _blocked(b.execute(dep.mandate(tenant_id="tenant-A")), "MANDATE_TENANT_MISMATCH")
    _blocked(b.execute(dep.raw_mandate(tenant_id=""), key="k-2"), "MANDATE_TENANT_MALFORMED")
    b.assert_nothing_happened()


def test_strict_is_the_default_for_the_library_and_the_builder(monkeypatch):
    from gateway.governance_api import _mandate_tenant_mode_from_env
    monkeypatch.delenv("MCC_MANDATE_TENANT_MODE", raising=False)
    assert _mandate_tenant_mode_from_env({}) == MANDATE_TENANT_STRICT
    assert _mandate_tenant_mode_from_env({"MCC_MANDATE_TENANT_MODE": ""}) == MANDATE_TENANT_STRICT
    assert _mandate_tenant_mode_from_env(
        {"MCC_MANDATE_TENANT_MODE": MANDATE_TENANT_LEGACY}) == MANDATE_TENANT_LEGACY
    with pytest.raises(ValueError):
        _mandate_tenant_mode_from_env({"MCC_MANDATE_TENANT_MODE": "off"})
    d = Deployment()
    assert d.gateway("tenant-A").service.mandate_tenant_mode == MANDATE_TENANT_STRICT


def test_library_default_follows_the_server_setting_and_rejects_unknown(monkeypatch):
    """GovernanceService() with no explicit mode reads the server's
    MCC_MANDATE_TENANT_MODE (unset -> strict); an unknown value refuses."""
    monkeypatch.setenv("MCC_MANDATE_TENANT_MODE", "nonsense")
    with pytest.raises(ValueError):
        GovernanceService(engine=None, coordinator=None, trust_set=TrustSet(), revocation_registry=None,
                          approvals=None)
    monkeypatch.setenv("MCC_MANDATE_TENANT_MODE", MANDATE_TENANT_LEGACY)
    svc = GovernanceService(engine=None, coordinator=None, trust_set=TrustSet(), revocation_registry=None,
                            approvals=None)
    assert svc.mandate_tenant_mode == MANDATE_TENANT_LEGACY


# ===========================================================================
# 5. Delegation (service boundary; it already binds a signed tenant)
# ===========================================================================

def test_delegation_cross_tenant_is_blocked_and_own_tenant_executes():
    import asyncio
    from tests.test_r2_numeric_constraint_http import DelegationStack
    s = DelegationStack()
    d = s.delegation()                                   # issued for tenant-1

    def run(tenant, key):
        return asyncio.run(s.service.execute_with_delegation(
            delegation=d, actor=ACTOR, action=ACTION, resource=RESOURCE, purpose="vendor_payment",
            context=payment(), tenant_id=tenant, idempotency_key=key))

    out = run("tenant-2", "d-x")
    assert out.status == "BLOCKED" and "TENANT_MISMATCH" in out.reason, out
    assert s.calls == []
    assert run("tenant-1", "d-ok").status == "EXECUTED" and len(s.calls) == 1
