"""V05 remediation, part 2: per-agent authenticated identity and mandate
subject binding.

Reproduced on main @ 1f0bd3a through real HTTP authentication. The gateway
authenticated only the TENANT (one shared agent X-API-Key per mount), and
``actor`` was a request field. So agent B, holding the same tenant key,
executed agent A's copied, tenant-bound mandate by naming A as ``actor``
(EXECUTED, actuator +1). B could also create an approval naming A and execute
it as A.

Contract (strict, the default):

* A server-side registry maps a presented X-API-Key (stored only as SHA-256)
  to exactly one (tenant_id, principal_id). It is never derived from the
  body, a mandate, or any other header.
* On identity routes (POST /mandates/execute, POST /approvals,
  POST /approvals/{id}/execute) the request must come from a registered,
  active credential of the mount's tenant, and that principal must equal
  ``actor`` and the signed mandate ``subject``.
* The shared tenant key grants NO identity there (403). Unknown keys get 401;
  revoked and other-tenant keys get 403.
* Refusals happen before any decision token, approval consumption,
  idempotency reservation, audit pre_actuation record or actuator call.
* A direct library caller must pass the trusted AuthenticatedAgent itself; an
  omitted one is refused (no fallback to ``actor``).

NOT covered: an attacker who holds agent A's OWN credential is A. This
contract authenticates credentials; it is not proof of possession.
Rotation and revocation are the response to a stolen key.
"""
from __future__ import annotations

import asyncio
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
from mcc_core.mandate import issue_mandate

from gateway.agent_identity import (
    AGENT_IDENTITY_LEGACY,
    AGENT_IDENTITY_STRICT,
    AgentCredentialConfigError,
    AgentCredentialRegistry,
    AuthenticatedAgent,
    agent_identity_error,
    agent_identity_mode_from_env,
    hash_agent_key,
)
from gateway.governance_api import mount_approval_routes, mount_mandate_routes
from gateway.governance_service import GovernanceService
from gateway.trust import TrustSet


@pytest.fixture(autouse=True, scope="module")
def _release_this_modules_garbage():
    yield
    gc.collect()


POLICY = "sha256:" + "0" * 64
A, B, C = "agent/payments-bot", "agent/intern", "agent/other-tenant-bot"
ACTION, RESOURCE, TX = "send_payment", "acct-1", "tx-1"
KEY_A, KEY_A2, KEY_B, KEY_C, KEY_REVOKED = (
    "key-agent-a", "key-agent-a-rotated", "key-agent-b", "key-agent-c", "key-revoked")
SHARED = {"tenant-A": "shared-tenant-key-A", "tenant-B": "shared-tenant-key-B"}


def payment(beneficiary="vendor-42", amount=100.0):
    return {"source": RESOURCE, "beneficiary_id": beneficiary, "amount": amount, "currency": "EUR"}


def registry(*, revoke_a2=False):
    def entry(cid, tenant, principal, key, status="active"):
        return {"credential_id": cid, "tenant_id": tenant, "principal_id": principal,
                "key_sha256": hash_agent_key(key), "status": status}
    return AgentCredentialRegistry.from_config({"agents": [
        entry("cred-a-1", "tenant-A", A, KEY_A),
        entry("cred-a-2", "tenant-A", A, KEY_A2, "revoked" if revoke_a2 else "active"),
        entry("cred-b-1", "tenant-A", B, KEY_B),
        entry("cred-old", "tenant-A", B, KEY_REVOKED, "revoked"),
        entry("cred-c-1", "tenant-B", C, KEY_C),
    ]})


class Deployment:
    """One trusted issuer, one shared credential registry, any number of
    tenant gateways (real FastAPI routes + real auth dependencies)."""

    def __init__(self, *, revoke_a2=False):
        self.issuer = SigningKey.generate("treasury-1")
        self.registry = registry(revoke_a2=revoke_a2)

    def mandate(self, *, subject=A, tenant_id="tenant-A", **kw):
        now = int(time.time())
        args = dict(issuer="issuer/treasury", subject=subject, action_scope=[ACTION],
                    resource_scope=[RESOURCE], constraints={"max_amount": 5000},
                    not_before=now - 10, not_after=now + 3600, issued_at=now - 10,
                    policy_hash=POLICY, tenant_id=tenant_id)
        args.update(kw)
        return issue_mandate(self.issuer, **args)

    def gateway(self, tenant="tenant-A", *, mode=AGENT_IDENTITY_STRICT, with_registry=True):
        return Gateway(self, tenant, mode=mode, registry=self.registry if with_registry else None)


class Gateway:
    def __init__(self, dep, tenant, *, mode, registry):
        self.tenant = tenant
        self.op = {"x-operator-key": f"op-{tenant}"}
        trust = TrustSet()
        trust.add_runtime_issuer("issuer/treasury", dep.issuer.kid, dep.issuer.public_key())
        approver = SigningKey.generate(f"apr-{tenant}")
        trust.add_runtime_issuer("mcc/approvals", approver.kid, approver.public_key())
        dk = SigningKey.generate(f"gw-{tenant}")
        engine = DecisionEngine(signing_key=dk, issuer="mcc/core", audience="gate",
                                policy_id="pilot/v1", policy_hash=POLICY, token_ttl_seconds=60)
        self.tokens: list = []
        real_issue = engine.issue_token

        def spy_issue(**kw):                     # count EVERY decision token issued
            tok = real_issue(**kw)
            self.tokens.append(tok)
            return tok
        engine.issue_token = spy_issue
        gate = ExecutionGate(trusted_keys={dk.kid: dk.public_key()}, audience="gate",
                             nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY)
        self.approvals = ApprovalService(InMemoryApprovalRegistry(), approver)
        self.audit_path = str(Path(tempfile.mkdtemp(prefix="mcc-v05id-")) / "audit.jsonl")
        coordinator = EnforcementCoordinator(
            gate=gate, idempotency=InMemoryIdempotencyRegistry(), velocity=InMemoryVelocityRegistry(),
            audit=AuditLog(self.audit_path), profiles=ProfileRegistry.default_pilot(),
            revocation_registry=InMemoryRevocationRegistry(), approvals=self.approvals)
        self.calls: list = []

        async def upstream(action, payload):
            self.calls.append((action, dict(payload)))
            return {"ok": True}

        self.service = GovernanceService(
            engine=engine, coordinator=coordinator, trust_set=trust,
            revocation_registry=InMemoryRevocationRegistry(), approvals=self.approvals,
            upstream=upstream, policy_hash=POLICY, agent_identity_mode=mode)
        app = FastAPI()
        for mount in (mount_mandate_routes, mount_approval_routes):
            mount(app, self.service, api_key=SHARED[tenant], operator_key=self.op["x-operator-key"],
                  tenant_id=tenant, agent_credentials=registry)
        self.client = TestClient(app, raise_server_exceptions=False)

    def post(self, url, body, *, key, headers=None):
        h = {"content-type": "application/json", **(headers or {})}
        if key is not None:
            h["x-api-key"] = key
        return self.client.post(url, headers=h, content=json.dumps(body))

    def execute(self, mandate, *, key, route="mandate", rid=None, actor=A, action=ACTION,
                resource=RESOURCE, context=None, transaction_id=TX, idem="k-1", headers=None):
        url = "/mandates/execute" if route == "mandate" else f"/approvals/{rid}/execute"
        return self.post(url, {"mandate": mandate, "actor": actor, "action": action, "resource": resource,
                               "context": payment() if context is None else context,
                               "transaction_id": transaction_id, "idempotency_key": idem},
                         key=key, headers=headers)

    def create_approval(self, *, key, actor=A, payload=None, transaction_id=TX):
        return self.post("/approvals", {"actor": actor, "action": ACTION, "resource": RESOURCE,
                                        "transaction_id": transaction_id, "policy_hash": POLICY,
                                        "payload": payload or payment()}, key=key)

    def approved(self, *, key=KEY_A, actor=A):
        r = self.create_approval(key=key, actor=actor)
        assert r.status_code == 200, r.text
        rid = r.json()["request_id"]
        a = self.client.post(f"/approvals/{rid}/approve", headers=self.op)
        assert a.status_code == 200, a.text
        return rid, a.json()["mandate"]

    def state(self, rid):
        return self.client.get(f"/approvals/{rid}", headers={"x-api-key": KEY_A}).json()["state"]

    def kinds(self):
        p = Path(self.audit_path)
        return [json.loads(x).get("kind") for x in p.read_text().splitlines() if x.strip()] if p.exists() else []

    def assert_nothing_happened(self):
        assert self.tokens == [], "a decision token was issued"
        assert self.calls == [], "the actuator was called"
        kinds = self.kinds()
        assert not [k for k in kinds if k == "pre_actuation" or (str(k).startswith("actuation_")
                                                                 and k != "actuation_rejected")], kinds


def _blocked(r, code):
    assert r.status_code == 200, (r.status_code, r.text)
    out = r.json()
    assert out["status"] == "BLOCKED" and out["decision"] == "DENY", out
    assert code in out["reason"], out


@pytest.fixture
def dep():
    return Deployment()


# ===========================================================================
# 1. The V05 attack: two agents, one tenant
# ===========================================================================

def test_agent_a_executes_its_own_mandate_exactly_once(dep):
    g = dep.gateway()
    r = g.execute(dep.mandate(), key=KEY_A)
    assert r.json()["status"] == "EXECUTED", r.text
    assert g.calls == [(ACTION, payment())] and len(g.tokens) == 1


def test_agent_b_with_as_copied_mandate_and_actor_a_is_blocked(dep):
    """The reproduced attack. Now refused before anything happens."""
    g = dep.gateway()
    _blocked(g.execute(dep.mandate(), key=KEY_B, actor=A), "AGENT_PRINCIPAL_MISMATCH")
    g.assert_nothing_happened()


def test_agent_b_with_as_copied_mandate_and_actor_b_is_blocked(dep):
    g = dep.gateway()
    _blocked(g.execute(dep.mandate(), key=KEY_B, actor=B), "SUBJECT_MISMATCH")
    g.assert_nothing_happened()


def test_rejected_attempt_reserves_nothing_and_legitimate_retry_works(dep):
    g = dep.gateway()
    m = dep.mandate()
    _blocked(g.execute(m, key=KEY_B, actor=A, idem="shared"), "AGENT_PRINCIPAL_MISMATCH")
    g.assert_nothing_happened()
    r = g.execute(m, key=KEY_A, idem="shared")              # same mandate, same idempotency key
    assert r.json()["status"] == "EXECUTED", r.text
    assert len(g.calls) == 1 and len(g.tokens) == 1


# ===========================================================================
# 2. Credential failures and identity spoofing (all fail closed)
# ===========================================================================

@pytest.mark.parametrize("key,status,detail", [
    ("not-a-registered-key", 401, "INVALID_API_KEY"),
    (KEY_REVOKED, 403, "AGENT_CREDENTIAL_REVOKED"),
    (SHARED["tenant-A"], 403, "AGENT_IDENTITY_REQUIRED"),
    (KEY_C, 403, "AGENT_CREDENTIAL_WRONG_TENANT"),
    ("", 401, "INVALID_API_KEY"),
], ids=["unknown", "revoked", "shared-tenant-key", "other-tenant-agent", "empty"])
def test_unusable_credentials_are_refused_on_every_identity_route(dep, key, status, detail):
    g = dep.gateway()
    rid, m = g.approved()
    for r in (g.execute(dep.mandate(), key=key),
              g.execute(m, key=key, route="approval", rid=rid),
              g.create_approval(key=key)):
        assert r.status_code == status and detail in r.text, (r.status_code, r.text)
    g.assert_nothing_happened()
    assert g.state(rid) == "APPROVED"


def test_missing_credential_is_refused(dep):
    g = dep.gateway()
    r = g.execute(dep.mandate(), key=None)
    assert r.status_code in (401, 422), r.text            # header required by the route signature
    g.assert_nothing_happened()


@pytest.mark.parametrize("headers", [
    {"x-mcc-identity": A}, {"x-agent-id": A}, {"x-principal": A}, {"x-forwarded-user": A},
    {"x-api-key-principal": A}, {"authorization": "Bearer " + KEY_A},
], ids=["x-mcc-identity", "x-agent-id", "x-principal", "x-forwarded-user", "x-api-key-principal",
        "bearer-of-a"])
def test_identity_cannot_come_from_other_headers(dep, headers):
    """Agent B's key with every header a confused proxy might trust: B stays B."""
    g = dep.gateway()
    _blocked(g.execute(dep.mandate(), key=KEY_B, actor=A, headers=headers), "AGENT_PRINCIPAL_MISMATCH")
    g.assert_nothing_happened()


@pytest.mark.parametrize("field", ["principal_id", "agent", "authenticated_agent", "tenant_id"])
def test_identity_cannot_come_from_the_body(dep, field):
    g = dep.gateway()
    r = g.post("/mandates/execute", {"mandate": dep.mandate(), "actor": A, "action": ACTION,
                                     "resource": RESOURCE, "context": payment(), "idempotency_key": "k",
                                     field: A}, key=KEY_B)
    assert r.status_code == 422, r.text                   # strict schema: unknown field refused
    g.assert_nothing_happened()


def test_rotated_credentials_both_work_and_revoking_one_blocks_only_it():
    d = Deployment()
    g = d.gateway()
    assert g.execute(d.mandate(), key=KEY_A, idem="k-1").json()["status"] == "EXECUTED"
    assert g.execute(d.mandate(), key=KEY_A2, idem="k-2").json()["status"] == "EXECUTED"
    d2 = Deployment(revoke_a2=True)
    g2 = d2.gateway()
    assert g2.execute(d2.mandate(), key=KEY_A2).status_code == 403
    assert g2.execute(d2.mandate(), key=KEY_A, idem="k-3").json()["status"] == "EXECUTED"


# ===========================================================================
# 3. Cross-tenant execution stays blocked (PR #134 unchanged)
# ===========================================================================

def test_cross_tenant_remains_blocked(dep):
    gb = dep.gateway("tenant-B")
    # C is authenticated in tenant-B; A's tenant-A mandate is still refused there.
    _blocked(gb.execute(dep.mandate(), key=KEY_C, actor=A), "AGENT_PRINCIPAL_MISMATCH")
    _blocked(gb.execute(dep.mandate(), key=KEY_C, actor=C, idem="k-2"), "SUBJECT_MISMATCH")
    # A mandate for C bound to tenant-A cannot run in tenant-B either.
    _blocked(gb.execute(dep.mandate(subject=C, tenant_id="tenant-A"), key=KEY_C, actor=C, idem="k-3"),
             "MANDATE_TENANT_MISMATCH")
    gb.assert_nothing_happened()
    ok = gb.execute(dep.mandate(subject=C, tenant_id="tenant-B"), key=KEY_C, actor=C, idem="k-4")
    assert ok.json()["status"] == "EXECUTED" and len(gb.calls) == 1


# ===========================================================================
# 4. Approvals: creation and both execution routes
# ===========================================================================

def test_agent_cannot_request_approval_in_another_agents_name(dep):
    g = dep.gateway()
    r = g.create_approval(key=KEY_B, actor=A)
    assert r.status_code == 403 and "AGENT_PRINCIPAL_MISMATCH" in r.text, r.text
    assert g.approvals.registry._records == {}
    g.assert_nothing_happened()


@pytest.mark.parametrize("route", ["approval", "mandate"])
def test_other_agent_cannot_execute_as_approvals_subject(dep, route):
    g = dep.gateway()
    rid, m = g.approved()
    _blocked(g.execute(m, key=KEY_B, actor=A, route=route, rid=rid), "AGENT_PRINCIPAL_MISMATCH")
    _blocked(g.execute(m, key=KEY_B, actor=B, route=route, rid=rid, idem="k-2"), "SUBJECT_MISMATCH")
    g.assert_nothing_happened()
    assert g.state(rid) == "APPROVED"                         # not consumed by the rejected attempts


@pytest.mark.parametrize("route", ["approval", "mandate"])
def test_approval_executes_once_for_its_subject_then_is_single_use(dep, route):
    g = dep.gateway()
    rid, m = g.approved()
    _blocked(g.execute(m, key=KEY_B, actor=A, route=route, rid=rid, idem="shared"),
             "AGENT_PRINCIPAL_MISMATCH")
    r = g.execute(m, key=KEY_A, route=route, rid=rid, idem="shared")    # legitimate retry
    assert r.json()["status"] == "EXECUTED", r.text
    again = g.execute(m, key=KEY_A, route=route, rid=rid, idem="again")
    assert again.json()["status"] == "BLOCKED", again.text
    assert len(g.calls) == 1


@pytest.mark.parametrize("route", ["approval", "mandate"])
@pytest.mark.parametrize("field,value", [("context", payment(beneficiary="attacker", amount=999.0)),
                                         ("transaction_id", "tx-evil"),
                                         ("action", "pay_vendor")],
                         ids=["payload", "transaction", "action"])
def test_substitution_blocked_even_for_the_right_agent(dep, route, field, value):
    g = dep.gateway()
    rid, m = g.approved()
    r = g.execute(m, key=KEY_A, route=route, rid=rid, **{field: value})
    assert r.json()["status"] == "BLOCKED", r.text
    assert g.calls == [] and g.state(rid) == "APPROVED"


def test_standing_mandate_substitution_blocked_for_the_right_agent(dep):
    g = dep.gateway()
    _blocked(g.execute(dep.mandate(), key=KEY_A, action="pay_vendor"), "ACTION_SCOPE")
    _blocked(g.execute(dep.mandate(), key=KEY_A, resource="acct-2", idem="k-2"), "RESOURCE_SCOPE")
    g.assert_nothing_happened()


# ===========================================================================
# 5. Library trust boundary and modes
# ===========================================================================

def test_service_without_agent_is_refused_never_falls_back_to_actor(dep):
    g = dep.gateway()
    out = asyncio.run(g.service.execute_with_mandate(
        mandate=dep.mandate(), actor=A, action=ACTION, resource=RESOURCE, context=payment(),
        idempotency_key="k", tenant_id="tenant-A"))
    assert out.status == "BLOCKED" and "AGENT_IDENTITY_REQUIRED" in out.reason, out
    g.assert_nothing_happened()


@pytest.mark.parametrize("fake", [A, {"tenant_id": "tenant-A", "principal_id": A}, object()],
                         ids=["str", "dict", "object"])
def test_service_rejects_an_untrusted_identity_object(dep, fake):
    g = dep.gateway()
    out = asyncio.run(g.service.execute_with_mandate(
        mandate=dep.mandate(), actor=A, action=ACTION, resource=RESOURCE, context=payment(),
        idempotency_key="k", tenant_id="tenant-A", agent=fake))
    assert out.status == "BLOCKED" and "AGENT_IDENTITY_INVALID" in out.reason, out
    g.assert_nothing_happened()


def test_service_with_trusted_agent_executes(dep):
    g = dep.gateway()
    out = asyncio.run(g.service.execute_with_mandate(
        mandate=dep.mandate(), actor=A, action=ACTION, resource=RESOURCE, context=payment(),
        idempotency_key="k", tenant_id="tenant-A",
        agent=AuthenticatedAgent("tenant-A", A, "cred-a-1")))
    assert out.status == "EXECUTED", out


def test_no_registry_configured_fails_closed_on_identity_routes(dep):
    g = dep.gateway(with_registry=False)
    r = g.execute(dep.mandate(), key=SHARED["tenant-A"])
    assert r.status_code == 403 and "AGENT_IDENTITY_REQUIRED" in r.text
    g.assert_nothing_happened()


def test_legacy_mode_is_explicit_and_documents_no_protection(dep):
    """Explicit legacy-shared-key: the shared key works with a caller-asserted
    actor (the pre-remediation exposure, documented), but a REGISTERED key is
    still bound to its principal."""
    g = dep.gateway(mode=AGENT_IDENTITY_LEGACY)
    assert g.execute(dep.mandate(), key=SHARED["tenant-A"], actor=A).json()["status"] == "EXECUTED"
    _blocked(g.execute(dep.mandate(), key=KEY_B, actor=A, idem="k-2"), "AGENT_PRINCIPAL_MISMATCH")


def test_modes_default_strict_and_unknown_refuses(monkeypatch):
    monkeypatch.delenv("MCC_AGENT_IDENTITY_MODE", raising=False)
    assert agent_identity_mode_from_env({}) == AGENT_IDENTITY_STRICT
    with pytest.raises(ValueError):
        agent_identity_mode_from_env({"MCC_AGENT_IDENTITY_MODE": "off"})
    assert agent_identity_error(None, tenant_id="t", actor="a", mode=AGENT_IDENTITY_STRICT)
    assert agent_identity_error(None, tenant_id="t", actor="a", mode="off")


@pytest.mark.parametrize("bad", [
    {"agents": [{"credential_id": "c", "tenant_id": "t", "principal_id": "p",
                 "key_sha256": hash_agent_key("k"), "status": "active"}] * 2},
    {"agents": [{"credential_id": "c", "tenant_id": "t", "principal_id": "p",
                 "key_sha256": "XYZ", "status": "active"}]},
    {"agents": [{"credential_id": "c", "tenant_id": "", "principal_id": "p",
                 "key_sha256": hash_agent_key("k"), "status": "active"}]},
    {"agents": [{"credential_id": "c", "tenant_id": "t", "principal_id": "p",
                 "key_sha256": hash_agent_key("k"), "status": "maybe"}]},
    {"agents": [{"credential_id": "c", "tenant_id": "t", "principal_id": "p",
                 "key_sha256": hash_agent_key("k"), "status": "active", "role": "admin"}]},
    {"agents": [{"credential_id": "c1", "tenant_id": "t", "principal_id": "p1",
                 "key_sha256": hash_agent_key("k"), "status": "active"},
                {"credential_id": "c2", "tenant_id": "t", "principal_id": "p2",
                 "key_sha256": hash_agent_key("k"), "status": "active"}]},
    {"agents": "nope"}, [], {"agents": [], "extra": 1},
], ids=["duplicate-entry", "bad-hash", "empty-tenant", "unknown-status", "unknown-field",
        "one-key-two-principals", "agents-not-list", "not-object", "extra-top-level"])
def test_ambiguous_or_malformed_registry_refuses_to_load(bad):
    with pytest.raises(AgentCredentialConfigError):
        AgentCredentialRegistry.from_config(bad)


def test_builder_reads_registry_and_refuses_a_bad_file(tmp_path, monkeypatch):
    from gateway.governance_api import AgentCredentialRegistry as R  # same class the builder uses
    good = tmp_path / "agents.json"
    good.write_text(json.dumps({"agents": [{"credential_id": "c", "tenant_id": "t", "principal_id": "p",
                                            "key_sha256": hash_agent_key("k"), "status": "active"}]}))
    assert len(R.from_file(str(good))) == 1
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(AgentCredentialConfigError):
        R.from_file(str(bad))


def test_shared_tenant_key_also_registered_as_agent_credential_refuses_to_mount(dep):
    """One secret cannot mean both 'any agent of this tenant' and 'agent A'."""
    from gateway.agent_identity import AgentCredentialConfigError as Err
    reg = AgentCredentialRegistry.from_config({"agents": [
        {"credential_id": "c", "tenant_id": "tenant-A", "principal_id": A,
         "key_sha256": hash_agent_key(SHARED["tenant-A"]), "status": "active"}]})
    g = dep.gateway()
    with pytest.raises(Err):
        mount_mandate_routes(FastAPI(), g.service, api_key=SHARED["tenant-A"], operator_key="op",
                             tenant_id="tenant-A", agent_credentials=reg)
