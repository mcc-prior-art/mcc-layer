"""R2 remediation regression suite -- non-finite and negative numeric values.

R2 (internal red-team assessment, redteam/ at cb5bd33, V02 x8): the shared
constraint comparison ``value > bound`` / ``value < bound`` is False for NaN,
and ``-inf`` / negative values satisfy ``value <= max``. A mandate with
``max_amount=5000`` therefore authorized -- and the actuator received --
``amount=NaN``, ``-inf``, ``-1e6`` (and ``"nan"`` / ``"-1e9"`` strings, which the
payment profile coerces with ``float()``). The same class of defect existed in
``DelegationAuthority`` (NaN passes ``amount <= 0 or amount > max``) and the
``main.py`` local fallback policy (``-inf``/negative satisfy ``<= 5000``).

Invariant under test:
  * a number that must be finite is rejected when it is NaN, +inf or -inf;
  * a number that must be non-negative is rejected when it is negative;
  * valid boundaries (0 and the exact ceiling) still work, and an over-ceiling
    FINITE value still CONSTRAINs (clamps) exactly as before.

Every actuating route asserts on the actuator itself: ZERO calls for an invalid
input and EXACTLY ONE call for the valid authorized request. Decision-only
routes (the two ``/evaluate`` services) assert that no executable signed token
is issued. Delegation has no HTTP route, so it is tested at the service
boundary (stated, not hidden).
"""
from __future__ import annotations

import json
import math
import tempfile
import time
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcc_core import (
    ApprovalService,
    AuditLog,
    ConsensusPolicy,
    ConsensusVerifier,
    DecisionEngine,
    DelegationVerifier,
    EnforcementCoordinator,
    ExecutionGate,
    InMemoryApprovalRegistry,
    InMemoryIdempotencyRegistry,
    InMemoryNonceRegistry,
    InMemoryRevocationRegistry,
    InMemoryVelocityRegistry,
    ProfileRegistry,
    SigningKey,
    issue_delegation,
    issue_vote,
)
from mcc_core.mandate import issue_mandate

from gateway.governance_api import (
    mount_approval_routes,
    mount_consensus_routes,
    mount_mandate_routes,
)
from gateway.governance_service import GovernanceService
from gateway.trust import TrustSet

from tests._agent_credentials import registry as agent_registry  # noqa: E402
from tests._agent_credentials import shared_tenant_key  # noqa: E402

POLICY = "sha256:" + "0" * 64
AGENT = {"x-api-key": "agent-key"}
OP = {"x-operator-key": "op-key"}
ACTOR = "agent/payments-bot"
RESOURCE = "acct-1"
FUTURE = 4_000_000_000
NAN = float("nan")
INF = float("inf")

# Values a finite, non-negative amount must never take. Strings are included
# because PaymentProfile coerces ``amount`` with float().
NON_FINITE = [("nan", NAN), ("pos-inf", INF), ("neg-inf", -INF),
              ("nan-string", "nan"), ("inf-string", "inf"), ("neg-inf-string", "-inf"),
              ("Infinity-string", "Infinity")]
NEGATIVE = [("neg-small", -0.01), ("neg-1", -1), ("neg-million", -1_000_000.0),
            ("neg-string", "-1e9")]
INVALID_AMOUNTS = NON_FINITE + NEGATIVE
INVALID_IDS = [i for i, _ in INVALID_AMOUNTS]
# Generic (non-payment) actions: no float() coercion, so only real numbers matter.
INVALID_GENERIC = [("nan", NAN), ("pos-inf", INF), ("neg-inf", -INF), ("neg", -50), ("neg-small", -0.5)]


def post_json(client, url, headers, body):
    """POST ``body`` as raw JSON with the non-standard NaN/Infinity literals
    allowed. httpx's ``json=`` refuses them, but a hostile client can send
    them and Starlette's ``json.loads`` accepts them, so the routes must be
    tested with exactly that wire format."""
    return client.post(url, headers={**headers, "content-type": "application/json"},
                       content=json.dumps(body, allow_nan=True))


def payment(amount=100.0, **kw):
    ctx = {"source": RESOURCE, "beneficiary_id": "vendor-42", "amount": amount, "currency": "EUR"}
    ctx.update(kw)
    return ctx


def _audit():
    return AuditLog(str(Path(tempfile.mkdtemp(prefix="mcc-r2-")) / "audit.jsonl"))


# ===========================================================================
# Governance gateway: /mandates/execute, /approvals/{id}/execute, /consensus/execute
# ===========================================================================

class GovGateway:
    def __init__(self):
        self.issuer = SigningKey.generate("treasury-1")
        self.approver = SigningKey.generate("mcc-approver-1")
        self.evals = [SigningKey.generate(f"eval-{i}") for i in range(3)]
        self.trust = TrustSet()
        self.trust.add_runtime_issuer("issuer/treasury", self.issuer.kid, self.issuer.public_key())
        self.trust.add_runtime_issuer("mcc/approvals", self.approver.kid, self.approver.public_key())
        dk = SigningKey.generate("gw-1")
        engine = DecisionEngine(signing_key=dk, issuer="mcc/core", audience="gate",
                                policy_id="pilot/v1", policy_hash=POLICY, token_ttl_seconds=60)
        gate = ExecutionGate(trusted_keys={dk.kid: dk.public_key()}, audience="gate",
                             nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY)
        self.revocation = InMemoryRevocationRegistry()
        self.approvals = ApprovalService(InMemoryApprovalRegistry(), self.approver)
        self.coordinator = EnforcementCoordinator(
            gate=gate, idempotency=InMemoryIdempotencyRegistry(),
            velocity=InMemoryVelocityRegistry(), audit=_audit(),
            profiles=ProfileRegistry.default_pilot(), revocation_registry=self.revocation,
            approvals=self.approvals)
        self.calls: list = []

        async def upstream(action, payload):
            self.calls.append((action, dict(payload)))
            return {"ok": True}

        verifier = ConsensusVerifier(trusted_keys={k.kid: k.public_key() for k in self.evals},
                                     policy=ConsensusPolicy(threshold=3))
        self.service = GovernanceService(
            engine=engine, coordinator=self.coordinator, trust_set=self.trust,
            revocation_registry=self.revocation, approvals=self.approvals,
            upstream=upstream, policy_hash=POLICY, consensus_verifier=verifier)
        app = FastAPI()
        for mount in (mount_mandate_routes, mount_approval_routes, mount_consensus_routes):
            # V05 (part 2): "agent-key" (the AGENT header) is ACTOR's registered
            # per-agent credential; the mount's shared tenant key is a separate,
            # unused value.
            mount(app, self.service, api_key=shared_tenant_key("agent-key"), operator_key="op-key",
                  tenant_id="tenant-1", agent_credentials=agent_registry("tenant-1", {ACTOR: "agent-key"}))
        self.client = TestClient(app)
        self._n = 0

    def _idem(self):
        self._n += 1
        return f"op-{self._n}"

    def mandate(self, *, action="send_payment", resource_scope=(RESOURCE,), constraints=None):
        now = int(time.time())
        return issue_mandate(self.issuer, issuer="issuer/treasury", subject=ACTOR,
                             action_scope=[action], resource_scope=list(resource_scope),
                             constraints={"max_amount": 5000} if constraints is None else constraints,
                             not_before=now - 10, not_after=now + 3600, issued_at=now - 10,
                             policy_hash=POLICY,
                             # V05: bound to this gateway's mounted tenant (strict tenant mode).
                             tenant_id="tenant-1")

    def mandate_execute(self, context, *, action="send_payment", resource=RESOURCE, mandate=None):
        r = post_json(self.client, "/mandates/execute", AGENT, {
            "mandate": mandate or self.mandate(), "actor": ACTOR, "action": action,
            "resource": resource, "context": context, "idempotency_key": self._idem()})
        assert r.status_code == 200, r.text
        return r.json()

    def approval_execute(self, context, *, constraints=None):
        """Human approves EXACTLY this (possibly malformed) payload -- in its
        canonical form, so the R1 exact-payload binding matches and only R2 can
        stop it -- under the given approval constraints; the agent executes it."""
        approved = dict(context)
        try:
            approved["amount"] = float(approved["amount"])
        except (TypeError, ValueError):
            pass
        body = {"actor": ACTOR, "action": "send_payment", "resource": RESOURCE,
                "transaction_id": "tx-1", "policy_hash": POLICY, "payload": approved,
                "constraints": {"max_amount": 5000} if constraints is None else constraints}
        r = post_json(self.client, "/approvals", AGENT, body)
        assert r.status_code == 200, r.text
        rid = r.json()["request_id"]
        a = self.client.post(f"/approvals/{rid}/approve", headers=OP)
        assert a.status_code == 200, a.text
        r = post_json(self.client, f"/approvals/{rid}/execute", AGENT, {
            "mandate": a.json()["mandate"], "actor": ACTOR, "action": "send_payment",
            "resource": RESOURCE, "context": context, "transaction_id": "tx-1",
            "idempotency_key": self._idem()})
        assert r.status_code == 200, r.text
        return r.json()

    def consensus_execute(self, context, *, action="send_payment", resource=RESOURCE):
        nonce = f"n-{self._idem()}"
        # Evaluators sign the exact canonical payload. If the profile itself
        # rejects the context, sign the raw context and STILL send the request:
        # the gateway must reject it on its own, never because the test skipped it.
        try:
            signed = ProfileRegistry.default_pilot().for_action(action).canonical_payload(context)
        except Exception:
            signed = context
        votes = [issue_vote(k, evaluator_id=k.kid, verdict="ALLOW", action=action, payload=signed,
                            actor=ACTOR, resource=resource, policy_hash=POLICY, nonce=nonce,
                            not_before=0, not_after=FUTURE,
                            tenant_id="tenant-1") for k in self.evals]   # F1: tenant-bound
        r = post_json(self.client, "/consensus/execute", AGENT, {
            "votes": votes, "actor": ACTOR, "action": action, "resource": resource,
            "context": context, "nonce": nonce, "idempotency_key": self._idem()})
        assert r.status_code == 200, r.text
        return r.json()


@pytest.fixture
def gw():
    return GovGateway()


# ---- /mandates/execute ----

@pytest.mark.parametrize("amount", [a for _, a in INVALID_AMOUNTS], ids=INVALID_IDS)
def test_mandates_execute_rejects_invalid_amount(gw, amount):
    out = gw.mandate_execute(payment(amount))
    assert out["status"] == "BLOCKED", out
    assert gw.calls == []


@pytest.mark.parametrize("value", [v for _, v in INVALID_GENERIC], ids=[i for i, _ in INVALID_GENERIC])
def test_mandates_execute_rejects_invalid_generic_max_value(gw, value):
    m = gw.mandate(action="discount_offer", resource_scope=(),
                   constraints={"max_requested_discount_percent": 20})
    out = gw.mandate_execute({"requested_discount_percent": value}, action="discount_offer",
                             resource=None, mandate=m)
    assert out["status"] == "BLOCKED", out
    assert gw.calls == []


@pytest.mark.parametrize("value", [NAN, INF, -INF], ids=["nan", "pos-inf", "neg-inf"])
def test_mandates_execute_rejects_non_finite_against_min_constraint(gw, value):
    m = gw.mandate(action="adjust_setting", resource_scope=(),
                   constraints={"min_replicas": 1})
    out = gw.mandate_execute({"replicas": value}, action="adjust_setting", resource=None, mandate=m)
    assert out["status"] == "BLOCKED", out
    assert gw.calls == []


@pytest.mark.parametrize("amount,decision,executed", [
    (0, "ALLOW", 0.0), (0.0, "ALLOW", 0.0), (-0.0, "ALLOW", 0.0), (100.0, "ALLOW", 100.0),
    (5000, "ALLOW", 5000.0), ("4999.99", "ALLOW", 4999.99),
    (7500, "CONSTRAIN", 5000), (1e300, "CONSTRAIN", 5000),
], ids=["zero", "zero-float", "neg-zero", "typical", "exact-ceiling", "numeric-string",
        "over-ceiling-clamped", "huge-finite-clamped"])
def test_mandates_execute_valid_boundaries_execute_exactly_once(gw, amount, decision, executed):
    out = gw.mandate_execute(payment(amount))
    assert out["status"] == "EXECUTED" and out["decision"] == decision, out
    assert len(gw.calls) == 1
    assert gw.calls[0][1]["amount"] == executed


@pytest.mark.parametrize("value,decision,executed", [(0, "ALLOW", 0), (20, "ALLOW", 20),
                                                     (25, "CONSTRAIN", 20)],
                         ids=["zero", "exact-ceiling", "over-clamped"])
def test_generic_max_valid_boundaries_execute_exactly_once(gw, value, decision, executed):
    m = gw.mandate(action="discount_offer", resource_scope=(),
                   constraints={"max_requested_discount_percent": 20})
    out = gw.mandate_execute({"requested_discount_percent": value}, action="discount_offer",
                             resource=None, mandate=m)
    assert out["status"] == "EXECUTED" and out["decision"] == decision, out
    assert gw.calls == [("discount_offer", {"requested_discount_percent": executed})]


def test_explicit_min_constraint_still_permits_its_own_negative_range(gw):
    """An explicit ``min_`` defines the lower bound: only the implicit
    non-negativity of an otherwise unbounded-below ``max_`` field is new."""
    m = gw.mandate(action="adjust_setting", resource_scope=(),
                   constraints={"min_delta": -10, "max_delta": 10})
    out = gw.mandate_execute({"delta": -5}, action="adjust_setting", resource=None, mandate=m)
    assert out["status"] == "EXECUTED" and out["decision"] == "ALLOW", out
    assert gw.calls == [("adjust_setting", {"delta": -5})]


def test_non_finite_constraint_bound_fails_closed(gw):
    m = gw.mandate(constraints={"max_amount": NAN})
    out = gw.mandate_execute(payment(100.0), mandate=m)
    assert out["status"] == "BLOCKED", out
    assert gw.calls == []


# ---- /approvals/{id}/execute ----

@pytest.mark.parametrize("amount", [NAN, INF, -INF, "nan", -1_000_000.0, "-1e9"],
                         ids=["nan", "pos-inf", "neg-inf", "nan-string", "neg-million", "neg-string"])
def test_approval_execute_rejects_invalid_amount_even_if_human_approved_it(gw, amount):
    out = gw.approval_execute(payment(amount))
    assert out["status"] == "BLOCKED", out
    assert gw.calls == []


@pytest.mark.parametrize("amount", [NAN, -1_000_000.0], ids=["nan", "neg-million"])
def test_approval_execute_rejects_invalid_amount_without_constraints(gw, amount):
    out = gw.approval_execute(payment(amount), constraints={})
    assert out["status"] == "BLOCKED", out
    assert gw.calls == []


@pytest.mark.parametrize("amount", [0.0, 100.0, 5000.0], ids=["zero", "typical", "exact-ceiling"])
def test_approval_execute_valid_executes_exactly_once(gw, amount):
    out = gw.approval_execute(payment(amount))
    assert out["status"] == "EXECUTED", out
    assert gw.calls == [("send_payment", payment(amount))]


# ---- /consensus/execute ----

@pytest.mark.parametrize("amount", [a for _, a in INVALID_AMOUNTS], ids=INVALID_IDS)
def test_consensus_execute_rejects_invalid_payment_amount(gw, amount):
    out = gw.consensus_execute(payment(amount))
    assert out["status"] == "BLOCKED", out
    assert gw.calls == []


@pytest.mark.parametrize("amount", [0.0, 100.0], ids=["zero", "typical"])
def test_consensus_execute_valid_executes_exactly_once(gw, amount):
    out = gw.consensus_execute(payment(amount))
    assert out["status"] == "EXECUTED", out
    assert gw.calls == [("send_payment", payment(amount))]


# ===========================================================================
# Enforced egress proxy: POST /v1/http/execute  (constraint max_body.amount)
# ===========================================================================

@pytest.fixture
def egress():
    from tests._egress_harness import EgressHarness
    return EgressHarness(max_amount=5000)


def _audit_kinds(path):
    if not Path(path).exists():
        return []
    return [json.loads(line).get("kind") for line in open(path, encoding="utf-8") if line.strip()]


def _egress_post(hz, **fields):
    return post_json(hz.client, "/v1/http/execute", hz.H, {"resource": "acct-1", **fields})


def _egress_run(hz, amount, idem):
    url = hz.url("/charge")
    body = {"amount": amount}
    r1 = _egress_post(hz, method="POST", url=url, body=body, actor="agent/egress",
                      transaction_id=idem, idempotency_key=idem).json()
    if r1.get("outcome") != "CONSENSUS_REQUIRED":
        return r1
    action = hz.canonical(method="POST", url=url, body=body)
    r2 = _egress_post(hz, method="POST", url=url, body=body, actor="agent/egress", transaction_id=idem,
                      idempotency_key=idem, challenge_id=r1["challenge_id"],
                 votes=hz.votes(action, actor="agent/egress", nonce=r1["nonce"]))
    return r2.json()


@pytest.mark.parametrize("amount", [NAN, INF, -INF, -1, -1_000_000.0],
                         ids=["nan", "pos-inf", "neg-inf", "neg-1", "neg-million"])
def test_egress_rejects_invalid_body_amount(egress, amount):
    out = _egress_run(egress, amount, "e-bad")
    assert out.get("executed") is not True, out
    assert out.get("outcome") not in ("ALLOW", "CONSTRAIN"), out
    assert egress.seen == []
    assert egress.executor.count() == 0
    # ``executor.count()`` only records SUCCESSFUL calls. On main, NaN/-inf were
    # authorized (pre_actuation ALLOW) and the executor WAS invoked -- it only
    # failed later serializing NaN (actuation_unknown). The audit chain proves
    # the actuator was never reached: no pre_actuation / actuation_* record.
    kinds = _audit_kinds(egress.settings.audit_log_path)
    assert not [k for k in kinds if k == "pre_actuation" or str(k).startswith("actuation_")
                and k != "actuation_rejected"], kinds


@pytest.mark.parametrize("amount,outcome,received", [(0, "ALLOW", 0), (5000, "ALLOW", 5000),
                                                     (7500, "CONSTRAIN", 5000)],
                         ids=["zero", "exact-ceiling", "over-clamped"])
def test_egress_valid_amount_executes_exactly_once(egress, amount, outcome, received):
    out = _egress_run(egress, amount, "e-ok")
    if outcome == "CONSTRAIN":
        # CONSTRAIN rewrites the body -> the egress runtime requires a fresh
        # consensus round over the clamped action before it can execute.
        assert out["outcome"] == "CONSTRAIN", out
        url = egress.url("/charge")
        body = {"amount": received}
        r1 = egress.post(method="POST", url=url, body=body, actor="agent/egress",
                         transaction_id="e-ok2", idempotency_key="e-ok2").json()
        action = egress.canonical(method="POST", url=url, body=body)
        out = egress.post(method="POST", url=url, body=body, actor="agent/egress",
                          transaction_id="e-ok2", idempotency_key="e-ok2",
                          challenge_id=r1["challenge_id"],
                          votes=egress.votes(action, actor="agent/egress", nonce=r1["nonce"])).json()
    assert out["executed"] is True, out
    assert egress.executor.count() == 1
    assert [s["body"]["amount"] for s in egress.seen] == [received]


# ===========================================================================
# Decision services (issue tokens, no actuator): gateway/app.py and main.py /evaluate
# ===========================================================================

@pytest.fixture
def gateway_app(monkeypatch, tmp_path):
    import gateway.app as gwapp
    monkeypatch.setattr(gwapp.settings, "audit_log_path", str(tmp_path / "audit.jsonl"))
    monkeypatch.setattr(gwapp, "gateway", gwapp.Gateway())
    return gwapp, TestClient(gwapp.app)


def _gw_evaluate(gateway_app, action, context, identity=ACTOR):
    gwapp, client = gateway_app
    r = post_json(client, "/evaluate", {"x-api-key": gwapp.settings.api_key},
                  {"identity": identity, "action": action, "context": context})
    assert r.status_code == 200, r.text
    return r.json()


@pytest.mark.parametrize("amount", [NAN, INF, -INF, -0.01, -1_000_000.0],
                         ids=["nan", "pos-inf", "neg-inf", "neg-small", "neg-million"])
def test_gateway_evaluate_issues_no_token_for_invalid_amount(gateway_app, amount):
    out = _gw_evaluate(gateway_app, "send_payment", {"amount": amount})
    assert out["decision"] not in ("ALLOW", "CONSTRAIN"), out
    assert out["decision_token"] is None


@pytest.mark.parametrize("value", [NAN, -INF, -1], ids=["nan", "neg-inf", "neg"])
def test_gateway_evaluate_issues_no_token_for_invalid_generic_value(gateway_app, value):
    out = _gw_evaluate(gateway_app, "discount_offer", {"requested_discount_percent": value},
                       identity="agent/axflow-clinic")
    assert out["decision"] not in ("ALLOW", "CONSTRAIN"), out
    assert out["decision_token"] is None


@pytest.mark.parametrize("value,decision", [(0, "ALLOW"), (20, "ALLOW"), (25, "CONSTRAIN")],
                         ids=["zero", "exact-ceiling", "over-clamped"])
def test_gateway_evaluate_valid_generic_value_still_issues_token(gateway_app, value, decision):
    out = _gw_evaluate(gateway_app, "discount_offer", {"requested_discount_percent": value},
                       identity="agent/axflow-clinic")
    assert out["decision"] == decision and out["decision_token"] is not None, out


@pytest.mark.parametrize("amount,decision", [(0, "ALLOW"), (5000, "ALLOW"), (7500, "CONSTRAIN")],
                         ids=["zero", "exact-ceiling", "over-clamped"])
def test_gateway_evaluate_valid_amount_still_issues_token(gateway_app, amount, decision):
    out = _gw_evaluate(gateway_app, "send_payment", {"amount": amount})
    assert out["decision"] == decision and out["decision_token"] is not None, out


@pytest.fixture
def main_app(monkeypatch, tmp_path):
    import main
    monkeypatch.setattr(main.settings, "use_opa", False)
    monkeypatch.setattr(main.settings, "audit_log_path", str(tmp_path / "audit.jsonl"))
    monkeypatch.setattr(main, "mcc", main.MCC())
    assert main.mcc.governance is None   # base mode: the fallback policy decides
    return main, TestClient(main.app)


def _main_evaluate(main_app, amount, sid):
    main, client = main_app
    r = post_json(client, "/evaluate", {"x-api-key": main.settings.api_key}, {
        "session_id": sid, "intent": "send_payment", "args": {"amount": amount}})
    assert r.status_code == 200, r.text
    return r.json()


@pytest.mark.parametrize("amount", [NAN, INF, -INF, "nan", "-inf", -0.01, -1_000_000.0, "-1e9"],
                         ids=["nan", "pos-inf", "neg-inf", "nan-string", "neg-inf-string",
                              "neg-small", "neg-million", "neg-string"])
def test_main_evaluate_fallback_issues_no_token_for_invalid_amount(main_app, amount):
    out = _main_evaluate(main_app, amount, f"s-{amount!r}")
    assert out["decision"] == "DENY", out
    assert out.get("decision_token") is None


@pytest.mark.parametrize("amount,decision", [(0, "ALLOW"), (5000, "ALLOW"), (7500, "ESCALATE"),
                                             (20000, "DENY")],
                         ids=["zero", "exact-ceiling", "escalate-band", "over-limit"])
def test_main_evaluate_fallback_valid_amounts_unchanged(main_app, amount, decision):
    out = _main_evaluate(main_app, amount, f"v-{amount}")
    assert out["decision"] == decision, out
    assert (out.get("decision_token") is not None) == (decision == "ALLOW")


# ===========================================================================
# Delegation (NO HTTP route exists -- service boundary GovernanceService.execute_with_delegation)
# ===========================================================================

class DelegationStack:
    def __init__(self):
        self.owner = SigningKey.generate("owner-1")
        dk = SigningKey.generate("gw-1")
        engine = DecisionEngine(signing_key=dk, issuer="mcc/core", audience="gate",
                                policy_id="pilot/v1", policy_hash=POLICY)
        gate = ExecutionGate(trusted_keys={dk.kid: dk.public_key()}, audience="gate",
                             nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY)
        coord = EnforcementCoordinator(
            gate=gate, idempotency=InMemoryIdempotencyRegistry(), velocity=InMemoryVelocityRegistry(),
            audit=_audit(), profiles=ProfileRegistry.default_pilot(),
            revocation_registry=InMemoryRevocationRegistry())
        self.calls: list = []

        async def upstream(action, payload):
            self.calls.append((action, dict(payload)))
            return {"ok": True}

        self.service = GovernanceService(
            engine=engine, coordinator=coord, trust_set=TrustSet(),
            revocation_registry=InMemoryRevocationRegistry(),
            approvals=ApprovalService(InMemoryApprovalRegistry(), SigningKey.generate("apr")),
            upstream=upstream, policy_hash=POLICY,
            delegation_verifier=DelegationVerifier(
                trusted_owner_keys={self.owner.kid: self.owner.public_key()},
                revocation_registry=InMemoryRevocationRegistry()))
        self._n = 0

    def delegation(self, max_amount=500.0):
        now = int(time.time())
        return issue_delegation(
            self.owner, owner_id="owner/alex", subject=ACTOR, tenant_id="tenant-1",
            purpose="vendor_payment", action_scope=["send_payment"], resource_scope=[RESOURCE],
            recipient_scope=["vendor-*"], currency="EUR", max_amount=max_amount,
            not_before=now - 10, not_after=now + 3600, issued_at=now - 10,
            consent_ref="sha256:consent-r2")

    def execute(self, amount, delegation=None):
        import asyncio
        self._n += 1
        return asyncio.run(self.service.execute_with_delegation(
            delegation=delegation or self.delegation(), actor=ACTOR, action="send_payment",
            resource=RESOURCE, purpose="vendor_payment", context=payment(amount),
            tenant_id="tenant-1", idempotency_key=f"d-{self._n}"))


@pytest.mark.parametrize("amount", [a for _, a in INVALID_AMOUNTS], ids=INVALID_IDS)
def test_delegation_rejects_invalid_amount(amount):
    s = DelegationStack()
    out = s.execute(amount)
    assert out.status == "BLOCKED", out
    assert s.calls == []


@pytest.mark.parametrize("amount", [100.0, 500.0], ids=["typical", "exact-ceiling"])
def test_delegation_valid_amount_executes_exactly_once(amount):
    s = DelegationStack()
    out = s.execute(amount)
    assert out.status == "EXECUTED", out
    assert s.calls == [("send_payment", payment(amount))]


@pytest.mark.parametrize("bad", [NAN, INF, -INF, -1.0, 0.0], ids=["nan", "pos-inf", "neg-inf", "neg", "zero"])
def test_delegation_issuance_rejects_unusable_max_amount(bad):
    with pytest.raises(ValueError):
        DelegationStack().delegation(max_amount=bad)


@pytest.mark.parametrize("amount", [NAN, INF, -INF], ids=["nan", "pos-inf", "neg-inf"])
def test_delegation_authority_itself_rejects_non_finite_amount(amount):
    """On main, a NaN amount passed DelegationAuthority (``nan <= 0`` and
    ``nan > max`` are both False) and was stopped only by the velocity layer.
    The authority must reject it on its own (defense in depth)."""
    import asyncio
    from mcc_core import DelegationAuthority
    s = DelegationStack()
    d = s.delegation()
    dec = asyncio.run(DelegationAuthority(s.service.delegation_verifier).authorize(
        d, subject=ACTOR, tenant_id="tenant-1", action="send_payment", resource=RESOURCE,
        recipient="vendor-42", currency="EUR", amount=amount, purpose="vendor_payment",
        policy_hash=POLICY))
    assert dec.verdict.value == "DENY", dec


def test_unit_constraint_helpers_reject_non_finite_and_negative():
    """Direct unit check of the shared trust-boundary helpers (both the
    gateway's MandateAuthority and the config AuthorityModel call these)."""
    from mcc_core.authority import _constraint_violations, apply_constraints
    c = {"max_amount": 5000}
    for bad in (NAN, INF, -INF, -1, -1e-9):
        assert _constraint_violations(c, {"amount": bad}), bad
        clamped, _ = apply_constraints(c, {"amount": bad})
        assert _constraint_violations(c, clamped), bad   # never clamped into compliance
    for ok in (0, 0.0, -0.0, 1, 5000):
        assert _constraint_violations(c, {"amount": ok}) == [], ok
    assert math.isfinite(apply_constraints(c, {"amount": 9e18})[0]["amount"])


# ===========================================================================
# R2 follow-up: booleans, unparseable / non-scalar values, missing amount
# ===========================================================================
#
# On e8f2b84 (the first R2 commit):
#   * a bool was accepted as a number everywhere (bool is an int subclass):
#     the egress upstream and generic actions RECEIVED the raw boolean the
#     policy had checked as 1/0, PaymentProfile turned ``true`` into a 1.0
#     payment (sidestepping delegation's own bool rejection), and both
#     /evaluate services issued ALLOW tokens;
#   * an unparseable / non-scalar payment amount ("abc", "", null, [1], {})
#     raised an unhandled exception (HTTP 500 / exception out of
#     execute_with_delegation) -- zero actuator calls, but no clean audited DENY;
#   * main.py's fallback substituted 0 for a MISSING amount and issued ALLOW.

BOOLS = [("true", True), ("false", False)]
UNPARSEABLE = [("abc", "abc"), ("empty", ""), ("null", None), ("list", [1]), ("object", {"a": 1}),
               ("overflow-string", "1e400")]


def _raw_ok(client):
    """Same app, but surface unhandled exceptions as HTTP 500 (what a real
    server returns) instead of re-raising them inside the test."""
    return TestClient(client.app, raise_server_exceptions=False)


@pytest.mark.parametrize("value", [v for _, v in BOOLS + UNPARSEABLE],
                         ids=[i for i, _ in BOOLS + UNPARSEABLE])
def test_mandates_execute_rejects_bool_and_unparseable_amount_cleanly(gw, value):
    gw.client = _raw_ok(gw.client)
    out = gw.mandate_execute(payment(value))   # asserts HTTP 200 (no unhandled 500)
    assert out["status"] == "BLOCKED" and out["decision"] == "DENY", out
    assert gw.calls == []


@pytest.mark.parametrize("value", [True, False], ids=["true", "false"])
def test_mandates_execute_rejects_bool_generic_value(gw, value):
    m = gw.mandate(action="discount_offer", resource_scope=(),
                   constraints={"max_requested_discount_percent": 20})
    out = gw.mandate_execute({"requested_discount_percent": value}, action="discount_offer",
                             resource=None, mandate=m)
    assert out["status"] == "BLOCKED", out
    assert gw.calls == []


@pytest.mark.parametrize("value", [True, "abc", None], ids=["true", "abc", "null"])
def test_approval_execute_rejects_bool_and_unparseable_amount(gw, value):
    gw.client = _raw_ok(gw.client)
    out = gw.approval_execute(payment(value))
    assert out["status"] == "BLOCKED", out
    assert gw.calls == []


@pytest.mark.parametrize("value", [True, "abc", None, [1]], ids=["true", "abc", "null", "list"])
def test_consensus_execute_rejects_bool_and_unparseable_amount_cleanly(gw, value):
    gw.client = _raw_ok(gw.client)
    out = gw.consensus_execute(payment(value))
    assert out["status"] == "BLOCKED", out
    assert gw.calls == []


@pytest.mark.parametrize("value", [True, False, "abc", None], ids=["true", "false", "abc", "null"])
def test_delegation_rejects_bool_and_unparseable_amount_without_raising(value):
    s = DelegationStack()
    out = s.execute(value)          # must return an outcome, never raise
    assert out.status == "BLOCKED", out
    assert s.calls == []


@pytest.mark.parametrize("value", [True, False], ids=["true", "false"])
def test_egress_rejects_bool_body_amount(egress, value):
    out = _egress_run(egress, value, "e-bool")
    assert out.get("executed") is not True and out.get("outcome") not in ("ALLOW", "CONSTRAIN"), out
    assert egress.seen == []
    assert "pre_actuation" not in _audit_kinds(egress.settings.audit_log_path)


@pytest.mark.parametrize("value", [True, False], ids=["true", "false"])
def test_gateway_evaluate_issues_no_token_for_bool_amount(gateway_app, value):
    out = _gw_evaluate(gateway_app, "send_payment", {"amount": value})
    assert out["decision"] not in ("ALLOW", "CONSTRAIN"), out
    assert out["decision_token"] is None


@pytest.mark.parametrize("value", [v for _, v in BOOLS + UNPARSEABLE],
                         ids=[i for i, _ in BOOLS + UNPARSEABLE])
def test_main_evaluate_fallback_rejects_bool_and_unparseable_cleanly(main_app, value):
    main, client = main_app
    r = post_json(_raw_ok(client), "/evaluate", {"x-api-key": main.settings.api_key}, {
        "session_id": f"u-{value!r}", "intent": "send_payment", "args": {"amount": value}})
    assert r.status_code == 200, r.text
    assert r.json()["decision"] == "DENY" and r.json().get("decision_token") is None


def test_main_evaluate_fallback_rejects_missing_amount(main_app):
    main, client = main_app
    r = post_json(client, "/evaluate", {"x-api-key": main.settings.api_key}, {
        "session_id": "missing", "intent": "send_payment", "args": {}})
    assert r.json()["decision"] == "DENY" and r.json().get("decision_token") is None


@pytest.mark.parametrize("amount,executed", [("1_000", 1000.0), (" 100 ", 100.0), ("4999.99", 4999.99)],
                         ids=["underscore", "whitespace", "decimal"])
def test_parseable_numeric_strings_still_execute_their_exact_value(gw, amount, executed):
    """Pre-existing behaviour preserved: a numeric string that parses is the
    exact amount authorized AND executed (canonical payload binds it)."""
    out = gw.mandate_execute(payment(amount))
    assert out["status"] == "EXECUTED", out
    assert [p["amount"] for _, p in gw.calls] == [executed]


# ===========================================================================
# main.py OPA path (MCC_USE_OPA=true) -- against a WORST-CASE allow-all OPA
# ===========================================================================
#
# No OPA binary is executed in this test suite (none is available in CI
# either). Instead the real OPAAdapter talks over real HTTP to a stub OPA
# server that ALLOWs everything -- the worst policy possible. The property
# under test is engine-independent: an invalid amount must never reach the
# policy engine and must never yield an ALLOW token, whatever the policy says.
# The canonical Rego itself is checked statically below.

ALL_INVALID = [v for _, v in INVALID_AMOUNTS + BOOLS + UNPARSEABLE]
ALL_INVALID_IDS = [i for i, _ in INVALID_AMOUNTS + BOOLS + UNPARSEABLE]


@pytest.fixture
def opa_main(monkeypatch, tmp_path):
    from examples._demo_server import DemoServer, free_port
    import main
    seen = []
    stub = FastAPI()

    @stub.post("/v1/data/{path:path}")
    async def data(path: str, body: dict):
        seen.append(body["input"])
        return {"result": {"decision": "ALLOW", "reason": "stub: allow-all", "constraints": {},
                           "policy_ref": "stub"}}

    port = free_port()
    server = DemoServer(stub, port).start()
    monkeypatch.setattr(main.settings, "use_opa", True)
    monkeypatch.setattr(main.settings, "opa_url", f"http://127.0.0.1:{port}")
    monkeypatch.setattr(main.settings, "audit_log_path", str(tmp_path / "audit.jsonl"))
    monkeypatch.setattr(main, "mcc", main.MCC())
    assert main.mcc.governance is None
    try:
        yield main, TestClient(main.app, raise_server_exceptions=False), seen
    finally:
        server.stop()


@pytest.mark.parametrize("amount", ALL_INVALID, ids=ALL_INVALID_IDS)
def test_main_opa_path_invalid_amount_never_reaches_opa_and_gets_no_token(opa_main, amount):
    main, client, seen = opa_main
    r = post_json(client, "/evaluate", {"x-api-key": main.settings.api_key}, {
        "session_id": f"o-{amount!r}", "intent": "send_payment", "args": {"amount": amount}})
    assert r.status_code == 200, r.text
    assert r.json()["decision"] == "DENY" and r.json().get("decision_token") is None, r.json()
    assert seen == []        # rejected before the policy engine was consulted


def test_main_opa_path_missing_amount_never_reaches_opa(opa_main):
    main, client, seen = opa_main
    r = post_json(client, "/evaluate", {"x-api-key": main.settings.api_key}, {
        "session_id": "o-missing", "intent": "send_payment", "args": {}})
    assert r.json()["decision"] == "DENY" and r.json().get("decision_token") is None
    assert seen == []


@pytest.mark.parametrize("amount", [0, 100, 5000], ids=["zero", "typical", "exact-ceiling"])
def test_main_opa_path_valid_amount_reaches_opa_exactly_once(opa_main, amount):
    main, client, seen = opa_main
    r = post_json(client, "/evaluate", {"x-api-key": main.settings.api_key}, {
        "session_id": f"ok-{amount}", "intent": "send_payment", "args": {"amount": amount}})
    assert r.json()["decision"] == "ALLOW" and r.json().get("decision_token") is not None
    assert [i["args"]["amount"] for i in seen] == [amount]


def test_main_opa_adapter_unserializable_input_is_a_denial_not_a_500(opa_main):
    """NaN anywhere in args (not just ``amount``, e.g. on an intent with no
    payment validation) is not JSON-serializable for OPA. It used to escape
    the adapter as an unhandled ValueError (HTTP 500); it is now a DENY."""
    main, client, seen = opa_main
    r = post_json(client, "/evaluate", {"x-api-key": main.settings.api_key}, {
        "session_id": "o-unser", "intent": "delete_user", "args": {"user_id": "u1", "score": NAN}})
    assert r.status_code == 200, r.text
    assert r.json()["decision"] == "DENY" and r.json().get("decision_token") is None
    assert seen == []


def test_canonical_rego_requires_a_non_negative_json_number_for_payments():
    """Static guard (no OPA binary in this environment or CI): both executable
    payment rules in the canonical policy must require ``is_number(amount)``,
    and ALLOW must require ``amount >= 0``; DENY stays the default."""
    import re
    src = (Path(__file__).resolve().parents[1] / "policies" / "mcc.rego").read_text()
    assert re.search(r'default decision := \{\s*"decision": "DENY"', src)
    rules = re.findall(r'decision := \{\s*"decision": "(ALLOW|ESCALATE)".*?"policy_ref": '
                       r'"mcc\.rego/send_payment/\w+"\s*\} if \{(.*?)\n\}', src, re.S)
    by_verdict = {v: body for v, body in rules}
    assert set(by_verdict) == {"ALLOW", "ESCALATE"}, by_verdict
    for verdict, body in by_verdict.items():
        assert "is_number(amount)" in body, verdict
    assert "amount >= 0" in by_verdict["ALLOW"]


# ===========================================================================
# main.py governance mode (challenge -> N-of-M quorum -> gate -> coordinator)
# ===========================================================================

@pytest.fixture
def gov_main(monkeypatch, tmp_path):
    import main
    evals = [SigningKey.generate(f"eval-{i}") for i in range(3)]
    trust = {"issuers": [{"issuer_id": f"e{i}", "enabled": True,
                          "keys": [{"kid": e.kid, "public_key_b64": e.public_key_b64(), "not_after": None}]}
                         for i, e in enumerate(evals)]}
    tf = tmp_path / "evaluators.json"
    tf.write_text(json.dumps(trust), encoding="utf-8")
    monkeypatch.setattr(main.settings, "use_opa", False)
    monkeypatch.setattr(main.settings, "consensus_trust_config", str(tf))
    monkeypatch.setattr(main.settings, "consensus_threshold", 3)
    monkeypatch.setattr(main.settings, "challenge_ttl_seconds", 120)
    monkeypatch.setattr(main.settings, "audit_log_path", str(tmp_path / "audit.jsonl"))
    mcc = main.MCC()
    assert mcc.governance is not None
    enforced = []
    real_enforce = mcc.governance.coordinator.enforce

    async def spy_enforce(**kw):
        enforced.append(kw.get("payload"))     # reaching enforce == reaching actuation
        return await real_enforce(**kw)

    mcc.governance.coordinator.enforce = spy_enforce
    monkeypatch.setattr(main, "mcc", mcc)
    return main, TestClient(main.app, raise_server_exceptions=False), evals, enforced


def _gov_decide(gov_main, amount, sid):
    main, client, evals, _ = gov_main
    H = {"x-api-key": main.settings.api_key}
    args = {"amount": amount}
    ch = post_json(client, "/evaluate/challenge", H, {"session_id": sid, "intent": "send_payment",
                                                      "args": args, "resource": "res-1"})
    assert ch.status_code == 200, ch.text
    ch = ch.json()
    votes = [issue_vote(e, evaluator_id=e.kid, verdict="ALLOW", action=ch["action"], payload=args,
                        actor=ch["actor"], resource=ch["resource"], policy_hash=ch["policy_hash"],
                        nonce=ch["nonce"], not_before=0, not_after=FUTURE) for e in evals]
    r = post_json(client, "/evaluate", H, {"session_id": sid, "intent": "send_payment", "args": args,
                                           "resource": "res-1", "challenge_id": ch["challenge_id"],
                                           "votes": votes, "idempotency_key": f"idem-{sid}"})
    assert r.status_code == 200, r.text
    return r.json()


@pytest.mark.parametrize("amount", ALL_INVALID, ids=ALL_INVALID_IDS)
def test_main_governance_mode_invalid_amount_full_quorum_still_no_token(gov_main, amount):
    """Even with a valid 3-of-3 quorum signed over the invalid payload, no
    ALLOW token is issued and the coordinator (actuation) is never reached."""
    out = _gov_decide(gov_main, amount, f"g-{ALL_INVALID.index(amount)}")
    assert out["decision"] == "DENY" and out.get("decision_token") is None, out
    assert gov_main[3] == []


@pytest.mark.parametrize("amount", [0, 100, 5000], ids=["zero", "typical", "exact-ceiling"])
def test_main_governance_mode_valid_amount_actuates_exactly_once(gov_main, amount):
    out = _gov_decide(gov_main, amount, f"v-{amount}")
    assert out["decision"] == "ALLOW" and out.get("decision_token") is not None, out
    assert gov_main[3] == [{"amount": amount}]
