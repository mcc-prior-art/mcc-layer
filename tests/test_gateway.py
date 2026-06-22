"""Gateway service tests: authority-driven /evaluate, signed tokens that pass
the execution gate, observe vs inline, and auditor verify/export.
"""

import asyncio

from fastapi.testclient import TestClient

from mcc_core import ExecutionGate, NonceRegistry, verify_token

import gateway.app as gw

run = asyncio.run


class FakeRedis:
    def __init__(self):
        self.store = {}

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.store:
            return None
        self.store[key] = value
        return True


def req(identity, action, context=None, mode=None):
    return gw.EvaluateRequest(
        identity=identity, action=action, context=context or {}, mode=mode
    )


def test_allow_returns_verifiable_signed_token():
    resp = gw.gateway.evaluate(
        req("agent/payments-bot", "send_payment", {"amount": 100}, mode="inline")
    )
    assert resp.decision == gw.Decision.ALLOW
    assert resp.decision_token is not None
    assert resp.signature == resp.decision_token["sig"]
    assert verify_token(resp.decision_token, gw.gateway.signing_key.public_key())
    assert resp.audit_id


def test_deny_returns_no_token():
    resp = gw.gateway.evaluate(req("agent/ops-bot", "delete_database", {}))
    assert resp.decision == gw.Decision.DENY
    assert resp.decision_token is None
    assert resp.signature is None


def test_constrain_rewrites_body_and_signs_over_it():
    resp = gw.gateway.evaluate(
        req("agent/payments-bot", "send_payment", {"amount": 99999}, mode="inline")
    )
    assert resp.decision == gw.Decision.CONSTRAIN
    assert resp.constraints == {"max_amount": 5000}
    # The body is rewritten and the token is signed over the rewritten body.
    assert resp.forward_context == {"amount": 5000}
    assert resp.applied_constraints
    # The token must verify against the clamped body through the gate.
    gate = ExecutionGate(
        trusted_keys={gw.gateway.signing_key.kid: gw.gateway.signing_key.public_key()},
        audience=gw.settings.token_audience,
        nonce_registry=NonceRegistry(FakeRedis()),
        policy_hash=gw.gateway.policy_hash,
    )
    result = run(
        gate.verify(
            resp.decision_token, action="send_payment", payload={"amount": 5000}
        )
    )
    assert result.allowed


def test_escalate_for_unknown_identity():
    resp = gw.gateway.evaluate(req("agent/nobody", "send_payment", {"amount": 1}))
    assert resp.decision == gw.Decision.ESCALATE
    assert resp.decision_token is None


def test_observe_mode_records_but_does_not_enforce():
    resp = gw.gateway.evaluate(req("agent/x", "delete_database", {}, mode="observe"))
    assert resp.decision == gw.Decision.DENY
    assert resp.enforce is False
    assert resp.audit_id  # still recorded


def test_inline_mode_enforces():
    resp = gw.gateway.evaluate(req("agent/x", "delete_database", {}, mode="inline"))
    assert resp.enforce is True


def test_token_passes_execution_gate():
    resp = gw.gateway.evaluate(
        req("agent/payments-bot", "send_payment", {"amount": 200}, mode="inline")
    )
    gate = ExecutionGate(
        trusted_keys={gw.gateway.signing_key.kid: gw.gateway.signing_key.public_key()},
        audience=gw.settings.token_audience,
        nonce_registry=NonceRegistry(FakeRedis()),
        policy_hash=gw.gateway.policy_hash,
    )
    result = run(
        gate.verify(
            resp.decision_token, action="send_payment", payload={"amount": 200}
        )
    )
    assert result.allowed


def test_token_policy_hash_binds_to_authority_config():
    resp = gw.gateway.evaluate(
        req("agent/payments-bot", "send_payment", {"amount": 10}, mode="inline")
    )
    assert resp.decision_token["policy_hash"] == gw.gateway.policy_hash


def test_verify_chain_after_evaluations():
    gw.gateway.evaluate(req("agent/payments-bot", "send_payment", {"amount": 1}))
    report = gw.gateway.verify_chain()
    assert report["valid"] is True
    assert report["entries"] >= 1


# ---- HTTP surface ----

client = TestClient(gw.app)
HEADERS = {"x-api-key": gw.settings.api_key}


def test_http_evaluate_requires_api_key():
    r = client.post("/evaluate", json={"identity": "a", "action": "x"})
    assert r.status_code in (401, 422)  # missing header


def test_http_evaluate_allow():
    r = client.post(
        "/evaluate",
        json={
            "identity": "agent/payments-bot",
            "action": "send_payment",
            "context": {"amount": 50},
            "mode": "inline",
        },
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "ALLOW"
    assert body["signature"]


def test_http_export_returns_signed_log():
    client.post(
        "/evaluate",
        json={"identity": "agent/ops-bot", "action": "read_account"},
        headers=HEADERS,
    )
    r = client.get("/export?fmt=json", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["signing"]["algorithm"] == "Ed25519"
    assert isinstance(body["entries"], list)
