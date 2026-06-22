"""Egress proxy tests.

These exercise the real enforcement path: a signed decision token verified
through an ExecutionGate (Ed25519 signature + single-use nonce + action/
payload binding), CONSTRAIN body rewriting, observe-mode transparency, and
fail-closed blocking on every error.
"""

import asyncio

from mcc_core import (
    DecisionEngine,
    ExecutionGate,
    InMemoryNonceRegistry,
    SigningKey,
)

from interceptors.egress_proxy import (
    ActionMapper,
    EgressGovernor,
    OutboundRequest,
    Route,
)

run = asyncio.run

AUDIENCE = "egress-gate-1"
POLICY_HASH = "sha256:pilotpolicy"


def mapper():
    return ActionMapper(
        [
            Route(action="send_payment", method="POST", host="*", path="*charge*"),
            Route(action="read_account", method="GET", host="*", path="*"),
            Route(action="delete_resource", method="DELETE", host="*", path="*"),
        ]
    )


def make_engine_and_gate():
    key = SigningKey.generate("proxy-test-key")
    engine = DecisionEngine(
        signing_key=key,
        issuer="mcc/test",
        audience=AUDIENCE,
        policy_id="pilot/v1",
        policy_hash=POLICY_HASH,
    )
    gate = ExecutionGate(
        trusted_keys={key.kid: key.public_key()},
        audience=AUDIENCE,
        nonce_registry=InMemoryNonceRegistry(),
        policy_hash=POLICY_HASH,
    )
    return engine, gate


def decide_signing(engine, *, verdict, action, forward_context, applied=None):
    """A decide() that signs a real token over the forwarded body, like the
    gateway does — so the gate's payload-hash check is meaningful."""

    async def decide(_payload):
        token = engine.issue_token(
            verdict=verdict,
            subject="agent/test",
            action=action,
            payload=forward_context,
            constraints={},
        )
        return {
            "decision": verdict,
            "enforce": True,
            "reason": verdict,
            "audit_id": "a1",
            "decision_token": token,
            "forward_context": forward_context,
            "applied_constraints": applied or [],
        }

    return decide


# ---- Action mapping ----

def test_action_mapper_matches_route():
    action, ctx = mapper().map(
        OutboundRequest(
            method="POST", url="http://payments.local/v1/charge", body={"amount": 100}
        )
    )
    assert action == "send_payment"
    assert ctx == {"amount": 100}


def test_action_mapper_unmapped_derives_deny_bound_action():
    action, _ = mapper().map(
        OutboundRequest(method="POST", url="http://evil.local/exfiltrate")
    )
    assert action == "post_evil.local"


# ---- ALLOW / CONSTRAIN forward, with token verification ----

def test_allow_forwards_after_gate_verifies():
    engine, gate = make_engine_and_gate()
    gov = EgressGovernor(
        mapper=mapper(),
        decide=decide_signing(
            engine, verdict="ALLOW", action="send_payment", forward_context={"amount": 10}
        ),
        gate=gate,
    )
    out = run(
        gov.govern(
            OutboundRequest(
                method="POST",
                url="http://payments.local/charge",
                headers={"X-MCC-Identity": "agent/payments-bot"},
                body={"amount": 10},
            )
        )
    )
    assert out.forward is True
    assert out.status_code == 200
    assert out.forward_body == {"amount": 10}


def test_constrain_forwards_rewritten_body():
    engine, gate = make_engine_and_gate()
    gov = EgressGovernor(
        mapper=mapper(),
        decide=decide_signing(
            engine,
            verdict="CONSTRAIN",
            action="send_payment",
            forward_context={"amount": 5000},
            applied=["amount: 99000 -> 5000 (max)"],
        ),
        gate=gate,
    )
    out = run(
        gov.govern(
            OutboundRequest(
                method="POST",
                url="http://payments.local/charge",
                body={"amount": 99000},
            )
        )
    )
    assert out.forward is True
    assert out.forward_body == {"amount": 5000}  # clamped body is what forwards
    assert out.applied_constraints


# ---- Signature + nonce enforcement (fail-closed) ----

def test_tampered_token_is_blocked():
    engine, gate = make_engine_and_gate()
    decide = decide_signing(
        engine, verdict="ALLOW", action="send_payment", forward_context={"amount": 10}
    )

    async def tampering_decide(payload):
        result = await decide(payload)
        result["decision_token"]["constraints"] = {"max_amount": 10 ** 12}  # break sig
        return result

    gov = EgressGovernor(mapper=mapper(), decide=tampering_decide, gate=gate)
    out = run(
        gov.govern(OutboundRequest(method="POST", url="http://x.local/charge", body={"amount": 10}))
    )
    assert out.forward is False
    assert out.status_code == 403
    assert "gate rejected token" in out.reason


def test_replayed_token_is_blocked_by_nonce():
    engine, gate = make_engine_and_gate()
    # Same token both times: the second use must fail the nonce check.
    token = engine.issue_token(
        verdict="ALLOW", subject="s", action="send_payment", payload={"amount": 10}
    )

    async def decide(_payload):
        return {
            "decision": "ALLOW",
            "enforce": True,
            "decision_token": token,
            "forward_context": {"amount": 10},
        }

    gov = EgressGovernor(mapper=mapper(), decide=decide, gate=gate)
    req = OutboundRequest(method="POST", url="http://x.local/charge", body={"amount": 10})
    first = run(gov.govern(req))
    second = run(gov.govern(req))
    assert first.forward is True
    assert second.forward is False
    assert "NONCE" in second.reason


def test_payload_mismatch_is_blocked():
    # Token authorizes amount=10, but the request body says amount=10000.
    engine, gate = make_engine_and_gate()

    async def decide(_payload):
        token = engine.issue_token(
            verdict="ALLOW", subject="s", action="send_payment", payload={"amount": 10}
        )
        return {
            "decision": "ALLOW",
            "enforce": True,
            "decision_token": token,
            "forward_context": {"amount": 10000},  # differs from signed payload
        }

    gov = EgressGovernor(mapper=mapper(), decide=decide, gate=gate)
    out = run(
        gov.govern(OutboundRequest(method="POST", url="http://x.local/charge", body={"amount": 10000}))
    )
    assert out.forward is False
    assert out.status_code == 403


def test_no_gate_configured_fails_closed():
    engine, _ = make_engine_and_gate()
    gov = EgressGovernor(
        mapper=mapper(),
        decide=decide_signing(
            engine, verdict="ALLOW", action="send_payment", forward_context={"amount": 1}
        ),
        gate=None,  # mandatory verification cannot happen
    )
    out = run(gov.govern(OutboundRequest(method="POST", url="http://x.local/charge", body={"amount": 1})))
    assert out.forward is False
    assert "fail-closed" in out.reason


# ---- Non-executable verdicts and errors ----

def test_deny_blocks_with_403():
    _, gate = make_engine_and_gate()

    async def decide(_p):
        return {"decision": "DENY", "enforce": True, "reason": "no"}

    gov = EgressGovernor(mapper=mapper(), decide=decide, gate=gate)
    out = run(gov.govern(OutboundRequest(method="DELETE", url="http://x.local/thing")))
    assert out.forward is False
    assert out.status_code == 403
    assert out.decision == "DENY"


def test_escalate_blocks_but_reports_real_verdict():
    _, gate = make_engine_and_gate()

    async def decide(_p):
        return {"decision": "ESCALATE", "enforce": True}

    gov = EgressGovernor(mapper=mapper(), decide=decide, gate=gate)
    out = run(gov.govern(OutboundRequest(method="POST", url="http://x.local/charge")))
    assert out.forward is False
    assert out.decision == "ESCALATE"  # not flattened to DENY


def test_gateway_unreachable_fails_closed():
    _, gate = make_engine_and_gate()

    async def boom(_p):
        raise ConnectionError("gateway down")

    gov = EgressGovernor(mapper=mapper(), decide=boom, gate=gate)
    out = run(gov.govern(OutboundRequest(method="POST", url="http://x.local/charge")))
    assert out.forward is False
    assert out.status_code == 502
    assert "fail-closed" in out.reason


# ---- Observe mode is transparent ----

def test_observe_mode_forwards_original_unchanged():
    _, gate = make_engine_and_gate()

    async def decide(_p):
        # Even though the verdict is DENY, observe never blocks and never rewrites.
        return {"decision": "DENY", "enforce": False}

    gov = EgressGovernor(mapper=mapper(), decide=decide, gate=gate)
    out = run(
        gov.govern(
            OutboundRequest(method="POST", url="http://x.local/charge", body={"amount": 99000})
        )
    )
    assert out.forward is True
    assert out.enforce is False
    assert out.forward_body == {"amount": 99000}  # original, untouched


def test_identity_extracted_from_header():
    captured = {}
    _, gate = make_engine_and_gate()

    async def decide(payload):
        captured.update(payload)
        return {"decision": "ESCALATE", "enforce": True}

    gov = EgressGovernor(mapper=mapper(), decide=decide, gate=gate)
    run(
        gov.govern(
            OutboundRequest(
                method="GET",
                url="http://acct.local/balance",
                headers={"x-mcc-identity": "agent/ops-bot"},
            )
        )
    )
    assert captured["identity"] == "agent/ops-bot"
    assert captured["action"] == "read_account"
