"""Live proof that the Control Room drives the REAL MCC-Core gateway.

Every test here talks to the actual ``gateway.app`` process started by
``backend.runtime.start_demo_runtime`` (see ``conftest.py``'s session-scoped
``runtime`` fixture) -- there is no mock, no stub, no second policy engine.
Numbered comments map each test to the corresponding item in the task's
"Testing requirements" list.

Each scenario in ``SCENARIOS`` is executed exactly ONCE for the whole test
session (the ``scenario_results`` fixture below) and every test reads from
that cache. This isn't just an efficiency choice: ``gateway/pilot_policy.py``
enforces a REAL velocity limit ("no more than 3 payments per actor per
minute" -- see ``PILOT_VELOCITY`` in that file), and re-running the payment
scenarios once per test would genuinely trip it, which would be this test
suite fighting the very fail-closed behavior it exists to prove.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

CONTROL_ROOM_DIR = Path(__file__).resolve().parents[1]
ROOT = CONTROL_ROOM_DIR.parents[1]
for _p in (str(ROOT), str(CONTROL_ROOM_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from mcc_core import AuditLog, public_key_from_b64, verify_token  # noqa: E402

from backend.scenarios import SCENARIOS, client_for, token_view  # noqa: E402
from backend.server import create_app  # noqa: E402


@pytest.fixture(scope="session")
def scenario_results(runtime):
    """Run every scenario exactly once for the whole test session."""
    return {scenario_id: fn(runtime) for scenario_id, fn in SCENARIOS.items()}


def stage(result, name):
    return next(s for s in result.stages if s.name == name)


# 1. The Control Room backend reaches the real canonical MCC Gateway.
def test_backend_reaches_the_real_gateway(runtime):
    client = client_for(runtime)
    health = client.health()
    assert health["status"] == "ok"
    assert client.is_ready() is True
    # Talk to it with a bare, independent HTTP client too -- proving the
    # gateway is a genuine separate network service, not something the
    # Control Room process fabricated in-memory.
    resp = httpx.get(f"{runtime.gateway_url}/health", timeout=5.0)
    assert resp.status_code == 200
    assert resp.json()["policy_hash"] == health["policy_hash"]


# 2. Decisions originate from the existing MCC-Core policy path
#    (gateway/pilot_policy.py, unmodified).
@pytest.mark.parametrize("scenario_id,expected_decision", [
    ("allow", "ALLOW"), ("deny", "DENY"), ("escalate", "ESCALATE"), ("constrain", "CONSTRAIN"),
])
def test_decisions_come_from_the_real_policy_path(scenario_results, scenario_id, expected_decision):
    result = scenario_results[scenario_id]
    decision_stage = stage(result, "mcc_decision")
    assert decision_stage.detail["decision"] == expected_decision
    # The reason text is the AuthorityModel's own wording -- not anything the
    # Control Room composed.
    reason = decision_stage.detail["reason"]
    assert "mandate" in reason or "requires=" in reason


# 3. Issued tokens are generated and signed by the existing runtime.
def test_decision_token_is_genuinely_signed_by_the_running_gateway(runtime):
    # F1: agent/payments-bot is a registered agent -> its OWN credential.
    client = client_for(runtime, "agent/payments-bot")
    health = client.health()
    public_key: Ed25519PublicKey = public_key_from_b64(health["signing"]["public_key_b64"])

    # A fresh /evaluate call -- decision preview only, no actuation, so it
    # does not count against any velocity limit. Use the gateway's own raw
    # response directly (the exact dict `pilot.client.MCCGatewayClient`
    # returns as `.decision_token`), not a reconstruction of the Control
    # Room's display formatting, so this test verifies precisely what the
    # runtime issued.
    proposal = client.propose(
        identity="agent/payments-bot", action="send_payment",
        context={"amount": 1.0, "currency": "USD",
                "source": "acct-signature-probe", "beneficiary_id": "ben-signature-probe"},
    )
    assert proposal.decision == "ALLOW"
    raw_token = proposal.decision_token
    assert raw_token is not None
    assert raw_token["kid"] == health["signing"]["kid"]

    # Independently verify with the cryptography library against the
    # gateway's own advertised public key -- proof this is a real Ed25519
    # signature from the real runtime, not a fabricated display value. (This
    # is TEST code verifying a claim, not UI logic -- the browser never
    # performs this verification; see server.py's docstring and
    # tools/control-room/README.md's trust-boundary section.)
    assert verify_token(raw_token, public_key) is True

    # A single flipped byte in the signature must fail -- proving this isn't
    # a verifier that always returns True.
    tampered = {**raw_token, "sig": raw_token["sig"][:-4] + ("AAAA" if raw_token["sig"][-4:] != "AAAA" else "BBBB")}
    assert verify_token(tampered, public_key) is False

    # And the Control Room's own display formatting (what actually reaches
    # the browser) carries the same signature and key id, unmodified.
    view = token_view(raw_token)
    assert view["signature"] == raw_token["sig"]
    assert view["signing_key_id"] == raw_token["kid"]


# 4. Execution requests pass through the real Execution Gate.
def test_execution_passes_through_the_real_gate(scenario_results):
    result = scenario_results["allow"]
    actuation_stage = stage(result, "actuation_result")
    assert actuation_stage.ok is True
    gate_stage = stage(result, "gate_and_actuation")
    assert gate_stage.detail["status"] == "EXECUTED"
    assert actuation_stage.detail["last_upstream_call"]["body"]["amount"] == 1000.0


# 5. Replay protection uses the existing nonce mechanism.
def test_replay_protection_uses_the_real_nonce_mechanism(scenario_results):
    result = scenario_results["replay"]
    assert result.passed is True
    first = stage(result, "first_execution")
    replayed = stage(result, "gate_and_actuation")
    assert first.ok is True and first.detail["status"] == "EXECUTED"
    assert replayed.ok is True and replayed.detail["executed"] is False


# 6. Modified actions are rejected by existing action-binding verification.
def test_tamper_rejected_by_real_action_binding(scenario_results):
    result = scenario_results["tamper"]
    assert result.passed is True
    gate_stage = stage(result, "gate_and_actuation")
    assert gate_stage.detail["executed"] is False


# 7. Invalid and expired tokens/evidence are rejected by the existing
#    verification path.
def test_invalid_signature_rejected(scenario_results):
    assert scenario_results["bad_signature"].passed is True


def test_expired_evidence_rejected(scenario_results):
    assert scenario_results["expired"].passed is True


# 8. Audit entries are produced by the existing audit mechanism.
def test_audit_entries_come_from_the_real_audit_log_on_disk(runtime, scenario_results):
    result = scenario_results["allow"]
    audit_stage = stage(result, "audit_record")
    assert audit_stage.ok is True
    matched = audit_stage.detail["matched_entries"]
    assert matched

    # Read the SAME file src/mcc_core/audit.py fsyncs to, directly off disk,
    # and verify its hash chain independently (AuditLog.verify_chain is the
    # existing audit mechanism's own verifier -- not something the Control
    # Room re-implemented).
    entries = [json.loads(line) for line in Path(runtime.audit_log_path).read_text().splitlines() if line.strip()]
    assert any(e.get("hash") == matched[0]["event_id"] for e in entries)
    assert AuditLog.verify_chain(runtime.audit_log_path) is True


# 9. The protocol runtime starts and operates without the Control Room.
def test_gateway_operates_via_plain_http_without_any_control_room_code(runtime):
    """Talk to the real gateway with nothing from tools/control-room in the
    call path at all -- no MCCGatewayClient, no server.py, no scenarios.py,
    just a bare HTTP POST. Proves the runtime this fixture started needs
    nothing from this package to serve a real request end to end."""
    resp = httpx.post(
        f"{runtime.gateway_url}/evaluate",
        headers={"x-api-key": runtime.api_key},
        json={"identity": "agent/ops-bot", "action": "read_infra", "context": {}},
    )
    assert resp.status_code == 200
    assert resp.json()["decision"] in ("ALLOW", "DENY", "ESCALATE", "CONSTRAIN")


# 10. Control Room failure has no effect on MCC-Core operation.
def test_control_room_backend_going_down_does_not_affect_the_gateway(runtime, scenario_results):
    """Build (and then deliberately never start serving -- simulating "the
    Control Room backend crashed before it came up") the BFF app, and
    confirm the real gateway answers exactly as before regardless."""
    app = create_app(runtime)  # noqa: F841 -- constructed, deliberately never served
    resp = httpx.get(f"{runtime.gateway_url}/health", timeout=5.0)
    assert resp.status_code == 200
    assert scenario_results["deny"].passed is True


# 11. No Core package imports/depends on tools/control-room --
#     see test_no_core_dependency.py.

# 12. No private keys or secrets are delivered to the browser.
def test_no_secrets_reach_the_http_responses(runtime, scenario_results):
    from starlette.testclient import TestClient

    app = create_app(runtime)
    with TestClient(app) as tc:
        blobs = [
            tc.get("/api/health").text,
            tc.get("/api/scenarios").text,
            tc.get("/api/audit/verify").text,
            # A propose-only call (no execution -> no velocity impact).
            tc.post("/api/propose", json={
                "identity": "agent/payments-bot", "action": "send_payment",
                "context": {"amount": 2, "currency": "USD",
                           "source": "acct-secret-probe", "beneficiary_id": "ben-secret-probe"},
            }).text,
        ]
    # Every already-computed scenario result is exactly what /api/scenarios/
    # {id}/run would serialize (server.py returns `result.to_dict()`
    # verbatim) -- check that JSON without re-executing the scenarios (which
    # would trip the real payment velocity limit a second time).
    blobs += [json.dumps(r.to_dict()) for r in scenario_results.values()]

    everything = "\n".join(blobs)
    assert runtime.operator_key not in everything
    assert runtime.api_key not in everything
    for agent_key in runtime.agent_keys.values():   # F1: per-agent keys never reach the browser
        assert agent_key not in everything
    for key in runtime.evaluator_keys:
        # The private key material itself, in every representation the
        # cryptography library can produce it in, must never appear.
        pem = key._private_key.private_bytes(  # noqa: SLF001 -- test-only introspection
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii")
        assert pem not in everything
        raw = key._private_key.private_bytes(  # noqa: SLF001
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        assert base64.b64encode(raw).decode("ascii") not in everything
