"""AXFlow clinic pilot — governance integration tests (PR #38).

Drive the business-domain clinic actions through the REAL gateway + evaluator
quorum + receipt-verifying governed executor pointed at the mock clinic service.
Proves the four verdict paths and the fail-closed invariants for the first
productized business pilot, reusing the existing machinery (no governance
duplicated). EXECUTED means a genuine, confirmed clinic receipt.

Not medical advice, not a medical device — a governed business-workflow pilot.
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))

import clinic_service.service as clinic  # noqa: E402
from examples._demo_server import DemoServer  # noqa: E402
from pilot.client import MCCGatewayClient  # noqa: E402
from pilot_notify import receipt_verifying_upstream  # noqa: E402
from pilot_notify.governed_upstream import payload_sha256  # noqa: E402

from integrations.voltagent.mcc_side.evaluator_quorum import QuorumSettings, build_quorum_app  # noqa: E402
from tests._notify_harness import API_KEY, OPERATOR_KEY, NotifyPilotHarness, _free_port  # noqa: E402

ACTOR = "agent/axflow-clinic"
CLINIC = "clinic-1"
COMPOSE = ROOT / "docker-compose.pilot-clinic-voltagent.yml"


class ClinicStack:
    """Real gateway + governed executor (-> mock clinic service) + evaluator quorum."""

    def __init__(self, *, upstream=None):
        clinic.reset_actions()
        self.cport = _free_port()
        self.csrv = DemoServer(clinic.app, self.cport)
        self.csrv.start()
        self.clinic_base = f"http://127.0.0.1:{self.cport}"
        self.harness = NotifyPilotHarness(
            upstream=upstream or receipt_verifying_upstream(self.clinic_base))
        qs = QuorumSettings({"MCC_QUORUM_GATEWAY_URL": self.harness.base_url,
                             "MCC_GATEWAY_API_KEY": API_KEY})
        self.q_app = build_quorum_app(self.harness.evaluators, qs)
        self.qport = _free_port()
        self.qsrv = DemoServer(self.q_app, self.qport)
        self.qsrv.start()
        self.quorum_url = f"http://127.0.0.1:{self.qport}"
        self.client = MCCGatewayClient(self.harness.base_url, api_key=API_KEY,
                                       operator_key=OPERATOR_KEY)

    def votes(self, *, action, context, nonce, votes_count=None):
        r = httpx.post(f"{self.quorum_url}/vote", headers={"x-api-key": API_KEY},
                       json={"actor": ACTOR, "action": action, "resource": CLINIC,
                             "context": context, "nonce": nonce}, timeout=10)
        r.raise_for_status()
        data = r.json()
        if votes_count is not None:
            data["votes"] = data["votes"][:votes_count]
        return data

    def govern(self, action, context, *, votes_count=None):
        d = self.client.propose(identity=ACTOR, action=action, resource_id=CLINIC,
                                actor_id=ACTOR, context=context)
        ch = self.client.issue_challenge(actor=ACTOR, action=action, resource=CLINIC,
                                         context=d.forward_context)
        qv = self.votes(action=action, context=context, nonce=ch["nonce"], votes_count=votes_count)
        # Round 25: a stable logical-operation identity is now mandatory for
        # actuation -- the test's own correlation_id is a natural one.
        idem = f"op-{context.get('correlation_id', ch['nonce'])}"
        out = self.client.execute_with_consensus(
            votes=qv["votes"], actor=ACTOR, action=action, resource=CLINIC,
            context=qv["authorized_context"], nonce=ch["nonce"], challenge_id=ch["challenge_id"],
            idempotency_key=idem)
        return d, qv, out

    def close(self):
        self.qsrv.stop()
        self.csrv.stop()
        self.harness.close()


@pytest.fixture()
def stack():
    s = ClinicStack()
    try:
        yield s
    finally:
        s.close()


def _ctx(corr, **extra):
    return {"actor_id": ACTOR, "clinic_id": CLINIC, "correlation_id": corr, **extra}


# 1 — ALLOW: normal appointment booking -> EXECUTED + verified receipt + audit.
def test_allow_appointment_booking(stack):
    d, _qv, out = stack.govern("appointment_book",
                               _ctx("c-book", patient_id="patient-1", appointment_time="2026-07-08T15:00"))
    assert d.decision.value == "ALLOW"
    assert out.executed and out.status == "EXECUTED"
    actions = clinic.recorded_actions()
    assert len(actions) == 1
    assert actions[0]["receipt"]["correlation_id"] == "c-book"
    assert actions[0]["receipt"]["action_type"] == "appointment_book"
    assert stack.client.verify_chain()["valid"] is True


# 2 — DENY: unsafe medical advice / prescription -> no execution, no receipt.
def test_deny_medical_advice(stack):
    d = stack.client.propose(identity=ACTOR, action="medical_advice_request", resource_id=CLINIC,
                             actor_id=ACTOR, context=_ctx("c-deny", patient_request="what antibiotics"))
    assert d.decision.value == "DENY"
    assert clinic.recorded_actions() == []


# 3 — CONSTRAIN: excessive discount is clamped; only the clamped payload executes.
def test_constrain_discount(stack):
    d, qv, out = stack.govern("discount_offer", _ctx("c-disc", patient_id="patient-2",
                                                     requested_discount_percent=90))
    assert d.decision.value == "CONSTRAIN"
    assert qv["authorized_context"]["requested_discount_percent"] == 20
    assert out.executed
    actions = clinic.recorded_actions()
    assert len(actions) == 1
    # Only the clamped payload was sent; the original 90 never was.
    assert actions[0]["payload"]["requested_discount_percent"] == 20
    assert all(a["payload"]["requested_discount_percent"] != 90 for a in actions)
    # The receipt payload hash binds the CONSTRAINED payload, not the original.
    assert actions[0]["receipt"]["payload_sha256"] == payload_sha256(actions[0]["payload"])


# 4 — CONSTRAIN: unauthorized priority bump is clamped to routine.
def test_constrain_priority(stack):
    d, qv, out = stack.govern("priority_mark", _ctx("c-prio", patient_id="patient-3", priority_level=3))
    assert d.decision.value == "CONSTRAIN"
    assert qv["authorized_context"]["priority_level"] == 1
    assert out.executed
    assert clinic.recorded_actions()[0]["payload"]["priority_level"] == 1


# 5 — ESCALATE: refund needs human approval; not executed before it; single-use.
def test_escalate_refund_requires_single_use_approval(stack):
    ctx = _ctx("c-refund", patient_id="patient-4")
    d = stack.client.propose(identity=ACTOR, action="refund_request", resource_id=CLINIC,
                             actor_id=ACTOR, context=ctx)
    assert d.decision.value == "ESCALATE"
    assert clinic.recorded_actions() == []  # nothing executed before approval

    appr = stack.client.request_approval(actor=ACTOR, action="refund_request", resource=CLINIC,
                                         payload=ctx)
    granted = stack.client.approve(appr["request_id"])
    first = stack.client.execute_with_approval(
        appr["request_id"], mandate=granted["mandate"], actor=ACTOR, action="refund_request",
        resource=CLINIC, context=ctx, idempotency_key="op-c-refund-a")
    assert first.executed
    # Replay of the same approval must fail (single-use) -- a distinct
    # idempotency key so the replay is blocked by the intended single-use
    # APPROVAL consumption, not an unrelated idempotency duplicate.
    second = stack.client.execute_with_approval(
        appr["request_id"], mandate=granted["mandate"], actor=ACTOR, action="refund_request",
        resource=CLINIC, context=ctx, idempotency_key="op-c-refund-b")
    assert not second.executed
    assert len(clinic.recorded_actions()) == 1  # executed exactly once


# 6 — ESCALATE: complaint also requires approval.
def test_escalate_complaint(stack):
    d = stack.client.propose(identity=ACTOR, action="complaint_escalate", resource_id=CLINIC,
                             actor_id=ACTOR, context=_ctx("c-complaint", patient_id="patient-5"))
    assert d.decision.value == "ESCALATE"


# 7 — direct bypass: consensus execute with no votes / too few votes fails closed.
def test_direct_bypass_without_authority_denied(stack):
    ctx = _ctx("c-bypass", patient_id="patient-6", appointment_time="2026-07-09T10:00")
    d = stack.client.propose(identity=ACTOR, action="appointment_book", resource_id=CLINIC,
                             actor_id=ACTOR, context=ctx)
    ch = stack.client.issue_challenge(actor=ACTOR, action="appointment_book", resource=CLINIC,
                                      context=d.forward_context)
    out = stack.client.execute_with_consensus(
        votes=[], actor=ACTOR, action="appointment_book", resource=CLINIC,
        context=d.forward_context, nonce=ch["nonce"], challenge_id=ch["challenge_id"])
    assert not out.executed
    assert clinic.recorded_actions() == []


# 8 — receipt verification: a forged/absent clinic receipt never yields EXECUTED.
def test_forged_receipt_not_executed():
    async def lying_upstream(action, payload):
        from pilot_notify import UpstreamReceiptError
        raise UpstreamReceiptError("no confirmed clinic receipt")

    s = ClinicStack(upstream=lying_upstream)
    try:
        _d, qv, out = s.govern("appointment_book",
                               _ctx("c-forge", patient_id="patient-7", appointment_time="t"))
        assert len(qv["votes"]) == 3            # governance authorized
        assert not out.executed                  # but no verified receipt -> not EXECUTED
        assert clinic.recorded_actions() == []
    finally:
        s.close()


# 9 — bypass topology: the clinic agent shares no network with the clinic service.
def test_clinic_agent_has_no_network_path_to_clinic_service():
    if not COMPOSE.exists():
        pytest.skip("clinic compose not present")
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    services = compose["services"]

    def nets(svc):
        n = svc.get("networks", [])
        return set(n) if isinstance(n, list) else set(n.keys())

    agent = next(k for k in services if "agent" in k)
    assert nets(services[agent]).isdisjoint(nets(services["clinic-service"]))
    # Only the gateway bridges the two networks.
    bridged = {k for k, s in services.items()
               if {"agent_edge", "gov_internal"}.issubset(nets(s))}
    assert "mcc-gateway" in bridged and "clinic-service" not in bridged and agent not in bridged
    # The agent is not given the clinic-service endpoint or an operator key.
    env = services[agent].get("environment", {}) or {}
    if isinstance(env, list):
        env = dict(e.split("=", 1) for e in env if "=" in e)
    assert "MCC_UPSTREAM_BASE" not in env and "MCC_GATEWAY_OPERATOR_API_KEY" not in env
