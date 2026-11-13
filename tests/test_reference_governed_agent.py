"""Deterministic tests for the framework-neutral reference governed agent.

Every governed-path test drives the REAL gateway (via the SDK over real HTTP,
through :class:`NotifyPilotHarness`) with the receipt-verifying governed executor
pointed at a real loopback mock notification service. EXECUTED means a genuine,
confirmed external receipt. Nothing governance-related is stubbed or bypassed; the
agent only ever talks to the gateway through ``mcc_client``.

No external API key, network egress, or LLM dependency is required: the default
:class:`DeterministicProvider` is fully offline and reproducible.
"""

from __future__ import annotations

import ast
import asyncio
import sys
import time
from pathlib import Path

import pytest
from fastapi import FastAPI, Request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))

from mcc_client import Approval, MCCClient  # noqa: E402
from mcc_client.models import ConsensusAuthorization, Decision  # noqa: E402

from mcc_core import issue_vote  # noqa: E402

from pilot_notify import (  # noqa: E402
    UpstreamReceiptError,
    payload_sha256,
    receipt_verifying_upstream,
    recorded_receipts,
    reset_receipts,
)

from examples._demo_server import DemoServer  # noqa: E402
from examples.reference_governed_agent import (  # noqa: E402
    ConsensusAuthorizer,
    DeterministicProvider,
    OptionalLLMProvider,
    ProgrammaticOperator,
    ProviderError,
    ReferenceGovernedAgent,
)
from examples.reference_governed_agent.authorizers import FAR_FUTURE  # noqa: E402

from tests._notify_harness import API_KEY, OPERATOR_KEY, NotifyPilotHarness, agent_key  # noqa: E402

PKG_DIR = ROOT / "examples" / "reference_governed_agent"
REQUEST = "Notify customer-123 that the appointment is confirmed"


# --------------------------------------------------------------------------- #
# Fixtures / helpers.                                                          #
# --------------------------------------------------------------------------- #

@pytest.fixture()
def harness():
    hz = NotifyPilotHarness()
    try:
        yield hz
    finally:
        hz.close()


@pytest.fixture(autouse=True)
def _reset():
    reset_receipts()
    yield


def _client(hz: NotifyPilotHarness, actor_id: str = None) -> MCCClient:
    # V05 (part 2): an agent acting as ``actor_id`` presents its OWN registered
    # credential (required on /approvals and the execute routes); without an
    # actor, the tenant's shared key (enough for /evaluate, /verify, consensus).
    key = agent_key(actor_id) if actor_id else API_KEY
    return MCCClient(hz.base_url, api_key=key, operator_key=OPERATOR_KEY, timeout=15.0)


def _authorizer(hz: NotifyPilotHarness, *, verdict: str = "ALLOW") -> ConsensusAuthorizer:
    return ConsensusAuthorizer(hz.evaluators, policy_hash=hz.policy_hash,
                               threshold=len(hz.evaluators), verdict=verdict,
                               profiles=hz.profiles)


def _agent(hz, *, scenario, operator=None, authorizer=None):
    """Build a reference agent whose provider deterministically drives ``scenario``."""
    provider = DeterministicProvider(**_PROVIDER[scenario])
    client = _client(hz, _PROVIDER[scenario]["actor_id"])
    return ReferenceGovernedAgent(
        client, provider=provider,
        operator=operator or ProgrammaticOperator(approve=True),
        authorizer=authorizer if authorizer is not None else _authorizer(hz))


_PROVIDER = {
    "allow": dict(actor_id="agent/notify-bot", priority="normal", channel="email"),
    "deny": dict(actor_id="agent/notify-bot", priority="normal", channel="pager"),
    "constrain": dict(actor_id="agent/notify-bot", priority="high", channel="email"),
    "escalate": dict(actor_id="agent/unknown", priority="normal", channel="email"),
}


# --------------------------------------------------------------------------- #
# 1. ALLOW -> genuine EXECUTED (confirmed receipt) + audit verifies.          #
# --------------------------------------------------------------------------- #

def test_allow_executes_via_governed_path(harness):
    result = _agent(harness, scenario="allow").handle(REQUEST)
    assert result.verdict == "ALLOW"
    assert result.execution_status == "EXECUTED" and result.executed
    receipts = recorded_receipts()
    assert len(receipts) == 1
    assert receipts[0]["receipt"]["correlation_id"] == result.proposal["payload"]["correlation_id"]
    assert result.audit_valid is True


# --------------------------------------------------------------------------- #
# 2. DENY -> no execution, external service never called.                     #
# --------------------------------------------------------------------------- #

def test_deny_never_reaches_service(harness):
    result = _agent(harness, scenario="deny").handle(REQUEST)
    assert result.verdict == "DENY"
    assert result.execution_status == "BLOCKED" and not result.executed
    assert result.reason  # denial reason is surfaced
    assert recorded_receipts() == []


# --------------------------------------------------------------------------- #
# 3. ESCALATE -> nothing executes before/without a valid approval.            #
# --------------------------------------------------------------------------- #

def test_escalate_not_executed_without_approval(harness):
    operator = ProgrammaticOperator(approve=False)
    result = _agent(harness, scenario="escalate", operator=operator).handle(REQUEST)
    assert result.verdict == "ESCALATE"
    assert result.approval_status == "REJECTED"
    assert result.execution_status == "BLOCKED" and not result.executed
    assert operator.decisions  # the operator was actually consulted
    assert recorded_receipts() == []


# --------------------------------------------------------------------------- #
# 4. ESCALATE -> EXECUTED only after a valid operator approval.               #
# --------------------------------------------------------------------------- #

def test_escalate_executes_after_valid_approval(harness):
    result = _agent(harness, scenario="escalate").handle(REQUEST)
    assert result.verdict == "ESCALATE"
    assert result.approval_status == "APPROVED"
    assert result.execution_status == "EXECUTED" and result.executed
    assert len(recorded_receipts()) == 1
    assert result.audit_valid is True


# --------------------------------------------------------------------------- #
# 5-7. Forged / expired / mismatched approval material fails closed.          #
# --------------------------------------------------------------------------- #

def test_forged_approval_fails_closed(harness):
    agent = _agent(harness, scenario="escalate")
    # Substitute a forged (unsigned) mandate for the operator's real one.
    agent._client.approve = lambda appr, **k: Approval(
        request_id=appr.request_id, state="APPROVED",
        mandate={"forged": True, "approval_id": appr.request_id})
    result = agent.handle(REQUEST)
    assert result.execution_status == "BLOCKED" and not result.executed
    assert recorded_receipts() == []


def test_expired_approval_fails_closed(harness):
    agent = _agent(harness, scenario="escalate")
    client = agent._client
    # Force a 1s TTL on the approval, then delay execution until it has expired.
    orig_request = client.request_approval
    client.request_approval = lambda d, **k: orig_request(d, ttl_seconds=1)
    orig_exec = client.execute_after_approval

    def slow_exec(d, appr, **k):
        time.sleep(1.4)
        return orig_exec(d, appr, **k)

    client.execute_after_approval = slow_exec
    result = agent.handle(REQUEST)
    assert result.execution_status == "BLOCKED" and not result.executed
    assert recorded_receipts() == []


def test_mismatched_approval_fails_closed(harness):
    agent = _agent(harness, scenario="escalate")
    client = agent._client
    # Approve a DIFFERENT operation and substitute its mandate for this one's.
    other_d = client.evaluate(actor_id="agent/other-unknown", action="send_notification",
                              resource="billing",
                              payload={"recipient": "x-1", "message": "m", "priority": 2,
                                       "channel": "email", "correlation_id": "corr-other"})
    # V05 (part 2): an agent may only request approval for itself, so the
    # OTHER operation is requested by agent/other-unknown with its own key.
    other_client = _client(harness, "agent/other-unknown")
    other_granted = client.approve(other_client.request_approval(other_d))
    client.approve = lambda appr, **k: Approval(
        request_id=appr.request_id, state="APPROVED", mandate=other_granted.mandate)
    result = agent.handle(REQUEST)
    # A mandate bound to a different operation cannot actuate this request.
    assert result.execution_status == "BLOCKED" and not result.executed
    assert recorded_receipts() == []


# --------------------------------------------------------------------------- #
# 8. ESCALATE preserves the exact original requested payload.                 #
# --------------------------------------------------------------------------- #

def test_escalate_preserves_original_payload(harness):
    result = _agent(harness, scenario="escalate").handle(REQUEST)
    assert result.executed
    original = result.proposal["payload"]
    assert result.final_payload == original           # exact original executed
    receipts = recorded_receipts()
    assert len(receipts) == 1
    assert receipts[0]["payload"] == original          # the service received the original


# --------------------------------------------------------------------------- #
# 9-10. CONSTRAIN executes ONLY the authoritative constrained payload.        #
# --------------------------------------------------------------------------- #

def test_constrain_executes_only_constrained_payload(harness):
    result = _agent(harness, scenario="constrain",
                    authorizer=_authorizer(harness, verdict="ALLOW")).handle(REQUEST)
    assert result.verdict == "CONSTRAIN"
    assert result.applied_constraints                  # a constraint was applied
    assert result.final_payload["priority"] == 3       # clamped authoritative body
    assert result.executed
    receipts = recorded_receipts()
    assert len(receipts) == 1
    assert receipts[0]["payload"]["priority"] == 3     # only the clamped payload sent


def test_original_not_used_after_constrain(harness):
    result = _agent(harness, scenario="constrain",
                    authorizer=_authorizer(harness, verdict="ALLOW")).handle(REQUEST)
    assert result.proposal["payload"]["priority"] == 9   # the agent proposed 9
    assert result.executed
    # The original, over-cap payload was never sent to the external service.
    assert all(r["payload"]["priority"] != 9 for r in recorded_receipts())


# --------------------------------------------------------------------------- #
# 11. An altered execution payload (votes over a tampered body) is rejected.  #
# --------------------------------------------------------------------------- #

class _TamperingAuthorizer:
    """A malicious authorizer that signs votes over a mutated payload — the gate
    must reject it (the votes no longer bind the authoritative body)."""

    def __init__(self, hz):
        self._hz = hz

    def material(self, client, decision: Decision):
        ch = client.issue_challenge(decision)
        tampered = dict(decision.authorized_payload, message="ALTERED-BY-AGENT")
        canonical = self._hz.profiles.for_action(decision.action).canonical_payload(tampered)
        votes = [issue_vote(e, evaluator_id=e.kid, verdict="ALLOW",
                            action=decision.action, payload=canonical, actor=decision.actor_id,
                            not_before=0, not_after=FAR_FUTURE, resource=decision.resource_id,
                            policy_hash=self._hz.policy_hash, nonce=ch["nonce"])
                 for e in self._hz.evaluators]
        return ConsensusAuthorization(votes=votes, challenge_id=ch["challenge_id"],
                                      nonce=ch["nonce"])


def test_altered_payload_rejected(harness):
    result = _agent(harness, scenario="allow",
                    authorizer=_TamperingAuthorizer(harness)).handle(REQUEST)
    assert result.execution_status == "BLOCKED" and not result.executed
    assert recorded_receipts() == []


# --------------------------------------------------------------------------- #
# 12. A bad governed-executor receipt -> the agent never reports EXECUTED.     #
# --------------------------------------------------------------------------- #

def test_bad_receipt_never_executed():
    async def bad_upstream(action, payload):
        raise UpstreamReceiptError("no confirmed receipt")

    hz = NotifyPilotHarness(upstream=bad_upstream)
    try:
        result = _agent(hz, scenario="allow").handle(REQUEST)
        assert result.verdict == "ALLOW"                 # governance authorized
        assert result.execution_status != "EXECUTED"     # but no confirmed receipt
        assert not result.executed
        assert recorded_receipts() == []
    finally:
        hz.close()


# --------------------------------------------------------------------------- #
# 13-15. The receipt-verifying executor fails closed on missing/false/          #
# mismatched receipts (why the agent can never see EXECUTED on a bad receipt). #
# --------------------------------------------------------------------------- #

class _LyingService:
    """A loopback service that returns a configurable (wrong) receipt."""

    def __init__(self):
        self.mode = "honest"
        self.app = FastAPI()

        @self.app.post("/{action}")
        async def _send(action: str, request: Request):  # noqa: ANN202
            payload = await request.json()
            corr = payload.get("correlation_id")
            if self.mode == "false":
                return {"received": False, "correlation_id": corr,
                        "payload_sha256": payload_sha256(payload)}
            if self.mode == "wrong_correlation":
                return {"received": True, "correlation_id": "WRONG",
                        "payload_sha256": payload_sha256(payload)}
            if self.mode == "wrong_hash":
                return {"received": True, "correlation_id": corr, "payload_sha256": "deadbeef"}
            return {"received": True, "correlation_id": corr,
                    "payload_sha256": payload_sha256(payload)}


@pytest.fixture()
def lying():
    svc = _LyingService()
    from tests._notify_harness import _free_port
    port = _free_port()
    server = DemoServer(svc.app, port)
    server.start()
    try:
        yield svc, f"http://127.0.0.1:{port}"
    finally:
        server.stop()


@pytest.mark.parametrize("mode", ["false", "wrong_correlation", "wrong_hash"])
def test_receipt_verification_fails_closed(lying, mode):
    svc, base = lying
    svc.mode = mode
    upstream = receipt_verifying_upstream(base)
    payload = {"recipient": "cust-1", "message": "hi", "priority": 2,
               "channel": "email", "correlation_id": "corr-x"}
    with pytest.raises(UpstreamReceiptError):
        asyncio.run(upstream("send_notification", payload))


# --------------------------------------------------------------------------- #
# 16. Redis outage fails closed (no execution).                               #
# --------------------------------------------------------------------------- #

def test_redis_outage_fails_closed():
    down = {"MCC_NONCE_BACKEND": "redis", "MCC_IDEMPOTENCY_BACKEND": "redis",
            "MCC_REDIS_URL": "redis://127.0.0.1:6390/0"}
    hz = NotifyPilotHarness(env=down)
    try:
        result = _agent(hz, scenario="allow").handle(REQUEST)
        assert result.execution_status == "BLOCKED" and not result.executed
        assert recorded_receipts() == []
    finally:
        hz.close()


# --------------------------------------------------------------------------- #
# 17. The audit chain verifies after a successful governed execution.         #
# --------------------------------------------------------------------------- #

def test_audit_chain_verifies_after_success(harness):
    result = _agent(harness, scenario="allow").handle(REQUEST)
    assert result.executed
    assert result.audit_valid is True
    # And an independent verification agrees.
    assert _client(harness).verify_audit_chain().get("valid") is True


# --------------------------------------------------------------------------- #
# 18. The agent exposes no direct external execution route (static guard).     #
# --------------------------------------------------------------------------- #

# The demo harness (_localstack) legitimately stands up the governed gateway the
# agent runs against; it is NOT the agent and is excluded (like tests/_notify_harness).
_AGENT_MODULES = ["__init__.py", "agent.py", "providers.py", "operator.py",
                  "actions.py", "models.py", "authorizers.py", "cli.py"]
_FORBIDDEN = {"httpx", "requests", "aiohttp", "urllib", "urllib.request", "http",
              "http.client", "socket", "socketserver", "subprocess", "websocket",
              "websockets", "ftplib", "smtplib", "telnetlib", "pilot_notify", "gateway"}


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


def test_agent_has_no_direct_external_execution_route():
    for mod in _AGENT_MODULES:
        imported = _imported_modules(PKG_DIR / mod)
        for name in imported:
            top = name.split(".")[0]
            assert name not in _FORBIDDEN and top not in _FORBIDDEN, (
                f"{mod} imports forbidden networking/execution module {name!r}")
    # The agent's only outward channel is the injected SDK client.
    agent = ReferenceGovernedAgent(MCCClient("http://127.0.0.1:1", api_key="k"))
    for forbidden in ("send", "http", "notify", "post", "request", "_session", "_socket"):
        assert not hasattr(agent, forbidden)


# --------------------------------------------------------------------------- #
# 19. The default provider needs no external API key / network.               #
# --------------------------------------------------------------------------- #

def test_deterministic_provider_needs_no_api_key(monkeypatch):
    # Scrub anything that could look like credentials — the provider must not care.
    for var in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "MCC_AGENT_LLM"):
        monkeypatch.delenv(var, raising=False)
    provider = DeterministicProvider()
    proposal = provider.propose(REQUEST)
    assert proposal.action == "send_notification"
    assert proposal.actor_id == "agent/notify-bot"
    assert proposal.payload["recipient"] == "customer-123"
    # Deterministic: identical requests -> identical proposals (bar the fresh id).
    again = provider.propose(REQUEST)
    assert {k: v for k, v in proposal.payload.items() if k != "correlation_id"} == \
           {k: v for k, v in again.payload.items() if k != "correlation_id"}


# --------------------------------------------------------------------------- #
# 20. An optional-LLM provider failure does NOT bypass governance.            #
# --------------------------------------------------------------------------- #

def test_optional_llm_failure_does_not_bypass_governance(harness):
    def boom(_request):
        raise RuntimeError("model unavailable")

    provider = OptionalLLMProvider(enabled=True, complete=boom)
    # Provider failure surfaces as ProviderError — never a proposal, never a bypass.
    with pytest.raises(ProviderError):
        provider.propose(REQUEST)

    # And through the agent: no proposal -> no evaluation, no execution, no receipt.
    agent = ReferenceGovernedAgent(
        _client(harness), provider=provider,
        operator=ProgrammaticOperator(approve=True), authorizer=_authorizer(harness))
    result = agent.handle(REQUEST)
    assert result.execution_status == "BLOCKED" and not result.executed
    assert result.error and "model unavailable" in result.error
    assert recorded_receipts() == []
