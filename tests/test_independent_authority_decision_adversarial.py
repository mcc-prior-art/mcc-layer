"""Adversarial runtime proof: independent authority-side ESCALATE decision.

Closes the gap PR #118 left open: an unattended operator sidecar that holds
the operator key and blindly calls ``/approve`` on whatever request_id it is
shown turns ESCALATE into automatic ALLOW for anything a compromised agent
can get the policy engine to escalate (or can itself fabricate via
``POST /approvals``). The invariant under test here is:

    AGENT-CONTROLLED INPUT != AUTHORITY DECISION
    PROPOSAL != PERMISSION

``mcc_core.authority_policy.AuthorityPolicy`` + the ``ApprovalService.approve()``
gate it gives (see ``src/mcc_core/approvals.py``) is the fix. No step here is
mocked: every test drives the REAL ``ApprovalService``/``AuthorityPolicy`` and,
for the mandatory cases, the REAL gateway HTTP stack
(``tests/_notify_harness.NotifyPilotHarness``) assembled by the actual shipped
``gateway.governance_api.build_governance_service`` -- the same function the
real ``gateway/app.py`` calls at import time.

Non-vacuity: every mandatory case that could plausibly pass by accident is
paired with a control run against a harness/service with NO authority_policy
configured (the architecture every pilot demo shipped with before this fix),
proving the identical forged/escalated operation WOULD have been auto-approved
there -- so this suite is catching a real, previously-exploitable gap.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import time
from pathlib import Path
from typing import Any, Dict

run = asyncio.run

import httpx
import pytest

from mcc_client import MCCClient, Verdict
from mcc_client.exceptions import MCCAuthenticationError
from mcc_core import (
    ApprovalService,
    AuthorityPolicy,
    AuthorityPolicyError,
    InMemoryApprovalRegistry,
    SigningKey,
)

from pilot_notify import recorded_receipts, reset_receipts
from tests._notify_harness import API_KEY, OPERATOR_KEY, NotifyPilotHarness

ROOT = Path(__file__).resolve().parents[1]

# The exact bounded policy the pilot ships (deploy/pilot/authority_policy.notify.json),
# duplicated here so this test is self-contained and does not silently drift if
# the shipped file changes shape without this suite noticing.
_POLICY_CONFIG: Dict[str, Any] = {
    "rules": [
        {
            "action": "send_notification",
            "tenant": "pilot",
            "actors": ["agent/unknown"],
            "resource_pattern": "notification-service",
            "payload_bounds": {"channel": {"in": ["email", "sms"]}, "priority": {"max": 3}},
        },
        {
            "action": "send_notification",
            "tenant": "pilot",
            "actors": ["agent/unknown"],
            "resource_pattern": "crm",
            "payload_bounds": {"channel": {"in": ["email", "sms"]}, "priority": {"max": 3}},
        },
    ],
}


def _load(name: str, rel_path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def _reset():
    reset_receipts()
    yield


@pytest.fixture()
def policy_path(tmp_path) -> str:
    p = tmp_path / "authority_policy.json"
    p.write_text(json.dumps(_POLICY_CONFIG), encoding="utf-8")
    return str(p)


@pytest.fixture()
def hz_gated(policy_path):
    """The FIXED architecture: the real gateway stack with the independent
    AuthorityPolicy wired in exactly as ``build_governance_service`` does for
    a real deployment (``MCC_AUTHORITY_POLICY_CONFIG``)."""
    harness = NotifyPilotHarness(env={"MCC_AUTHORITY_POLICY_CONFIG": policy_path})
    try:
        yield harness
    finally:
        harness.close()


@pytest.fixture()
def hz_ungated():
    """The PRE-FIX architecture: no authority_policy configured at all --
    bare 'an authenticated operator key says so' approve(). Used ONLY to
    prove non-vacuity; never treated as acceptable in production."""
    harness = NotifyPilotHarness()
    try:
        yield harness
    finally:
        harness.close()


def _client(hz, *, key: str = API_KEY) -> MCCClient:
    return MCCClient(hz.base_url, api_key=key, timeout=15.0)


def _escalate(hz, *, actor="agent/unknown", action="send_notification",
              resource="notification-service", payload=None, idem="op-1"):
    """Drive a REAL ESCALATE through /evaluate + request_approval -- the
    actual SDK call path every agent in this repo uses."""
    client = _client(hz)
    payload = dict(payload or {"recipient": "cust-1", "message": "hi",
                                "priority": 2, "channel": "email"})
    payload.setdefault("correlation_id", idem)
    d = client.evaluate(actor_id=actor, action=action, resource=resource,
                        payload=payload, idempotency_key=idem)
    assert d.verdict == Verdict.ESCALATE, f"expected ESCALATE, got {d.verdict}: {d.reason}"
    approval = client.request_approval(d)
    return client, d, approval


def _approve_raw(hz, request_id: str, *, operator_key: str = OPERATOR_KEY):
    return httpx.post(f"{hz.base_url}/approvals/{request_id}/approve",
                      headers={"x-api-key": API_KEY, "x-operator-key": operator_key},
                      timeout=10.0)


# ===========================================================================
# CASE A -- direct self-authorization: every proposer-visible authority
# primitive, attempted directly by a fully compromised agent. 0 approvals.
# ===========================================================================

class TestCaseA_DirectSelfAuthorization:
    def test_agent_client_has_no_usable_approve_without_an_operator_key(self, hz_gated):
        client, d, approval = _escalate(hz_gated, idem="case-a-1")
        with pytest.raises(MCCAuthenticationError):
            client.approve(approval)
        assert recorded_receipts() == []

    def test_forged_operator_header_rejected(self, hz_gated):
        client, d, approval = _escalate(hz_gated, idem="case-a-2")
        r = _approve_raw(hz_gated, approval.request_id, operator_key="forged-not-the-real-key")
        assert r.status_code == 403
        assert recorded_receipts() == []

    def test_missing_operator_header_rejected(self, hz_gated):
        client, d, approval = _escalate(hz_gated, idem="case-a-3")
        r = httpx.post(f"{hz_gated.base_url}/approvals/{approval.request_id}/approve",
                       headers={"x-api-key": API_KEY}, timeout=10.0)
        assert r.status_code == 403
        assert recorded_receipts() == []

    def test_proposer_facing_client_exposes_no_authority_primitive(self, hz_gated):
        # Static boundary: GovernanceClient-style proposer object (the plain
        # MCCClient) has no sign/mint/trust-admin method at all.
        client = _client(hz_gated)
        for forbidden in ("sign_token", "mint_mandate", "issue_mandate", "trust_admin"):
            assert not hasattr(client, forbidden)


# ===========================================================================
# CASE B (MANDATORY) -- indirect self-authorization: forge every field,
# retry indefinitely, no independent authority decision supplied. 0 approvals.
# ===========================================================================

class TestCaseB_IndirectSelfAuthorization:
    def test_forged_unbounded_action_never_approved(self, hz_gated):
        """send_payment holds no ALLOW rule at all in the independent
        policy -- however the agent dresses up the request, it is denied."""
        client, d, approval = _escalate(
            hz_gated, action="send_payment", resource="payments",
            payload={"amount": 999999, "beneficiary": "attacker-account",
                     "recipient": "attacker", "message": "x"},
            idem="case-b-1")
        r = _approve_raw(hz_gated, approval.request_id)
        assert r.status_code != 200 or r.json().get("mandate") is None
        assert recorded_receipts() == []

    def test_forged_out_of_bound_payload_never_approved(self, hz_gated):
        """Same action/actor/resource the policy knows about, but
        priority/channel OUTSIDE the independently configured bound."""
        client, d, approval = _escalate(
            hz_gated, payload={"recipient": "victim", "message": "x",
                               "priority": 9, "channel": "pager"},
            idem="case-b-2")
        r = _approve_raw(hz_gated, approval.request_id)
        assert r.status_code != 200 or r.json().get("mandate") is None
        assert recorded_receipts() == []

    def test_forged_resource_never_approved(self, hz_gated):
        client, d, approval = _escalate(
            hz_gated, resource="attacker-controlled-resource",
            payload={"recipient": "victim", "message": "x", "priority": 1,
                     "channel": "email"},
            idem="case-b-3")
        r = _approve_raw(hz_gated, approval.request_id)
        assert r.status_code != 200 or r.json().get("mandate") is None
        assert recorded_receipts() == []

    def test_retry_indefinitely_still_never_approved(self, hz_gated):
        client, d, approval = _escalate(
            hz_gated, action="send_payment", resource="payments",
            payload={"amount": 1, "beneficiary": "x"}, idem="case-b-4")
        for _ in range(8):
            r = _approve_raw(hz_gated, approval.request_id)
            assert r.status_code != 200 or r.json().get("mandate") is None
        assert recorded_receipts() == []

    def test_non_vacuity_old_architecture_would_have_approved_this(self, hz_ungated):
        """Proof this suite is meaningful: the IDENTICAL forged send_payment
        escalation, against a harness with NO independent authority policy
        (every pilot demo's architecture before this fix), DOES get
        approved by a bare operator-key holder."""
        client, d, approval = _escalate(
            hz_ungated, action="send_payment", resource="payments",
            payload={"amount": 999999, "beneficiary": "attacker-account"},
            idem="case-b-old")
        r = _approve_raw(hz_ungated, approval.request_id)
        assert r.status_code == 200
        assert r.json().get("mandate") is not None


# ===========================================================================
# CASE C -- a legitimate ESCALATE, with NO independent authority decision
# ever supplied, is still not permission. Poll/retry/wait -> stays blocked.
# ===========================================================================

class TestCaseC_LegitimateEscalateIsStillNotPermission:
    def test_pending_forever_without_a_decision(self, hz_gated):
        client, d, approval = _escalate(
            hz_gated, action="send_payment", resource="payments",
            payload={"amount": 10, "beneficiary": "legit"}, idem="case-c-1")
        for _ in range(5):
            status = client._t.get(f"/approvals/{approval.request_id}")
            assert status["state"] == "PENDING"
            time.sleep(0.05)
        assert recorded_receipts() == []


# ===========================================================================
# CASE D -- shared-state tampering: mutate every bound field independently.
# Every mismatch fails closed, 0 actuator calls.
# ===========================================================================

class TestCaseD_SharedStateTampering:
    """The real operator script (gateway_approval_operator.py) reads ONLY
    the request_id pointer from agent-written coordination state -- proven
    directly against the shipped script here, reusing the loading pattern
    from test_authority_principal_separation_adversarial_reference_agent.py."""

    def test_operator_script_ignores_every_other_field(self, hz_gated, tmp_path, monkeypatch):
        monkeypatch.setenv("MCC_GATEWAY_OPERATOR_API_KEY", OPERATOR_KEY)
        monkeypatch.setenv("MCC_GATEWAY_URL", hz_gated.base_url)
        operator = _load("gateway_approval_operator_case_d",
                         "deploy/pilot/gateway_approval_operator.py")

        client, d, approval = _escalate(hz_gated, idem="case-d-1")
        tampered = {
            "requestId": approval.request_id,
            "actor": "agent/ATTACKER", "action": "send_payment",
            "resource": "attacker-resource", "payload": {"amount": 999999},
            "context": {"amount": 999999}, "amount": 999999,
            "recipient": "attacker", "correlationId": "not-the-real-one",
            "transaction_id": "forged-txn", "logical_operation_id": "forged-op",
            "tenant": "attacker-tenant", "policy_hash": "forged-hash",
        }
        with operator.httpx.Client(timeout=15.0) as hc:
            result = operator._process_one(hc, tampered)

        # Bound to the REAL stored record (agent/unknown / send_notification /
        # notification-service, within policy) -- the tampered fields were
        # never read, so the mandate reflects the TRUE operation and is
        # granted on its own (within-policy) merits, not the forged ones.
        assert result["mandate"] is not None
        assert result["mandate"]["subject"] == "agent/unknown"
        assert result["mandate"]["action_scope"] == ["send_notification"]
        assert recorded_receipts() == []


# ===========================================================================
# CASE F -- authority unavailable: a missing/unusable policy fails closed.
# ===========================================================================

class TestCaseF_AuthorityUnavailable:
    def test_missing_policy_file_refuses_startup(self, tmp_path):
        with pytest.raises(AuthorityPolicyError):
            AuthorityPolicy.from_file(str(tmp_path / "does-not-exist.json"))

    def test_malformed_policy_file_refuses_startup(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not valid json", encoding="utf-8")
        with pytest.raises(AuthorityPolicyError):
            AuthorityPolicy.from_file(str(p))

    def test_empty_rules_refused_not_treated_as_unrestricted(self):
        with pytest.raises(AuthorityPolicyError):
            AuthorityPolicy.from_config({"rules": []})

    def test_authority_policy_itself_denies_missing_logical_operation_id(self):
        """Unit-level proof of the primitive's fail-closed rule."""
        policy = AuthorityPolicy.from_config(_POLICY_CONFIG)
        decision = policy.decide(
            tenant_id="pilot", actor="agent/unknown", action="send_notification",
            resource="notification-service", payload={"channel": "email", "priority": 1},
            payload_hash=None, policy_hash=None, logical_operation_id=None)
        assert decision.verdict == "DENY"
        assert "LOGICAL_OPERATION_ID" in decision.reason

    def test_approve_always_supplies_a_non_empty_logical_operation_id(self):
        """ApprovalService.approve() binds to the record's own request_id --
        server-generated, never empty -- so the missing-logical-operation-id
        failure mode above can never actually be reached through the real
        approval flow; the invariant holds by construction, not merely by a
        runtime check that might be skipped."""
        async def _go():
            svc = ApprovalService(InMemoryApprovalRegistry(), SigningKey.generate("k"),
                                  authority_policy=AuthorityPolicy.from_config(_POLICY_CONFIG))
            rid = await svc.request(actor="agent/unknown", action="send_notification",
                                    resource="notification-service", tenant_id="pilot",
                                    payload={"channel": "email", "priority": 1},
                                    transaction_id=None)
            return rid, await svc.approve(rid)

        rid, mandate = run(_go())
        assert rid  # the logical_operation_id approve() actually used
        assert mandate is not None


# ===========================================================================
# CASE G -- forged authority artifacts (ids/mandates/signatures) never
# produce an actuator call.
# ===========================================================================

class TestCaseG_ForgedAuthority:
    def test_forged_approval_id_rejected(self, hz_gated):
        client, d, approval = _escalate(hz_gated, idem="case-g-1")
        r = _approve_raw(hz_gated, "req-does-not-exist-at-all")
        assert r.status_code != 200
        assert recorded_receipts() == []

    def test_forged_mandate_rejected_at_consume(self):
        async def _go():
            svc = ApprovalService(InMemoryApprovalRegistry(), SigningKey.generate("k"),
                                  authority_policy=AuthorityPolicy.from_config(_POLICY_CONFIG))
            rid = await svc.request(actor="agent/unknown", action="send_notification",
                                    resource="notification-service", tenant_id="pilot",
                                    payload={"channel": "email", "priority": 1},
                                    transaction_id="op-g", payload_hash="sha256:aaaa")
            mandate = await svc.approve(rid)
            assert mandate is not None
            # Forged action_hash never matches the REAL stored record.
            return await svc.consume(rid, action_hash="sha256:forged",
                                     transaction_id="op-g", payload_hash="sha256:aaaa")

        result = run(_go())
        assert result.ok is False


# ===========================================================================
# CASE H -- replay: one legitimate authority result, used exactly once.
# ===========================================================================

class TestCaseH_Replay:
    def test_single_use_consume(self):
        from mcc_core import hash_action

        async def _go():
            svc = ApprovalService(InMemoryApprovalRegistry(), SigningKey.generate("k"),
                                  authority_policy=AuthorityPolicy.from_config(_POLICY_CONFIG))
            rid = await svc.request(actor="agent/unknown", action="send_notification",
                                    resource="notification-service", tenant_id="pilot",
                                    payload={"channel": "email", "priority": 1},
                                    transaction_id="op-h", payload_hash="sha256:bbbb")
            mandate = await svc.approve(rid)
            assert mandate is not None
            ah = hash_action("send_notification")
            first = await svc.consume(rid, action_hash=ah, transaction_id="op-h",
                                      payload_hash="sha256:bbbb")
            second = await svc.consume(rid, action_hash=ah, transaction_id="op-h",
                                       payload_hash="sha256:bbbb")
            return first, second

        first, second = run(_go())
        assert first.ok is True
        assert second.ok is False
        assert second.state == "CONSUMED"


# ===========================================================================
# CASE I -- cross-operation substitution: valid authority for A never
# actuates B, one field at a time.
# ===========================================================================

class TestCaseI_CrossOperationSubstitution:
    def test_each_mismatched_field_fails_closed(self):
        from mcc_core import hash_action

        async def _go():
            svc = ApprovalService(InMemoryApprovalRegistry(), SigningKey.generate("k"),
                                  authority_policy=AuthorityPolicy.from_config(_POLICY_CONFIG))
            rid = await svc.request(actor="agent/unknown", action="send_notification",
                                    resource="notification-service", tenant_id="pilot",
                                    payload={"channel": "email", "priority": 1},
                                    transaction_id="op-i-A", payload_hash="sha256:cccc")
            mandate = await svc.approve(rid)
            assert mandate is not None
            ah = hash_action("send_notification")

            # transaction_id changed -> operation B, not A.
            r1 = await svc.consume(rid, action_hash=ah, transaction_id="op-i-B",
                                   payload_hash="sha256:cccc")
            # payload_hash changed -> different payload, not A's.
            r2 = await svc.consume(rid, action_hash=ah, transaction_id="op-i-A",
                                   payload_hash="sha256:dddd")
            # action_hash changed -> different action, not A's.
            r3 = await svc.consume(rid, action_hash=hash_action("send_payment"),
                                   transaction_id="op-i-A", payload_hash="sha256:cccc")
            return r1, r2, r3

        r1, r2, r3 = run(_go())
        assert r1.ok is False
        assert r2.ok is False
        assert r3.ok is False


# ===========================================================================
# CASE K -- the original vulnerability class, explicit regression test:
# compromised agent -> valid-looking escalation -> attacker-controlled
# coordination state -> unattended operator observes it. Must NOT convert
# into valid authority merely because the request exists.
# ===========================================================================

class TestCaseK_CompromisedAgentAutoApprovalRegression:
    def test_unattended_operator_cannot_be_tricked_into_approving(
        self, hz_gated, monkeypatch,
    ):
        """Simulates the PR #118 shape exactly: the agent writes an
        escalation.json for an operation OUTSIDE the independent policy's
        bound; the unattended operator sidecar processes it as soon as it
        appears. The system must not convert this into valid authority."""
        monkeypatch.setenv("MCC_GATEWAY_OPERATOR_API_KEY", OPERATOR_KEY)
        monkeypatch.setenv("MCC_GATEWAY_URL", hz_gated.base_url)
        operator = _load("gateway_approval_operator_case_k",
                         "deploy/pilot/gateway_approval_operator.py")

        # A "compromised agent" escalates an unbounded action (send_payment)
        # -- MCC-Core's real policy engine genuinely returns ESCALATE here
        # (agent/unknown holds no mandate), exactly like a real compromised
        # proposer would observe and exploit.
        client, d, approval = _escalate(
            hz_gated, action="send_payment", resource="payments",
            payload={"amount": 50000, "beneficiary": "attacker-account"},
            idem="case-k-1")

        state = {"requestId": approval.request_id}  # the ONLY thing a real
        # unattended operator ever reads from agent-written coordination state.
        with operator.httpx.Client(timeout=15.0) as hc:
            result = operator._process_one(hc, state)

        assert result["mandate"] is None, (
            "the unattended operator must not auto-convert an escalated, "
            "out-of-policy operation into valid authority"
        )
        assert recorded_receipts() == []

    def test_non_vacuity_same_scenario_against_old_unattended_blind_approval(
        self, hz_ungated, monkeypatch,
    ):
        """The identical scenario, against a harness with NO independent
        authority policy configured -- the architecture every pilot demo
        shipped with before this fix. This DOES convert into valid
        authority, proving the regression test above is non-vacuous."""
        monkeypatch.setenv("MCC_GATEWAY_OPERATOR_API_KEY", OPERATOR_KEY)
        monkeypatch.setenv("MCC_GATEWAY_URL", hz_ungated.base_url)
        operator = _load("gateway_approval_operator_case_k_old",
                         "deploy/pilot/gateway_approval_operator.py")

        client, d, approval = _escalate(
            hz_ungated, action="send_payment", resource="payments",
            payload={"amount": 50000, "beneficiary": "attacker-account"},
            idem="case-k-old")
        state = {"requestId": approval.request_id}
        with operator.httpx.Client(timeout=15.0) as hc:
            result = operator._process_one(hc, state)

        assert result["mandate"] is not None, (
            "non-vacuity check failed: the old unattended-blind-approval "
            "architecture was expected to approve this forged/out-of-policy "
            "escalation, which is exactly the vulnerability this suite fixes"
        )


# ===========================================================================
# Direct runtime proof for the THIRD shipped script (notify_pilot_agent.py):
# the new mandate-only operator contract + agent-side execute-after-mandate
# still cooperate correctly end-to-end, gated by the independent policy.
# ===========================================================================

class TestNotifyPilotAgentScriptStillWorksEndToEnd:
    def test_full_scenario_matrix_with_gated_operator(self, hz_gated, tmp_path, monkeypatch):
        import threading

        monkeypatch.setenv("MCC_GATEWAY_URL", hz_gated.base_url)
        monkeypatch.setenv("MCC_GATEWAY_API_KEY", API_KEY)
        monkeypatch.setenv("MCC_PILOT_STATE_DIR", str(tmp_path))
        monkeypatch.setenv("MCC_APPROVAL_WAIT_TIMEOUT_S", "8")
        monkeypatch.setenv("MCC_APPROVAL_POLL_INTERVAL_S", "0.2")
        agent = _load("notify_pilot_agent_e2e", "deploy/pilot/notify_pilot_agent.py")
        # The minimal test harness app has no /ready route (unlike the real
        # gateway.app); the harness is already up by the time this test
        # runs, so the readiness poll adds nothing here.
        agent._wait_ready = lambda client: None

        monkeypatch.setenv("MCC_GATEWAY_OPERATOR_API_KEY", OPERATOR_KEY)
        monkeypatch.setenv("MCC_OPERATOR_POLL_INTERVAL_S", "0.2")
        operator = _load("gateway_approval_operator_notify_e2e",
                         "deploy/pilot/gateway_approval_operator.py")
        op_thread = threading.Thread(target=operator.main, daemon=True)
        op_thread.start()

        exit_code = agent.main()
        assert exit_code == 0
