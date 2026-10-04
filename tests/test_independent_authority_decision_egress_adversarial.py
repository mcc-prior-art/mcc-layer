"""Adversarial runtime proof for the egress_proxy path specifically
(``docker-compose.pilot.yml`` / ``governed_agent_pilot_operator.py``) --
the independent authority-side ESCALATE decision, against the REAL
``egress_proxy`` app (``tests/_egress_harness.EgressHarness``), not a mock.

Companion to ``test_independent_authority_decision_adversarial.py`` (the
gateway/governance_api.py path); this covers the SEPARATE ``GovernedMCCClient``
+ ``OperatorConsole`` code path used by the egress proxy, which the task
explicitly names (``governed_agent_pilot_operator.py``).
"""

from __future__ import annotations

import importlib.util
import json
import tempfile
from pathlib import Path

from tests._egress_harness import EgressHarness

ROOT = Path(__file__).resolve().parents[1]

# Mirrors deploy/pilot/authority_policy.egress.json exactly.
_POLICY_CONFIG = {
    "rules": [
        {
            "action": "http.request",
            "tenant": "governed-agent-demo",
            "actors": ["agent/intern"],
            "resource_pattern": "crm:campaign:*",
            "payload_bounds": {
                "method": {"eq": "POST"},
                "body.currency": {"eq": "EUR"},
                "body.amount": {"max": 5000},
            },
        },
    ],
}


def _load(name: str, rel_path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _policy_file(tmp_path) -> str:
    p = tmp_path / "authority_policy.egress.json"
    p.write_text(json.dumps(_POLICY_CONFIG), encoding="utf-8")
    return str(p)


def _gated_harness(tmp_path, *, require_consensus: bool = False) -> EgressHarness:
    return EgressHarness(
        require_consensus=require_consensus,
        env={"MCC_EGRESS_AUTHORITY_POLICY_CONFIG": _policy_file(tmp_path)},
    )


def test_case_b_forged_unbounded_amount_never_approved(tmp_path):
    """A compromised agent escalates a budget increase far above the
    independently configured bound (5000 EUR) -- no independent decision
    allows it, so approve() grants nothing."""
    hz = _gated_harness(tmp_path)
    try:
        r = hz.post(method="POST", url=hz.url("/campaigns/camp-42/budget"),
                   body={"amount": 999999, "currency": "EUR"},
                   actor="agent/intern", resource="crm:campaign:camp-42",
                   transaction_id="egress-b-1", idempotency_key="egress-b-1")
        body = r.json()
        assert body["outcome"] == "ESCALATE"
        rid = body["approval_request_id"]

        approved = hz.approve(rid)
        assert approved.status_code != 200 or approved.json().get("approved") is not True
        assert hz.seen == [] and hz.executor.count() == 0
    finally:
        pass


def test_case_b_within_bound_is_approved(tmp_path):
    """Positive control: the exact bounded amount the policy allows IS
    approved -- proving the gate is a real bound, not a blanket deny."""
    hz = _gated_harness(tmp_path)
    try:
        r = hz.post(method="POST", url=hz.url("/campaigns/camp-42/budget"),
                   body={"amount": 4000, "currency": "EUR"},
                   actor="agent/intern", resource="crm:campaign:camp-42",
                   transaction_id="egress-b-2", idempotency_key="egress-b-2")
        body = r.json()
        assert body["outcome"] == "ESCALATE"
        rid = body["approval_request_id"]

        approved = hz.approve(rid)
        assert approved.status_code == 200
        assert approved.json().get("approved") is True
    finally:
        pass


def test_case_k_unattended_operator_cannot_be_tricked(tmp_path, monkeypatch):
    """The REAL governed_agent_pilot_operator.py script, pointed at the
    gated harness, reading ONLY the request_id from agent-written state,
    cannot be tricked into approving an out-of-policy escalation."""
    hz = _gated_harness(tmp_path)
    try:
        monkeypatch.setenv("MCC_EGRESS_OPERATOR_API_KEY", "op-key")
        monkeypatch.setenv("MCC_GATEWAY_URL", "http://unused-this-test-calls-hz-directly")
        operator = _load("governed_agent_pilot_operator_case_k",
                         "deploy/pilot/governed_agent_pilot_operator.py")

        r = hz.post(method="POST", url=hz.url("/campaigns/camp-42/budget"),
                   body={"amount": 999999, "currency": "EUR"},
                   actor="agent/intern", resource="crm:campaign:camp-42",
                   transaction_id="egress-k-1", idempotency_key="egress-k-1")
        rid = r.json()["approval_request_id"]

        # Exercise the REAL script's approve-only function against the
        # REAL harness's TestClient (API-compatible with httpx.Client for
        # the single .post() call this function makes).
        operator.GATEWAY = ""  # unused by _approve_once's call below
        approved = operator._approve_once(hz.client, rid)
        assert approved is False
        assert hz.seen == [] and hz.executor.count() == 0
    finally:
        pass


def test_non_vacuity_old_architecture_would_have_approved_this(tmp_path):
    """The identical forged escalation, against a harness with NO
    independent authority policy configured (every demo's architecture
    before this fix), IS approved by the bare operator key."""
    hz = EgressHarness(require_consensus=False)  # no authority_policy env
    try:
        r = hz.post(method="POST", url=hz.url("/campaigns/camp-42/budget"),
                   body={"amount": 999999, "currency": "EUR"},
                   actor="agent/intern", resource="crm:campaign:camp-42",
                   transaction_id="egress-old-1", idempotency_key="egress-old-1")
        rid = r.json()["approval_request_id"]
        approved = hz.approve(rid)
        assert approved.status_code == 200
        assert approved.json().get("approved") is True
    finally:
        pass
