"""Round 26/27 — logical_operation_id handling in the VoltAgent/AXFlow clinic
ESCALATE continuation, and (V05 part 2) the APPROVE-ONLY operator step.

``integrations/voltagent/mcc_side/operator_cli.py`` is the operator-side
process for an ESCALATE: it reads the ``escalation.json`` state the agent
recorded at proposal time and grants the approval.

V05 part 2 moved the governed EXECUTION out of the operator: the operator never
holds or presents an agent credential and never calls ``/execute``. It hands the
granted single-use mandate back (``approval.json``) and the escalating agent
executes from its own container with its own credential
(``integrations/voltagent/src/approved-continuation.ts``).

The Round 26/27 invariants are therefore enforced at BOTH points:

* here (operator): a state file without a valid original ``correlationId``
  fails closed BEFORE any operator action -- not approved, not executed, zero
  gateway calls (unchanged assertions below);
* here (operator): the hand-off carries the SAME ``correlationId`` verbatim
  (never derived from mutable context, never the approval ``requestId``);
* in the agent: execution reuses that ``correlationId`` as the idempotency key,
  refuses a missing/blank/non-string one before any call, and reports a
  gateway ``BLOCKED`` (e.g. MISSING_LOGICAL_OPERATION_ID) as failure --
  ``integrations/voltagent/tests/agent-credential.test.ts``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from integrations.voltagent.mcc_side import operator_cli  # noqa: E402


def _write_state(tmp_path: Path, **fields) -> Path:
    state = {
        "requestId": "req-xyz",
        "actor": "agent/notify-bot",
        "resource": "crm",
        "context": {"recipient": "c-1", "message": "hi"},
        "correlationId": "corr-preserve-me",
    }
    state.update(fields)
    path = tmp_path / "escalation.json"
    path.write_text(json.dumps(state), encoding="utf-8")
    return path


def _install_mock_gateway(monkeypatch, handler):
    real_client = httpx.Client

    def fake_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(operator_cli.httpx, "Client", fake_client)


def _set_env(monkeypatch, tmp_path):
    monkeypatch.setenv("MCC_OPERATOR_GATEWAY_URL", "http://mock-gateway")
    monkeypatch.setenv("MCC_GATEWAY_OPERATOR_API_KEY", "op-key")
    monkeypatch.setenv("MCC_PILOT_STATE_DIR", str(tmp_path))
    # The operator needs, and is given, NO agent credential of any kind.
    for name in ("MCC_GATEWAY_API_KEY", "MCC_AGENT_API_KEYS", "MCC_AGENT_CREDENTIAL_FILE"):
        monkeypatch.delenv(name, raising=False)


def _approving_gateway(seen):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.path, dict(request.headers)))
        if request.url.path.endswith("/approve"):
            return httpx.Response(200, json={"state": "APPROVED", "mandate": {"m": 1}})
        return httpx.Response(500, json={"error": "operator must call nothing else"})
    return handler


def test_operator_hands_back_the_proposal_correlation_id_and_never_executes(tmp_path, monkeypatch):
    """The hand-off carries the SAME logical-operation id the original
    proposal recorded (its correlationId) -- never a missing one, never a
    freshly minted one, never derived from the mutable context -- and the
    operator calls ONLY /approve, with ONLY its operator credential."""
    seen = []
    _write_state(tmp_path, correlationId="corr-preserve-me")
    _install_mock_gateway(monkeypatch, _approving_gateway(seen))
    _set_env(monkeypatch, tmp_path)

    rc = operator_cli.main([])

    assert rc == 0
    assert [p for p, _ in seen] == ["/approvals/req-xyz/approve"]
    headers = seen[0][1]
    assert headers.get("x-operator-key") == "op-key"
    assert "x-api-key" not in headers          # no agent / tenant credential presented
    handoff = json.loads((tmp_path / "approval.json").read_text())
    assert handoff["correlationId"] == "corr-preserve-me"
    assert handoff["requestId"] == "req-xyz"
    assert handoff["state"] == "APPROVED" and handoff["mandate"] == {"m": 1}
    assert handoff["correlationId"] != json.dumps({"recipient": "c-1", "message": "hi"})


def test_two_operator_runs_for_two_different_escalations_keep_two_different_ids(tmp_path, monkeypatch):
    """Two distinct logical operations never collapse onto one id just
    because they share a gateway or a state directory."""
    seen = []
    _install_mock_gateway(monkeypatch, _approving_gateway(seen))
    _set_env(monkeypatch, tmp_path)

    _write_state(tmp_path, correlationId="corr-op-a", requestId="req-a")
    assert operator_cli.main([]) == 0
    first = json.loads((tmp_path / "approval.json").read_text())

    _write_state(tmp_path, correlationId="corr-op-b", requestId="req-b")
    assert operator_cli.main([]) == 0
    second = json.loads((tmp_path / "approval.json").read_text())

    assert (first["requestId"], first["correlationId"]) == ("req-a", "corr-op-a")
    assert (second["requestId"], second["correlationId"]) == ("req-b", "corr-op-b")
    assert all(not p.endswith("/execute") for p, _ in seen)


def test_missing_correlation_id_in_state_fails_closed_never_falls_back_to_request_id(
    tmp_path, monkeypatch
):
    """Round 27: request_id is NEVER treated as equivalent to the original
    logical_operation_id. A state file lacking correlationId (legacy,
    malformed, or hand-edited) fails closed BEFORE any operator action: not
    approved, not executed -- zero gateway calls, not even /approve."""
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(500, json={"error": "must never be called"})

    state = {
        "requestId": "req-no-corr",
        "actor": "agent/notify-bot",
        "resource": "crm",
        "context": {"recipient": "c-1"},
        # correlationId deliberately omitted -- the exact legacy/malformed case.
    }
    (tmp_path / "escalation.json").write_text(json.dumps(state), encoding="utf-8")
    _install_mock_gateway(monkeypatch, handler)
    _set_env(monkeypatch, tmp_path)

    rc = operator_cli.main([])

    assert rc == 1
    assert calls == []  # zero actuator invocations -- not even /approve ran
    assert not (tmp_path / "approval.json").exists()


@pytest.mark.parametrize("bad_correlation_id", ["", "   ", None, 12345])
def test_blank_or_non_string_correlation_id_also_fails_closed(
    tmp_path, monkeypatch, bad_correlation_id
):
    """Empty, whitespace-only, null, or non-string correlationId values are
    exactly as invalid as a missing key -- never coerced, never repaired."""
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(500, json={"error": "must never be called"})

    state = {
        "requestId": "req-bad-corr",
        "actor": "agent/notify-bot",
        "resource": "crm",
        "context": {"recipient": "c-1"},
        "correlationId": bad_correlation_id,
    }
    (tmp_path / "escalation.json").write_text(json.dumps(state), encoding="utf-8")
    _install_mock_gateway(monkeypatch, handler)
    _set_env(monkeypatch, tmp_path)

    rc = operator_cli.main([])

    assert rc == 1
    assert calls == []
    assert not (tmp_path / "approval.json").exists()


@pytest.mark.parametrize("response", [
    httpx.Response(403, json={"detail": "AUTHORITY_POLICY_DENIED"}),
    httpx.Response(200, json={"state": "DENIED", "mandate": None}),
])
def test_refused_approval_surfaces_as_failure_and_hands_nothing_back(tmp_path, monkeypatch, response):
    """Positive control at the transport contract: a gateway that refuses the
    approval (independent authority policy, or no mandate) makes the operator
    report failure (rc=1) and hand NO mandate to the agent."""
    def handler(request: httpx.Request) -> httpx.Response:
        return response

    _write_state(tmp_path, correlationId="corr-would-be-refused")
    _install_mock_gateway(monkeypatch, handler)
    _set_env(monkeypatch, tmp_path)

    assert operator_cli.main([]) == 1
    assert not (tmp_path / "approval.json").exists()


def test_operator_without_operator_key_is_disabled(tmp_path, monkeypatch):
    _write_state(tmp_path)
    _set_env(monkeypatch, tmp_path)
    monkeypatch.delenv("MCC_GATEWAY_OPERATOR_API_KEY")
    assert operator_cli.main([]) == 1
    assert not (tmp_path / "approval.json").exists()
