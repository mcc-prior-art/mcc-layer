"""Round 26/27 — logical_operation_id propagation through the VoltAgent/AXFlow
clinic operator continuation step.

``integrations/voltagent/mcc_side/operator_cli.py`` is the operator-side
process that continues an ESCALATE after approval: it reads the
``escalation.json`` state the agent recorded at proposal time and POSTs
``/approvals/{id}/execute``. Round 25 made ``idempotency_key`` mandatory at
the coordinator; these tests prove this script reuses the SAME logical
operation identity the original proposal recorded (its ``correlationId``) --
never a fresh one, never derived from mutable context/payload.

Round 27 closes a gap in Round 26's own fallback: a state file missing
``correlationId`` used to fall back to the approval's own ``request_id`` --
an identifier from a different subsystem, minted at a different time, never
proven equivalent to the original logical operation. That fallback is now
removed; a state without its original ``correlationId`` fails closed before
any operator action (not approved, not executed -- zero actuator
invocations), rather than substituting a different identity.
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
    monkeypatch.setenv("MCC_GATEWAY_API_KEY", "agent-key")
    # V05 (part 2): the operator CLI executes with the escalated agent's OWN key.
    monkeypatch.setenv("MCC_AGENT_API_KEYS", '{"agent/notify-bot": "agent-key-notify-bot"}')
    monkeypatch.setenv("MCC_GATEWAY_OPERATOR_API_KEY", "op-key")
    monkeypatch.setenv("MCC_PILOT_STATE_DIR", str(tmp_path))


def test_operator_continuation_reuses_the_proposal_correlation_id(tmp_path, monkeypatch):
    """The exact bug Round 26 closes: the execute body must carry the SAME
    idempotency_key as the original proposal (its correlationId), never a
    missing one and never a freshly-minted one."""
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/approve"):
            return httpx.Response(200, json={"state": "APPROVED", "mandate": {"m": 1}})
        if path.endswith("/execute"):
            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json={"status": "EXECUTED", "execution": {"ok": True}})
        if path.endswith("/verify"):
            return httpx.Response(200, json={"valid": True})
        return httpx.Response(404, json={"error": "unexpected path", "path": path})

    _write_state(tmp_path, correlationId="corr-preserve-me")
    _install_mock_gateway(monkeypatch, handler)
    _set_env(monkeypatch, tmp_path)

    rc = operator_cli.main()

    assert rc == 0
    assert captured["body"]["idempotency_key"] == "corr-preserve-me"
    # Never derived from the mutable context/payload -- an independent
    # operation-binding identity, not a hash or copy of the business content.
    assert captured["body"]["idempotency_key"] != captured["body"]["context"]


def test_two_operator_runs_for_two_different_escalations_get_two_different_ids(
    tmp_path, monkeypatch
):
    """Two distinct logical operations (two different escalations) must never
    collapse onto the same idempotency_key just because they share a gateway
    or a state directory."""
    seen_keys = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/approve"):
            return httpx.Response(200, json={"state": "APPROVED", "mandate": {"m": 1}})
        if path.endswith("/execute"):
            body = json.loads(request.content)
            seen_keys.append(body["idempotency_key"])
            return httpx.Response(200, json={"status": "EXECUTED", "execution": {"ok": True}})
        if path.endswith("/verify"):
            return httpx.Response(200, json={"valid": True})
        return httpx.Response(404)

    _install_mock_gateway(monkeypatch, handler)
    _set_env(monkeypatch, tmp_path)

    _write_state(tmp_path, correlationId="corr-op-a", requestId="req-a")
    assert operator_cli.main() == 0

    _write_state(tmp_path, correlationId="corr-op-b", requestId="req-b")
    assert operator_cli.main() == 0

    assert seen_keys == ["corr-op-a", "corr-op-b"]


def test_missing_correlation_id_in_state_fails_closed_never_falls_back_to_request_id(
    tmp_path, monkeypatch
):
    """Round 27: request_id is NEVER treated as equivalent to the original
    logical_operation_id -- they are minted by different subsystems, at
    different times, for different purposes, and the implementation cannot
    prove they name the same canonical operation. A state file from an
    older/foreign recorder that lacks correlationId entirely (legacy,
    malformed, or hand-edited) must fail closed BEFORE any operator action:
    not approved, not executed -- zero actuator invocations, and not even
    the approval endpoint is called."""
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

    rc = operator_cli.main()

    assert rc == 1
    assert calls == []  # zero actuator invocations -- not even /approve ran


@pytest.mark.parametrize("bad_correlation_id", ["", "   ", None, 12345])
def test_blank_or_non_string_correlation_id_also_fails_closed(
    tmp_path, monkeypatch, bad_correlation_id
):
    """Empty, whitespace-only, null, or non-string correlationId values are
    exactly as invalid as a missing key entirely -- never coerced to a
    string, never treated as present, never silently repaired."""
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

    rc = operator_cli.main()

    assert rc == 1
    assert calls == []


def test_gateway_rejection_for_missing_id_would_surface_as_failure(tmp_path, monkeypatch):
    """Positive control proving these tests actually exercise the coordinator's
    invariant end-to-end at the transport-contract level: a gateway that
    returns MISSING_LOGICAL_OPERATION_ID must make the operator script report
    failure (rc=1), never silently succeed."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/approve"):
            return httpx.Response(200, json={"state": "APPROVED", "mandate": {"m": 1}})
        if path.endswith("/execute"):
            return httpx.Response(200, json={
                "status": "BLOCKED",
                "reason": "MISSING_LOGICAL_OPERATION_ID: a valid, non-empty idempotency_key "
                          "is required for protected execution; fail-closed",
            })
        if path.endswith("/verify"):
            return httpx.Response(200, json={"valid": True})
        return httpx.Response(404)

    _write_state(tmp_path, correlationId="corr-would-be-blocked")
    _install_mock_gateway(monkeypatch, handler)
    _set_env(monkeypatch, tmp_path)

    rc = operator_cli.main()

    assert rc == 1
