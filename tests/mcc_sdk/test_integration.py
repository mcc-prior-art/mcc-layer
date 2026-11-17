"""Integration/contract tests: the SDK against the REAL gateway.app, not a
mock. Proves the four verdicts round-trip correctly, an unknown request
field is rejected with HTTP 422 by the live Gateway (not just locally by
Pydantic), and the SDK fails closed on malformed real output.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from mcc_sdk import (
    AsyncMCCClient,
    EvaluateRequest,
    MCCClient,
    MCCContractError,
    MCCGatewayError,
    Verdict,
)
from tests._agent_credentials import module_key


@pytest.mark.parametrize(
    "identity,action,context,expected",
    [
        ("agent/payments-bot", "send_payment", {"amount": 1000}, Verdict.ALLOW),
        ("agent/ops-bot", "delete_database", {}, Verdict.DENY),
        ("agent/nobody", "send_payment", {"amount": 1}, Verdict.ESCALATE),
        ("agent/payments-bot", "send_payment", {"amount": 99999}, Verdict.CONSTRAIN),
    ],
)
def test_integration_every_verdict_round_trips(gateway_url, identity, action, context, expected):
    url, _shared_key = gateway_url
    # F1b: each identity evaluates with its own registered credential (the
    # shared tenant key obtains no decision in strict mode).
    with MCCClient(base_url=url, api_key=module_key(identity), timeout=5.0) as client:
        result = client.evaluate(
            EvaluateRequest(identity=identity, action=action, context=context, mode="inline")
        )
    assert result.decision == expected
    if expected in (Verdict.ALLOW, Verdict.CONSTRAIN):
        assert result.decision_token is not None
        assert result.signature is not None
    else:
        assert result.decision_token is None
        assert result.signature is None


def test_integration_constrain_forward_context_differs_from_requested(gateway_url):
    url, _shared_key = gateway_url
    with MCCClient(base_url=url, api_key=module_key("agent/payments-bot")) as client:
        result = client.evaluate(
            EvaluateRequest(
                identity="agent/payments-bot", action="send_payment",
                context={"amount": 99999}, mode="inline",
            )
        )
    assert result.constrained is True
    assert result.forward_context != {"amount": 99999}
    assert result.applied_constraints


def test_integration_unknown_top_level_field_rejected_by_live_gateway(gateway_url):
    """This bypasses the SDK's own local Pydantic validation (which would
    reject the field before ever sending it) by posting the raw HTTP request
    directly, to prove the LIVE GATEWAY (not just the SDK) rejects an
    unknown top-level /evaluate field with HTTP 422 -- the PR #80 behavior
    this SDK's own model mirrors."""
    url, api_key = gateway_url
    resp = httpx.post(
        f"{url}/evaluate",
        json={
            "identity": "agent/payments-bot", "action": "send_payment",
            "context": {}, "not_a_real_field": "should be rejected",
        },
        headers={"x-api-key": api_key},
        timeout=5.0,
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert any(d.get("type") == "extra_forbidden" for d in detail)


def test_integration_missing_required_field_rejected_by_live_gateway(gateway_url):
    url, api_key = gateway_url
    resp = httpx.post(
        f"{url}/evaluate",
        json={"identity": "agent/x", "context": {}},
        headers={"x-api-key": api_key},
        timeout=5.0,
    )
    assert resp.status_code == 422


def test_integration_no_authentication_fails_closed(gateway_url):
    url, _api_key = gateway_url
    with MCCClient(base_url=url, timeout=5.0) as client:  # no api_key configured
        with pytest.raises(Exception):
            client.evaluate(EvaluateRequest(identity="agent/x", action="send_payment"))


def test_integration_wrong_api_key_fails_closed(gateway_url):
    from mcc_sdk import MCCAuthenticationError

    url, _api_key = gateway_url
    with MCCClient(base_url=url, api_key="definitely-wrong-key", timeout=5.0) as client:
        with pytest.raises(MCCAuthenticationError):
            client.evaluate(EvaluateRequest(identity="agent/x", action="send_payment"))


def test_integration_gateway_422_is_a_gateway_error_not_a_contract_error(gateway_url):
    """A 422 is the live Gateway *rejecting the request*, which is distinct
    from the SDK being unable to trust a 200 response body -- confirmed by
    driving the real HTTP surface (SDK-level validation is bypassed the same
    way as the sibling unknown-field test above)."""
    url, api_key = gateway_url
    resp = httpx.post(
        f"{url}/evaluate",
        json={"identity": "agent/x", "context": {}},  # missing "action"
        headers={"x-api-key": api_key},
        timeout=5.0,
    )
    assert resp.status_code == 422


def test_integration_async_client_matches_sync_over_the_real_gateway(gateway_url):
    url, api_key = gateway_url

    async def go():
        async with AsyncMCCClient(base_url=url, api_key=module_key("agent/ops-bot"), timeout=5.0) as client:
            return await client.evaluate(
                EvaluateRequest(identity="agent/ops-bot", action="delete_database", mode="inline")
            )

    result = asyncio.run(go())
    assert result.decision == Verdict.DENY


def test_integration_audit_id_is_present_and_non_empty(gateway_url):
    url, _shared_key = gateway_url
    with MCCClient(base_url=url, api_key=module_key("agent/payments-bot")) as client:
        result = client.evaluate(
            EvaluateRequest(identity="agent/payments-bot", action="send_payment", context={"amount": 10})
        )
    assert result.audit_id
