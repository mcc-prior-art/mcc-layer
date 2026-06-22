"""Egress proxy tests: action mapping and fail-closed enforcement, with the
gateway round trip stubbed so no sockets are needed.
"""

import asyncio

from interceptors.egress_proxy import (
    ActionMapper,
    EgressGovernor,
    OutboundRequest,
    Route,
)

run = asyncio.run


def mapper():
    return ActionMapper(
        [
            Route(action="send_payment", method="POST", host="*", path="*charge*"),
            Route(action="read_account", method="GET", host="*", path="*"),
            Route(action="delete_resource", method="DELETE", host="*", path="*"),
        ]
    )


def test_action_mapper_matches_route():
    action, ctx = mapper().map(
        OutboundRequest(
            method="POST",
            url="http://payments.local/v1/charge",
            body={"amount": 100},
        )
    )
    assert action == "send_payment"
    assert ctx == {"amount": 100}


def test_action_mapper_unmapped_derives_deny_bound_action():
    action, _ = mapper().map(
        OutboundRequest(method="POST", url="http://evil.local/exfiltrate")
    )
    assert action == "post_evil.local"  # no policy -> gateway will DENY


def decide_returning(result):
    async def decide(_payload):
        return result

    return decide


def test_allow_forwards():
    gov = EgressGovernor(
        mapper=mapper(),
        decide=decide_returning(
            {"decision": "ALLOW", "enforce": True, "audit_id": "a1"}
        ),
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


def test_deny_blocks_with_403():
    gov = EgressGovernor(
        mapper=mapper(),
        decide=decide_returning({"decision": "DENY", "enforce": True, "reason": "no"}),
    )
    out = run(
        gov.govern(OutboundRequest(method="DELETE", url="http://x.local/thing"))
    )
    assert out.forward is False
    assert out.status_code == 403


def test_observe_mode_forwards_even_on_deny():
    gov = EgressGovernor(
        mapper=mapper(),
        decide=decide_returning({"decision": "DENY", "enforce": False}),
    )
    out = run(
        gov.govern(OutboundRequest(method="DELETE", url="http://x.local/thing"))
    )
    assert out.forward is True  # observe never blocks
    assert out.enforce is False


def test_gateway_unreachable_fails_closed():
    async def boom(_payload):
        raise ConnectionError("gateway down")

    gov = EgressGovernor(mapper=mapper(), decide=boom)
    out = run(gov.govern(OutboundRequest(method="POST", url="http://x.local/charge")))
    assert out.forward is False
    assert out.status_code == 502
    assert "fail-closed" in out.reason


def test_identity_extracted_from_header():
    captured = {}

    async def decide(payload):
        captured.update(payload)
        return {"decision": "ALLOW", "enforce": True}

    gov = EgressGovernor(mapper=mapper(), decide=decide)
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
