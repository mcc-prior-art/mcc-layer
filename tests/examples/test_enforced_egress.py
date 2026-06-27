"""End-to-end: the enforced egress proxy over its HTTP API (consensus-required).

Drives ALLOW / DENY / ESCALATE / CONSTRAIN through the real embedded runtime to a
live loopback upstream, plus replay, tampering, no-bypass, SSRF, and infra
fail-closed. The upstream records exactly what it received, so we can prove that
denied/escalated/original-constrained actions never reach it.
"""

import pytest

from egress_proxy.executor import UnauthorizedExecution
from tests._egress_harness import EgressHarness


@pytest.fixture
def hz():
    return EgressHarness()


def _round1(hz, **fields):
    """Issue the challenge for an action (consensus mode round 1)."""
    return hz.post(**fields).json()


# ----------------------------- ALLOW -----------------------------

def test_allow_executes_once_and_reaches_upstream(hz):
    url = hz.url("/charge")
    r1 = _round1(hz, method="POST", url=url, body={"amount": 1000},
                 actor="agent/egress", transaction_id="t1", idempotency_key="i1")
    assert r1["outcome"] == "CONSENSUS_REQUIRED"
    action = hz.canonical(method="POST", url=url, body={"amount": 1000})
    r2 = hz.post(method="POST", url=url, body={"amount": 1000}, actor="agent/egress",
                 transaction_id="t1", idempotency_key="i1", challenge_id=r1["challenge_id"],
                 votes=hz.votes(action, actor="agent/egress", nonce=r1["nonce"]))
    body = r2.json()
    assert r2.status_code == 200 and body["outcome"] == "ALLOW" and body["executed"]
    assert body["upstream_status"] == 200
    assert hz.seen == [{"method": "POST", "path": "charge", "body": {"amount": 1000}}]
    assert hz.executor.count() == 1


# ----------------------------- DENY -----------------------------

def test_deny_zero_upstream(hz):
    url = hz.url("/charge")
    r1 = _round1(hz, method="DELETE", url=url, body={"amount": 1}, actor="agent/egress",
                 transaction_id="td", idempotency_key="idd")
    action = hz.canonical(method="DELETE", url=url, body={"amount": 1})
    r2 = hz.post(method="DELETE", url=url, body={"amount": 1}, actor="agent/egress",
                 transaction_id="td", idempotency_key="idd", challenge_id=r1["challenge_id"],
                 votes=hz.votes(action, actor="agent/egress", nonce=r1["nonce"]))
    assert r2.status_code == 403 and r2.json()["outcome"] == "DENY"
    assert hz.seen == [] and hz.executor.count() == 0


# ----------------------------- ESCALATE -----------------------------

def test_escalate_no_call_then_executes_after_approval(hz):
    url = hz.url("/charge")
    r1 = _round1(hz, method="POST", url=url, body={"amount": 10}, actor="agent/intern",
                 transaction_id="te", idempotency_key="ide")
    action = hz.canonical(method="POST", url=url, body={"amount": 10})
    votes = hz.votes(action, actor="agent/intern", nonce=r1["nonce"])
    r2 = hz.post(method="POST", url=url, body={"amount": 10}, actor="agent/intern",
                 transaction_id="te", idempotency_key="ide", challenge_id=r1["challenge_id"],
                 votes=votes).json()
    assert r2["outcome"] == "ESCALATE" and not r2["executed"]
    assert hz.seen == [] and hz.executor.count() == 0
    rid = r2["approval_request_id"]
    assert hz.approve(rid).json()["approved"]
    # Resubmit with the approval (+ the same consensus material).
    r3 = hz.post(method="POST", url=url, body={"amount": 10}, actor="agent/intern",
                 transaction_id="te", idempotency_key="ide", challenge_id=r1["challenge_id"],
                 votes=votes, approval_id=rid).json()
    assert r3["outcome"] == "ALLOW" and r3["executed"]
    assert hz.executor.count() == 1


def test_escalate_invalid_approval_denied(hz):
    url = hz.url("/charge")
    r1 = _round1(hz, method="POST", url=url, body={"amount": 10}, actor="agent/intern",
                 transaction_id="te2", idempotency_key="ide2")
    action = hz.canonical(method="POST", url=url, body={"amount": 10})
    votes = hz.votes(action, actor="agent/intern", nonce=r1["nonce"])
    hz.post(method="POST", url=url, body={"amount": 10}, actor="agent/intern",
            transaction_id="te2", idempotency_key="ide2", challenge_id=r1["challenge_id"],
            votes=votes)
    r3 = hz.post(method="POST", url=url, body={"amount": 10}, actor="agent/intern",
                 transaction_id="te2", idempotency_key="ide2", challenge_id=r1["challenge_id"],
                 votes=votes, approval_id="approval-forged")
    assert not r3.json()["executed"] and hz.executor.count() == 0


# ----------------------------- CONSTRAIN re-consensus -----------------------------

def test_constrain_new_hash_fresh_consensus_only_clamped_executes(hz):
    url = hz.url("/charge")
    r1 = _round1(hz, method="POST", url=url, body={"amount": 10000}, actor="agent/egress",
                 transaction_id="tc", idempotency_key="idc")
    action = hz.canonical(method="POST", url=url, body={"amount": 10000})
    r2 = hz.post(method="POST", url=url, body={"amount": 10000}, actor="agent/egress",
                 transaction_id="tc", idempotency_key="idc", challenge_id=r1["challenge_id"],
                 votes=hz.votes(action, actor="agent/egress", nonce=r1["nonce"])).json()
    assert r2["outcome"] == "CONSTRAIN" and not r2["executed"]
    constrained = r2["constrained_action"]
    assert constrained["body.amount"] == 5000
    # The constrained action has a DIFFERENT hash and a fresh challenge.
    assert r2["action_hash"] != hz.canonical(method="POST", url=url, body={"amount": 10000})
    assert r2["challenge_id"] and r2["nonce"]
    assert hz.seen == [] and hz.executor.count() == 0  # original never executed

    r3 = hz.post(method="POST", url=url, body={"amount": 5000}, actor="agent/egress",
                 transaction_id="tc", idempotency_key="idc", constrained=True,
                 challenge_id=r2["challenge_id"],
                 votes=hz.votes(constrained, actor="agent/egress", nonce=r2["nonce"],
                                payload=constrained)).json()
    assert r3["outcome"] == "CONSTRAIN" and r3["executed"]
    assert hz.seen == [{"method": "POST", "path": "charge", "body": {"amount": 5000}}]
    assert all(s["body"].get("amount") != 10000 for s in hz.seen)


def test_constrain_original_votes_cannot_execute_clamped(hz):
    url = hz.url("/charge")
    r1 = _round1(hz, method="POST", url=url, body={"amount": 10000}, actor="agent/egress",
                 transaction_id="tc2", idempotency_key="idc2")
    action = hz.canonical(method="POST", url=url, body={"amount": 10000})
    orig_votes = hz.votes(action, actor="agent/egress", nonce=r1["nonce"])
    r2 = hz.post(method="POST", url=url, body={"amount": 10000}, actor="agent/egress",
                 transaction_id="tc2", idempotency_key="idc2", challenge_id=r1["challenge_id"],
                 votes=orig_votes).json()
    constrained = r2["constrained_action"]
    # Re-submit the clamped body but with the ORIGINAL (10000-bound) votes.
    r3 = hz.post(method="POST", url=url, body={"amount": 5000}, actor="agent/egress",
                 transaction_id="tc2", idempotency_key="idc2", constrained=True,
                 challenge_id=r2["challenge_id"], votes=orig_votes).json()
    assert not r3["executed"] and hz.executor.count() == 0


# ----------------------------- replay / tampering -----------------------------

def _allow_pair(hz, *, txn, idem, amount=1000):
    url = hz.url("/charge")
    r1 = _round1(hz, method="POST", url=url, body={"amount": amount}, actor="agent/egress",
                 transaction_id=txn, idempotency_key=idem)
    action = hz.canonical(method="POST", url=url, body={"amount": amount})
    return url, r1, hz.votes(action, actor="agent/egress", nonce=r1["nonce"])


def test_replay_same_challenge_denied(hz):
    url, r1, votes = _allow_pair(hz, txn="t1", idem="i1")
    a = hz.post(method="POST", url=url, body={"amount": 1000}, actor="agent/egress",
                transaction_id="t1", idempotency_key="i1", challenge_id=r1["challenge_id"],
                votes=votes).json()
    assert a["executed"]
    b = hz.post(method="POST", url=url, body={"amount": 1000}, actor="agent/egress",
                transaction_id="t1b", idempotency_key="i1b", challenge_id=r1["challenge_id"],
                votes=votes).json()
    assert not b["executed"] and hz.executor.count() == 1


@pytest.mark.parametrize("tamper", ["url", "method", "body", "actor", "votes"])
def test_tampering_after_challenge_denied(hz, tamper):
    url = hz.url("/charge")
    r1 = _round1(hz, method="POST", url=url, body={"amount": 1000}, actor="agent/egress",
                 transaction_id="tt", idempotency_key="itt")
    action = hz.canonical(method="POST", url=url, body={"amount": 1000})
    votes = hz.votes(action, actor="agent/egress", nonce=r1["nonce"])
    fields = dict(method="POST", url=url, body={"amount": 1000}, actor="agent/egress",
                  transaction_id="tt", idempotency_key="itt",
                  challenge_id=r1["challenge_id"], votes=votes)
    if tamper == "url":
        fields["url"] = hz.url("/other")
    elif tamper == "method":
        fields["method"] = "PUT"
    elif tamper == "body":
        fields["body"] = {"amount": 9999}
    elif tamper == "actor":
        fields["actor"] = "agent/someone-else"
    elif tamper == "votes":
        fields["votes"] = hz.votes(hz.canonical(method="POST", url=url, body={"amount": 9999}),
                                   actor="agent/egress", nonce=r1["nonce"])
    r = hz.post(**fields).json()
    assert not r["executed"] and hz.executor.count() == 0


# ----------------------------- no bypass / SSRF -----------------------------

def test_executor_refuses_unsigned_call(hz):
    import asyncio
    ex = hz.executor
    with pytest.raises(UnauthorizedExecution):
        asyncio.run(ex.execute("http.request", {"scheme": "http", "host": "x", "port": 80,
                                                "method": "GET", "path": "/"}))
    with pytest.raises(UnauthorizedExecution):
        asyncio.run(ex.execute("http.request", {}, authorization={"decision": "DENY"}))
    assert ex.count() == 0


def test_submission_ssrf_blocks_metadata_host():
    # A non-loopback proxy rejects link-local/metadata destinations at submission.
    hz = EgressHarness()
    # Override the destination policy to default (no loopback) and target metadata IP.
    r = hz.post(method="GET", url="http://169.254.169.254/latest/meta-data",
                actor="agent/egress", transaction_id="s", idempotency_key="s")
    assert r.json()["outcome"] == "INVALID_REQUEST" and hz.executor.count() == 0


# ----------------------------- infra fail-closed -----------------------------

def test_redis_unavailable_fails_closed_zero_upstream():
    from mcc_core import RedisNonceRegistry
    from tests._fakeredis import DownRedis

    hz = EgressHarness()
    # Swap in a down-Redis nonce registry on the embedded runtime's gate.
    hz.app.state.egress_service.rt.client.gate.nonce_registry = RedisNonceRegistry(
        DownRedis(), namespace="x:")
    url, r1, votes = _allow_pair(hz, txn="t", idem="i")
    r = hz.post(method="POST", url=url, body={"amount": 1000}, actor="agent/egress",
                transaction_id="t", idempotency_key="i", challenge_id=r1["challenge_id"],
                votes=votes).json()
    assert not r["executed"] and hz.seen == [] and hz.executor.count() == 0
