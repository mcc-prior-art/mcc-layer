"""Workstream A -- Exclusive Execution Path (PR #71).

Tests MCC-Core's central invariant -- "no verified authority, no execution"
-- strictly black-box, through the real actuator's (``egress_proxy``) public
HTTP API. Every attack below is a distinct way an attacker (or a buggy/
malicious adapter, or a compromised agent) might try to reach the protected
external effect (the real ``pilot_notify`` sink) WITHOUT a verified,
correctly bound N-of-M evaluator consensus. The pass condition for every
attack is the same: the actuator's response never reports
``{"outcome": "ALLOW", "executed": true}``, AND the external effect sink's
own, independently observed receipt count never increases. Observing the
receipt count (rather than trusting the actuator's own claim) is what makes
this a genuine black-box proof rather than a self-report.

Eight required attacks (see ``docs/EXCLUSIVE_EXECUTION_PATH.md``):

  A1  direct actuator invocation without completing consensus
  A2  stolen endpoint / wrong client credential (bad ``x-api-key``)
  A3  reused credential -- replaying an already-consumed challenge+votes
  A4  adapter-to-actuator bypass -- votes from a DIFFERENT trust domain
      (the Gateway's own evaluator pool, not the actuator's)
  A5  agent-to-actuator bypass -- a self-signed, never-trusted evaluator key
  A6  alternate network route -- a destination outside the allowed host set
  A7  forged gate identity -- a structurally valid vote with a tampered
      signature
  A8  valid-token-direct-to-actuator -- fully valid, correctly signed votes,
      but bound to a DIFFERENT operation (nonce/challenge) than the one
      being submitted

A6 is answered entirely by the actuator's own SSRF/allowed-host enforcement
and does not depend on network segmentation; the harder claim -- that an
attacker with raw network access to the notify sink could reach it directly,
bypassing the actuator's application logic altogether -- is a network-
segmentation property this single-host test CANNOT observe, and is recorded
as a stated limitation in ``ASSUMPTIONS_AND_LIMITS.md`` rather than silently
assumed away.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict

import httpx


def _request(sut, *, transaction_id: str, url: str, actor: str = "agent/egress",
             resource: str = "notify") -> Dict[str, Any]:
    return {
        "method": "POST", "url": url, "headers": {},
        "body": {"recipient": "ops", "message": "assurance-attack-probe", "correlation_id": transaction_id},
        "actor": actor, "resource": resource,
        "transaction_id": transaction_id, "idempotency_key": transaction_id,
    }


def test_a1_direct_actuator_invocation_without_consensus(sut):
    """A1: propose an action and never complete the consensus handshake."""
    before = sut.notification_receipt_count()

    tx = str(uuid.uuid4())
    proposal = sut.propose_notification(transaction_id=tx, idempotency_key=tx)

    assert proposal["outcome"] != "ALLOW"
    assert proposal["executed"] is False
    assert sut.notification_receipt_count() == before


def test_a2_stolen_endpoint_wrong_client_credential(sut):
    """A2: the caller knows the actuator's URL but not its client API key."""
    before = sut.notification_receipt_count()

    tx = str(uuid.uuid4())
    r = httpx.post(
        f"{sut.actuator_url}/v1/http/execute", headers={"x-api-key": "not-the-real-key"},
        json=_request(sut, transaction_id=tx, url=f"{sut.notify_url}/send_notification"), timeout=10.0,
    )

    assert r.status_code in (401, 403)
    assert sut.notification_receipt_count() == before


def test_a3_reused_credential_replayed_challenge(sut):
    """A3: a fully authorized flow completes once (proving the positive path
    is real), then the identical challenge_id + votes are replayed verbatim.
    The replay must not produce a SECOND external effect."""
    before = sut.notification_receipt_count()

    tx = str(uuid.uuid4())
    proposal = sut.propose_notification(transaction_id=tx, idempotency_key=tx)
    votes = sut.actuator_votes(
        action="http.request", payload=sut.canonical_notification_action(proposal),
        actor="agent/egress", resource="notify", nonce=proposal["nonce"],
    )
    first = sut.submit_notification_votes(proposal, votes=votes)
    assert first["outcome"] == "ALLOW" and first["executed"] is True
    assert sut.notification_receipt_count() == before + 1

    replay = sut.submit_notification_votes(proposal, votes=votes)
    assert not (replay["outcome"] == "ALLOW" and replay["executed"] is True)
    assert sut.notification_receipt_count() == before + 1


def test_a4_adapter_to_actuator_bypass_wrong_trust_domain(sut):
    """A4: votes signed by the GATEWAY's evaluator pool -- a real, valid
    consensus in ITS OWN trust domain -- submitted to the actuator, which
    trusts a different evaluator pool entirely."""
    before = sut.notification_receipt_count()

    tx = str(uuid.uuid4())
    proposal = sut.propose_notification(transaction_id=tx, idempotency_key=tx)
    wrong_domain_votes = sut.gateway_votes(
        action="http.request", payload=sut.canonical_notification_action(proposal),
        actor="agent/egress", resource="notify", nonce=proposal["nonce"],
    )
    result = sut.submit_notification_votes(proposal, votes=wrong_domain_votes)

    assert not (result["outcome"] == "ALLOW" and result["executed"] is True)
    assert sut.notification_receipt_count() == before


def test_a5_agent_to_actuator_bypass_self_signed_forged_evaluator(sut):
    """A5: an agent mints its own Ed25519 key and signs its own "evaluator"
    votes -- a key that was never registered in the actuator's trust store."""
    before = sut.notification_receipt_count()

    tx = str(uuid.uuid4())
    proposal = sut.propose_notification(transaction_id=tx, idempotency_key=tx)
    payload = sut.canonical_notification_action(proposal)
    forged_vote = sut.forge_vote(
        action="http.request", payload=payload, actor="agent/egress", resource="notify",
        nonce=proposal["nonce"],
    )
    forged_votes = [forged_vote] * 3  # even three "independent" ballots from the same untrusted key must not count

    result = sut.submit_notification_votes(proposal, votes=forged_votes)

    assert not (result["outcome"] == "ALLOW" and result["executed"] is True)
    assert sut.notification_receipt_count() == before


def test_a6_alternate_network_route_disallowed_host(sut):
    """A6: the proposed destination is outside the actuator's allowed host
    set -- rejected by SSRF/allowlist enforcement regardless of consensus."""
    before = sut.notification_receipt_count()

    tx = str(uuid.uuid4())
    r = httpx.post(
        f"{sut.actuator_url}/v1/http/execute", headers={"x-api-key": sut.actuator_key()},
        json=_request(sut, transaction_id=tx, url="http://evil.example.com/send_notification"), timeout=10.0,
    )
    body = r.json()

    assert not (body.get("outcome") == "ALLOW" and body.get("executed") is True)
    assert sut.notification_receipt_count() == before


def test_a7_forged_gate_identity_tampered_signature(sut):
    """A7: an otherwise well-formed, correctly bound vote whose signature
    bytes have been tampered with after signing."""
    before = sut.notification_receipt_count()

    tx = str(uuid.uuid4())
    proposal = sut.propose_notification(transaction_id=tx, idempotency_key=tx)
    votes = sut.actuator_votes(
        action="http.request", payload=sut.canonical_notification_action(proposal),
        actor="agent/egress", resource="notify", nonce=proposal["nonce"],
    )
    tampered = sut.tamper_signature(votes[0])

    result = sut.submit_notification_votes(proposal, votes=[tampered] + votes[1:])

    assert not (result["outcome"] == "ALLOW" and result["executed"] is True)
    assert sut.notification_receipt_count() == before


def test_a8_valid_token_direct_to_actuator_wrong_binding(sut):
    """A8: fully valid, correctly signed votes for a DIFFERENT, genuinely
    issued operation are submitted against this operation's challenge."""
    before = sut.notification_receipt_count()

    tx_a, tx_b = str(uuid.uuid4()), str(uuid.uuid4())
    proposal_a = sut.propose_notification(transaction_id=tx_a, idempotency_key=tx_a)
    proposal_b = sut.propose_notification(transaction_id=tx_b, idempotency_key=tx_b)
    votes_for_a = sut.actuator_votes(
        action="http.request", payload=sut.canonical_notification_action(proposal_a),
        actor="agent/egress", resource="notify", nonce=proposal_a["nonce"],
    )

    result = sut.submit_notification_votes(proposal_b, votes=votes_for_a)

    assert not (result["outcome"] == "ALLOW" and result["executed"] is True)
    assert sut.notification_receipt_count() == before
