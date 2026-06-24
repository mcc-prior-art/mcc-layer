"""Consensus challenge service + registry tests.

The gateway issues a strong one-time nonce inside a challenge bound to the exact
operation, persists it with a TTL, and consumes it exactly once. Unknown,
expired, reused, or mismatched challenges fail closed.
"""

import asyncio

from mcc_core import (
    ChallengeService,
    ChallengeState,
    InMemoryChallengeRegistry,
    hash_payload,
)

run = asyncio.run
NOW = 1_780_000_000
ACTION = "deploy_release"
ACTOR = "agent/ops"
RESOURCE = "cluster-1"
POLICY_HASH = "sha256:policy-v1"
PAYLOAD = {"target": "cluster-1", "environment": "prod"}
PAYLOAD_HASH = hash_payload(PAYLOAD)


def service():
    return ChallengeService(InMemoryChallengeRegistry())


def issue(svc, *, action=ACTION, actor=ACTOR, resource=RESOURCE, payload_hash=PAYLOAD_HASH,
          policy_hash=POLICY_HASH, ttl=120, now=NOW):
    return run(svc.issue(action=action, actor=actor, resource=resource,
                         payload_hash=payload_hash, policy_hash=policy_hash,
                         ttl_seconds=ttl, now=now))


def consume(svc, cid, *, action=ACTION, actor=ACTOR, resource=RESOURCE, payload_hash=PAYLOAD_HASH,
            policy_hash=POLICY_HASH, nonce, now=NOW):
    return run(svc.consume(cid, action=action, actor=actor, resource=resource,
                           payload_hash=payload_hash, policy_hash=policy_hash,
                           nonce=nonce, now=now))


# ---- Issuance ----

def test_issue_mints_strong_unique_nonce_and_binding():
    svc = service()
    a = issue(svc)
    b = issue(svc)
    assert a.challenge_id != b.challenge_id
    assert a.nonce != b.nonce
    assert len(a.nonce) >= 32 and a.state == ChallengeState.ISSUED.value
    assert a.action == ACTION and a.actor == ACTOR and a.resource == RESOURCE
    assert a.payload_hash == PAYLOAD_HASH and a.policy_hash == POLICY_HASH
    assert a.expires_at == NOW + 120
    # The public view carries the nonce + binding but no internal state field.
    view = a.public_view()
    assert view["nonce"] == a.nonce and "state" not in view


# ---- Single-use consume ----

def test_consume_exactly_once():
    svc = service()
    rec = issue(svc)
    first = consume(svc, rec.challenge_id, nonce=rec.nonce)
    second = consume(svc, rec.challenge_id, nonce=rec.nonce)
    assert first.ok and first.state == ChallengeState.CONSUMED.value
    assert not second.ok and second.state == ChallengeState.CONSUMED.value


def test_unknown_challenge_rejected():
    svc = service()
    r = consume(svc, "chal-does-not-exist", nonce="whatever")
    assert not r.ok and "UNKNOWN_CHALLENGE" in r.reason


def test_expired_challenge_rejected():
    svc = service()
    rec = issue(svc, ttl=60)  # expires at NOW+60
    r = consume(svc, rec.challenge_id, nonce=rec.nonce, now=NOW + 61)
    assert not r.ok and "EXPIRED" in r.reason.upper()


# ---- Binding mismatch ----

def test_nonce_mismatch_rejected():
    svc = service()
    rec = issue(svc)
    assert not consume(svc, rec.challenge_id, nonce="not-the-nonce").ok


def test_action_mismatch_rejected():
    svc = service()
    rec = issue(svc)
    assert not consume(svc, rec.challenge_id, action="other_action", nonce=rec.nonce).ok


def test_actor_mismatch_rejected():
    svc = service()
    rec = issue(svc)
    assert not consume(svc, rec.challenge_id, actor="agent/evil", nonce=rec.nonce).ok


def test_resource_mismatch_rejected():
    svc = service()
    rec = issue(svc)
    assert not consume(svc, rec.challenge_id, resource="cluster-2", nonce=rec.nonce).ok


def test_payload_mismatch_rejected():
    svc = service()
    rec = issue(svc)
    assert not consume(svc, rec.challenge_id, payload_hash=hash_payload({"x": 1}), nonce=rec.nonce).ok


def test_policy_hash_mismatch_rejected():
    svc = service()
    rec = issue(svc)
    assert not consume(svc, rec.challenge_id, policy_hash="sha256:other", nonce=rec.nonce).ok


def test_mismatch_does_not_consume_the_challenge():
    # A mismatched attempt must not burn the challenge: the legitimate operation
    # can still consume it afterwards.
    svc = service()
    rec = issue(svc)
    assert not consume(svc, rec.challenge_id, nonce="wrong").ok
    assert consume(svc, rec.challenge_id, nonce=rec.nonce).ok


# ---- Concurrency ----

def test_concurrent_consume_single_winner():
    svc = service()
    rec = issue(svc)

    async def race():
        return await asyncio.gather(*[
            svc.consume(rec.challenge_id, action=ACTION, actor=ACTOR, resource=RESOURCE,
                        payload_hash=PAYLOAD_HASH, policy_hash=POLICY_HASH, nonce=rec.nonce, now=NOW)
            for _ in range(16)])

    results = run(race())
    assert sum(1 for r in results if r.ok) == 1
