"""Multi-instance consensus challenge against a modelled Redis.

A shared store stands in for one Redis behind two RedisChallengeRegistry
instances. Proven: a challenge issued on one instance is visible on the other,
consumed exactly once across both (no double-spend), expires by TTL, and fails
closed when the backend is down.
"""

import asyncio

import pytest

from mcc_core import ChallengeService, RedisChallengeRegistry, hash_payload
from mcc_core.challenge import ChallengeRecord, ChallengeState

run = asyncio.run
ACTION = "deploy_release"
ACTOR = "agent/ops"
RESOURCE = "cluster-1"
POLICY_HASH = "sha256:p"
PAYLOAD = {"target": "cluster-1"}
PH = hash_payload(PAYLOAD)


class FakeRedis:
    """SET NX / GET with optional TTL against an injectable clock. A shared
    ``store`` lets two registries model the same Redis."""

    def __init__(self, store=None, clock=None):
        self.store = store if store is not None else {}
        self.clock = clock or (lambda: 0.0)

    def _expired(self, key, now):
        cur = self.store.get(key)
        return cur is not None and cur[1] is not None and cur[1] <= now

    async def set(self, key, value, nx=False, ex=None):
        now = self.clock()
        if self._expired(key, now):
            del self.store[key]
        if nx and key in self.store:
            return None
        self.store[key] = (value, (now + ex) if ex else None)
        return True

    async def get(self, key):
        now = self.clock()
        if self._expired(key, now):
            del self.store[key]
        cur = self.store.get(key)
        return None if cur is None else cur[0]


class DownRedis:
    async def set(self, *a, **k):
        raise ConnectionError("down")

    async def get(self, *a, **k):
        raise ConnectionError("down")


def svc(store, clock=None):
    return ChallengeService(RedisChallengeRegistry(FakeRedis(store, clock)))


def consume_args(rec):
    return dict(action=ACTION, actor=ACTOR, resource=RESOURCE, payload_hash=PH,
                policy_hash=POLICY_HASH, nonce=rec.nonce)


def test_challenge_visible_across_instances():
    store = {}
    a, b = svc(store), svc(store)
    rec = run(a.issue(action=ACTION, actor=ACTOR, resource=RESOURCE, payload_hash=PH,
                      policy_hash=POLICY_HASH, ttl_seconds=120, now=0))
    seen = run(b.get(rec.challenge_id, now=0))
    assert seen is not None and seen.nonce == rec.nonce and seen.state == ChallengeState.ISSUED.value


def test_consume_exactly_once_across_instances():
    store = {}
    a, b = svc(store), svc(store)
    rec = run(a.issue(action=ACTION, actor=ACTOR, resource=RESOURCE, payload_hash=PH,
                      policy_hash=POLICY_HASH, ttl_seconds=120, now=0))
    r1 = run(a.consume(rec.challenge_id, now=0, **consume_args(rec)))
    r2 = run(b.consume(rec.challenge_id, now=0, **consume_args(rec)))
    assert r1.ok and not r2.ok  # exactly one instance wins


def test_concurrent_consume_two_instances_single_winner():
    store = {}
    a, b = svc(store), svc(store)
    rec = run(a.issue(action=ACTION, actor=ACTOR, resource=RESOURCE, payload_hash=PH,
                      policy_hash=POLICY_HASH, ttl_seconds=120, now=0))

    async def race():
        return await asyncio.gather(*[
            (a if i % 2 == 0 else b).consume(rec.challenge_id, now=0, **consume_args(rec))
            for i in range(16)])

    results = run(race())
    assert sum(1 for r in results if r.ok) == 1


def test_challenge_expires_by_ttl():
    store = {}
    clock = {"t": 0.0}
    a = svc(store, clock=lambda: clock["t"])
    rec = run(a.issue(action=ACTION, actor=ACTOR, resource=RESOURCE, payload_hash=PH,
                      policy_hash=POLICY_HASH, ttl_seconds=60, now=0))
    clock["t"] = 61.0  # past the Redis key TTL -> key gone
    assert run(a.get(rec.challenge_id, now=61)) is None
    assert not run(a.consume(rec.challenge_id, now=61, **consume_args(rec))).ok


def test_backend_down_fails_closed():
    down = ChallengeService(RedisChallengeRegistry(DownRedis()))
    rec = ChallengeRecord(
        challenge_id="chal-x", nonce="n", action=ACTION, action_hash="sha256:a", actor=ACTOR,
        resource=RESOURCE, payload_hash=PH, policy_hash=POLICY_HASH,
        state=ChallengeState.ISSUED.value, issued_at=0, expires_at=120)
    assert run(down.registry.create(rec)) is False           # create fails closed
    assert run(down.get("chal-x", now=0)) is None             # get fails closed
    assert not run(down.consume("chal-x", now=0, **consume_args(rec))).ok  # consume fails closed
