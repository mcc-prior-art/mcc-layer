"""Velocity / aggregate control tests.

Covers cumulative ceilings across separately-signed transactions (anti-
splitting), per-window count and new-destination caps, configurable outcomes,
the concurrency safety property (total reserved never exceeds the ceiling), and
fail-closed on registry outage.
"""

import asyncio

import pytest

from mcc_core import (
    InMemoryVelocityRegistry,
    RedisVelocityRegistry,
    VelocityDescriptor,
    VelocityLimit,
    Verdict,
)

run = asyncio.run


class VelFakeRedis:
    def __init__(self):
        self.kv = {}
        self.sets = {}

    async def incr(self, key):
        self.kv[key] = int(self.kv.get(key, 0)) + 1
        return self.kv[key]

    async def decr(self, key):
        self.kv[key] = int(self.kv.get(key, 0)) - 1
        return self.kv[key]

    async def incrbyfloat(self, key, amt):
        self.kv[key] = float(self.kv.get(key, 0.0)) + float(amt)
        return self.kv[key]

    async def sadd(self, key, member):
        s = self.sets.setdefault(key, set())
        if member in s:
            return 0
        s.add(member)
        return 1

    async def scard(self, key):
        return len(self.sets.get(key, set()))

    async def srem(self, key, member):
        s = self.sets.get(key, set())
        if member in s:
            s.discard(member)
            return 1
        return 0

    async def expire(self, key, ttl):
        return True


class DownRedis:
    def __getattr__(self, _name):
        async def boom(*a, **k):
            raise ConnectionError("down")

        return boom


def both():
    return [InMemoryVelocityRegistry(), RedisVelocityRegistry(VelFakeRedis())]


def desc(actor="a1", source="s1", amount=None, destination=None, action="send_payment"):
    return VelocityDescriptor(
        dimensions={"actor": actor, "source": source, "action": action, "policy_scope": "p"},
        amount=amount,
        destination=destination,
    )


# ---- Cumulative amount ceiling / anti-splitting ----

@pytest.mark.parametrize("reg", both())
def test_four_transactions_cannot_bypass_cumulative_ceiling(reg):
    # Each 3000 is individually fine; together they must not exceed 10000.
    limit = VelocityLimit(name="amt", window_seconds=3600, max_amount=10000,
                          aggregate_by=("actor",))
    outcomes = [run(reg.reserve(limit, desc(amount=3000), now=1000.0)) for _ in range(4)]
    verdicts = [o.verdict for o in outcomes]
    assert verdicts[:3] == [Verdict.ALLOW, Verdict.ALLOW, Verdict.ALLOW]
    assert verdicts[3] == Verdict.DENY  # 12000 > 10000


@pytest.mark.parametrize("reg", both())
def test_cumulative_limit_spans_distinct_destinations(reg):
    # Splitting one large payment into several to different beneficiaries still
    # aggregates by actor against the amount ceiling.
    limit = VelocityLimit(name="amt", window_seconds=3600, max_amount=5000,
                          aggregate_by=("actor",))
    a = run(reg.reserve(limit, desc(amount=3000, destination="b1"), now=1000.0))
    b = run(reg.reserve(limit, desc(amount=3000, destination="b2"), now=1000.0))
    assert a.verdict == Verdict.ALLOW
    assert b.verdict == Verdict.DENY  # 6000 > 5000 even to a different beneficiary


# ---- Count + new-destination caps ----

@pytest.mark.parametrize("reg", both())
def test_max_count_per_window(reg):
    limit = VelocityLimit(name="cnt", window_seconds=3600, max_count=2)
    v = [run(reg.reserve(limit, desc(), now=1000.0)).verdict for _ in range(3)]
    assert v == [Verdict.ALLOW, Verdict.ALLOW, Verdict.DENY]


@pytest.mark.parametrize("reg", both())
def test_max_new_destinations_per_window(reg):
    limit = VelocityLimit(name="dst", window_seconds=3600, max_new_destinations=2)
    assert run(reg.reserve(limit, desc(destination="b1"), now=1000.0)).verdict == Verdict.ALLOW
    assert run(reg.reserve(limit, desc(destination="b2"), now=1000.0)).verdict == Verdict.ALLOW
    assert run(reg.reserve(limit, desc(destination="b3"), now=1000.0)).verdict == Verdict.DENY
    # A repeat of an already-seen destination is not a new one.
    assert run(reg.reserve(limit, desc(destination="b1"), now=1000.0)).verdict == Verdict.ALLOW


# ---- Aggregation scoping ----

@pytest.mark.parametrize("reg", both())
def test_different_actors_have_independent_budgets(reg):
    limit = VelocityLimit(name="amt", window_seconds=3600, max_amount=5000,
                          aggregate_by=("actor",))
    assert run(reg.reserve(limit, desc(actor="a1", amount=5000), now=1000.0)).verdict == Verdict.ALLOW
    assert run(reg.reserve(limit, desc(actor="a2", amount=5000), now=1000.0)).verdict == Verdict.ALLOW


@pytest.mark.parametrize("reg", both())
def test_window_resets_in_next_bucket(reg):
    limit = VelocityLimit(name="amt", window_seconds=100, max_amount=5000,
                          aggregate_by=("actor",))
    assert run(reg.reserve(limit, desc(amount=5000), now=1000.0)).verdict == Verdict.ALLOW
    assert run(reg.reserve(limit, desc(amount=5000), now=1000.0)).verdict == Verdict.DENY
    # Next window bucket: budget refreshed.
    assert run(reg.reserve(limit, desc(amount=5000), now=1200.0)).verdict == Verdict.ALLOW


# ---- Configurable outcome ----

@pytest.mark.parametrize("reg", both())
def test_on_exceed_outcome_is_configurable(reg):
    limit = VelocityLimit(name="amt", window_seconds=3600, max_amount=1000,
                          on_exceed=Verdict.ESCALATE)
    assert run(reg.reserve(limit, desc(amount=500), now=1000.0)).verdict == Verdict.ALLOW
    over = run(reg.reserve(limit, desc(amount=5000), now=1000.0))
    assert over.verdict == Verdict.ESCALATE
    assert not over.reserved


# ---- Concurrency safety: never over-allow ----

@pytest.mark.parametrize("reg", both())
def test_concurrent_aggregate_race_never_exceeds_ceiling(reg):
    limit = VelocityLimit(name="amt", window_seconds=3600, max_amount=10000,
                          aggregate_by=("actor",))

    async def race():
        return await asyncio.gather(
            *[reg.reserve(limit, desc(amount=3000), now=1000.0) for _ in range(20)]
        )

    outcomes = run(race())
    winners = [o for o in outcomes if o.verdict == Verdict.ALLOW]
    # The safety property: the total reserved never exceeds the ceiling.
    assert len(winners) * 3000 <= 10000
    assert len(winners) >= 1


# ---- Fail-closed ----

def test_velocity_registry_outage_fails_closed():
    reg = RedisVelocityRegistry(DownRedis())
    limit = VelocityLimit(name="amt", window_seconds=3600, max_amount=10000)
    out = run(reg.reserve(limit, desc(amount=100), now=1000.0))
    assert out.verdict == Verdict.DENY
    assert not out.reserved
