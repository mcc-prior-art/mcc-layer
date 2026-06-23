"""Idempotency registry tests: lifecycle, concurrency, durability, fail-closed.

Covers same-key duplicate denial, exactly-one concurrent winner, the terminal
EXECUTED state, stale-RESERVED recovery via TTL, restart persistence, and
fail-closed on registry outage.
"""

import asyncio

import pytest

from mcc_core import (
    IdempotencyConfigError,
    IdempotencyState,
    InMemoryIdempotencyRegistry,
    RedisIdempotencyRegistry,
    ReserveStatus,
    idempotency_registry_from_env,
)

run = asyncio.run


class IdemFakeRedis:
    """SET NX / GET / DELETE with optional TTL against an injectable clock.
    A shared ``store`` lets two registry instances model the same Redis."""

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

    async def delete(self, key):
        self.store.pop(key, None)
        return 1


class DownRedis:
    async def set(self, *a, **k):
        raise ConnectionError("down")

    async def get(self, *a, **k):
        raise ConnectionError("down")

    async def delete(self, *a, **k):
        raise ConnectionError("down")


def redis_reg(store=None, clock=None):
    return RedisIdempotencyRegistry(IdemFakeRedis(store, clock))


# ---- First / duplicate ----

@pytest.mark.parametrize("reg", [InMemoryIdempotencyRegistry(), redis_reg()])
def test_first_reservation_succeeds(reg):
    res = run(reg.reserve("op-1"))
    assert res.ok
    assert res.status == ReserveStatus.RESERVED


@pytest.mark.parametrize("reg", [InMemoryIdempotencyRegistry(), redis_reg()])
def test_duplicate_reservation_denied(reg):
    assert run(reg.reserve("op-1")).ok
    second = run(reg.reserve("op-1"))
    assert not second.ok
    assert second.status == ReserveStatus.DUPLICATE_INFLIGHT


def test_different_tokens_sharing_one_idempotency_key_conflict():
    reg = InMemoryIdempotencyRegistry()
    # Two different operations (different bindings) presenting the same key.
    assert run(reg.reserve("dup-key", binding="payload-hash-A")).ok
    second = run(reg.reserve("dup-key", binding="payload-hash-B"))
    assert not second.ok  # the key is already claimed


# ---- Terminal EXECUTED ----

@pytest.mark.parametrize("reg", [InMemoryIdempotencyRegistry(), redis_reg()])
def test_executed_can_never_execute_again(reg):
    assert run(reg.reserve("op-1")).ok
    run(reg.mark_executed("op-1"))
    again = run(reg.reserve("op-1"))
    assert not again.ok
    assert again.status == ReserveStatus.DUPLICATE_EXECUTED


@pytest.mark.parametrize("reg", [InMemoryIdempotencyRegistry(), redis_reg()])
def test_failed_release_frees_key_for_retry(reg):
    assert run(reg.reserve("op-1")).ok
    run(reg.mark_failed("op-1"))
    assert run(reg.reserve("op-1")).ok  # retryable after failure


# ---- Concurrency: exactly one winner ----

@pytest.mark.parametrize(
    "reg", [InMemoryIdempotencyRegistry(), redis_reg()]
)
def test_concurrent_duplicate_exactly_one_winner(reg):
    async def race():
        return await asyncio.gather(*[reg.reserve("op-1") for _ in range(50)])

    results = run(race())
    winners = [r for r in results if r.ok]
    assert len(winners) == 1
    assert all(r.status == ReserveStatus.DUPLICATE_INFLIGHT for r in results if not r.ok)


# ---- TTL / stale-RESERVED recovery ----

def test_stale_reserved_recovers_after_ttl():
    clock = {"t": 1000.0}
    reg = redis_reg(clock=lambda: clock["t"])
    assert run(reg.reserve("op-1", ttl_seconds=5)).ok
    assert not run(reg.reserve("op-1", ttl_seconds=5)).ok  # still reserved
    clock["t"] += 6  # the crashed holder's reservation lapses
    assert run(reg.reserve("op-1", ttl_seconds=5)).ok  # recovered


# ---- Restart persistence (shared Redis across instances) ----

def test_executed_persists_across_restart():
    store = {}
    before = RedisIdempotencyRegistry(IdemFakeRedis(store))
    assert run(before.reserve("op-1")).ok
    run(before.mark_executed("op-1"))
    # New process / instance, same Redis:
    after = RedisIdempotencyRegistry(IdemFakeRedis(store))
    assert run(after.get_state("op-1")) == IdempotencyState.EXECUTED
    assert run(after.reserve("op-1")).status == ReserveStatus.DUPLICATE_EXECUTED


# ---- Fail-closed ----

def test_registry_outage_fails_closed():
    reg = RedisIdempotencyRegistry(DownRedis())
    res = run(reg.reserve("op-1"))
    assert not res.ok
    assert res.status == ReserveStatus.ERROR


def test_invalid_key_fails_closed():
    reg = InMemoryIdempotencyRegistry()
    assert not run(reg.reserve("")).ok


# ---- Backend selection (no silent fallback) ----

def test_factory_defaults_to_memory():
    assert isinstance(idempotency_registry_from_env({}), InMemoryIdempotencyRegistry)


def test_factory_redis_requires_url():
    with pytest.raises(IdempotencyConfigError):
        idempotency_registry_from_env({"MCC_IDEMPOTENCY_BACKEND": "redis"})


def test_factory_unknown_backend_raises():
    with pytest.raises(IdempotencyConfigError):
        idempotency_registry_from_env({"MCC_IDEMPOTENCY_BACKEND": "etcd"})
