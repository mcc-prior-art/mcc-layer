"""RedisNonceRegistry tests: atomic single-use claims, cross-instance replay
rejection, TTL bounds/derivation, and fail-closed on every failure mode.

Redis is doubled in-process (no server needed); the real-server path is
exercised by the `nonce-redis-smoke` CI job via scripts/redis_nonce_smoke.py.
"""

import asyncio

import pytest

from mcc_core import (
    DecisionEngine,
    ExecutionGate,
    InMemoryNonceRegistry,
    NonceConfigError,
    RedisNonceRegistry,
    SigningKey,
    nonce_registry_from_env,
)

run = asyncio.run
NOW = 1_780_000_000


# =========================
# Redis doubles
# =========================

class FakeRedis:
    """Atomic SET NX (ignores ex); shareable across registries."""

    def __init__(self):
        self.store = {}

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.store:
            return None
        self.store[key] = value
        return True


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def now(self):
        return self.t


class TimeFakeRedis:
    """SET NX EX that honours expiry against an injectable clock."""

    def __init__(self, clock: Clock):
        self.clock = clock
        self.store = {}  # key -> expires_at | None

    async def set(self, key, value, nx=False, ex=None):
        now = self.clock.now()
        exp = self.store.get(key)
        if key in self.store and exp is not None and exp <= now:
            del self.store[key]
        if nx and key in self.store:
            return None
        self.store[key] = (now + ex) if ex else None
        return True


class DownRedis:
    async def set(self, *a, **k):
        raise ConnectionError("redis unavailable")


class SlowRedis:
    async def set(self, *a, **k):
        await asyncio.sleep(5)
        return True


class WeirdRedis:
    async def set(self, *a, **k):
        return 0  # neither True nor None -> indeterminate


class RecordingRedis:
    """Records the ex (TTL) it was asked to set."""

    def __init__(self):
        self.store = set()
        self.last_ex = None

    async def set(self, key, value, nx=False, ex=None):
        self.last_ex = ex
        if nx and key in self.store:
            return None
        self.store.add(key)
        return True


# =========================
# Core behaviour
# =========================

def test_first_consumption_succeeds():
    reg = RedisNonceRegistry(FakeRedis())
    assert run(reg.consume("n1")) is True


def test_replay_is_denied():
    reg = RedisNonceRegistry(FakeRedis())
    assert run(reg.consume("n1")) is True
    assert run(reg.consume("n1")) is False


def test_empty_or_non_string_nonce_rejected():
    reg = RedisNonceRegistry(FakeRedis())
    assert run(reg.consume("")) is False
    assert run(reg.consume(None)) is False


def test_two_instances_sharing_redis_reject_cross_instance_replay():
    shared = FakeRedis()
    reg_a = RedisNonceRegistry(shared)
    reg_b = RedisNonceRegistry(shared)
    # First use on instance A, replay attempted on instance B.
    assert run(reg_a.consume("shared-nonce")) is True
    assert run(reg_b.consume("shared-nonce")) is False


def test_expired_record_is_reusable_only_as_a_fresh_slot():
    # A nonce record with a finite TTL frees its slot after expiry. That is safe
    # because the gate derives the TTL to be >= the token's validity window, so
    # by the time the slot frees the original token is itself expired and is
    # rejected before nonce consumption is ever reached. Here we show the slot
    # reuse directly at the registry level.
    clock = Clock(t=1000.0)
    reg = RedisNonceRegistry(TimeFakeRedis(clock))
    assert run(reg.consume("n", ttl_seconds=2)) is True
    assert run(reg.consume("n", ttl_seconds=2)) is False  # still live -> replay denied
    clock.t += 3  # advance past the record's TTL
    assert run(reg.consume("n", ttl_seconds=2)) is True  # slot freed -> fresh claim


# =========================
# Fail-closed
# =========================

def test_redis_outage_fails_closed():
    reg = RedisNonceRegistry(DownRedis())
    assert run(reg.consume("n")) is False


def test_redis_timeout_fails_closed():
    reg = RedisNonceRegistry(SlowRedis(), op_timeout_seconds=0.05)
    assert run(reg.consume("n")) is False


def test_indeterminate_result_fails_closed():
    reg = RedisNonceRegistry(WeirdRedis())
    assert run(reg.consume("n")) is False


# =========================
# Concurrency: exactly one winner
# =========================

def test_concurrent_consumption_permits_exactly_one_winner():
    shared = FakeRedis()
    reg = RedisNonceRegistry(shared)

    async def race():
        return await asyncio.gather(*[reg.consume("contended") for _ in range(64)])

    results = run(race())
    assert sum(1 for r in results if r is True) == 1
    assert sum(1 for r in results if r is False) == 63


# =========================
# TTL bounds + derivation
# =========================

def test_ttl_is_clamped_to_safe_bounds():
    rec = RecordingRedis()
    reg = RedisNonceRegistry(rec, min_ttl_seconds=5, max_ttl_seconds=100)
    run(reg.consume("a", ttl_seconds=1))
    assert rec.last_ex == 5  # clamped up to the floor
    run(reg.consume("b", ttl_seconds=99999))
    assert rec.last_ex == 100  # clamped down to the ceiling


def test_gate_derives_nonce_ttl_from_token_window():
    key = SigningKey.generate("k1")
    engine = DecisionEngine(
        signing_key=key,
        issuer="mcc/test",
        audience="gate",
        policy_id="p",
        policy_hash="sha256:p",
        token_ttl_seconds=60,
    )
    rec = RecordingRedis()
    gate = ExecutionGate(
        trusted_keys={key.kid: key.public_key()},
        audience="gate",
        nonce_registry=RedisNonceRegistry(rec),
        policy_hash="sha256:p",
        nonce_clock_skew_seconds=30,
    )
    token = engine.issue_token(
        verdict="ALLOW", subject="s", action="act", payload={"x": 1}, now=NOW
    )
    result = run(gate.verify(token, action="act", payload={"x": 1}, now=NOW))
    assert result.allowed
    # remaining validity (60) + skew (30) = 90, within [1, 300]
    assert rec.last_ex == 90


# =========================
# Two gate instances sharing Redis (end-to-end through the gate)
# =========================

def test_two_gates_sharing_redis_reject_token_replay():
    key = SigningKey.generate("k1")
    engine = DecisionEngine(
        signing_key=key, issuer="mcc/test", audience="gate",
        policy_id="p", policy_hash="sha256:p", token_ttl_seconds=60,
    )
    shared = FakeRedis()

    def make_gate():
        return ExecutionGate(
            trusted_keys={key.kid: key.public_key()},
            audience="gate",
            nonce_registry=RedisNonceRegistry(shared),
            policy_hash="sha256:p",
        )

    g1, g2 = make_gate(), make_gate()
    token = engine.issue_token(
        verdict="ALLOW", subject="s", action="act", payload={"x": 1}, now=NOW
    )
    first = run(g1.verify(token, action="act", payload={"x": 1}, now=NOW))
    replay = run(g2.verify(token, action="act", payload={"x": 1}, now=NOW))
    assert first.allowed
    assert not replay.allowed
    assert "NONCE_REJECTED" in replay.reason


# =========================
# Backend selection (no silent fallback)
# =========================

def test_factory_defaults_to_memory():
    assert isinstance(nonce_registry_from_env({}), InMemoryNonceRegistry)


def test_factory_redis_requires_url_no_fallback():
    with pytest.raises(NonceConfigError):
        nonce_registry_from_env({"MCC_NONCE_BACKEND": "redis"})


def test_factory_redis_builds_redis_registry():
    reg = nonce_registry_from_env(
        {"MCC_NONCE_BACKEND": "redis", "MCC_REDIS_URL": "redis://127.0.0.1:6379/0"}
    )
    assert isinstance(reg, RedisNonceRegistry)


def test_factory_unknown_backend_raises():
    with pytest.raises(NonceConfigError):
        nonce_registry_from_env({"MCC_NONCE_BACKEND": "sqlite"})
