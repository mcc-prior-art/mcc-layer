"""ProposalRegistry tests: Redis-backed atomicity/fail-closed semantics (via
a hand-rolled fake Redis client implementing exactly the Lua scripts
``RedisProposalRegistry`` sends -- the same convention
``tests/test_idempotency.py`` uses for ``RedisIdempotencyRegistry``, so a
live Redis server is not required for the suite), plus the
``MCC_PROPOSAL_BACKEND`` environment factory (Section 19).

Phase 2 (MCC_UNIVERSAL_PROPOSAL_SERVICE_PHASE2) changed the wire format from
a ``binding|created_at`` pipe-delimited string to a single JSON document
(``{"binding", "created_at", "action", "resource", "payload"}``) -- a
proposal's governable content, not merely its binding hash, must be durably
available so a later authorization decision has ONE source of truth (see
``gateway/proposal_execution_service.py``). ``FakeRedis`` below mirrors the
new ``_REGISTER_LUA`` exactly, in plain Python.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from mcc_proposal.registry import (
    ProposalBackendUnavailable,
    ProposalConfigError,
    ProposalRegisterStatus,
    RedisProposalRegistry,
    proposal_registry_from_env,
)
from mcc_proposal.registry import InMemoryProposalRegistry, _REGISTER_LUA

run = asyncio.run


class FakeRedis:
    """Minimal fake matching exactly the ``eval``/``get`` calls
    ``RedisProposalRegistry`` makes -- no live Redis server needed."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    async def eval(self, script, numkeys, key, candidate_json, binding, principal=""):
        assert script == _REGISTER_LUA
        cur = self.store.get(key)
        if cur is None:
            self.store[key] = candidate_json
            return ["REGISTERED", binding]
        try:
            decoded = json.loads(cur)
            existing_binding = decoded["binding"]
        except (ValueError, KeyError, TypeError):
            return ["ERROR", ""]
        # F1b: mirrors the Lua owner check (ARGV[3]; absent owner == "").
        if (decoded.get("principal_id") or "") != principal:
            return ["BINDING_CONFLICT", existing_binding]
        if existing_binding == binding:
            return ["IDEMPOTENT_DUPLICATE", existing_binding]
        return ["BINDING_CONFLICT", existing_binding]

    async def get(self, key):
        return self.store.get(key)


class DownRedis:
    async def eval(self, *a, **k):
        raise ConnectionError("down")

    async def get(self, *a, **k):
        raise ConnectionError("down")


def reg(fake=None) -> RedisProposalRegistry:
    return RedisProposalRegistry(fake or FakeRedis(), namespace="mcc:v1:test:proposal:")


def test_redis_first_registration_succeeds():
    r = run(reg().register(tenant_id="t", logical_operation_id="op-1", binding="b1"))
    assert r.status == ProposalRegisterStatus.REGISTERED
    assert r.binding == "b1"


def test_redis_identical_binding_is_idempotent_duplicate():
    fake = FakeRedis()
    r1 = run(reg(fake).register(tenant_id="t", logical_operation_id="op-2", binding="b1"))
    r2 = run(reg(fake).register(tenant_id="t", logical_operation_id="op-2", binding="b1"))
    assert r1.status == ProposalRegisterStatus.REGISTERED
    assert r2.status == ProposalRegisterStatus.IDEMPOTENT_DUPLICATE
    assert r2.binding == "b1"


def test_redis_different_binding_is_conflict_and_never_overwrites():
    fake = FakeRedis()
    run(reg(fake).register(tenant_id="t", logical_operation_id="op-3", binding="b1"))
    r2 = run(reg(fake).register(tenant_id="t", logical_operation_id="op-3", binding="b2"))
    assert r2.status == ProposalRegisterStatus.BINDING_CONFLICT
    assert r2.binding == "b1"  # the ORIGINAL binding, never overwritten
    got = run(reg(fake).get(tenant_id="t", logical_operation_id="op-3"))
    assert got.binding == "b1"


def test_redis_binding_containing_delimiter_characters_is_fine_under_json():
    """Phase 1's pipe-delimited wire format made a binding containing '|' a
    structural hazard, rejected outright. Phase 2's JSON wire format makes
    that whole hazard class impossible by construction (json.dumps escapes
    any content unambiguously) -- proving the underlying invariant (a
    proposal's stored binding is never corrupted/misparsed by adversarial
    content) now holds unconditionally, rather than by restricting input."""
    r = run(reg().register(tenant_id="t", logical_operation_id="op-4", binding="has|pipe|chars"))
    assert r.status == ProposalRegisterStatus.REGISTERED
    got = run(reg(FakeRedis()).register(tenant_id="t", logical_operation_id="op-4b", binding="has|pipe|chars"))
    assert got.status == ProposalRegisterStatus.REGISTERED
    assert got.binding == "has|pipe|chars"


def test_redis_empty_binding_is_rejected():
    r = run(reg().register(tenant_id="t", logical_operation_id="op-4c", binding=""))
    assert r.status == ProposalRegisterStatus.ERROR


def test_redis_non_json_serializable_payload_is_rejected_with_zero_mutation():
    """A payload that cannot be JSON-encoded (e.g. a Python set) must never
    corrupt the stored record or silently drop content -- fail closed before
    any Redis write."""
    fake = FakeRedis()
    r = run(reg(fake).register(
        tenant_id="t", logical_operation_id="op-4d", binding="b1",
        action="a", resource="r", payload={"bad": {1, 2, 3}},
    ))
    assert r.status == ProposalRegisterStatus.ERROR
    assert fake.store == {}


def test_redis_register_and_get_round_trip_action_resource_payload():
    fake = FakeRedis()
    r = run(reg(fake).register(
        tenant_id="t", logical_operation_id="op-4e", binding="b1",
        action="send_payment", resource="acct-1", payload={"amount": 10},
    ))
    assert r.status == ProposalRegisterStatus.REGISTERED
    got = run(reg(fake).get(tenant_id="t", logical_operation_id="op-4e"))
    assert got.action == "send_payment"
    assert got.resource == "acct-1"
    assert got.payload == {"amount": 10}


def test_redis_malformed_stored_json_raises_backend_unavailable():
    fake = FakeRedis()
    r = reg(fake)
    fake.store[r._key("t", "op-4f")] = "not valid json"
    with pytest.raises(ProposalBackendUnavailable):
        run(r.get(tenant_id="t", logical_operation_id="op-4f"))


def test_redis_down_register_is_error_fail_closed():
    r = run(reg(DownRedis()).register(tenant_id="t", logical_operation_id="op-5", binding="b1"))
    assert r.status == ProposalRegisterStatus.ERROR


def test_redis_down_get_raises_backend_unavailable_never_none():
    with pytest.raises(ProposalBackendUnavailable):
        run(reg(DownRedis()).get(tenant_id="t", logical_operation_id="op-6"))


def test_redis_tenant_scoping_keys_are_distinct():
    r = reg()
    key_a = r._key("tenant-a", "same-id")
    key_b = r._key("tenant-b", "same-id")
    assert key_a != key_b


# -- env factory (Section 19) ------------------------------------------------- #

def test_env_default_is_in_memory():
    r = proposal_registry_from_env({})
    assert isinstance(r, InMemoryProposalRegistry)


def test_env_enforcement_mode_refuses_memory_default():
    with pytest.raises(ProposalConfigError):
        proposal_registry_from_env({"MCC_DEPLOYMENT_MODE": "enforcement"})


def test_env_enforcement_mode_refuses_explicit_memory():
    with pytest.raises(ProposalConfigError):
        proposal_registry_from_env({
            "MCC_DEPLOYMENT_MODE": "enforcement", "MCC_PROPOSAL_BACKEND": "memory",
        })


def test_env_redis_requires_url_no_silent_fallback():
    with pytest.raises(ProposalConfigError):
        proposal_registry_from_env({"MCC_PROPOSAL_BACKEND": "redis"})


def test_env_redis_with_url_builds_redis_registry():
    r = proposal_registry_from_env({
        "MCC_PROPOSAL_BACKEND": "redis", "MCC_REDIS_URL": "redis://localhost:6379/0",
    })
    assert isinstance(r, RedisProposalRegistry)


def test_env_unknown_backend_rejected():
    with pytest.raises(ProposalConfigError):
        proposal_registry_from_env({"MCC_PROPOSAL_BACKEND": "carrier-pigeon"})


# -- Phase 2 remediation: legacy Phase-1 wire-format upgrade compatibility --- #
#
# Strategy A (docs/MCC_UNIVERSAL_PROPOSAL_SERVICE_PHASE2.md Section 12):
# a Phase-1 "binding|created_at" record is RECOGNIZED (never treated as
# corruption), exposed as a proposal record with NO executable content
# (action/resource/payload all None) -- never guessed, widened, or silently
# reinterpreted as an executable Phase-2 proposal.

def test_legacy_pipe_format_record_is_recognized_with_no_executable_content():
    fake = FakeRedis()
    r = reg(fake)
    key = r._key("t", "op-legacy")
    fake.store[key] = "sha256:legacy-binding-abc123|1700000000.0"

    got = run(r.get(tenant_id="t", logical_operation_id="op-legacy"))
    assert got is not None
    assert got.binding == "sha256:legacy-binding-abc123"
    assert got.created_at == 1700000000.0
    assert got.action is None
    assert got.resource is None
    assert got.payload is None


def test_legacy_pipe_format_with_unparseable_created_at_is_backend_unavailable():
    """A legacy binding could itself have contained '|' -- ``split('|', 1)``
    takes only the FIRST pipe as the delimiter (exactly as Phase 1's own
    reader did), so the remainder fails to parse as a float and this is
    correctly refused, never silently misparsed."""
    fake = FakeRedis()
    r = reg(fake)
    key = r._key("t", "op-legacy3")
    fake.store[key] = "sha256:abc|def|1700000000.0"  # "def|1700000000.0" is not a float
    with pytest.raises(ProposalBackendUnavailable):
        run(r.get(tenant_id="t", logical_operation_id="op-legacy3"))


def test_legacy_pipe_format_with_empty_binding_is_backend_unavailable():
    fake = FakeRedis()
    r = reg(fake)
    key = r._key("t", "op-legacy4")
    fake.store[key] = "|1700000000.0"
    with pytest.raises(ProposalBackendUnavailable):
        run(r.get(tenant_id="t", logical_operation_id="op-legacy4"))
