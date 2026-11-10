"""V07 - Replay of a previously approved action."""
import time

import pytest
from _harness import *
from mcc_core import ExecutionGate, InMemoryIdempotencyRegistry, InMemoryNonceRegistry


def _replay(stack, tok, payload=None):
    async def ex():
        stack.executed.append(("REPLAY", {}))
    return run(stack.coordinator.enforce(token=tok, action=ACTION, payload=payload or payment(),
                                         executor=ex))


@attack(vector=7, severity="critical", title="Straight replay of a used decision token")
def test_token_replay_same_instance():
    s = Stack()
    toks = spy_tokens(s)
    run(s.execute(s.mandate(), idempotency_key="k"))
    r = _replay(s, toks[0])
    assert len(s.executed) == 1, r.reason


@attack(vector=7, severity="critical", title="Replay of a used token with a different payload")
def test_token_replay_other_payload():
    s = Stack()
    toks = spy_tokens(s)
    run(s.execute(s.mandate(), idempotency_key="k"))
    r = _replay(s, toks[0], payment(amount=4999, beneficiary_id="attacker"))
    assert len(s.executed) == 1, r.reason


@attack(vector=7, severity="high", kind="known-limitation",
        title="Replay after process restart with in-memory nonce + idempotency registries (dev/pilot default)")
def test_token_replay_after_restart_memory_backend():
    s = Stack()
    toks = spy_tokens(s)
    run(s.execute(s.mandate(), idempotency_key="k"))
    # "Restart": same signing key + audit file, fresh volatile registries.
    s.coordinator.gate = ExecutionGate(
        trusted_keys={s.signing_key.kid: s.signing_key.public_key()}, audience="pilot",
        nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY_HASH)
    s.coordinator.idempotency = InMemoryIdempotencyRegistry()
    r = _replay(s, toks[0])
    assert len(s.executed) == 1, f"token replayed after restart ({r.reason}); window = token TTL"


@attack(vector=7, severity="high", title="Enforcement mode refuses volatile replay state")
def test_enforcement_mode_refuses_memory_backends():
    from mcc_core.nonce import NonceConfigError, nonce_registry_from_env
    for env in ({"MCC_DEPLOYMENT_MODE": "enforcement"},
                {"MCC_DEPLOYMENT_MODE": "enforcement", "MCC_NONCE_BACKEND": "memory"}):
        with pytest.raises(NonceConfigError):
            nonce_registry_from_env(env)


@attack(vector=7, severity="medium", kind="hardening",
        title="Gate accepts a replay when its nonce TTL cap is shorter than the token lifetime")
def test_gate_nonce_ttl_shorter_than_token_lifetime():
    s = Stack()
    s.gate.max_nonce_ttl_seconds = 1          # operator misconfiguration: cap < token TTL (60s)
    toks = spy_tokens(s)
    run(s.execute(s.mandate(), idempotency_key="k"))
    time.sleep(1.3)
    res = run(s.gate.verify(toks[0], action=ACTION, payload=payment()))
    assert not res.allowed, "gate re-verified a used token after its nonce record expired"


@attack(vector=7, severity="high",
        title="Same misconfiguration end-to-end: idempotency still blocks the re-execution")
def test_coordinator_blocks_replay_even_if_nonce_slot_freed():
    s = Stack()
    s.gate.max_nonce_ttl_seconds = 1
    toks = spy_tokens(s)
    run(s.execute(s.mandate(), idempotency_key="k"))
    time.sleep(1.3)
    r = _replay(s, toks[0])
    assert len(s.executed) == 1, r.reason
