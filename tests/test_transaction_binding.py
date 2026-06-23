"""Transaction-binding tests.

Every executable token is bound to the exact authorized operation. Generic
identity fields (actor, resource, transaction) are checked at the gate; payment
fields (beneficiary, amount, currency) live in the canonical payload and are
covered by payload_hash. Any substitution is denied. Non-payment actions, which
carry none of the payment vocabulary, keep working unchanged.
"""

import asyncio

from mcc_core import (
    DecisionEngine,
    ExecutionGate,
    InMemoryNonceRegistry,
    PaymentProfile,
    SigningKey,
)

run = asyncio.run
NOW = 1_780_000_000
PROFILE = PaymentProfile()

PAYMENT_CTX = {"source": "acct-1", "beneficiary_id": "ben-1", "amount": 1000, "currency": "usd"}


def engine():
    key = SigningKey.generate("k1")
    return key, DecisionEngine(
        signing_key=key, issuer="mcc/test", audience="gate",
        policy_id="pilot/v1", policy_hash="sha256:p", token_ttl_seconds=60,
    )


def gate(key):
    return ExecutionGate(
        trusted_keys={key.kid: key.public_key()},
        audience="gate",
        nonce_registry=InMemoryNonceRegistry(),
        policy_hash="sha256:p",
    )


def payment_token(eng, *, actor="actor-1", resource="acct-1", txn="txn-1", idem="idem-1", ctx=None):
    ctx = ctx or PAYMENT_CTX
    payload = PROFILE.canonical_payload(ctx)
    return eng.issue_token(
        verdict="ALLOW", subject=actor, action="send_payment", payload=payload,
        transaction_id=txn, idempotency_key=idem, actor_id=actor, resource_id=resource,
        auth_claims=PROFILE.auth_claims(ctx), now=NOW,
    ), payload


# ---- Token carries the generic binding fields ----

def test_token_carries_operation_binding_fields():
    key, eng = engine()
    token, _ = payment_token(eng)
    for f in ("transaction_id", "idempotency_key", "actor_id", "resource_id", "auth_claims"):
        assert f in token
    assert token["auth_claims"]["beneficiary_id"] == "ben-1"
    assert token["auth_claims"]["amount"] == 1000.0
    assert token["auth_claims"]["currency"] == "USD"


# ---- Generic identity substitution (checked at the gate) ----

def test_actor_substitution_denied():
    key, eng = engine()
    token, payload = payment_token(eng, actor="actor-1")
    res = run(gate(key).verify(token, action="send_payment", payload=payload,
                               binding={"actor_id": "actor-EVIL"}, now=NOW))
    assert not res.allowed
    assert "BINDING_MISMATCH" in res.reason


def test_resource_substitution_denied():
    key, eng = engine()
    token, payload = payment_token(eng, resource="acct-1")
    res = run(gate(key).verify(token, action="send_payment", payload=payload,
                               binding={"resource_id": "acct-EVIL"}, now=NOW))
    assert not res.allowed
    assert "BINDING_MISMATCH" in res.reason


def test_transaction_id_substitution_denied():
    key, eng = engine()
    token, payload = payment_token(eng, txn="txn-1")
    res = run(gate(key).verify(token, action="send_payment", payload=payload,
                               binding={"transaction_id": "txn-EVIL"}, now=NOW))
    assert not res.allowed
    assert "BINDING_MISMATCH" in res.reason


def test_matching_binding_allows():
    key, eng = engine()
    token, payload = payment_token(eng, actor="actor-1", resource="acct-1", txn="txn-1")
    res = run(gate(key).verify(
        token, action="send_payment", payload=payload,
        binding={"actor_id": "actor-1", "resource_id": "acct-1", "transaction_id": "txn-1"},
        now=NOW,
    ))
    assert res.allowed


# ---- Payment-field substitution (covered by payload_hash) ----

def test_beneficiary_substitution_denied():
    key, eng = engine()
    token, _ = payment_token(eng, ctx={**PAYMENT_CTX, "beneficiary_id": "ben-1"})
    tampered = PROFILE.canonical_payload({**PAYMENT_CTX, "beneficiary_id": "ben-EVIL"})
    res = run(gate(key).verify(token, action="send_payment", payload=tampered, now=NOW))
    assert not res.allowed
    assert "PAYLOAD_HASH_MISMATCH" in res.reason


def test_amount_substitution_denied():
    key, eng = engine()
    token, _ = payment_token(eng, ctx={**PAYMENT_CTX, "amount": 1000})
    tampered = PROFILE.canonical_payload({**PAYMENT_CTX, "amount": 999999})
    res = run(gate(key).verify(token, action="send_payment", payload=tampered, now=NOW))
    assert not res.allowed
    assert "PAYLOAD_HASH_MISMATCH" in res.reason


def test_currency_substitution_denied():
    key, eng = engine()
    token, _ = payment_token(eng, ctx={**PAYMENT_CTX, "currency": "usd"})
    tampered = PROFILE.canonical_payload({**PAYMENT_CTX, "currency": "eur"})
    res = run(gate(key).verify(token, action="send_payment", payload=tampered, now=NOW))
    assert not res.allowed
    assert "PAYLOAD_HASH_MISMATCH" in res.reason


# ---- Non-payment actions remain compatible ----

def test_non_payment_action_without_binding_still_works():
    key, eng = engine()
    # A generic action: no payment fields, no binding claims required.
    payload = {"target": "cache-1"}
    token = eng.issue_token(verdict="ALLOW", subject="agent", action="purge_cache",
                            payload=payload, now=NOW)
    res = run(gate(key).verify(token, action="purge_cache", payload=payload, now=NOW))
    assert res.allowed


def test_unbound_token_is_not_falsely_bound():
    # A token with no actor_id is not actor-bound; the gate must not invent one.
    key, eng = engine()
    payload = {"x": 1}
    token = eng.issue_token(verdict="ALLOW", subject="agent", action="act",
                            payload=payload, now=NOW)
    res = run(gate(key).verify(token, action="act", payload=payload,
                               binding={"actor_id": "whoever"}, now=NOW))
    assert res.allowed  # token.actor_id is None -> not compared
