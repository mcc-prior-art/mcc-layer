"""V13 - Signature verification: non-strict Ed25519, key confusion, unknown/revoked key, downgrade."""
import base64
import copy

import pytest
from _harness import *
from mcc_core import SigningKey


def _fresh_token(s, **kw):
    return s.engine.issue_token(verdict="ALLOW", subject=ACTOR, action=ACTION, payload=payment(),
                                idempotency_key=kw.pop("idem", "k"), tenant_id=TENANT, actor_id=ACTOR,
                                resource_id=RESOURCE, **kw)


def _enforce(s, tok, payload=None):
    async def ex():
        s.executed.append(("X", payload or payment()))
    try:
        return run(s.coordinator.enforce(token=tok, action=ACTION, payload=payload or payment(), executor=ex))
    except Exception as exc:
        return exc


MUTATIONS = {
    "amount-claim": lambda t: t["auth_claims"].update(amount=1),
    "decision": lambda t: t.update(decision="CONSTRAIN"),
    "exp": lambda t: t.update(exp=t["exp"] + 3600),
    "nonce": lambda t: t.update(nonce="fresh-nonce"),
    "idempotency_key": lambda t: t.update(idempotency_key="other"),
    "tenant": lambda t: t.update(tenant_id="tenant-2"),
    "mandate_id": lambda t: t.update(mandate_id="mdt-other"),
    "kid-none": lambda t: t.update(kid=None),
    "kid-unknown": lambda t: t.update(kid="mcc-core-dev-key-1"),
    "kid-list": lambda t: t.update(kid=["gw-signing-1"]),
    "sig-empty": lambda t: t.update(sig=""),
    "sig-missing": lambda t: t.pop("sig"),
    "sig-zero": lambda t: t.update(sig=base64.b64encode(b"\x00" * 64).decode()),
    "sig-list": lambda t: t.update(sig=[t["sig"]]),
    "alg-none": lambda t: t.update(alg="none", sig=""),
    "extra-claim": lambda t: t.update(admin=True),
}


@attack(vector=13, severity="critical", title="Any change to a signed token invalidates it")
@pytest.mark.parametrize("name", list(MUTATIONS))
def test_mutated_token_rejected(name):
    s = Stack()
    tok = copy.deepcopy(_fresh_token(s))
    MUTATIONS[name](tok)
    r = _enforce(s, tok)
    assert s.executed == [], getattr(r, "reason", r)


@attack(vector=13, severity="critical", title="Key confusion: token signed by a key trusted for another role")
def test_token_signed_by_mandate_issuer_or_approver_key():
    s = Stack()
    for key in (s.issuer_key, s.approver_key, SigningKey.generate(s.signing_key.kid)):
        tok = _fresh_token(s)
        claims = {k: v for k, v in tok.items() if k not in ("sig", "kid")}
        _enforce(s, key.sign_token(claims))
    assert s.executed == []


@attack(vector=13, severity="critical", title="Artifact confusion: a decision token presented as a mandate")
def test_decision_token_is_not_a_mandate():
    s = Stack()
    tok = _fresh_token(s)
    run(s.execute(tok, idempotency_key="k2"))
    s.trust.add_runtime_issuer("gw", s.signing_key.kid, s.signing_key.public_key())   # even if trusted
    run(s.execute(tok, idempotency_key="k3"))
    assert s.executed == []


@attack(vector=13, severity="critical", title="Mandate signed by a revoked key / disabled issuer")
def test_revoked_or_disabled_issuer_key():
    s = Stack()
    m = s.mandate()
    s.trust.revoke_key(s.issuer_key.kid)
    run(s.execute(m, idempotency_key="k1"))
    s2 = Stack()
    m2 = s2.mandate()
    s2.trust.disable_issuer("issuer/treasury")
    run(s2.execute(m2, idempotency_key="k1"))
    assert s.executed == [] and s2.executed == []


@attack(vector=13, severity="medium", title="Signature malleability cannot mint a second usable token")
def test_signature_encoding_malleability_is_not_a_replay():
    s = Stack()
    tok = _fresh_token(s)
    _enforce(s, tok)
    variant = dict(tok, sig=tok["sig"] + "\n ")        # lenient base64: same bytes, different string
    _enforce(s, variant)
    assert len(s.executed) == 1, "re-encoded signature produced a second execution"


@attack(vector=13, severity="critical", title="Wrong audience / wrong policy hash")
def test_audience_and_policy_binding():
    from mcc_core import DecisionEngine
    s = Stack()
    for kw in (dict(audience="other-gate", policy_hash=POLICY_HASH),
               dict(audience="pilot", policy_hash="sha256:" + "1" * 64)):
        eng = DecisionEngine(signing_key=s.signing_key, issuer="mcc/core", policy_id="pilot/v1", **kw)
        tok = eng.issue_token(verdict="ALLOW", subject=ACTOR, action=ACTION, payload=payment(),
                              idempotency_key="k", tenant_id=TENANT)
        _enforce(s, tok)
    assert s.executed == []


@attack(vector=13, severity="critical", title="DENY / ESCALATE can never be turned into an executable token")
def test_non_executable_verdicts():
    from mcc_core.core import TokenNotIssuable
    s = Stack()
    for v in ("DENY", "ESCALATE"):
        with pytest.raises(TokenNotIssuable):
            s.engine.issue_token(verdict=v, subject=ACTOR, action=ACTION, payload=payment())
