"""V03 - Context forgery: spoofed identity, role, or prior approval."""
import copy

from _harness import *
from mcc_core import SigningKey
from mcc_core.mandate import issue_mandate
import time


@attack(vector=3, severity="critical", title="Mandate issued to another subject")
def test_other_subjects_mandate_rejected():
    s = Stack()
    m = s.mandate(subject="agent/treasurer")
    out = run(s.execute(m, idempotency_key="k"))          # caller is agent/payments-bot
    assert s.executed == [], out.reason


@attack(vector=3, severity="critical", title="Mandate signed by an attacker key with a trusted kid label")
def test_forged_mandate_with_trusted_kid():
    s = Stack()
    evil = SigningKey.generate(s.issuer_key.kid)          # same kid, different key
    now = int(time.time())
    m = issue_mandate(evil, issuer="issuer/treasury", subject=ACTOR, action_scope=["*"],
                      resource_scope=[], constraints={}, not_before=now - 5, not_after=now + 600)
    out = run(s.execute(m, idempotency_key="k", context=payment(amount=10**6)))
    assert s.executed == [], out.reason


@attack(vector=3, severity="critical", title="Tampered mandate (constraints / scope / expiry widened)")
def test_tampered_mandate_rejected():
    s = Stack()
    for field, value in [("constraints", {}), ("action_scope", ["*"]), ("resource_scope", []),
                         ("exp", 2**40), ("subject", "agent/other"), ("revocation_required", False)]:
        m = copy.deepcopy(s.mandate(revocation_required=True))
        m[field] = value
        run(s.execute(m, idempotency_key=f"k-{field}", actor=m["subject"], context=payment(amount=10**6)))
    assert s.executed == [], f"executed {s.executed}"


@attack(vector=3, severity="critical", title="Forged prior approval (self-minted approval mandate)")
def test_forged_approval_mandate_rejected():
    s = Stack()
    evil = SigningKey.generate("approver-1")
    now = int(time.time())
    m = issue_mandate(evil, issuer="mcc/approvals", subject=ACTOR, action_scope=[ACTION],
                      resource_scope=[RESOURCE], not_before=now - 5, not_after=now + 600,
                      extra={"approval_id": "req-forged", "single_use": True})
    out = run(s.service.execute_with_approval(mandate=m, actor=ACTOR, action=ACTION, resource=RESOURCE,
                                              context=payment(amount=10**6), idempotency_key="k",
                                              tenant_id=TENANT))
    assert s.executed == [], out.reason


@attack(vector=3, severity="high", title="Resource outside mandate scope / omitted resource")
def test_resource_scope_enforced():
    s = Stack()
    m = s.mandate()
    run(s.execute(m, idempotency_key="k1", resource="acct-999"))
    run(s.execute(m, idempotency_key="k2", resource=None))
    run(s.execute(m, idempotency_key="k3", resource="acct-1/../acct-999"))
    assert s.executed == [], f"executed {s.executed}"


@attack(vector=3, severity="high", title="Token minted for one actor/resource replayed with a different binding")
def test_token_binding_mismatch_rejected():
    s = Stack()
    toks = spy_tokens(s)
    run(s.execute(s.mandate(), idempotency_key="k"))
    tok = dict(toks[0])
    n = len(s.executed)

    async def ex():
        s.executed.append(("REPLAY", {}))
    for binding in ({"actor_id": "agent/other"}, {"resource_id": "acct-999"}, {"tenant_id": "tenant-2"}):
        run(s.coordinator.enforce(token=tok, action=ACTION, payload=payment(), executor=ex,
                                  request_binding=binding))
    assert len(s.executed) == n, f"executed {s.executed[n:]}"
