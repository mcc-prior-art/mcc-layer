"""V16 - CONSTRAIN / ESCALATE: constraint not enforced at the gate; escalation resolving to ALLOW."""
from _harness import *


def _approved(s, payload=None, **kw):
    req = run(s.service.create_approval(actor=ACTOR, action=ACTION, resource=RESOURCE,
                                        transaction_id="tx-1", policy_hash=POLICY_HASH,
                                        tenant_id=TENANT, payload=payload or payment(amount=100.0), **kw))
    return req["request_id"], run(s.service.approve(req["request_id"]))


def _approval_exec(s, m, ctx, key, tx="tx-1"):
    return run(s.service.execute_with_approval(mandate=m, actor=ACTOR, action=ACTION, resource=RESOURCE,
                                               context=ctx, transaction_id=tx, idempotency_key=key,
                                               tenant_id=TENANT))


def _mandate_exec(s, m, ctx, key, tx="tx-1"):
    return run(s.service.execute_with_mandate(mandate=m, actor=ACTOR, action=ACTION, resource=RESOURCE,
                                              context=ctx, transaction_id=tx, idempotency_key=key,
                                              tenant_id=TENANT))


@attack(vector=16, severity="critical", title="CONSTRAIN: only the clamped payload reaches the actuator")
def test_constrain_executes_only_clamped_payload():
    s = Stack()
    toks = spy_tokens(s)
    out = run(s.execute(s.mandate(), idempotency_key="k", context=payment(amount=7500)))
    assert out.decision == "CONSTRAIN" and [p["amount"] for _, p in s.executed] == [5000]
    assert toks[0]["decision"] == "CONSTRAIN" and toks[0]["constraints"] == {"max_amount": 5000}


@attack(vector=16, severity="critical", title="ESCALATE: pending / denied / expired approval never executes")
def test_unapproved_escalation_never_executes():
    s = Stack()
    req = run(s.service.create_approval(actor=ACTOR, action=ACTION, resource=RESOURCE, tenant_id=TENANT,
                                        payload=payment()))
    rid = req["request_id"]
    fake = {"approval_id": rid, "kid": s.approver_key.kid, "sig": "AAAA"}
    _approval_exec(s, fake, payment(), "k1")
    run(s.service.deny(rid))
    assert run(s.service.approve(rid)) is None
    req2 = run(s.service.create_approval(actor=ACTOR, action=ACTION, resource=RESOURCE, tenant_id=TENANT,
                                         payload=payment(), ttl_seconds=1))
    import time; time.sleep(1.2)
    assert run(s.service.approve(req2["request_id"])) is None
    assert s.executed == []


@attack(vector=16, severity="critical", title="Approval route: different payload / second use / after invalidation")
def test_approval_route_binds_payload_and_is_single_use():
    s = Stack()
    rid, m = _approved(s)
    _approval_exec(s, m, payment(amount=999_999.0), "k-evil")
    assert s.executed == []
    _approval_exec(s, m, payment(amount=100.0), "k-ok")
    _approval_exec(s, m, payment(amount=100.0), "k-again")
    assert len(s.executed) == 1
    s2 = Stack()
    rid2, m2 = _approved(s2)
    run(s2.service.invalidate(rid2))
    _approval_exec(s2, m2, payment(amount=100.0), "k")
    assert s2.executed == []


@attack(vector=16, severity="critical",
        title="Approval-minted mandate presented on the plain mandate route executes a DIFFERENT payload")
def test_approval_mandate_on_mandate_route_other_payload():
    s = Stack()
    rid, m = _approved(s)                                 # human approved: 100.0 EUR -> vendor-42
    out = _mandate_exec(s, m, payment(amount=1_000_000.0, beneficiary_id="attacker-acct"), "evil", tx="tx-x")
    assert s.executed == [], \
        f"approved 100.0->vendor-42; executed {s.executed[0][1]} ({out.status}/{out.decision}); payload_hash binding skipped"


@attack(vector=16, severity="critical",
        title="Approval-minted 'single_use' mandate is reusable on the plain mandate route")
def test_approval_mandate_on_mandate_route_is_reusable():
    s = Stack()
    rid, m = _approved(s)
    for i in range(5):
        _mandate_exec(s, m, payment(amount=100.0), f"again-{i}", tx=f"tx-{i}")
    state = run(s.service.get_approval(rid))["state"]
    assert len(s.executed) <= 1, f"single_use approval executed {len(s.executed)} times; approval state still {state}"


@attack(vector=16, severity="critical",
        title="Invalidated approval still executes via the plain mandate route")
def test_invalidated_approval_on_mandate_route():
    s = Stack()
    rid, m = _approved(s)
    assert run(s.service.invalidate(rid))                 # operator pulls the approval back
    out = _mandate_exec(s, m, payment(amount=100.0), "k")
    assert s.executed == [], f"operator-invalidated approval executed ({out.status}); state={run(s.service.get_approval(rid))['state']}"


@attack(vector=16, severity="high", title="Agent-supplied constraints on the approval request cannot widen the approved payload")
def test_approval_request_constraints_do_not_widen():
    s = Stack()
    rid, m = _approved(s, constraints={"max_amount": 10**12})
    _approval_exec(s, m, payment(amount=10**9), "k")
    assert s.executed == []
