"""V15 - Time: clock skew, expiry boundaries, nonce store lost on restart."""
import time

from _harness import *


@attack(vector=15, severity="critical", title="Expired / not-yet-valid mandate, including the exact boundary")
def test_mandate_validity_window():
    s = Stack()
    now = int(time.time())
    for kw in (dict(not_before=now - 100, not_after=now - 1), dict(not_before=now - 100, not_after=now),
               dict(not_before=now + 30, not_after=now + 600), dict(not_before=now + 5, not_after=now - 5)):
        run(s.execute(s.mandate(**kw), idempotency_key=f"k-{kw['not_after']}-{kw['not_before']}"))
    assert s.executed == []


@attack(vector=15, severity="high", title="Token never outlives the mandate that justified it")
def test_token_exp_clamped_to_mandate_exp():
    s = Stack()
    toks = spy_tokens(s)
    now = int(time.time())
    m = s.mandate(not_after=now + 3)
    run(s.execute(m, idempotency_key="k"))
    assert toks and toks[0]["exp"] <= m["exp"], (toks[0]["exp"], m["exp"])


@attack(vector=15, severity="critical", title="Expired decision token (boundary: now == exp)")
def test_expired_token_rejected():
    s = Stack()
    past = int(time.time()) - 120
    tok = s.engine.issue_token(verdict="ALLOW", subject=ACTOR, action=ACTION, payload=payment(),
                               idempotency_key="k", tenant_id=TENANT, now=past)

    async def ex():
        s.executed.append(("X", {}))
    run(s.coordinator.enforce(token=tok, action=ACTION, payload=payment(), executor=ex))
    tok2 = s.engine.issue_token(verdict="ALLOW", subject=ACTOR, action=ACTION, payload=payment(),
                                idempotency_key="k2", tenant_id=TENANT, now=int(time.time()) - 60)
    run(s.coordinator.enforce(token=tok2, action=ACTION, payload=payment(), executor=ex))
    assert s.executed == []


@attack(vector=15, severity="high", title="Token issued in the future (nbf) / with non-integer window")
def test_future_or_malformed_window():
    s = Stack()

    async def ex():
        s.executed.append(("X", {}))
    tok = s.engine.issue_token(verdict="ALLOW", subject=ACTOR, action=ACTION, payload=payment(),
                               idempotency_key="k", tenant_id=TENANT, now=int(time.time()) + 600)
    run(s.coordinator.enforce(token=tok, action=ACTION, payload=payment(), executor=ex))
    assert s.executed == []


@attack(vector=15, severity="low", kind="hardening",
        title="EnforcementCoordinator.enforce(now=...) lets the caller choose the clock")
def test_caller_cannot_supply_enforcement_time():
    s = Stack()
    past = int(time.time()) - 3600
    tok = s.engine.issue_token(verdict="ALLOW", subject=ACTOR, action=ACTION, payload=payment(),
                               idempotency_key="k", tenant_id=TENANT, now=past)   # expired 59 min ago

    async def ex():
        s.executed.append(("X", {}))
    run(s.coordinator.enforce(token=tok, action=ACTION, payload=payment(), executor=ex, now=past + 1))
    assert s.executed == [], "hour-old expired token executed because the caller passed now=<past>"


@attack(vector=15, severity="medium", kind="design-gap",
        title="Agent-chosen approval TTL is unbounded")
def test_approval_ttl_is_capped():
    s = Stack()
    req = run(s.service.create_approval(actor=ACTOR, action=ACTION, resource=RESOURCE, tenant_id=TENANT,
                                        payload=payment(), ttl_seconds=10 * 365 * 86400))
    m = run(s.service.approve(req["request_id"]))
    life = m["exp"] - m["nbf"]
    assert life <= 86400, f"approval mandate valid for {life // 86400} days (ttl_seconds is set by the requesting agent)"
