"""V05 - Multi-agent collusion: subagent A obtains, subagent B executes."""
from _harness import *


@attack(vector=5, severity="high", kind="design-gap",
        title="Mandate is a bearer credential: any caller can present it by naming its subject as 'actor'")
def test_mandate_requires_proof_of_possession():
    # Agent A ("agent/payments-bot") holds the mandate. Agent B ("agent/intern") sees the
    # signed JSON (shared memory, tool output, log) and calls execute naming A as actor.
    # /mandates/execute takes `actor` from the request body; the only caller authentication
    # is the shared X-API-Key (gateway/governance_api.py::_auth_deps).
    s = Stack()
    leaked = s.mandate()                       # issued to agent/payments-bot
    out = run(s.service.execute_with_mandate(  # called by agent/intern
        mandate=leaked, actor=leaked["subject"], action=ACTION, resource=RESOURCE,
        context=payment(beneficiary_id="intern-mule"), idempotency_key="b-1", tenant_id=TENANT))
    assert s.executed == [], \
        f"second agent executed with first agent's mandate: {s.executed} ({out.status})"


@attack(vector=5, severity="critical", title="A obtains human approval, B executes a different operation with it")
def test_approval_obtained_by_a_executed_by_b_with_other_payload():
    s = Stack()
    req = run(s.service.create_approval(actor=ACTOR, action=ACTION, resource=RESOURCE,
                                        transaction_id="tx-1", policy_hash=POLICY_HASH,
                                        tenant_id=TENANT, payload=payment(amount=100.0)))
    mandate = run(s.service.approve(req["request_id"]))        # human approves 100 EUR to vendor-42
    out = run(s.service.execute_with_mandate(                  # colluding agent, plain mandate route
        mandate=mandate, actor=ACTOR, action=ACTION, resource=RESOURCE,
        context=payment(amount=1_000_000.0, beneficiary_id="attacker-acct"),
        transaction_id="tx-evil", idempotency_key="evil-1", tenant_id=TENANT))
    assert s.executed == [], \
        f"approved 100.0 -> vendor-42, executed {s.executed} ({out.status}/{out.decision})"


@attack(vector=5, severity="high", title="Decision token minted for agent A enforced on behalf of agent B")
def test_token_for_a_cannot_be_enforced_for_b():
    s = Stack()
    toks = spy_tokens(s)
    run(s.execute(s.mandate(), idempotency_key="a-1"))
    n = len(s.executed)

    async def ex():
        s.executed.append(("B-EXEC", {}))
    r = run(s.coordinator.enforce(token=toks[0], action=ACTION, payload=payment(), executor=ex,
                                  request_binding={"actor_id": "agent/intern"}))
    assert len(s.executed) == n, r.reason
