"""V18 - Policy downgrade: stale or older policy version accepted."""
from _harness import *
from mcc_core import DecisionEngine

OLD = "sha256:" + "a" * 64


@attack(vector=18, severity="critical", title="Mandate bound to an older policy hash")
def test_mandate_bound_to_old_policy_rejected():
    s = Stack()
    out = run(s.execute(s.mandate(policy_hash=OLD), idempotency_key="k"))
    assert s.executed == [], out.reason


@attack(vector=18, severity="critical", title="Decision token issued under an older policy hash")
def test_token_from_old_policy_rejected():
    s = Stack()
    old_engine = DecisionEngine(signing_key=s.signing_key, issuer="mcc/core", audience="pilot",
                                policy_id="pilot/v0", policy_hash=OLD)
    tok = old_engine.issue_token(verdict="ALLOW", subject=ACTOR, action=ACTION, payload=payment(),
                                 idempotency_key="k", tenant_id=TENANT)

    async def ex():
        s.executed.append(("X", {}))
    r = run(s.coordinator.enforce(token=tok, action=ACTION, payload=payment(), executor=ex))
    assert s.executed == [], r.reason


@attack(vector=18, severity="low", kind="design-gap",
        title="Mandate issued without policy_hash stays valid across policy rotations")
def test_unbound_mandate_survives_policy_rotation():
    s = Stack()
    out = run(s.execute(s.mandate(policy_hash=None), idempotency_key="k"))
    assert s.executed == [], "mandate with policy_hash=None accepted under the current policy (binding is optional)"


@attack(vector=18, severity="medium", kind="design-gap",
        title="Approval policy binding is chosen by the requesting agent (omit it -> unbound approval)")
def test_approval_policy_binding_is_not_caller_optional():
    s = Stack()
    req = run(s.service.create_approval(actor=ACTOR, action=ACTION, resource=RESOURCE, tenant_id=TENANT,
                                        payload=payment(), policy_hash=None))
    m = run(s.service.approve(req["request_id"]))
    assert m["policy_hash"] == POLICY_HASH, f"approval mandate policy_hash={m['policy_hash']!r} (taken from the agent's request)"


@attack(vector=18, severity="medium", kind="hardening",
        title="Policy bundle is loaded without a pinned expected hash")
def test_policy_bundle_load_is_pinned():
    import re
    src = (ROOT / "main.py").read_text()
    call = re.search(r"PolicyBundle\.from_file\(([^)]*)\)", src, re.S).group(1)
    assert "expected_hash" in call, "main.py: PolicyBundle.from_file(path, policy_id) - a swapped policy file is accepted and its new hash signed into tokens"
