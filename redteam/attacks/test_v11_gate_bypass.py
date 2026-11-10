"""V11 - Gate bypass: any code path that reaches an actuator without the execution gate."""
import ast
import re

from _harness import *

RUNTIME_DIRS = ["gateway", "src/mcc_core", "egress_proxy", "interceptors"]


@attack(vector=11, severity="critical", title="GovernanceService reaches the upstream only inside coordinator.enforce")
def test_upstream_only_called_from_enforced_executor():
    src = (ROOT / "gateway" / "governance_service.py").read_text()
    tree = ast.parse(src)
    callers = []
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for node in ast.walk(fn):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "upstream"):
                    callers.append(fn.name)
    assert set(callers) <= {"executor", "_run"}, f"upstream called from {callers}"


@attack(vector=11, severity="critical", title="With the real gate trusting no key, no public execute_* path reaches the actuator")
def test_gate_rejection_blocks_every_service_path():
    s = Stack()
    s.gate.trusted_keys = {}          # real gate, real verify(): it now trusts no signer at all
    run(s.execute(s.mandate(), idempotency_key="k1"))
    req = run(s.service.create_approval(actor=ACTOR, action=ACTION, resource=RESOURCE,
                                        tenant_id=TENANT, payload=payment()))
    m = run(s.service.approve(req["request_id"]))
    run(s.service.execute_with_approval(mandate=m, actor=ACTOR, action=ACTION, resource=RESOURCE,
                                        context=payment(), idempotency_key="k2", tenant_id=TENANT))
    run(s.service.execute_with_delegation(delegation={}, actor=ACTOR, action=ACTION, resource=RESOURCE,
                                          purpose="p", context=payment(), idempotency_key="k3",
                                          tenant_id=TENANT))
    run(s.service.execute_with_consensus(votes=[], actor=ACTOR, action=ACTION, resource=RESOURCE,
                                         context=payment(), idempotency_key="k4", tenant_id=TENANT))
    assert s.executed == [], f"executed with the gate closed: {s.executed}"


@attack(vector=11, severity="medium", kind="hardening",
        title="HTTPEgressExecutor accepts an unsigned dict as its 'verified decision token'")
def test_egress_executor_verifies_token_signature():
    # egress_proxy/executor.py cannot be imported here (httpx missing), so the REAL source of
    # HTTPEgressExecutor._is_authorized is extracted and executed unchanged.
    src = (ROOT / "egress_proxy" / "executor.py").read_text()
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_is_authorized")
    fn.decorator_list = []
    ns = {"Any": object, "EXECUTABLE": ("ALLOW", "CONSTRAIN")}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "executor.py", "exec"), ns)
    forged = {"decision": "ALLOW", "action": "create_lead"}        # no kid, no sig, no nonce
    assert ns["_is_authorized"](forged, "create_lead") is False, \
        "executor.execute() authorizes any dict {'decision':'ALLOW','action':<action>} - no signature check"


@attack(vector=11, severity="low", kind="hardening",
        title="ExecutionGate.verify skips action/payload binding when the caller omits them")
def test_gate_requires_action_and_payload_binding():
    s = Stack()
    tok = s.engine.issue_token(verdict="ALLOW", subject=ACTOR, action=ACTION, payload=payment(amount=1))
    res = run(s.gate.verify(tok))            # caller forgot action= / payload=
    assert not res.allowed, "gate verified a token without checking what is about to be executed"


@attack(vector=11, severity="high", title="No runtime module issues tokens or calls an actuator outside the governed path")
def test_no_unexpected_token_issuers():
    offenders = []
    for d in RUNTIME_DIRS:
        for p in (ROOT / d).rglob("*.py"):
            text = p.read_text()
            if re.search(r"\.sign_token\(", text) and p.name not in (
                    "signing.py", "core.py", "mandate.py", "delegation.py", "consensus.py",
                    "challenge.py", "approvals.py"):
                offenders.append(str(p.relative_to(ROOT)))
    assert offenders == [], f"unexpected signers: {offenders}"
