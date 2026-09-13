"""INV-06 — Executor cannot authorize.

Constitutional principle: "No plane may usurp the role of another";
"Intelligence proposes; authority verifies; execution enforces."

The executor must only execute an already-verified decision. It must
never contain fallback authorization logic such as
``if agent_requested_action: execute``.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
from pathlib import Path

from ._stack import NOW, Stack

run = asyncio.run

ROOT = Path(__file__).resolve().parents[2]

# Real, existing actuator/executor entrypoints in this repository (not new
# code written for this suite) -- the ones a governed executor actually
# dispatches through.
ACTUATOR_ENTRYPOINTS = [
    (ROOT / "examples" / "gpt6_astra_reference" / "github_actuator.py", "GitHubIssueActuator"),
]
EXECUTOR_MODULES = [
    ROOT / "examples" / "gpt6_astra_reference" / "github_actuator.py",
    ROOT / "egress_proxy" / "executor.py",
]

FORBIDDEN_AUTHORITY_NAMES = {
    "AuthorityModel", "DecisionEngine", "issue_token", "MandateRegistry", "ExecutionGate",
}


def _imported_names(source: str):
    tree = ast.parse(source)
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
    return names


def test_actuator_call_signature_has_no_agent_request_or_authority_parameter():
    """The real GitHubIssueActuator's dispatch entrypoint takes exactly
    (action, payload) -- there is structurally no 'requested_by_agent'/
    'agent_says_ok'/'decision' parameter an ``if agent_requested_action:
    execute`` style fallback could even be written against."""
    import sys

    sys.path.insert(0, str(ROOT))
    from examples.gpt6_astra_reference.github_actuator import GitHubIssueActuator

    params = list(inspect.signature(GitHubIssueActuator.__call__).parameters)
    assert params == ["self", "action", "payload"]
    forbidden = {"requested_by_agent", "agent_says_ok", "decision", "verdict", "authorized", "allow"}
    assert forbidden.isdisjoint(params)


def test_actuator_modules_never_import_authority_or_decision_primitives():
    """Real, existing actuator/executor modules must never import the
    Authority-plane primitives -- an executor that could construct its
    own AuthorityModel/DecisionEngine/issue_token call could authorize
    itself, exactly the fallback this invariant forbids."""
    violations = []
    for path in EXECUTOR_MODULES:
        if not path.exists():
            continue
        names = _imported_names(path.read_text(encoding="utf-8"))
        bad = names & FORBIDDEN_AUTHORITY_NAMES
        if bad:
            violations.append((str(path), sorted(bad)))
    assert violations == [], f"executor modules must never import authority primitives: {violations}"


def test_non_vacuity_authority_import_in_executor_would_be_caught():
    """Non-vacuity: a planted 'from mcc_core import AuthorityModel' in an
    executor-shaped source string is actually caught by the same scan."""
    planted = "from mcc_core import AuthorityModel, DecisionEngine\n"
    names = _imported_names(planted)
    assert names & FORBIDDEN_AUTHORITY_NAMES == {"AuthorityModel", "DecisionEngine"}


def test_dumb_always_execute_executor_is_still_never_called_without_valid_token(tmp_path):
    """Even an executor callback with ZERO internal guard logic of its own
    (it would run unconditionally if invoked) is still never invoked when
    the token is missing or invalid -- the gating is entirely upstream of
    the executor, so the executor cannot be the thing that authorizes."""
    stack = Stack(tmp_path)
    calls = []

    async def unconditional_executor():
        # deliberately has no "if agent_requested_action" or any other
        # guard -- if this function runs at all, the side effect happens
        calls.append("SIDE EFFECT HAPPENED")
        return "done"

    forged = stack.issue_allow(idempotency_key="op-1", signing_key=stack.untrusted_key)
    result = run(stack.coordinator.enforce(token=forged, action="send_email", payload={"body": "hi"}, executor=unconditional_executor, now=NOW))
    assert result.status.value == "BLOCKED"
    assert calls == [], "the unconditional executor must never run without a gate-verified token"


def test_dumb_always_execute_executor_does_run_with_a_genuinely_valid_token(tmp_path):
    """Positive control: the same unconditional executor DOES run when a
    real, valid token is presented -- proving the coordinator is what
    gates it, not some accidental universal block."""
    stack = Stack(tmp_path)
    calls = []

    async def unconditional_executor():
        calls.append("SIDE EFFECT HAPPENED")
        return "done"

    token = stack.issue_allow(idempotency_key="op-1", payload={"body": "hi"})
    result = run(stack.coordinator.enforce(token=token, action="send_email", payload={"body": "hi"}, executor=unconditional_executor, now=NOW))
    assert result.status.value == "EXECUTED"
    assert calls == ["SIDE EFFECT HAPPENED"]
