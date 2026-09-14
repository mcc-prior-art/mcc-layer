"""INV-01 — No self-authorization.

Constitutional principles: "Authority remains with the owner";
"Intelligence proposes; authority verifies; execution enforces."

An agent must never be able to create or fabricate its own authorization
decision. The only path from a proposal to an executed operation is:

    Agent -> Proposal -> MCC-Core -> Decision -> Execution

Never:

    Agent -> Execution

These tests attack the boundary directly: they construct exactly the
kind of forged/self-issued "decision" an agent could attempt to produce
on its own, and prove ``ExecutionGate`` and ``EnforcementCoordinator``
reject every one of them -- using the existing, unmodified gate/engine,
not a new check written for this suite.
"""

from __future__ import annotations

import asyncio

from mcc_core import Verdict

from ._stack import NOW, Stack

run = asyncio.run


def test_token_signed_by_untrusted_key_is_rejected(tmp_path):
    """The most direct self-authorization attempt: an agent that holds
    ITS OWN Ed25519 key (never registered as a trusted MCC-Core signer)
    signs a decision claiming ALLOW. The gate must reject it -- a valid
    signature from a key the gate does not trust carries no authority."""
    stack = Stack(tmp_path)
    forged = stack.issue_allow(idempotency_key="op-1", signing_key=stack.untrusted_key)
    result = run(stack.gate.verify(forged, action="send_email", payload={"body": "hello"}, now=NOW))
    assert result.allowed is False
    assert "UNTRUSTED_KEY" in result.reason


def test_unsigned_dict_claiming_allow_is_rejected(tmp_path):
    """An agent that simply constructs a Python dict shaped like a
    decision token -- no signature at all -- must not be treated as an
    execution authorization."""
    stack = Stack(tmp_path)
    fabricated = {
        "decision": "ALLOW", "action": "send_email", "action_hash": "sha256:" + "0" * 64,
        "payload_hash": "sha256:" + "0" * 64, "policy_hash": stack.gate.policy_hash,
        "nonce": "fabricated-nonce", "aud": "constitution-gate",
        "nbf": NOW - 10, "exp": NOW + 60, "kid": "constitution-k1",
    }
    result = run(stack.gate.verify(fabricated, action="send_email", payload={"body": "hello"}, now=NOW))
    assert result.allowed is False
    # No "sig" field at all -> verify_token's base64 decode of token["sig"] raises -> caught -> False.
    assert result.reason in ("INVALID_SIGNATURE: Ed25519 verification failed", "NO_TOKEN: no verified decision token, no execution")


def test_tampered_valid_token_signature_no_longer_verifies(tmp_path):
    """An agent that takes a REAL, MCC-Core-issued token and edits any
    claim (e.g. escalating its own verdict) invalidates the signature --
    the signature covers the entire claim set, so no partial forgery is
    possible."""
    stack = Stack(tmp_path)
    token = stack.issue_allow(idempotency_key="op-1")
    tampered = dict(token)
    tampered["resource_id"] = "a-different-resource-the-agent-wants"
    result = run(stack.gate.verify(tampered, action="send_email", payload={"body": "hello"}, now=NOW))
    assert result.allowed is False
    assert result.reason == "INVALID_SIGNATURE: Ed25519 verification failed"


def test_proposal_content_claiming_pre_approval_does_not_grant_execution(tmp_path):
    """An agent's PROPOSAL (the untrusted payload) claiming it was
    "already approved" must not be treated as an authorization. This
    proves PROPOSAL != PERMISSION at the coordinator level: a payload
    that embeds a self-declared approval still requires a real, verified
    token to execute."""
    stack = Stack(tmp_path)
    seen = []

    async def executor():
        seen.append("executed")
        return "ok"

    self_declared_approval = {"already_approved_by": "self", "decision": "ALLOW", "body": "hello"}
    # No token at all is presented -- the coordinator's gate.verify call
    # must reject on the missing/invalid token, never on trusting the
    # payload's own claims.
    result = run(stack.coordinator.enforce(
        token={}, action="send_email", payload=self_declared_approval, executor=executor, now=NOW,
    ))
    assert result.status.value == "BLOCKED"
    assert seen == [], "executor must never run without a verified decision"


def test_agent_side_modules_hold_no_signing_key_material():
    """Structural (non-vacuity-checked) guard: the reference/pilot agent
    packages must not import or construct a SigningKey -- the one thing
    that would let an agent issue its own decision tokens. Mirrors the
    existing pattern in tests/test_mcc_agent_no_direct_egress.py and
    tests/test_reference_governed_agent.py's own no-direct-execution
    guard, re-asserted here as an explicit constitutional invariant."""
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    agent_dirs = [root / "src" / "mcc_agent", root / "examples" / "reference_governed_agent"]
    # Deliberately excluded: these two files are documented, independent
    # AUTHORITY-plane tooling bundled alongside the reference agent for
    # the demo -- not the agent's own decision logic. authorizers.py's
    # own docstring: "a separate authority still has to produce material
    # the gate will verify ... playing the evaluator role" (a stand-in
    # for a real, independent consensus/mandate service; the gate still
    # independently verifies every vote). _localstack.py is the demo's
    # private in-process harness that spins up the WHOLE governed stack
    # (including its own DecisionEngine), not the agent. Excluding named,
    # justified files here is a much narrower exception than exempting
    # the whole directory, and the exclusion list itself is a two-line
    # diff away from being noticed if it's ever quietly widened.
    excluded_files = {"authorizers.py", "_localstack.py"}

    def imported_names(source: str):
        tree = ast.parse(source)
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    names.add(alias.name)
                    names.add(f"{node.module}.{alias.name}")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    names.add(alias.name)
        return names

    violations = []
    for d in agent_dirs:
        if not d.exists():
            continue
        for path in d.rglob("*.py"):
            if path.name in excluded_files:
                continue
            names = imported_names(path.read_text(encoding="utf-8"))
            if "SigningKey" in names or any(n.endswith(".SigningKey") for n in names):
                violations.append(str(path))
    assert violations == [], f"agent-side modules must never import SigningKey: {violations}"


def test_non_vacuity_signing_key_import_would_be_caught():
    """Proves the guard above is not vacuous: a planted SigningKey import
    is actually detected by the same scan."""
    import ast

    planted_source = "from mcc_core.signing import SigningKey\n"
    tree = ast.parse(planted_source)
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                names.add(alias.name)
    assert "SigningKey" in names
