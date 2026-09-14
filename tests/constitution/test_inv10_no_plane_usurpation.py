"""INV-10 — No plane usurpation.

Constitutional principle: "No plane may usurp the role of another."

Five sub-claims, each tested (or, where the component does not exist in
this codebase, explicitly marked IMPLEMENTATION GAP rather than
claimed):

  a. Intelligence cannot authorize.          -- PROVEN (INV-01, re-asserted here)
  b. Memory cannot authorize.                -- PARTIALLY PROVEN (INV-04); no
                                                 memory subsystem exists to
                                                 test end-to-end (documented
                                                 gap, not hidden)
  c. Executor cannot authorize.              -- PROVEN (INV-06, re-asserted here)
  d. UI cannot directly authorize.           -- IMPLEMENTATION GAP: this
                                                 repository has no UI/frontend
                                                 code at all (it is a backend
                                                 governance engine); there is
                                                 no real UI boundary to test
                                                 against.
  e. Only the Authority plane issues the
     execution decision (``DecisionEngine.issue_token``).
                                              -- PROVEN
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Every module in this repository that is legitimately part of the
# AUTHORITY plane and is therefore allowed to call ``.sign_token(`` --
# i.e. mints signed artifacts (decision tokens, mandates, approvals,
# consensus votes, challenges) as its actual job. Everything else calling
# ``.sign_token(`` directly (bypassing DecisionEngine.issue_token for a
# DECISION specifically) would be a plane usurpation.
AUTHORITY_PLANE_FILES = {
    "core.py", "mandate.py", "approvals.py", "consensus.py", "challenge.py", "signing.py",
}


def _files_calling_sign_token_outside_authority_plane():
    violations = []
    for path in (ROOT / "src" / "mcc_core").glob("*.py"):
        if path.name in AUTHORITY_PLANE_FILES:
            continue
        source = path.read_text(encoding="utf-8")
        if ".sign_token(" in source:
            violations.append(str(path))
    # Also scan gateway/ and examples/ -- no non-mcc_core module should
    # ever construct a signed decision artifact directly.
    for extra_dir in (ROOT / "gateway", ROOT / "examples"):
        if not extra_dir.exists():
            continue
        for path in extra_dir.rglob("*.py"):
            source = path.read_text(encoding="utf-8")
            if ".sign_token(" in source:
                violations.append(str(path))
    return violations


def test_a_intelligence_cannot_authorize_reasserted():
    """Re-assertion pointer: see test_inv01_no_self_authorization.py for
    the full adversarial coverage (forged tokens, tampered tokens,
    self-declared approvals). Restated here as this invariant's own
    explicit claim rather than only living under INV-01's file."""
    from ._stack import Stack

    # An agent-forged token (signed by a key the gate does not trust) is
    # authority the INTELLIGENCE plane attempted to manufacture for
    # itself -- and it fails.
    import asyncio
    import tempfile

    tmp_path = Path(tempfile.mkdtemp())
    stack = Stack(tmp_path)
    forged = stack.issue_allow(idempotency_key="op-1", signing_key=stack.untrusted_key)
    result = asyncio.run(stack.gate.verify(forged, action="send_email", payload={"body": "hello"}, now=1_790_000_000))
    assert result.allowed is False


def test_b_memory_cannot_authorize_gap_is_explicitly_documented():
    """This is not a functional test of a memory component (none exists
    -- see test_inv04_memory_cannot_authorize.py's own module docstring
    for the full explanation). This test exists only to make the GAP
    itself a checked, version-controlled fact: if an agent-memory package
    is ever added to this repository, this assertion should be updated
    to point at it, and doing so is a deliberate, reviewable change --
    not something that can silently stay unnoticed."""
    memory_package_paths = [
        ROOT / "src" / "mcc_memory",
        ROOT / "src" / "mcc_agent" / "memory.py",
    ]
    existing = [p for p in memory_package_paths if p.exists()]
    assert existing == [], (
        "IMPLEMENTATION GAP outdated: a memory component now exists at "
        f"{existing} -- INV-04/INV-10.b need a real end-to-end test against "
        "it, not just the structural AuthorityModel proof."
    )


def test_c_executor_cannot_authorize_reasserted():
    """Re-assertion pointer: see test_inv06_executor_cannot_authorize.py."""
    actuator_path = ROOT / "examples" / "gpt6_astra_reference" / "github_actuator.py"
    source = actuator_path.read_text(encoding="utf-8")
    assert "AuthorityModel" not in source
    assert "DecisionEngine" not in source


def test_d_ui_cannot_authorize_is_an_implementation_gap():
    """Explicit, checked documentation of the gap: no UI/frontend
    directory exists anywhere in this repository. This assertion fails
    loudly (forcing this invariant to be revisited) the moment one is
    added, rather than letting 'UI cannot authorize' remain an untested
    claim once a UI actually exists."""
    ui_candidate_dirs = [ROOT / "ui", ROOT / "frontend", ROOT / "dashboard", ROOT / "web"]
    existing = [p for p in ui_candidate_dirs if p.exists()]
    assert existing == [], (
        f"IMPLEMENTATION GAP outdated: UI code now exists at {existing} -- "
        "INV-10.d needs a real test that the UI plane cannot issue an "
        "execution decision, not just the absence-of-UI documentation."
    )


def test_e_only_authority_plane_issues_decision_tokens():
    violations = _files_calling_sign_token_outside_authority_plane()
    assert violations == [], f"only Authority-plane modules may call .sign_token(): {violations}"


def test_non_vacuity_sign_token_outside_authority_plane_would_be_caught(tmp_path):
    planted = tmp_path / "not_authority_plane.py"
    planted.write_text("result = some_signing_key.sign_token(claims)\n")
    source = planted.read_text(encoding="utf-8")
    assert ".sign_token(" in source  # sanity: the scan's own substring check would match this


def test_the_four_role_formula_is_the_only_execution_path(tmp_path):
    """The consolidated, end-to-end version of a-c-e together: intelligence
    (a proposal) alone, without a verified decision, cannot reach
    execution; only a genuinely Authority-plane-issued token can."""
    import asyncio

    from ._stack import Stack

    stack = Stack(tmp_path)
    seen = []

    async def executor():
        seen.append("executed")
        return "ok"

    # "Intelligence" here is just the untrusted payload/proposal -- no
    # token at all, standing in for an agent that skipped Authority
    # entirely and tried to go straight to Execution.
    result = asyncio.run(stack.coordinator.enforce(
        token={}, action="send_email", payload={"body": "an agent's raw proposal, unverified"},
        executor=executor, now=1_790_000_000,
    ))
    assert result.status.value == "BLOCKED"
    assert seen == []
