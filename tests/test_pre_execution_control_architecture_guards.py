"""Static architecture guards for PR-2 (Pre-Execution Attestation Control
Integration).

Proves, by AST inspection (not just convention/review), the invariants the
task specification requires as *structural* guarantees rather than test
behavior alone:

* ``gateway/governance_api.py`` (the FastAPI transport layer) never calls
  ``DecisionEngine.issue_token`` directly, and never imports the attestation
  verifier itself -- it is transport-only, exactly as its own module
  docstring states. The only executable-token issuance path is
  ``GovernanceService``.
* ``GovernanceService.execute_with_mandate`` / ``execute_with_consensus`` --
  the two governed runtime methods that call ``issue_token`` -- always call
  the PR-2 attestation gate (``self._attestation_gate``) *before*
  ``self.engine.issue_token`` in source order, for every ``issue_token`` call
  site in the file. There is no route to token issuance in this file that
  skips the gate.
* The new Control boundary (``gateway/pre_execution_control.py``) carries no
  LLM/model-SDK/agent-framework/probabilistic-reasoning dependency and
  exposes no such surface on ``PreExecutionControl`` -- mandatory test #28
  ("no LLM/model/agent-framework dependency exists in the new Control
  path"). This mirrors ``tests/test_mcc_attestation_architecture_guards.py``
  and ``tests/test_mcc_agent_no_direct_egress.py``'s AST-guard style.
* The strict HTTP execute schemas carry no pre-computed "verified"/"trusted"
  boolean the caller could use to assert attestation validity without the
  server re-verifying the raw document itself (mandatory test #25 at the
  transport-schema level).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GOVERNANCE_API = ROOT / "gateway" / "governance_api.py"
GOVERNANCE_SERVICE = ROOT / "gateway" / "governance_service.py"
PRE_EXECUTION_CONTROL = ROOT / "gateway" / "pre_execution_control.py"

# Mirrors tests/test_mcc_attestation_architecture_guards.py's FORBIDDEN_ROOTS:
# LLM/model SDKs, agent frameworks, and probabilistic/ML runtimes have no
# business anywhere in the deterministic Control decision path.
FORBIDDEN_ROOTS = {
    "anthropic", "openai", "google", "cohere", "transformers", "torch",
    "tensorflow", "llama_index", "langchain",
    "langgraph", "crewai", "autogen_core", "autogen_agentchat", "voltagent",
}


def _tree(path: Path) -> ast.AST:
    return ast.parse(path.read_text(), filename=str(path))


def _imported_module_names(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                yield node.module


def _call_names(tree: ast.AST):
    """Yield ``(qualified_name, lineno)`` for every call expression, where
    ``qualified_name`` is the dotted attribute chain for ``a.b.c(...)`` calls
    or the bare name for ``f(...)`` calls."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute):
            parts = [func.attr]
            cur = func.value
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            yield ".".join(reversed(parts)), node.lineno
        elif isinstance(func, ast.Name):
            yield func.id, node.lineno


def test_files_exist():
    assert GOVERNANCE_API.is_file()
    assert GOVERNANCE_SERVICE.is_file()
    assert PRE_EXECUTION_CONTROL.is_file()


# ---------------------------------------------------------------------------
# governance_api.py: transport-only -- never issues a token directly, never
# imports the attestation verifier itself.
# ---------------------------------------------------------------------------


def test_governance_api_never_calls_issue_token_directly():
    tree = _tree(GOVERNANCE_API)
    bad = [(name, lineno) for name, lineno in _call_names(tree)
           if name == "issue_token" or name.endswith(".issue_token")]
    assert not bad, f"gateway/governance_api.py calls issue_token directly: {bad}"


def test_governance_api_never_imports_attestation_verifier_directly():
    """The HTTP layer must reach attestation verification only through
    GovernanceService -> PreExecutionControl -> mcc_attestation.verify_attestation
    -- never by importing the verifier itself into a route handler."""
    tree = _tree(GOVERNANCE_API)
    bad = [mod for mod in _imported_module_names(tree)
           if mod == "mcc_attestation.verifier" or mod.startswith("mcc_attestation.verifier.")]
    assert not bad, f"gateway/governance_api.py imports the verifier directly: {bad}"


def test_governance_api_defines_no_local_authorize_or_verify_function():
    """No route module-level function should itself decide ALLOW/DENY --
    every decision comes from GovernanceService."""
    tree = _tree(GOVERNANCE_API)
    forbidden = {"authorize", "verify_attestation", "issue_token", "decide"}
    names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    assert not (names & forbidden), names & forbidden


# ---------------------------------------------------------------------------
# governance_service.py: every issue_token call site is preceded, in source
# order within the same function, by the PR-2 attestation gate.
# ---------------------------------------------------------------------------


def _function_defs(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def test_every_issue_token_call_site_is_gated_by_attestation_first():
    tree = _tree(GOVERNANCE_SERVICE)
    checked_any = False
    for func in _function_defs(tree):
        calls = list(_call_names(func))
        issue_calls = [ln for name, ln in calls if name.endswith(".issue_token")]
        if not issue_calls:
            continue
        checked_any = True
        gate_calls = [ln for name, ln in calls if name.endswith("_attestation_gate")]
        assert gate_calls, (
            f"{func.name} calls engine.issue_token but never calls "
            f"self._attestation_gate -- attestation could be bypassed"
        )
        assert min(gate_calls) < min(issue_calls), (
            f"{func.name} calls self._attestation_gate (line {min(gate_calls)}) "
            f"AFTER engine.issue_token (line {min(issue_calls)}) -- a token "
            f"could be issued before the attestation gate runs"
        )
    assert checked_any, (
        "no function in gateway/governance_service.py calls engine.issue_token "
        "-- this guard would pass vacuously; the file's issuance surface changed "
        "and this test must be updated to look at the new call sites"
    )


def test_governance_service_has_exactly_three_issue_token_call_sites():
    """Documents and pins the known runtime issuance surface (PR-2 final
    report item #11): execute_with_mandate and execute_with_consensus.
    execute_with_approval delegates to execute_with_mandate rather than
    calling issue_token a third time. Verifiable Delegation added
    execute_with_delegation as a genuine, deliberate, reviewed third call
    site (not a silent addition) -- any further new call site must again
    deliberately update this guard."""
    tree = _tree(GOVERNANCE_SERVICE)
    sites = []
    for func in _function_defs(tree):
        for name, lineno in _call_names(func):
            if name.endswith(".issue_token"):
                sites.append((func.name, lineno))
    assert {name for name, _ in sites} == {
        "execute_with_mandate", "execute_with_consensus", "execute_with_delegation",
    }
    assert len(sites) == 3


def test_execute_with_approval_delegates_and_forwards_attestation():
    """execute_with_approval must not issue a token itself; it must delegate
    to execute_with_mandate and forward the attestation argument through
    (otherwise the ESCALATE path could silently drop the requirement)."""
    tree = _tree(GOVERNANCE_SERVICE)
    for func in _function_defs(tree):
        if func.name != "execute_with_approval":
            continue
        calls = list(_call_names(func))
        assert not any(name.endswith(".issue_token") for name, _ in calls)
        assert any(name.endswith("execute_with_mandate") for name, _ in calls)
        # The call must pass attestation= as a keyword, not drop it silently.
        for node in ast.walk(func):
            if isinstance(node, ast.Call):
                func_name = getattr(node.func, "attr", getattr(node.func, "id", None))
                if func_name == "execute_with_mandate":
                    kwnames = {kw.arg for kw in node.keywords}
                    assert "attestation" in kwnames, (
                        "execute_with_approval's call to execute_with_mandate "
                        "does not forward attestation="
                    )
        return
    pytest.fail("execute_with_approval not found in gateway/governance_service.py")


# ---------------------------------------------------------------------------
# pre_execution_control.py: no LLM/model/agent-framework dependency anywhere
# in the new Control path (mandatory test #28).
# ---------------------------------------------------------------------------


def test_pre_execution_control_has_no_llm_or_agent_framework_import():
    tree = _tree(PRE_EXECUTION_CONTROL)
    bad = []
    for mod in _imported_module_names(tree):
        root = mod.split(".")[0]
        if root in FORBIDDEN_ROOTS or mod in FORBIDDEN_ROOTS:
            bad.append(mod)
    assert not bad, f"gateway/pre_execution_control.py imports forbidden module(s): {bad}"


def test_pre_execution_control_class_has_no_llm_or_reasoning_surface():
    import inspect

    from gateway.pre_execution_control import PreExecutionControl

    public = {n for n in dir(PreExecutionControl) if not n.startswith("_")}
    forbidden = {"model", "llm", "provider", "prompt", "reasoning", "client", "call_model"}
    assert not (public & forbidden), public & forbidden

    params = set(inspect.signature(PreExecutionControl.evaluate).parameters)
    assert not (params & forbidden), params & forbidden


def test_pre_execution_control_defines_no_authorize_or_execute_function():
    """Mirrors the PR-1 verifier guard: Control decides whether required
    evidence and authority exist, deterministically -- it does not itself
    become a second authority/execution surface with its own verbs."""
    import gateway.pre_execution_control as control_module

    public = {n for n in dir(control_module) if not n.startswith("_")}
    forbidden_names = {"authorize", "execute", "allow", "grant"}
    overlap = {n for n in public if n.lower() in forbidden_names}
    assert not overlap, overlap


def test_pre_execution_control_does_not_import_decision_engine():
    """Control decides whether issuance MAY proceed; it must never itself be
    able to mint a token (that stays exclusively DecisionEngine's, called
    only from GovernanceService after Control returns ok)."""
    tree = _tree(PRE_EXECUTION_CONTROL)
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == "DecisionEngine":
            pytest.fail("gateway/pre_execution_control.py references DecisionEngine")
        if isinstance(node, ast.Attribute) and node.attr == "DecisionEngine":
            pytest.fail("gateway/pre_execution_control.py references DecisionEngine")


# ---------------------------------------------------------------------------
# HTTP schemas: no pre-computed "verified"/"trusted" bypass field (mandatory
# test #25 at the transport-schema level).
# ---------------------------------------------------------------------------


def test_execute_request_schemas_carry_no_precomputed_verification_flag():
    """A caller must never be able to assert 'verified=True', 'trusted=True',
    or similar for an attestation over the wire -- the server always
    re-verifies the raw EvidenceAttestation itself (PR-1's verify_attestation,
    invoked by Control). Only a raw ``attestation`` document field is allowed."""
    import gateway.governance_api as api

    forbidden_fields = {
        "verified", "attestation_verified", "trusted", "attestation_trusted",
        "attestation_valid", "skip_attestation", "bypass_attestation",
        "attestation_result",
    }
    for cls_name in (
        "MandateExecuteRequest", "ApprovalExecuteRequest", "ConsensusExecuteRequest",
    ):
        cls = getattr(api, cls_name)
        fields = set(cls.model_fields.keys())
        overlap = fields & forbidden_fields
        assert not overlap, f"{cls_name} carries a bypass-shaped field: {overlap}"
