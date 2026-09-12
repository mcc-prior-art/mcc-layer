"""Framework/provider/domain-neutrality static guards (PR #112).

AST-based import checks + literal-token scans, modeled on
``tests/test_proposal_execution_api_architecture_guards.py``: prove that
the Core execution-authority boundary (``gateway/proposal_execution_service.py``,
``gateway/proposal_execution_api.py``, ``gateway/proposal_execution_stack.py``)
never imports a specific model/provider SDK, a specific agent framework,
or GitHub-specific vocabulary -- GitHub concepts must remain entirely
behind the actuator/adapter boundary (``examples/phase2_live_sandbox/``,
``examples/gpt6_astra_reference/``), never inside the files that decide
whether an action is authorized.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, List, Set

ROOT = Path(__file__).resolve().parents[1]

CORE_BOUNDARY_FILES = [
    ROOT / "gateway" / "proposal_execution_service.py",
    ROOT / "gateway" / "proposal_execution_api.py",
    ROOT / "gateway" / "proposal_execution_stack.py",
]

# Specific agent-framework / orchestration SDKs. MCC-Core must not become
# structurally dependent on any of these -- frameworks may transport
# proposals from the outside, never decide authority from the inside.
FORBIDDEN_FRAMEWORK_MODULES = {
    "langgraph", "crewai", "autogen", "autogen_core", "autogen_agentchat",
    "voltagent", "mcp", "mcp.server", "mcp.client", "a2a",
}

# Specific model/provider SDKs. Proposal evaluation must never depend on
# which of these produced the proposal.
FORBIDDEN_PROVIDER_MODULES = {
    "openai", "anthropic", "google.generativeai", "boto3", "azure",
}

# GitHub-specific (or any other single execution-domain's) API vocabulary.
# These identifiers/literals belong ONLY inside an actuator/adapter
# (examples/phase2_live_sandbox, examples/gpt6_astra_reference) -- never
# inside the generic authority/execution boundary.
FORBIDDEN_DOMAIN_TOKENS = (
    "api.github.com", "/repos/", "octokit", "IssueIn", "GITHUB_ISSUE_ACTION",
    "GitHubIssueActuator", "GitHubSandboxUpstream", "GitHubActuatorConfig",
    "html_url", "issue_number",
)


def _imported_modules(source: str) -> Set[str]:
    tree = ast.parse(source)
    modules: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def _check_files(files: Iterable[Path]) -> List[str]:
    violations: List[str] = []
    for path in files:
        source = path.read_text(encoding="utf-8")
        modules = _imported_modules(source)
        try:
            rel = path.relative_to(ROOT)
        except ValueError:
            rel = path
        for m in modules:
            if m in FORBIDDEN_FRAMEWORK_MODULES or any(
                m == f or m.startswith(f + ".") for f in FORBIDDEN_FRAMEWORK_MODULES
            ):
                violations.append(f"{rel}: forbidden framework import {m!r}")
            if m in FORBIDDEN_PROVIDER_MODULES or any(
                m == f or m.startswith(f + ".") for f in FORBIDDEN_PROVIDER_MODULES
            ):
                violations.append(f"{rel}: forbidden provider-SDK import {m!r}")
        for token in FORBIDDEN_DOMAIN_TOKENS:
            if token in source:
                violations.append(f"{rel}: forbidden domain-specific token {token!r}")
    return violations


def test_core_execution_boundary_has_no_framework_imports():
    violations = _check_files(CORE_BOUNDARY_FILES)
    assert not violations, "\n".join(violations)


def test_core_execution_boundary_files_were_actually_found():
    for f in CORE_BOUNDARY_FILES:
        assert f.exists(), f"expected file not found: {f}"
    assert len(CORE_BOUNDARY_FILES) == 3


def test_universal_proof_package_stack_has_no_framework_or_provider_imports():
    """``examples/universal_execution_proof/stack.py`` is the composition
    layer used by BOTH the GitHub-backed and the generic-ledger-backed
    proof -- it must stay domain/actuator-agnostic; only
    ``run_live_proof.py`` (an explicit reference-domain wiring script, not
    part of MCC-Core) may reference GitHub."""
    stack_file = ROOT / "examples" / "universal_execution_proof" / "stack.py"
    violations = _check_files([stack_file])
    assert not violations, "\n".join(violations)


def test_generic_ledger_actuator_has_no_domain_specific_vocabulary():
    ledger_file = ROOT / "examples" / "universal_execution_proof" / "generic_ledger_actuator.py"
    violations = _check_files([ledger_file])
    assert not violations, "\n".join(violations)


# --------------------------------------------------------------------------- #
# Non-vacuity: the guard must actually catch a planted coupling.
# --------------------------------------------------------------------------- #

_PLANTED_FRAMEWORK_COUPLING = '''
import langgraph
from openai import OpenAI

def evaluate_via_framework():
    return langgraph.StateGraph()
'''

_PLANTED_DOMAIN_COUPLING = '''
"""A deliberately vulnerable stand-in that leaks GitHub-specific
vocabulary into what should be a domain-neutral authority boundary."""

GITHUB_ISSUE_ACTION = "create_github_issue"

def authorize(action, resource):
    if resource.startswith("api.github.com"):
        return True
'''


def test_non_vacuity_guard_catches_planted_framework_and_provider_coupling():
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(_PLANTED_FRAMEWORK_COUPLING)
        path = Path(f.name)
    try:
        violations = _check_files([path])
    finally:
        path.unlink()
    assert violations, "the guard should have flagged framework/provider coupling"
    assert any("langgraph" in v for v in violations)
    assert any("openai" in v for v in violations)


def test_non_vacuity_guard_catches_planted_domain_coupling():
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(_PLANTED_DOMAIN_COUPLING)
        path = Path(f.name)
    try:
        violations = _check_files([path])
    finally:
        path.unlink()
    assert violations, "the guard should have flagged GitHub-specific vocabulary"
    assert any("GITHUB_ISSUE_ACTION" in v or "api.github.com" in v for v in violations)


def test_non_vacuity_guard_accepts_the_real_core_boundary_files_unmodified():
    assert not _check_files(CORE_BOUNDARY_FILES)
