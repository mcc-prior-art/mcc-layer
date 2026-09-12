"""Static architecture guards for the External Pilot Integration Pack's
bring-your-own-agent client (PR #113).

Modeled directly on
``tests/test_proposal_execution_api_architecture_guards.py`` (PR #111)
and ``tests/test_universal_execution_proof_architecture_guards.py`` (PR
#112): AST-based import/name/call-token checks, not runtime behavior
tests, so a future change cannot silently smuggle a second authority
mechanism, a signing key, a direct actuator invocation, or a direct
``ProposalExecutionService``/``EnforcementCoordinator`` call into what
must remain a plain, unprivileged HTTP caller.

``gateway/proposal_execution_service.py``, ``gateway/proposal_execution_api.py``,
and ``gateway/proposal_execution_stack.py`` (the MCC-Core-side boundary
files: provider/framework/domain neutrality) are DELIBERATELY NOT
rescanned here -- ``tests/test_proposal_execution_api_architecture_guards.py``
and ``tests/test_universal_execution_proof_architecture_guards.py``
already guard them, unmodified by this PR, and both remain part of the
full suite; duplicating that scan here would be exactly the kind of
unnecessary guard duplication the task explicitly asks to avoid.
"""

from __future__ import annotations

import ast
import tempfile
from pathlib import Path
from typing import Iterable, List, Set

ROOT = Path(__file__).resolve().parents[1]

CLIENT_FILES = [
    ROOT / "examples" / "external_pilot" / "client" / "mcc_pilot_client.py",
    ROOT / "examples" / "external_pilot" / "client" / "example_producer.py",
]

FORBIDDEN_MODULES = {
    "mcc_core", "mcc_core.gate", "mcc_core.coordinator", "mcc_core.authority",
    "mcc_core.core", "mcc_core.signing", "mcc_core.mandate", "mcc_core.approvals",
    "mcc_core.consensus", "mcc_core.velocity", "mcc_core.nonce", "mcc_core.policy",
    "gateway.proposal_execution_service", "gateway.proposal_execution_stack",
    "gateway.governance_service", "gateway.governance_api",
    "mcc_proposal.service", "mcc_proposal.registry",
    "egress_proxy.executor", "pilot_notify.governed_upstream", "clinic_service",
    "pilot.outbound_executor",
    # Model-provider / agent-framework SDKs the bring-your-own-agent
    # producer template must never require (Section 3/4 of the task).
    "openai", "anthropic", "langgraph", "crewai", "autogen", "autogen_core",
    "autogen_agentchat", "voltagent", "mcp", "mcp.server", "mcp.client", "a2a",
}
FORBIDDEN_NAMES = {
    "EnforcementCoordinator", "ExecutionGate", "AuthorityModel", "DecisionEngine",
    "SigningKey", "ProposalExecutionService", "ResourceBoundUpstream",
    "build_proposal_execution_stack", "MandateAuthority", "MandateVerifier",
    "ApprovalService", "ConsensusVerifier", "HTTPEgressExecutor", "GovernanceService",
}
FORBIDDEN_SIGNING_NAMES = {"SigningKey", "verify_token", "public_key_from_b64", "sign_token", "issue_token"}
FORBIDDEN_CALL_TOKENS = (
    "EnforcementCoordinator(", "ExecutionGate(", "AuthorityModel(", "AuthorityModel.evaluate(",
    "DecisionEngine(", ".issue_token(", ".enforce(", "ResourceBoundUpstream(",
    ".execute(resource=", "ProposalExecutionService(", ".authorize_and_execute(",
)
# Actuator/domain-specific vocabulary that must never leak into the
# bring-your-own-agent producer template -- it is domain-neutral by
# construction (Section 3: "Do NOT depend on GitHub semantics").
FORBIDDEN_DOMAIN_TOKENS = ("api.github.com", "GITHUB_ISSUE_ACTION", "GitHubIssueActuator", "html_url")


def _imported_modules_and_names(source: str) -> "tuple[Set[str], Set[str]]":
    tree = ast.parse(source)
    modules: Set[str] = set()
    names: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
            for alias in node.names:
                names.add(alias.name)
    return modules, names


def _check_source(source: str, *, label: str) -> List[str]:
    violations: List[str] = []
    modules, names = _imported_modules_and_names(source)
    for m in modules:
        if m in FORBIDDEN_MODULES or any(m == f or m.startswith(f + ".") for f in FORBIDDEN_MODULES):
            violations.append(f"{label}: forbidden import of module {m!r}")
    for n in names:
        if n in FORBIDDEN_NAMES:
            violations.append(f"{label}: forbidden import of name {n!r}")
    if "mcc_core.signing" in modules:
        bad = names & FORBIDDEN_SIGNING_NAMES
        if bad:
            violations.append(f"{label}: imports signing-authority name(s) {sorted(bad)} from mcc_core.signing")
    for token in FORBIDDEN_CALL_TOKENS:
        if token in source:
            violations.append(f"{label}: forbidden call/reference {token!r}")
    for token in FORBIDDEN_DOMAIN_TOKENS:
        if token in source:
            violations.append(f"{label}: forbidden domain-specific token {token!r}")
    return violations


def _check_files(files: Iterable[Path]) -> List[str]:
    violations: List[str] = []
    for path in files:
        source = path.read_text(encoding="utf-8")
        try:
            rel = path.relative_to(ROOT)
        except ValueError:
            rel = path
        violations.extend(_check_source(source, label=str(rel)))
    return violations


def test_client_files_were_actually_found():
    for f in CLIENT_FILES:
        assert f.exists(), f"expected file not found: {f}"


def test_bring_your_own_agent_client_has_no_authority_signing_or_actuator_access():
    violations = _check_files(CLIENT_FILES)
    assert not violations, "\n".join(violations)


def test_client_only_reaches_execution_via_real_http():
    """Positive counterpart: the client MUST use httpx (real HTTP), not
    merely avoid the forbidden names -- otherwise the negative check
    above would trivially pass against an unrelated/empty file."""
    source = (ROOT / "examples" / "external_pilot" / "client" / "mcc_pilot_client.py").read_text(encoding="utf-8")
    assert "import httpx" in source
    assert '"/v1/proposals"' in source
    assert "/execute" in source


_PRODUCER_TEMPLATE_ALLOWED_MODULES = {"__future__", "typing"}


def test_producer_template_never_imports_a_provider_or_framework_sdk():
    """The bring-your-own-agent template itself: zero provider/framework
    dependency, by construction (it doesn't even import httpx -- it is a
    pure dict-in, dict-out translation function). The ONLY imports it may
    have are from the stdlib ``typing`` module and ``__future__``."""
    source = (ROOT / "examples" / "external_pilot" / "client" / "example_producer.py").read_text(encoding="utf-8")
    modules, _names = _imported_modules_and_names(source)
    extra = modules - _PRODUCER_TEMPLATE_ALLOWED_MODULES
    assert not extra, f"producer template has unexpected import(s): {extra}"


# --------------------------------------------------------------------------- #
# Non-vacuity: the guard must actually catch a planted bypass.
# --------------------------------------------------------------------------- #

_PLANTED_DIRECT_SERVICE_SOURCE = '''
"""A deliberately vulnerable stand-in: calls ProposalExecutionService
directly instead of going through the real HTTP boundary."""

from gateway.proposal_execution_service import ProposalExecutionService


async def bypass_execute(service: ProposalExecutionService, tenant_id, op_id):
    return await service.authorize_and_execute(tenant_id=tenant_id, logical_operation_id=op_id)
'''

_PLANTED_SIGNING_KEY_SOURCE = '''
"""A deliberately vulnerable stand-in: the client possesses a signing key
and mints its own authority token."""

from mcc_core.signing import SigningKey


def mint_my_own_authority():
    key = SigningKey.generate("client-side-forged-key")
    return key
'''

_PLANTED_DIRECT_ACTUATOR_SOURCE = '''
"""A deliberately vulnerable stand-in: the client holds and calls the
actuator directly, bypassing authority evaluation entirely."""

from gateway.proposal_execution_service import ResourceBoundUpstream


async def bypass(upstream: ResourceBoundUpstream):
    return await upstream.execute(resource="res-1", action="whatever", payload={})
'''

_PLANTED_PROVIDER_SDK_SOURCE = '''
"""A deliberately non-neutral producer: requires the OpenAI SDK."""

import openai


def build_proposal_from_agent_output(agent_output):
    return {"payload": agent_output}
'''


def test_non_vacuity_guard_catches_a_planted_direct_service_call():
    violations = _check_source(_PLANTED_DIRECT_SERVICE_SOURCE, label="planted-direct-service")
    assert violations
    assert any("ProposalExecutionService" in v for v in violations)


def test_non_vacuity_guard_catches_a_planted_client_side_signing_key():
    violations = _check_source(_PLANTED_SIGNING_KEY_SOURCE, label="planted-signing-key")
    assert violations
    assert any("SigningKey" in v or "mcc_core.signing" in v for v in violations)


def test_non_vacuity_guard_catches_a_planted_direct_actuator_call():
    violations = _check_source(_PLANTED_DIRECT_ACTUATOR_SOURCE, label="planted-direct-actuator")
    assert violations
    assert any("ResourceBoundUpstream" in v or ".execute(resource=" in v for v in violations)


def test_non_vacuity_guard_catches_a_planted_provider_sdk_dependency():
    violations = _check_source(_PLANTED_PROVIDER_SDK_SOURCE, label="planted-provider-sdk")
    assert violations
    assert any("openai" in v for v in violations)


def test_non_vacuity_guard_accepts_the_real_client_files_unmodified():
    """Sanity check that the guard is not so strict it would also reject
    the actual shipped client files."""
    real_violations = _check_files(CLIENT_FILES)
    assert not real_violations
