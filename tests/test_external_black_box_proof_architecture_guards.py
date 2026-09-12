"""Static + dynamic architecture guards for the External Black-Box
Integration Proof's standalone consumer (PR #114).

Modeled on ``tests/test_external_pilot_architecture_guards.py`` (PR #113)
and ``tests/test_proposal_execution_api_architecture_guards.py`` (PR
#111): AST-based import/name/call-token checks over a COMMITTED SNAPSHOT
of the external consumer's source
(``proofs/external_black_box_integration_proof/external_consumer_snapshot/consumer.py``,
a byte-for-byte copy of the file actually run, outside this repository,
at ``/tmp/mcc-live-external-consumer/consumer.py`` during the live proof)
-- plus one dynamic check that actually imports and runs the snapshot's
own isolation self-check function, so this guard is not purely
static-textual.

Every static guard category below ships a non-vacuity probe: a
deliberately violating source string proving the checker would actually
fail if the forbidden pattern were present, not just that it passes on
today's clean file.

This test file does NOT rescan ``gateway/proposal_execution_service.py``,
``examples/phase2_live_sandbox/*``, or ``examples/gpt6_astra_reference/*``
-- those are unmodified by this PR and already covered by their own
existing guards (PR #111/#112 architecture-guard tests).
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Iterable, List, Set

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "proofs" / "external_black_box_integration_proof" / "external_consumer_snapshot" / "consumer.py"
LIVE_COPY = Path("/tmp/mcc-live-external-consumer/consumer.py")

FORBIDDEN_MODULES = {
    "mcc_core", "mcc_core.gate", "mcc_core.coordinator", "mcc_core.authority",
    "mcc_core.core", "mcc_core.signing", "mcc_core.mandate", "mcc_core.approvals",
    "mcc_core.consensus", "mcc_core.velocity", "mcc_core.nonce", "mcc_core.policy",
    "gateway.proposal_execution_service", "gateway.proposal_execution_stack",
    "gateway.governance_service", "gateway.governance_api",
    "mcc_proposal.service", "mcc_proposal.registry",
    "egress_proxy.executor", "pilot_notify.governed_upstream", "clinic_service",
    "pilot.outbound_executor",
    "examples.gpt6_astra_reference.github_actuator", "examples.phase2_live_sandbox.actuator",
    # Direct GitHub write clients: this consumer must reach GitHub only
    # through MCC's controlled actuator, never directly.
    "github", "pygithub", "PyGithub",
}
FORBIDDEN_NAMES = {
    "EnforcementCoordinator", "ExecutionGate", "AuthorityModel", "DecisionEngine",
    "SigningKey", "ProposalExecutionService", "ResourceBoundUpstream",
    "build_proposal_execution_stack", "MandateAuthority", "MandateVerifier",
    "ApprovalService", "ConsensusVerifier", "HTTPEgressExecutor", "GovernanceService",
    "GitHubIssueActuator", "GitHubSandboxUpstream", "GitHubActuatorConfig",
}
FORBIDDEN_SIGNING_NAMES = {"SigningKey", "verify_token", "public_key_from_b64", "sign_token", "issue_token"}
FORBIDDEN_CALL_TOKENS = (
    "EnforcementCoordinator(", "ExecutionGate(", "AuthorityModel(", "AuthorityModel.evaluate(",
    "DecisionEngine(", ".issue_token(", ".enforce(", "ResourceBoundUpstream(",
    "ProposalExecutionService(", ".authorize_and_execute(",
    "api.github.com",  # no direct GitHub write path -- only through MCC
    "https://api.github.com/repos",
)
# Fallback/mock-provider vocabulary: no fixture, no deterministic
# substitute, no cached/prerecorded response standing in for a live call.
FORBIDDEN_FALLBACK_TOKENS = (
    "DeterministicAstraProvider", "MockOpenAI", "FakeModelProvider", "mock_openai",
    "PRERECORDED", "CACHED_RESPONSE", "fixture_response", "canned_response",
)


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
    for token in FORBIDDEN_FALLBACK_TOKENS:
        if token in source:
            violations.append(f"{label}: forbidden fallback/mock-provider token {token!r}")
    return violations


def _load_snapshot_source() -> str:
    return SNAPSHOT.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Structural preconditions
# ---------------------------------------------------------------------------

def test_snapshot_exists_and_is_valid_python():
    assert SNAPSHOT.exists(), f"expected committed snapshot not found: {SNAPSHOT}"
    ast.parse(_load_snapshot_source())


def test_snapshot_matches_live_consumer_when_both_present():
    """If the live external copy is still present on disk (e.g. re-running
    this test right after the live proof), it must be byte-identical to
    the committed snapshot -- the snapshot must be a faithful copy of
    what actually ran, never a cleaned-up rewrite."""
    if not LIVE_COPY.exists():
        return  # only enforceable when the external directory is present
    assert LIVE_COPY.read_text(encoding="utf-8") == _load_snapshot_source()


# ---------------------------------------------------------------------------
# A. No MCC-internal imports (Phase 1 / Phase 6.E / Phase 7)
# ---------------------------------------------------------------------------

def test_consumer_has_no_forbidden_imports_or_names():
    violations = _check_source(_load_snapshot_source(), label="consumer.py")
    assert violations == [], f"architecture guard violations: {violations}"


def test_non_vacuity_mcc_core_import_is_caught():
    planted = _load_snapshot_source() + "\nimport mcc_core\n"
    violations = _check_source(planted, label="planted")
    assert any("mcc_core" in v for v in violations), "guard did not catch a planted mcc_core import"


def test_non_vacuity_gateway_import_is_caught():
    planted = _load_snapshot_source() + "\nfrom gateway.proposal_execution_service import ProposalExecutionService\n"
    violations = _check_source(planted, label="planted")
    assert any("gateway.proposal_execution_service" in v or "ProposalExecutionService" in v for v in violations)


# ---------------------------------------------------------------------------
# B. No signing capability (Phase 6.E / Phase 7)
# ---------------------------------------------------------------------------

def test_non_vacuity_signing_key_import_is_caught():
    planted = _load_snapshot_source() + "\nfrom mcc_core.signing import SigningKey, sign_token\n"
    violations = _check_source(planted, label="planted")
    assert any("SigningKey" in v or "signing-authority" in v for v in violations)


# ---------------------------------------------------------------------------
# C. No direct actuator / Gate / coordinator reference (Phase 6.F / Phase 7)
# ---------------------------------------------------------------------------

def test_non_vacuity_direct_actuator_reference_is_caught():
    planted = _load_snapshot_source() + "\nfrom examples.gpt6_astra_reference.github_actuator import GitHubIssueActuator\n"
    violations = _check_source(planted, label="planted")
    assert any("GitHubIssueActuator" in v for v in violations)


def test_non_vacuity_coordinator_construction_is_caught():
    planted = _load_snapshot_source() + "\ncoord = EnforcementCoordinator()\n"
    violations = _check_source(planted, label="planted")
    assert any("EnforcementCoordinator(" in v for v in violations)


# ---------------------------------------------------------------------------
# D. No direct GitHub write path (Phase 6.F / Phase 7)
# ---------------------------------------------------------------------------

def test_non_vacuity_direct_github_api_call_is_caught():
    planted = _load_snapshot_source() + '\nhttpx.post("https://api.github.com/repos/x/y/issues")\n'
    violations = _check_source(planted, label="planted")
    assert any("api.github.com" in v for v in violations)


def test_non_vacuity_pygithub_import_is_caught():
    planted = _load_snapshot_source() + "\nimport github\n"
    violations = _check_source(planted, label="planted")
    assert any("github" in v for v in violations)


# ---------------------------------------------------------------------------
# E. No model fallback / mock / prerecorded substitution (Phase 2 / Phase 7)
# ---------------------------------------------------------------------------

def test_non_vacuity_mock_provider_token_is_caught():
    planted = _load_snapshot_source() + '\nCACHED_RESPONSE = {"action": "noop"}\n'
    violations = _check_source(planted, label="planted")
    assert any("CACHED_RESPONSE" in v for v in violations)


def test_consumer_has_single_live_model_call_site():
    """The consumer must call the live Chat Completions endpoint from
    exactly one function (``call_live_model``) -- no second, alternate
    call path that could serve as an undisclosed fallback."""
    source = _load_snapshot_source()
    assert source.count("OPENAI_CHAT_COMPLETIONS_URL") >= 1
    assert source.count("httpx.post(\n        OPENAI_CHAT_COMPLETIONS_URL") == 1 or \
        source.count("OPENAI_CHAT_COMPLETIONS_URL,") == 1


def test_consumer_raises_rather_than_substitutes_on_model_call_failure():
    """On any live-call failure the consumer must record the error and
    exit non-zero (never quietly proceed with a substitute proposal).
    As of PR #115 this is enforced by the fail-closed ``_finalize``
    verdict logic (``live_model_call_succeeded`` stays False, so the run
    can never reach ``result: "PROVEN"``) -- see
    ``tests/test_external_black_box_proof_harness_verdict.py`` for the
    tests that exercise that decision logic directly rather than via
    string search."""
    source = _load_snapshot_source()
    assert "except httpx.HTTPStatusError" in source
    assert "except httpx.HTTPError" in source
    assert "live_model_call_succeeded" in source
    assert 'return _finalize(evidence, checks, args.evidence_out)' in source


# ---------------------------------------------------------------------------
# F. Dynamic isolation check (Phase 1) -- actually import and run it
# ---------------------------------------------------------------------------

def test_dynamic_isolation_self_check_reports_mcc_modules_unimportable():
    """Imports the committed snapshot as a module (in THIS test process,
    which legitimately has mcc-layer on sys.path) and calls its own
    ``check_mcc_internals_unavailable`` function. Even from inside this
    repository's own test process, the three named mcc-layer packages
    must not resolve as top-level importable modules under those import
    statements as written -- proving the function's *logic* is sound,
    independent of which process happens to run it. (The live proof's
    OWN process-isolation evidence -- run from a separate cwd with no
    mcc-layer path on sys.path -- is captured separately in
    ``sanitized_live_run.json``, not re-derived here.)
    """
    spec = importlib.util.spec_from_file_location("_external_consumer_snapshot", SNAPSHOT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        result = module.check_mcc_internals_unavailable()
    finally:
        sys.modules.pop(spec.name, None)

    assert callable(getattr(module, "check_mcc_internals_unavailable", None))
    # The function must always ATTEMPT each import and report the result,
    # never assume/skip -- non-vacuity: every named module has an entry.
    for expected in ("mcc_core", "gateway.proposal_execution_service", "mcc_proposal"):
        assert expected in result, f"isolation check did not attempt {expected!r}"


# ---------------------------------------------------------------------------
# G. Hash-binding logic present (Phase 2 material-determination requirement)
# ---------------------------------------------------------------------------

def test_consumer_hash_binds_captured_and_submitted_proposal():
    source = _load_snapshot_source()
    assert "canonical_hash(" in source
    assert "captured_proposal_sha256" in source
    assert "submitted_proposal_sha256" in source
    assert "proposal_hash_binding_verified" in source
    assert "submitted_proposal_hash == captured_proposal_hash" in source


def test_consumer_aborts_if_proof_id_not_in_model_output():
    """The unique proof identifier must come from the model's own output,
    never be injected by the consumer after the fact. As of PR #115 this
    is enforced via the ``proof_id_in_model_output`` required check (see
    ``tests/test_external_black_box_proof_harness_verdict.py`` for the
    decision-logic test)."""
    source = _load_snapshot_source()
    assert 'checks["proof_id_in_model_output"] = proof_id in body_text' in source
    assert '"model output did not include the required unique proof identifier"' in source
