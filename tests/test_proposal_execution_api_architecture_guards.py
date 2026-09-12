"""Static architecture guards for the Pilot Execution API (PR #111).

Modeled on ``tests/test_proposal_service_architecture_guards.py`` /
``tests/test_mcc_agent_no_direct_egress.py``: AST-based import/reference
checks, not runtime behavior tests, so a future refactor cannot silently
smuggle a second authority mechanism, a second Gate/coordinator, or a
direct actuator bypass into the HTTP transport layer.

``gateway/proposal_execution_api.py`` (the router) is scanned; it may
import ONLY ``gateway.proposal_execution_service`` (the existing Phase 2
bridge boundary) and ``gateway.proposal_api`` (the shared tenant-auth
dependency) for anything authority/execution-shaped -- never the Gate, the
coordinator, the authority model, the decision engine, a signing key, or
the stack BUILDER module (which legitimately constructs those primitives,
but the router must only ever receive an already-built
``ProposalExecutionService``, exactly mirroring how
``gateway/proposal_api.py`` only ever receives an already-built
``MCCProposalService``).

``gateway/proposal_execution_stack.py`` (the builder) is DELIBERATELY NOT
scanned by this guard -- unlike the router, its entire job is to construct
the Phase 2 authority/execution machinery (exactly like
``examples/phase2_live_sandbox/stack.py``, which is likewise unguarded).
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, List, Set

ROOT = Path(__file__).resolve().parents[1]

ROUTER_FILE = ROOT / "gateway" / "proposal_execution_api.py"

FORBIDDEN_MODULES = {
    "mcc_core.gate", "mcc_core.coordinator", "mcc_core.authority", "mcc_core.core",
    "mcc_core.mandate", "mcc_core.approvals", "mcc_core.consensus",
    "mcc_core.velocity", "mcc_core.nonce", "mcc_core.policy",
    "gateway.governance_service", "gateway.governance_api",
    "gateway.proposal_execution_stack",
    "egress_proxy.executor", "pilot_notify.governed_upstream",
    "clinic_service", "pilot.outbound_executor",
}
FORBIDDEN_NAMES = {
    "EnforcementCoordinator", "ExecutionGate", "MandateAuthority", "MandateVerifier",
    "ApprovalService", "ConsensusVerifier", "HTTPEgressExecutor", "GovernanceService",
    "AuthorityModel", "DecisionEngine", "SigningKey",
    "ResourceBoundUpstream", "build_proposal_execution_stack",
}
FORBIDDEN_SIGNING_NAMES = {"SigningKey", "verify_token", "public_key_from_b64"}
# Direct-call tokens: even if a forbidden name were smuggled in via an
# aliased import (``import X as Y``), these substrings catch the actual
# invocation shape a bypass would need.
FORBIDDEN_CALL_TOKENS = (
    "EnforcementCoordinator(", "ExecutionGate(", "AuthorityModel(", "AuthorityModel.evaluate(",
    "DecisionEngine(", ".issue_token(", ".enforce(", "ResourceBoundUpstream(", ".execute(resource=",
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
    return violations


def _check_files(files: Iterable[Path]) -> List[str]:
    violations: List[str] = []
    for path in files:
        source = path.read_text(encoding="utf-8")
        violations.extend(_check_source(source, label=str(path.relative_to(ROOT))))
    return violations


def test_router_has_no_governance_authority_or_actuator_imports():
    violations = _check_files([ROUTER_FILE])
    assert not violations, "\n".join(violations)


def test_router_only_reaches_execution_via_the_existing_bridge():
    """Positive counterpart to the negative check above: the router MUST
    import the existing Phase 2 bridge boundary (not merely avoid the
    forbidden names) -- otherwise the negative check would trivially pass
    against an empty or unrelated file."""
    source = ROUTER_FILE.read_text(encoding="utf-8")
    assert "from gateway.proposal_execution_service import" in source
    assert "ProposalExecutionService" in source
    assert "authorize_and_execute" in source


def test_router_file_was_actually_found_and_non_trivial():
    assert ROUTER_FILE.exists()
    assert len(ROUTER_FILE.read_text(encoding="utf-8")) > 500


# --------------------------------------------------------------------------- #
# Non-vacuity: the guard must actually catch a planted bypass.
# --------------------------------------------------------------------------- #

_PLANTED_BYPASS_SOURCE = '''
"""A deliberately vulnerable stand-in for the router: calls the actuator
directly, bypassing ProposalExecutionService entirely -- no authority
evaluation, no signed token, no coordinator, no idempotency admission."""

from fastapi import FastAPI

from gateway.proposal_execution_service import ResourceBoundUpstream


def mount_bypass_routes(app: FastAPI, upstream: ResourceBoundUpstream) -> None:
    @app.post("/v1/operations/{logical_operation_id}/execute")
    async def bypass_execute(logical_operation_id: str):
        return await upstream.execute(resource="res-1", action="whatever", payload={})
'''

_PLANTED_SECOND_GATE_SOURCE = '''
"""A deliberately vulnerable stand-in that builds its own second Gate /
EnforcementCoordinator right inside the transport layer instead of
delegating to the existing Phase 2 bridge."""

from mcc_core.gate import ExecutionGate
from mcc_core.coordinator import EnforcementCoordinator


def build_second_execution_path():
    gate = ExecutionGate(trusted_keys={}, audience="x", nonce_registry=None, policy_hash="x")
    return EnforcementCoordinator(gate=gate, idempotency=None, velocity=None, audit=None, profiles=None)
'''


def test_non_vacuity_guard_catches_a_planted_direct_actuator_bypass():
    violations = _check_source(_PLANTED_BYPASS_SOURCE, label="planted-bypass")
    assert violations, "the guard should have flagged a router that calls the actuator directly"
    assert any("ResourceBoundUpstream" in v for v in violations)


def test_non_vacuity_guard_catches_a_planted_second_gate_and_coordinator():
    violations = _check_source(_PLANTED_SECOND_GATE_SOURCE, label="planted-second-gate")
    assert violations, "the guard should have flagged a router that builds its own Gate/Coordinator"
    assert any("mcc_core.gate" in v or "mcc_core.coordinator" in v for v in violations)


def test_non_vacuity_guard_accepts_the_real_router_unmodified():
    """Sanity check that the guard is not so strict it would also reject
    the actual shipped router (which is exactly what tests above already
    assert, restated here as an explicit non-vacuity pairing: the guard
    distinguishes the real file from the planted ones, not just rejects
    everything)."""
    real_violations = _check_files([ROUTER_FILE])
    assert not real_violations
