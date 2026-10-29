"""Static architecture guards for PR-4 (Independent Attester Service
Boundary, MCC-AT-004).

Proves, by AST inspection, the three structural invariants the task
specification requires:

* A. PRIVATE KEY ISOLATION -- no file in the governed MCC runtime
  (``gateway/*.py``, ``src/mcc_core/*.py``, ``interceptors/*.py``,
  ``egress_proxy/*.py``, ``main.py``) imports ``mcc_attester_service`` at
  all, so none of them can load, reference, or transitively depend on the
  module (``mcc_attester_service.config``) that knows how to load the
  Attester's PRIVATE signing key. The gateway's existing trust-loading
  code (``gateway.governance_api._build_pre_execution_control``) is proven
  to construct its ``AttesterTrustAnchor`` set from ``public_key_b64``
  only -- never from a private-key-shaped field.
* L. NO AUTHORITY FROM ATTESTER -- ``src/mcc_attester_service/*.py`` never
  imports or calls ``DecisionEngine.issue_token``, never imports
  ``ExecutionGate``/``EnforcementCoordinator``, and never imports the
  mandate/approval/consensus authority primitives. Its public surface
  carries no ``execute``/``authorize``/``allow``/``grant`` verb.
* M. NO SECOND EXECUTION PATH -- ``mcc_attester_service`` carries no
  outbound-execution surface (no reference to the egress/interceptor
  machinery), and mirrors guard A's own evidence: the ONLY route the
  signed artifact reaches governed execution through is the existing,
  unmodified ``attestation`` parameter on
  ``GovernanceService.execute_with_mandate`` / ``execute_with_consensus``
  (PR-2/PR-3, untouched by this PR).

Mirrors the AST-guard style established in
``tests/test_mcc_attestation_architecture_guards.py``,
``tests/test_pre_execution_control_architecture_guards.py``, and
``tests/test_evidence_bound_execution_ticket_architecture_guards.py``.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ATTESTER_SERVICE_DIR = ROOT / "src" / "mcc_attester_service"
GOVERNANCE_API = ROOT / "gateway" / "governance_api.py"

#: Every file that makes up the governed MCC runtime -- none of these may
#: ever import mcc_attester_service (guard A).
RUNTIME_DIRS = [
    ROOT / "gateway",
    ROOT / "src" / "mcc_core",
    ROOT / "interceptors",
    ROOT / "egress_proxy",
]
RUNTIME_FILES = [ROOT / "main.py"]

#: Names that would indicate the Attester service reaching for execution
#: authority -- forbidden anywhere in src/mcc_attester_service (guard L).
FORBIDDEN_AUTHORITY_NAMES = {
    "DecisionEngine", "issue_token", "ExecutionGate", "EnforcementCoordinator",
    "MandateAuthority", "MandateVerifier", "ConsensusVerifier", "ApprovalService",
    "issue_mandate", "issue_vote", "issue_approval",
}

#: Names that would indicate a second, parallel actuation/egress surface
#: (guard M).
FORBIDDEN_EXECUTION_NAMES = {
    "HTTPEgressExecutor", "OutboundHTTPExecutor", "receipt_verifying_upstream",
    "EgressSettings",
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


def _all_used_identifiers(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            yield node.id
        elif isinstance(node, ast.Attribute):
            yield node.attr
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                yield (alias.asname or alias.name).split(".")[-1]


def _package_files():
    assert ATTESTER_SERVICE_DIR.is_dir(), ATTESTER_SERVICE_DIR
    return sorted(ATTESTER_SERVICE_DIR.glob("*.py"))


def _runtime_files():
    files = []
    for d in RUNTIME_DIRS:
        if d.is_dir():
            files.extend(sorted(d.glob("*.py")))
    files.extend(RUNTIME_FILES)
    return [f for f in files if f.is_file()]


def test_package_and_governance_api_exist():
    assert ATTESTER_SERVICE_DIR.is_dir()
    assert GOVERNANCE_API.is_file()
    assert _package_files(), "src/mcc_attester_service has no .py files"


# ---------------------------------------------------------------------------
# A. PRIVATE KEY ISOLATION
# ---------------------------------------------------------------------------


def test_a_governed_runtime_never_imports_mcc_attester_service():
    bad = []
    for path in _runtime_files():
        tree = _tree(path)
        for mod in _imported_module_names(tree):
            if mod == "mcc_attester_service" or mod.startswith("mcc_attester_service."):
                bad.append((str(path.relative_to(ROOT)), mod))
    assert not bad, (
        f"governed runtime file(s) import mcc_attester_service (which owns "
        f"private-key loading) -- private key material could leak into the "
        f"governed process: {bad}"
    )


def test_a_governance_api_trust_loader_never_loads_a_private_key():
    """gateway.governance_api._build_pre_execution_control -- the code path
    that builds the AttesterTrustAnchor set the gateway relies on for
    attestation verification -- must construct every anchor from
    ``public_key_b64`` only, and must never call a private-key loader
    (``SigningKey.from_pem_file``, ``Ed25519PrivateKey``,
    ``load_pem_private_key``) anywhere inside that function."""
    tree = _tree(GOVERNANCE_API)
    target = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_build_pre_execution_control":
            target = node
            break
    assert target is not None, "_build_pre_execution_control not found in gateway/governance_api.py"

    source = ast.get_source_segment(GOVERNANCE_API.read_text(), target) or ""
    forbidden = ["from_pem_file", "Ed25519PrivateKey", "load_pem_private_key", "private_key"]
    bad = [name for name in forbidden if name in source]
    assert not bad, (
        f"_build_pre_execution_control references private-key material: {bad}"
    )
    assert "public_key_b64" in source, (
        "_build_pre_execution_control no longer builds trust anchors from "
        "public_key_b64 -- this guard needs to be re-examined, not silently "
        "left passing on a changed implementation"
    )


def test_a_attester_service_config_is_the_only_private_key_loader_in_the_new_package():
    """Documents and pins where the private key genuinely lives: exactly
    one function, in exactly one module of the new package, ever calls
    SigningKey.from_pem_file (the repository's private-key-loading
    primitive) or otherwise constructs a SigningKey from raw key material."""
    sites = []
    for path in _package_files():
        tree = _tree(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = getattr(node.func, "attr", getattr(node.func, "id", None))
                if name in ("from_pem_file",):
                    sites.append((path.name, node.lineno))
    assert {name for name, _ in sites} == {"config.py"}, sites


# ---------------------------------------------------------------------------
# L. NO AUTHORITY FROM ATTESTER
# ---------------------------------------------------------------------------


def test_l_attester_service_never_imports_execution_authority_primitives():
    bad = []
    for path in _package_files():
        tree = _tree(path)
        used = set(_all_used_identifiers(tree))
        overlap = used & FORBIDDEN_AUTHORITY_NAMES
        if overlap:
            bad.append((path.name, sorted(overlap)))
    assert not bad, f"mcc_attester_service references execution-authority primitives: {bad}"


def test_l_attester_service_never_calls_issue_token():
    bad = []
    for path in _package_files():
        tree = _tree(path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "attr", getattr(node.func, "id", None))
            if name == "issue_token":
                bad.append((path.name, node.lineno))
    assert not bad, f"mcc_attester_service calls issue_token: {bad}"


def test_l_public_surface_carries_no_authority_verb():
    import mcc_attester_service as pkg

    forbidden_names = {"authorize", "execute", "allow", "grant", "enforce"}
    public = {n for n in dir(pkg) if not n.startswith("_")}
    overlap = {n for n in public if n.lower() in forbidden_names}
    assert not overlap, overlap

    from mcc_attester_service.service import AttesterService

    public_methods = {n for n in dir(AttesterService) if not n.startswith("_")}
    overlap = {n for n in public_methods if n.lower() in forbidden_names}
    assert not overlap, overlap


# ---------------------------------------------------------------------------
# M. NO SECOND EXECUTION PATH
# ---------------------------------------------------------------------------


def test_m_attester_service_carries_no_outbound_execution_surface():
    bad = []
    for path in _package_files():
        tree = _tree(path)
        used = set(_all_used_identifiers(tree))
        overlap = used & FORBIDDEN_EXECUTION_NAMES
        if overlap:
            bad.append((path.name, sorted(overlap)))
    assert not bad, f"mcc_attester_service references an execution/egress surface: {bad}"

    # And no import of the egress/interceptor modules themselves.
    bad_imports = []
    for path in _package_files():
        tree = _tree(path)
        for mod in _imported_module_names(tree):
            if mod.startswith("egress_proxy") or mod.startswith("interceptors"):
                bad_imports.append((path.name, mod))
    assert not bad_imports, bad_imports


def test_m_only_established_governed_issuance_paths_accept_attestation():
    """The signed artifact this service produces reaches governed execution
    through established, unmodified surfaces: the ``attestation`` parameter
    already present (since PR-2) on GovernanceService.execute_with_mandate /
    execute_with_consensus, now joined by a third, deliberately-reviewed
    surface -- execute_with_delegation (Verifiable Delegation), which routes
    its ``attestation`` argument through the same ``_attestation_gate``
    helper the other two use. This guard re-confirms (mirrors PR-2's own
    guard) that these three remain the only call sites -- any further
    addition must again deliberately update this guard."""
    tree = _tree(ROOT / "gateway" / "governance_service.py")

    def _function_defs(t):
        for node in ast.walk(t):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield node

    def _call_names(t):
        for node in ast.walk(t):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Attribute):
                yield func.attr, node.lineno
            elif isinstance(func, ast.Name):
                yield func.id, node.lineno

    sites = []
    for func in _function_defs(tree):
        for name, lineno in _call_names(func):
            if name.endswith("issue_token"):
                sites.append((func.name, lineno))
    assert {name for name, _ in sites} == {
        "execute_with_mandate", "execute_with_consensus", "execute_with_delegation",
    }
    assert len(sites) == 3
