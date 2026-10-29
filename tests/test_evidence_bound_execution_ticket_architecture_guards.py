"""Static architecture guards for PR-3 (Evidence-Bound Execution Ticket,
MCC-AT-003).

Proves, by AST inspection (not just convention/review), the seven structural
invariants the task specification requires:

1. Both governed token-issuance paths (``execute_with_mandate`` and
   ``execute_with_consensus`` in ``gateway/governance_service.py``) propagate
   the Control-derived ``evidence_digest`` into ``DecisionEngine.issue_token``.
2. The governed execution path propagates the exact evidence artifact down to
   ``ExecutionGate``: ``governance_service.py``'s ``_run`` passes
   ``evidence=`` into ``coordinator.enforce``, and ``coordinator.py``'s
   ``enforce`` passes ``evidence=`` into ``gate.verify``.
3. Inside ``ExecutionGate._verify``, the evidence-binding check occurs before
   nonce consumption, in source order -- so a missing/wrong/malformed
   evidence artifact can never burn the token's one-time nonce.
4. No governed-runtime code outside ``gateway/governance_service.py`` calls
   ``DecisionEngine.issue_token`` -- there is no second, evidence-blind
   issuance route.
5. ``ExecutionGate`` (``src/mcc_core/gate.py``) never imports or invokes
   ``mcc_attestation`` or any semantic verification/trust-store/claim-policy
   surface -- it performs only a deterministic canonical-document hash
   comparison; PR-2's ``PreExecutionControl`` owns semantic verification.
6. The ``evidence`` / ``evidence_digest`` keyword arguments used for PR-3's
   binding appear ONLY at the established call sites (governance_service.py,
   coordinator.py, gate.py, pre_execution_control.py) -- no second actuation
   path was introduced elsewhere in the governed runtime or transport layer.
7. The HTTP execute schemas carry no caller-supplied ``evidence_digest``
   field, and the governed runtime methods that accept an evidence artifact
   accept only the raw ``attestation`` document -- never a pre-computed
   digest a caller could substitute for Control's own derivation.

Mirrors the AST-guard style established in
``tests/test_mcc_attestation_architecture_guards.py`` and
``tests/test_pre_execution_control_architecture_guards.py``.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GOVERNANCE_API = ROOT / "gateway" / "governance_api.py"
GOVERNANCE_SERVICE = ROOT / "gateway" / "governance_service.py"
PRE_EXECUTION_CONTROL = ROOT / "gateway" / "pre_execution_control.py"
COORDINATOR = ROOT / "src" / "mcc_core" / "coordinator.py"
GATE = ROOT / "src" / "mcc_core" / "gate.py"
CORE = ROOT / "src" / "mcc_core" / "core.py"

# Files where genuine PR-3 evidence-binding keyword arguments are expected.
# Any other file using ``evidence=`` / ``evidence_digest=`` as a *keyword
# argument name* would indicate a second, undocumented actuation path.
KNOWN_EVIDENCE_SITES = {GOVERNANCE_SERVICE, COORDINATOR, GATE, PRE_EXECUTION_CONTROL}

# Every module the governed runtime and transport layer are made of, scanned
# for guard #6 (excluding tests, docs, examples, and unrelated subsystems
# such as mcc_compliance/mcc_evidence, which define their own, unrelated
# "evidence_digest" concept for the Certified Adapter Program).
SCANNED_DIRS = [
    ROOT / "gateway",
    ROOT / "src" / "mcc_core",
    ROOT / "interceptors",
    ROOT / "egress_proxy",
]
SCANNED_FILES = [ROOT / "main.py"]


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
    """Yield ``(qualified_name, lineno, call_node)`` for every call
    expression, where ``qualified_name`` is the dotted attribute chain for
    ``a.b.c(...)`` calls or the bare name for ``f(...)`` calls."""
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
            yield ".".join(reversed(parts)), node.lineno, node
        elif isinstance(func, ast.Name):
            yield func.id, node.lineno, node


def _function_defs(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def test_files_exist():
    for path in (GOVERNANCE_API, GOVERNANCE_SERVICE, PRE_EXECUTION_CONTROL,
                 COORDINATOR, GATE, CORE):
        assert path.is_file(), path


# ---------------------------------------------------------------------------
# Guard 1: both issue_token call sites propagate evidence_digest.
# ---------------------------------------------------------------------------


def test_both_issuance_paths_pass_evidence_digest_to_issue_token():
    tree = _tree(GOVERNANCE_SERVICE)
    checked = set()
    for func in _function_defs(tree):
        if func.name not in ("execute_with_mandate", "execute_with_consensus", "execute_with_delegation"):
            continue
        for name, lineno, call in _call_names(func):
            if not name.endswith(".issue_token"):
                continue
            checked.add(func.name)
            kwnames = {kw.arg for kw in call.keywords}
            assert "evidence_digest" in kwnames, (
                f"{func.name}'s call to issue_token (line {lineno}) does not "
                f"pass evidence_digest= -- the Control-derived digest would "
                f"never reach the token"
            )
    assert checked == {"execute_with_mandate", "execute_with_consensus", "execute_with_delegation"}, (
        f"expected all governed issuance paths to call issue_token, found: {checked}"
    )


# ---------------------------------------------------------------------------
# Guard 2: the exact evidence artifact is propagated to the Gate.
# ---------------------------------------------------------------------------


def test_run_passes_evidence_to_coordinator_enforce():
    tree = _tree(GOVERNANCE_SERVICE)
    for func in _function_defs(tree):
        if func.name != "_run":
            continue
        for name, lineno, call in _call_names(func):
            if name.endswith(".enforce"):
                kwnames = {kw.arg for kw in call.keywords}
                assert "evidence" in kwnames, (
                    f"_run's call to coordinator.enforce (line {lineno}) does "
                    f"not pass evidence= -- ExecutionGate could never see the "
                    f"evidence artifact"
                )
                return
        pytest.fail("_run does not call coordinator.enforce")
    pytest.fail("_run not found in gateway/governance_service.py")


def test_coordinator_enforce_passes_evidence_to_gate_verify():
    tree = _tree(COORDINATOR)
    for func in _function_defs(tree):
        if func.name != "enforce":
            continue
        for name, lineno, call in _call_names(func):
            if name.endswith(".verify"):
                kwnames = {kw.arg for kw in call.keywords}
                assert "evidence" in kwnames, (
                    f"coordinator.enforce's call to gate.verify (line {lineno}) "
                    f"does not pass evidence= -- ExecutionGate would never see "
                    f"the evidence artifact"
                )
                return
        pytest.fail("enforce does not call gate.verify")
    pytest.fail("enforce not found in src/mcc_core/coordinator.py")


# ---------------------------------------------------------------------------
# Guard 3: evidence binding is checked before nonce consumption.
# ---------------------------------------------------------------------------


def test_gate_checks_evidence_before_consuming_nonce():
    tree = _tree(GATE)
    for func in _function_defs(tree):
        if func.name != "_verify":
            continue
        evidence_line = None
        nonce_consume_line = None
        for node in ast.walk(func):
            if isinstance(node, ast.Attribute) and node.attr == "get":
                # token.get("evidence_digest")
                if (isinstance(node.value, ast.Name) and node.value.id == "token"):
                    parent_call = node
                    # find the enclosing Call to inspect its single arg
                    for call_node in ast.walk(func):
                        if (isinstance(call_node, ast.Call)
                                and call_node.func is node
                                and call_node.args
                                and isinstance(call_node.args[0], ast.Constant)
                                and call_node.args[0].value == "evidence_digest"):
                            evidence_line = min(
                                evidence_line or call_node.lineno, call_node.lineno
                            )
            if isinstance(node, ast.Call):
                name = getattr(node.func, "attr", getattr(node.func, "id", None))
                if name == "consume":
                    nonce_consume_line = node.lineno
        assert evidence_line is not None, (
            "could not locate token.get('evidence_digest') in ExecutionGate._verify"
        )
        assert nonce_consume_line is not None, (
            "could not locate the nonce_registry.consume(...) call in "
            "ExecutionGate._verify"
        )
        assert evidence_line < nonce_consume_line, (
            f"evidence binding (line {evidence_line}) must precede nonce "
            f"consumption (line {nonce_consume_line}) so a bad evidence "
            f"artifact never burns the token's nonce"
        )
        return
    pytest.fail("_verify not found in src/mcc_core/gate.py")


# ---------------------------------------------------------------------------
# Guard 4: no issuance route outside governance_service.py.
# ---------------------------------------------------------------------------


def test_no_new_issue_token_call_site_outside_governance_service():
    """No file introduced or touched by PR-3 gains a new, evidence-blind
    ``issue_token`` call site.

    ``main.py`` (a standalone pre-PR-2 demo runtime with its own
    ``DecisionEngine``/``EnforcementCoordinator`` instances) and
    ``gateway/app.py`` (the ``/evaluate`` observe/inline HTTP route, which
    never routes through ``GovernanceService``) already call ``issue_token``
    directly -- this pre-dates PR-2's attestation-gate integration entirely
    (PR-2's own architecture guard scoped its "exactly two call sites" check
    to ``governance_service.py`` alone, not repo-wide, for the same reason).
    Neither file is modified by PR-2 or PR-3, and neither is part of the
    Control-gated governed execution path this PR extends. They are pinned
    here as a known, pre-existing exception -- not silently ignored -- so
    that a genuinely NEW bypass call site anywhere else is still caught."""
    known_pre_existing_exceptions = {ROOT / "main.py", ROOT / "gateway" / "app.py"}
    other_files = [
        ROOT / "main.py",
        ROOT / "gateway" / "app.py",
        ROOT / "gateway" / "governance_api.py",
        ROOT / "interceptors" / "egress_proxy.py",
        ROOT / "egress_proxy" / "executor.py",
        ROOT / "egress_proxy" / "app.py",
    ]
    bad = []
    for path in other_files:
        if not path.is_file() or path in known_pre_existing_exceptions:
            continue
        tree = _tree(path)
        for name, lineno, _ in _call_names(tree):
            if name == "issue_token" or name.endswith(".issue_token"):
                bad.append((str(path.relative_to(ROOT)), lineno))
    assert not bad, (
        f"issue_token called outside gateway/governance_service.py at a new, "
        f"unreviewed site: {bad}"
    )
    # The pinned exceptions must still exist and still be untouched by this
    # PR's diff -- if either gains attestation/evidence plumbing later, that
    # is a deliberate, separate change, not something to silently absorb here.
    for path in known_pre_existing_exceptions:
        assert path.is_file()


def test_governance_service_still_has_exactly_three_issue_token_call_sites():
    """Pins the known issuance surface: a new call site, if ever added, must
    deliberately update this guard, not silently bypass evidence-digest
    propagation (guard #1 above). Verifiable Delegation added
    ``execute_with_delegation`` as a third, deliberate, reviewed call site
    (it propagates evidence_digest exactly like the other two -- see
    gateway/governance_service.py)."""
    tree = _tree(GOVERNANCE_SERVICE)
    sites = []
    for func in _function_defs(tree):
        for name, lineno, _ in _call_names(func):
            if name.endswith(".issue_token"):
                sites.append((func.name, lineno))
    assert {name for name, _ in sites} == {
        "execute_with_mandate", "execute_with_consensus", "execute_with_delegation",
    }
    assert len(sites) == 3


# ---------------------------------------------------------------------------
# Guard 5: ExecutionGate carries no semantic attestation/verification logic.
# ---------------------------------------------------------------------------


def test_gate_does_not_import_mcc_attestation():
    tree = _tree(GATE)
    bad = [mod for mod in _imported_module_names(tree)
           if mod == "mcc_attestation" or mod.startswith("mcc_attestation.")]
    assert not bad, f"src/mcc_core/gate.py imports mcc_attestation: {bad}"


def test_gate_does_not_import_pre_execution_control():
    tree = _tree(GATE)
    bad = [mod for mod in _imported_module_names(tree)
           if "pre_execution_control" in mod]
    assert not bad, f"src/mcc_core/gate.py imports pre_execution_control: {bad}"


def test_gate_source_references_no_semantic_verification_names():
    """The Gate's *code* (identifiers actually used -- names, attributes,
    calls; comments/docstrings are prose, not logic, and may legitimately
    explain the boundary in words) must never reference attester/trust-store/
    claim-policy identifiers -- only a generic document-hash comparison
    (``hash_document``) and the pre-existing token primitives."""
    tree = _tree(GATE)
    forbidden = {
        "verify_attestation", "AttestationVerifier", "TrustStore",
        "AttestationRequirement", "AttesterTrustStore", "claim_policy",
        "risk_class",
    }
    used_identifiers = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used_identifiers.add(node.id)
        elif isinstance(node, ast.Attribute):
            used_identifiers.add(node.attr)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                used_identifiers.add((alias.asname or alias.name).split(".")[-1])
    bad = used_identifiers & forbidden
    assert not bad, f"src/mcc_core/gate.py's code references semantic attestation logic: {bad}"


# ---------------------------------------------------------------------------
# Guard 6: no second actuation path -- evidence keywords appear only at the
# established call sites.
# ---------------------------------------------------------------------------


def _iter_scanned_files():
    for d in SCANNED_DIRS:
        if d.is_dir():
            yield from sorted(d.glob("*.py"))
    yield from SCANNED_FILES


def test_evidence_keyword_arguments_appear_only_at_known_sites():
    offenders = set()
    for path in _iter_scanned_files():
        if not path.is_file():
            continue
        tree = _tree(path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            kwnames = {kw.arg for kw in node.keywords}
            if "evidence" in kwnames or "evidence_digest" in kwnames:
                offenders.add(path)
    assert offenders <= KNOWN_EVIDENCE_SITES, (
        f"evidence-binding keyword arguments found outside the established "
        f"call sites: {sorted(str(p.relative_to(ROOT)) for p in offenders - KNOWN_EVIDENCE_SITES)}"
    )
    # Sanity: the known sites really do use it (guard would pass vacuously
    # if the whole feature were silently deleted from one of them).
    assert offenders == KNOWN_EVIDENCE_SITES, (
        f"expected evidence-binding keyword arguments in exactly "
        f"{sorted(str(p.relative_to(ROOT)) for p in KNOWN_EVIDENCE_SITES)}, "
        f"found {sorted(str(p.relative_to(ROOT)) for p in offenders)}"
    )


# ---------------------------------------------------------------------------
# Guard 7: caller-supplied evidence_digest cannot bypass Control.
# ---------------------------------------------------------------------------


def test_execute_request_schemas_carry_no_caller_supplied_evidence_digest():
    import gateway.governance_api as api

    forbidden_fields = {"evidence_digest", "verified_evidence_digest", "attestation_verified"}
    for cls_name in (
        "MandateExecuteRequest", "ApprovalExecuteRequest", "ConsensusExecuteRequest",
    ):
        cls = getattr(api, cls_name)
        fields = set(cls.model_fields.keys())
        overlap = fields & forbidden_fields
        assert not overlap, f"{cls_name} carries a caller-supplied evidence digest: {overlap}"


def test_governance_service_public_methods_accept_only_raw_attestation():
    """execute_with_mandate / execute_with_consensus must accept only the raw
    ``attestation`` document from a caller -- never a pre-computed
    ``evidence_digest`` a caller could substitute for Control's own trusted
    derivation. ``evidence_digest`` may appear only as an internal local
    variable / issue_token keyword, never as a parameter name of a public
    entry point."""
    import inspect

    from gateway.governance_service import GovernanceService

    for name in ("execute_with_mandate", "execute_with_consensus"):
        method = getattr(GovernanceService, name)
        params = set(inspect.signature(method).parameters)
        assert "attestation" in params, f"{name} lost its attestation parameter"
        assert "evidence_digest" not in params, (
            f"{name} accepts a caller-supplied evidence_digest parameter -- "
            f"this would let a caller bypass Control's own derivation"
        )


def test_decision_engine_issue_token_evidence_digest_is_not_reachable_from_auth_claims():
    """evidence_digest must be a first-class claim baked in only by
    DecisionEngine itself from its own keyword argument -- never smuggled in
    via the caller-controlled ``auth_claims`` dict, which would let a caller
    forge an evidence binding without Control ever verifying anything."""
    tree = _tree(CORE)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "issue_token":
            source = ast.get_source_segment(CORE.read_text(), node) or ""
            assert 'auth_claims["evidence_digest"]' not in source
            assert "auth_claims.get(\"evidence_digest\")" not in source
            assert "auth_claims.pop(\"evidence_digest\")" not in source
            return
    pytest.fail("issue_token not found in src/mcc_core/core.py")
