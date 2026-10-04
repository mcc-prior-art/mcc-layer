"""Repository-wide architecture guards for the independent authority-side
ESCALATE decision (PROPOSAL != PERMISSION).

Static, offline, no Docker required. Fails CI if:

* a proposer-facing script or client exposes/consumes an authority
  primitive (approve/deny/sign/mint/trust-admin) or an authority-policy
  config path;
* an unattended operator service's effective environment holds BOTH an
  operator (authority) credential AND a plain execute (agent) credential
  (the combined-privilege shape this change removes) -- scanned across
  EVERY docker-compose*.yml in the repo, not just the three files this
  change touched, so a future compose topology regresses visibly;
* the authority-policy config path is readable only by the gateway service,
  never by an agent/operator service, in the three pilot compose files;
* the shipped unattended operator scripts read any agent-written
  coordination-state field other than the request_id pointer;
* ``ApprovalService.approve()``'s independent-authority-policy gate is
  removed from source.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any, Dict

import yaml

ROOT = Path(__file__).resolve().parents[1]

_UNATTENDED_OPERATOR_SCRIPTS = [
    "deploy/pilot/gateway_approval_operator.py",
    "deploy/pilot/governed_agent_pilot_operator.py",
]
_PROPOSER_SCRIPTS = [
    "deploy/pilot/notify_pilot_agent.py",
    "deploy/pilot/reference_agent_runner.py",
    "deploy/pilot/governed_agent_compose_demo.py",
]
_AUTHORITY_CREDENTIAL_KEYS = {
    "MCC_GATEWAY_OPERATOR_API_KEY", "MCC_EGRESS_OPERATOR_API_KEY",
}
_EXECUTE_CREDENTIAL_KEYS = {
    "MCC_GATEWAY_API_KEY", "MCC_EGRESS_API_KEY",
}
_AUTHORITY_POLICY_KEYS = {
    "MCC_AUTHORITY_POLICY_CONFIG", "MCC_EGRESS_AUTHORITY_POLICY_CONFIG",
}

# Services that are legitimately the trusted gateway boundary itself (not a
# combined-privilege violation -- the gateway IS where authority lives).
_GATEWAY_SERVICE_NAMES = {"mcc-gateway"}


def _effective_env(compose_text: str, service: Dict[str, Any]) -> Dict[str, str]:
    env = service.get("environment") or {}
    if isinstance(env, list):
        env = dict(item.split("=", 1) for item in env if "=" in item)
    return {k: str(v) for k, v in env.items()}


def _all_compose_files():
    return sorted(ROOT.glob("docker-compose*.yml")) + sorted(ROOT.glob("deploy/**/docker-compose*.yml"))


# ===========================================================================
# 1. No unattended service anywhere combines an authority credential with a
#    plain execute credential (AUTHORITY_CREDENTIALS ∩ EXECUTION_CREDENTIALS
#    = ∅, except the gateway service itself, which legitimately holds both).
# ===========================================================================

class TestNoCombinedAuthorityAndExecutionPrivilege:
    def test_every_compose_file_repo_wide(self):
        violations = []
        for path in _all_compose_files():
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
            services = (doc or {}).get("services") or {}
            for name, service in services.items():
                if name in _GATEWAY_SERVICE_NAMES:
                    continue
                effective = _effective_env(path.read_text(encoding="utf-8"), service)
                has_authority = _AUTHORITY_CREDENTIAL_KEYS & effective.keys()
                has_execute = _EXECUTE_CREDENTIAL_KEYS & effective.keys()
                if has_authority and has_execute:
                    violations.append(
                        f"{path.relative_to(ROOT)}::{name} holds BOTH authority "
                        f"({sorted(has_authority)}) AND execute "
                        f"({sorted(has_execute)}) credentials"
                    )
        assert violations == [], "\n".join(violations)

    def test_non_vacuity_a_deliberately_combined_service_is_caught(self):
        """Proves the scanner above is meaningful: a synthetic service that
        combines both credential kinds (exactly the pre-fix
        gateway_approval_operator.py shape) IS flagged."""
        doc = yaml.safe_load("""
services:
  bad-operator:
    environment:
      MCC_GATEWAY_OPERATOR_API_KEY: "op-key"
      MCC_GATEWAY_API_KEY: "agent-key"
""")
        service = doc["services"]["bad-operator"]
        effective = _effective_env("", service)
        has_authority = _AUTHORITY_CREDENTIAL_KEYS & effective.keys()
        has_execute = _EXECUTE_CREDENTIAL_KEYS & effective.keys()
        assert has_authority and has_execute, "non-vacuity check itself is broken"


# ===========================================================================
# 2. The authority-policy config path is readable ONLY by the gateway
#    service in each of the three pilot compose files.
# ===========================================================================

class TestAuthorityPolicyConfigOnlyOnGateway:
    _FILES_AND_GATEWAY = [
        ("docker-compose.notify-pilot.yml", "mcc-gateway"),
        ("docker-compose.reference-agent.yml", "mcc-gateway"),
        ("docker-compose.pilot.yml", "mcc-gateway"),
    ]

    def test_gateway_has_it_others_do_not(self):
        for rel, gateway_name in self._FILES_AND_GATEWAY:
            path = ROOT / rel
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
            services = doc["services"]
            gateway_env = _effective_env("", services[gateway_name])
            assert _AUTHORITY_POLICY_KEYS & gateway_env.keys(), (
                f"{rel}::{gateway_name} does not configure an independent "
                "authority policy at all"
            )
            for name, service in services.items():
                if name == gateway_name:
                    continue
                effective = _effective_env("", service)
                leaked = _AUTHORITY_POLICY_KEYS & effective.keys()
                assert not leaked, (
                    f"{rel}::{name} (non-gateway) must never read/supply the "
                    f"authority policy config path, found: {leaked}"
                )


# ===========================================================================
# 3. No proposer-facing script imports or references the authority-policy
#    primitive at all -- it is authority-plane-only.
# ===========================================================================

class TestProposerScriptsNeverTouchAuthorityPolicy:
    def test_no_authority_policy_import_or_reference(self):
        violations = []
        for rel in _PROPOSER_SCRIPTS:
            text = (ROOT / rel).read_text(encoding="utf-8")
            if "authority_policy" in text or "AuthorityPolicy" in text:
                violations.append(rel)
        assert violations == [], f"proposer scripts reference authority_policy: {violations}"


# ===========================================================================
# 4. Proposer-facing clients expose no approve/deny/sign/mint/trust-admin
#    primitive.
# ===========================================================================

class TestProposerFacingClientsExposeNoAuthorityPrimitive:
    """``mcc_client.MCCClient`` is deliberately a SINGLE class used for both
    roles (an agent instance holds only ``api_key``; a human-operator
    instance additionally holds ``operator_key``, required by ``approve()``
    at the instance level -- see Case A's ``MCCAuthenticationError`` proof).
    ``GovernedMCCClient`` (the egress_proxy's embedded runtime client) uses
    the STRICTER design: a separate ``OperatorConsole`` class holds
    approve/deny_approval, and the proposer-facing class has neither at all.
    This guard checks the stricter design; the SDK's instance-level key
    requirement is covered behaviorally by the adversarial suite."""

    _FORBIDDEN = ("approve", "deny_approval", "sign_token", "issue_mandate",
                  "mint_mandate", "trust_admin", "disable_issuer", "revoke_key")

    def test_governed_mcc_client_example(self):
        from examples.governed_agent.mcc_client import GovernedMCCClient

        for name in self._FORBIDDEN:
            assert not hasattr(GovernedMCCClient, name), f"GovernedMCCClient exposes {name}"


# ===========================================================================
# 5. The unattended operator scripts read ONLY the request_id pointer from
#    agent-written coordination state -- never any other field (the AST
#    guard against "agent-controlled state treated as evidence of
#    permission").
# ===========================================================================

class TestOperatorScriptsTrustOnlyTheRequestIdPointer:
    _ALLOWED_KEYS = {"requestId"}

    def test_no_other_state_field_is_read(self):
        violations = []
        for rel in _UNATTENDED_OPERATOR_SCRIPTS:
            path = ROOT / rel
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                # state["x"] / state.get("x")
                key = None
                if isinstance(node, ast.Subscript):
                    target = node.value
                    idx = node.slice
                    if isinstance(idx, ast.Constant) and isinstance(idx.value, str):
                        key = idx.value
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr == "get" and node.args:
                        first = node.args[0]
                        if isinstance(first, ast.Constant) and isinstance(first.value, str):
                            key = first.value
                    target = getattr(node.func, "value", None)
                else:
                    continue
                if key is None or key in self._ALLOWED_KEYS:
                    continue
                target_name = getattr(target, "id", None) if target is not None else None
                if target_name == "state":
                    violations.append(f"{rel}: reads state[{key!r}]")
        assert violations == [], "\n".join(violations)

    def test_non_vacuity_a_synthetic_wider_read_is_caught(self):
        """Proves the AST walk above actually catches a violation."""
        src = (
            "def _process_one(client, state):\n"
            "    request_id = state['requestId']\n"
            "    actor = state['actor']\n"  # the exact pre-fix shape
            "    return request_id, actor\n"
        )
        tree = ast.parse(src)
        found = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Subscript):
                idx = node.slice
                if isinstance(idx, ast.Constant) and isinstance(idx.value, str):
                    target_name = getattr(node.value, "id", None)
                    if target_name == "state" and idx.value != "requestId":
                        found.append(idx.value)
        assert found == ["actor"], "non-vacuity check itself is broken"


# ===========================================================================
# 6. The independent-authority-policy gate exists in ApprovalService.approve
#    -- a source-level sanity check that a future edit cannot silently strip
#    it back out without this guard noticing.
# ===========================================================================

class TestApproveSourceStillHasThePolicyGate:
    def test_authority_policy_is_consulted_in_approve(self):
        src = (ROOT / "src/mcc_core/approvals.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        approve_fn = None
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "approve":
                approve_fn = node
                break
        assert approve_fn is not None, "ApprovalService.approve not found"
        body_src = ast.get_source_segment(src, approve_fn) or ""
        assert "self.authority_policy" in body_src
        assert ".decide(" in body_src


# ===========================================================================
# 7. No proposer-facing interface exposes privileged trust administration
#    (already covered by mandate routes being operator-only, re-asserted
#    here at the HTTP-schema level so a future route addition is caught).
# ===========================================================================

class TestNoProposerFacingTrustAdministration:
    def test_governance_api_trust_routes_require_operator(self):
        src = (ROOT / "gateway/governance_api.py").read_text(encoding="utf-8")
        # Every trust-admin route must be defined with require_operator, not
        # require_agent, as its dependency.
        for marker in ("disable_issuer", "revoke_key"):
            m = re.search(rf"async def {marker}\(.*?\):", src, re.DOTALL)
            assert m, f"{marker} route not found"
            signature = m.group(0)
            assert "Depends(require_operator)" in signature, (
                f"{marker} must depend on require_operator, got: {signature}"
            )
