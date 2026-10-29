"""Deployment-configuration completeness guard (fresh, independent check —
not re-asserting any prior report): every pilot Compose file that stands up
an operator-credentialed ESCALATE-approval sidecar must also wire an
independent ``MCC_AUTHORITY_POLICY_CONFIG`` on its gateway service.

``src/mcc_core/approvals.py``'s ``ApprovalService.approve()`` only requires
its own independently-configured ``AuthorityPolicy`` ALLOW when one is
actually supplied (``authority_policy=None`` is the deliberate, correct
setting for a genuinely ATTENDED human-approval deployment — see that
module's own docstring). The gap this guard closes is deployment
configuration, not application logic: a pilot whose "operator" step is a
single non-interactive command (``make pilot-approve`` /
``make clinic-pilot-approve``, both running ``operator_cli.py``, which
calls ``/approve`` with no confirmation prompt and no per-request content
review) is, in substance, an UNATTENDED approval path. Per
``gateway/governance_api.py``'s own ``build_governance_service`` comment,
an unattended deployment is exactly the case ``MCC_AUTHORITY_POLICY_CONFIG``
exists to gate — without it, any holder of the operator key can approve
(and the paired agent can then execute) ANY pending ESCALATE regardless of
its content, reproducing the pre-PR#119 "an authenticated operator key
alone is sufficient" gap for that specific deployment, independent of
whether the underlying ApprovalService code is itself correct.

This test does not demonstrate an exploit (no server is started, nothing is
approved or executed) — it is a static, non-sensitive presence check over
already-public, already-committed Compose YAML, in the same spirit as
``tests/test_mcc_agent_no_direct_egress.py``'s import-boundary guard.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]

# Compose files that stand up a non-interactive, scripted ESCALATE-approval
# path (an operator-keyed sidecar service, OR a Makefile target that runs
# the shared, non-interactive operator_cli.py / gateway_approval_operator.py
# against this file's gateway) are "unattended" for this guard's purposes.
_COMPOSE_FILES_WITH_SCRIPTED_OPERATOR_STEP = [
    "docker-compose.notify-pilot.yml",
    "docker-compose.reference-agent.yml",
    "docker-compose.voltagent.yml",
    "docker-compose.pilot-voltagent.yml",
    "docker-compose.pilot-clinic-voltagent.yml",
]


def _load_compose(name: str) -> dict:
    path = ROOT / name
    if not path.exists():
        pytest.skip(f"{name} not present in this checkout")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _gateway_like_services(compose: dict) -> dict:
    services = compose.get("services") or {}
    return {
        name: svc for name, svc in services.items()
        if "gateway" in name and isinstance(svc, dict)
    }


def _env_of(service: dict) -> dict:
    env = service.get("environment")
    if env is None:
        return {}
    if isinstance(env, dict):
        return env
    # list form: ["KEY=value", ...]
    out = {}
    for item in env:
        if isinstance(item, str) and "=" in item:
            k, _, v = item.partition("=")
            out[k] = v
    return out


@pytest.mark.parametrize("compose_file", _COMPOSE_FILES_WITH_SCRIPTED_OPERATOR_STEP)
def test_scripted_operator_deployments_configure_an_authority_policy(compose_file):
    """Every Compose file that gives SOMETHING a way to call
    ``/approve`` non-interactively (an operator-keyed sidecar service, or —
    per this file's own Makefile targets — a scripted `docker compose exec`
    into the gateway itself) must also set MCC_AUTHORITY_POLICY_CONFIG on
    its gateway service(s). A missing policy there is not fail-closed
    application behavior being bypassed; it is the independent-authority
    check never being turned on for that deployment in the first place."""
    compose = _load_compose(compose_file)
    gateways = _gateway_like_services(compose)
    assert gateways, f"{compose_file}: expected at least one *gateway* service"

    unconfigured = [
        name for name, svc in gateways.items()
        if "MCC_AUTHORITY_POLICY_CONFIG" not in _env_of(svc)
    ]
    assert not unconfigured, (
        f"{compose_file}: gateway service(s) {unconfigured} accept operator-"
        "key-authenticated ESCALATE approval (this file ships a non-"
        "interactive operator path: an operator-keyed sidecar service, or a "
        "Makefile target that scripts operator_cli.py against this "
        "gateway) but never configure MCC_AUTHORITY_POLICY_CONFIG. "
        "Approving an ESCALATE in this deployment currently requires only "
        "the operator key, with no independent content check -- see "
        "src/mcc_core/approvals.py's ApprovalService.approve() and "
        "gateway/governance_api.py's build_governance_service(). This is a "
        "deployment-configuration gap, not an application-code defect: add "
        "MCC_AUTHORITY_POLICY_CONFIG (and the corresponding policy file) to "
        "this gateway service, mirroring docker-compose.notify-pilot.yml / "
        "docker-compose.reference-agent.yml."
    )
