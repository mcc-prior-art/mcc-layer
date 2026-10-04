"""Agent/operator credential separation (confirmed finding @ 8a62f7920a976e34a4ebbc33574bf47b89db9ddf).

Two kinds of coverage:

1. A REAL runtime reproduction (``test_runtime_*``) against the actual
   ``egress_proxy`` application, synthetic credentials, and a local loopback
   mock upstream (``tests/_egress_harness.py``, the repository's own existing
   harness -- never production credentials, never a real external call):
   agent action -> ESCALATE; approval with the agent's own key -> 403;
   approval with the real operator key -> 200; resubmission -> ALLOW,
   exactly one upstream invocation; an unapproved/never-approved resubmission
   produces zero upstream effects.

2. Structural regression tests (``test_compose_*``) over the fixed Docker
   Compose files, proving the EFFECTIVE merged environment a deployed agent
   container would receive -- not merely the absence of one YAML string --
   never contains a privileged (operator/signing/upstream-credential) value,
   using synthetic marker values standing in for real secrets. Each test is
   paired with a non-vacuity check that runs the identical assertion against
   the historical, confirmed-vulnerable file content at the finding's own
   commit (via ``git show``) and shows it WOULD have failed there -- proving
   the check actually detects the original bug, not just the fixed state.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

import pytest
import yaml

from tests._egress_harness import EgressHarness

ROOT = Path(__file__).resolve().parents[1]
CONFIRMED_FINDING_COMMIT = "8a62f7920a976e34a4ebbc33574bf47b89db9ddf"

# ---------------------------------------------------------------------------
# Part 1: real runtime reproduction
# ---------------------------------------------------------------------------


@pytest.fixture
def hz():
    return EgressHarness(require_consensus=False)


def test_runtime_agent_action_escalates_with_zero_upstream_effect(hz):
    url = hz.url("/charge")
    r = hz.post(method="POST", url=url, body={"amount": 10}, actor="agent/intern",
                transaction_id="sep-1", idempotency_key="sep-1")
    body = r.json()
    assert body["outcome"] == "ESCALATE" and not body["executed"]
    assert hz.seen == [] and hz.executor.count() == 0


def test_runtime_agent_cannot_approve_its_own_escalate(hz):
    """Reproduces finding step 2: approval attempted with only the agent's
    own key (simulating an agent that was handed, or guessed, the operator
    endpoint) is rejected -- 403, and crucially produces zero upstream
    effects, not merely a rejected HTTP response."""
    url = hz.url("/charge")
    r = hz.post(method="POST", url=url, body={"amount": 10}, actor="agent/intern",
                transaction_id="sep-2", idempotency_key="sep-2")
    rid = r.json()["approval_request_id"]

    bad = hz.client.post(f"/v1/approvals/{rid}/approve", headers={"x-operator-key": hz.H["x-api-key"]})
    assert bad.status_code == 403
    assert bad.json()["detail"] == "INVALID_OPERATOR_KEY"
    assert hz.seen == [] and hz.executor.count() == 0


def test_runtime_independent_operator_can_approve_and_it_executes_exactly_once(hz):
    """Reproduces finding steps 3-4: the REAL, independent operator key
    (never held by the agent in the fixed compose files) approves, and the
    resubmitted operation executes exactly once against the mock upstream."""
    url = hz.url("/charge")
    r = hz.post(method="POST", url=url, body={"amount": 10}, actor="agent/intern",
                transaction_id="sep-3", idempotency_key="sep-3")
    rid = r.json()["approval_request_id"]

    approved = hz.approve(rid)
    assert approved.status_code == 200
    assert approved.json()["approved"] is True
    assert hz.seen == [] and hz.executor.count() == 0, "approval alone must not execute anything"

    executed = hz.post(method="POST", url=url, body={"amount": 10}, actor="agent/intern",
                       transaction_id="sep-3", idempotency_key="sep-3", approval_id=rid).json()
    assert executed["outcome"] == "ALLOW" and executed["executed"] is True
    assert hz.executor.count() == 1
    assert hz.seen == [{"method": "POST", "path": "charge", "body": {"amount": 10}}]


def test_runtime_unapproved_resubmission_produces_zero_upstream_effects(hz):
    """A resubmission with no approval_id at all (the never-approved case)
    must never reach the upstream, regardless of how many times retried."""
    url = hz.url("/charge")
    r = hz.post(method="POST", url=url, body={"amount": 10}, actor="agent/intern",
                transaction_id="sep-4", idempotency_key="sep-4")
    assert r.json()["outcome"] == "ESCALATE"

    retry = hz.post(method="POST", url=url, body={"amount": 10}, actor="agent/intern",
                    transaction_id="sep-4", idempotency_key="sep-4")
    assert retry.json()["executed"] is False
    assert hz.seen == [] and hz.executor.count() == 0


def test_runtime_forged_approval_id_denied_with_zero_upstream_effects(hz):
    url = hz.url("/charge")
    hz.post(method="POST", url=url, body={"amount": 10}, actor="agent/intern",
            transaction_id="sep-5", idempotency_key="sep-5")
    forged = hz.post(method="POST", url=url, body={"amount": 10}, actor="agent/intern",
                     transaction_id="sep-5", idempotency_key="sep-5", approval_id="forged-request-id")
    assert forged.json()["executed"] is False
    assert hz.seen == [] and hz.executor.count() == 0


# ---------------------------------------------------------------------------
# Part 2: structural regression over the fixed Compose files
# ---------------------------------------------------------------------------

# Synthetic stand-ins for every variable named in deploy/pilot/.env.example /
# .env.pilot.example -- never a real secret. PRIVILEGED entries are the ones
# this finding is about; AGENT_SCOPED entries are what the agent legitimately
# needs and must still resolve correctly after the fix.
PRIVILEGED_MARKERS = {
    "MCC_GATEWAY_OPERATOR_API_KEY": "SYNTHETIC-PRIVILEGED-GATEWAY-OPERATOR-0001",
    "MCC_EGRESS_OPERATOR_API_KEY": "SYNTHETIC-PRIVILEGED-EGRESS-OPERATOR-0002",
    "MCC_EGRESS_CRED_EXAMPLE_API": "SYNTHETIC-PRIVILEGED-UPSTREAM-CRED-0003",
    "MCC_EGRESS_MTLS_KEY": "/secrets/SYNTHETIC-PRIVILEGED-MTLS-KEY-0004",
}
# The KEY NAMES that must never appear in an agent service's effective
# environment at all, regardless of whether the value arrived via env_file
# indirection, `${VAR}` interpolation, or a literal hardcoded string --
# catches every style this finding's variants actually used in this repo.
FORBIDDEN_KEY_NAMES = frozenset(PRIVILEGED_MARKERS)
AGENT_SCOPED = {
    "MCC_GATEWAY_API_KEY": "SYNTHETIC-AGENT-GATEWAY-KEY-1001",
    "MCC_EGRESS_API_KEY": "SYNTHETIC-AGENT-EGRESS-KEY-1002",
    "MCC_VOLTAGENT_ACTOR": "agent/notify-bot",
    "MCC_VOLTAGENT_RESOURCE": "crm",
    "MCC_VOLTAGENT_MODEL_PROVIDER": "deterministic",
    "MCC_VOLTAGENT_MODEL": "",
    "OPENAI_API_KEY": "",
    "MCC_PILOT_STATE_DIR": "/pilot-state",
    "MCC_GATEWAY_URL": "http://mcc-gateway:8001",
    "MCC_QUORUM_URL": "http://evaluator-quorum:8080",
}
SYNTHETIC_ENV: Dict[str, str] = {**PRIVILEGED_MARKERS, **AGENT_SCOPED}

_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(:?[-?])?([^}]*)\}")


def _interpolate(value: Any, env: Dict[str, str]) -> Any:
    if not isinstance(value, str):
        return value

    def _sub(m: "re.Match[str]") -> str:
        name, op, rest = m.group(1), m.group(2), m.group(3)
        if name in env and env[name] != "":
            return env[name]
        if op in ("-", ":-"):
            return rest
        if op in ("?", ":?"):
            # Required-but-missing: real `docker compose` would refuse to
            # start. Surface that distinctly rather than silently blanking.
            return "<<REQUIRED_VAR_MISSING>>"
        return env.get(name, "")

    return _VAR_RE.sub(_sub, value)


def _effective_service_env(compose_text: str, service_name: str, env: Dict[str, str]) -> Dict[str, str]:
    """Simulates docker compose's own merge: env_file contents (every line,
    unfiltered -- real compose semantics) merged with, then overridden by,
    the service's explicit `environment:` mapping, with `${...}` resolved
    against `env` (standing in for the shell / --env-file substitution
    source). Returns the resulting effective environment."""
    doc = yaml.safe_load(compose_text)
    service = doc["services"][service_name]

    effective: Dict[str, str] = {}
    if "env_file" in service:
        # A blanket env_file hands the container EVERY variable in the
        # referenced file -- simulate the worst case: all of SYNTHETIC_ENV
        # (the full documented .env/.env.pilot content) lands in the
        # container, exactly as real `env_file:` semantics would do if the
        # operator populated every documented variable.
        effective.update(env)

    explicit = service.get("environment") or {}
    if isinstance(explicit, list):
        explicit = dict(item.split("=", 1) for item in explicit if "=" in item)
    for key, raw in explicit.items():
        effective[key] = _interpolate(raw, env)

    return effective


def _historical_text(path: str) -> str:
    result = subprocess.run(
        ["git", "show", f"{CONFIRMED_FINDING_COMMIT}:{path}"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    return result.stdout


@pytest.mark.parametrize(
    "path,service",
    [
        ("deploy/pilot/docker-compose.yml", "reference-egress-agent"),
        ("docker-compose.voltagent.yml", "voltagent-agent"),
        ("docker-compose.pilot-voltagent.yml", "voltagent-agent"),
        ("docker-compose.pilot-clinic-voltagent.yml", "clinic-agent"),
    ],
)
class TestAgentCredentialSeparation:
    def test_fixed_effective_env_excludes_all_privileged_markers(self, path, service):
        current_text = (ROOT / path).read_text(encoding="utf-8")
        effective = _effective_service_env(current_text, service, SYNTHETIC_ENV)

        leaked_by_value = {k: v for k, v in effective.items() if v in PRIVILEGED_MARKERS.values()}
        assert leaked_by_value == {}, f"{path}::{service} still inherits privileged credentials: {leaked_by_value}"

        # Key-name check: catches a privileged var even when its value is a
        # literal hardcoded string rather than an interpolated/env_file one
        # (docker-compose.voltagent.yml's original bug was exactly this --
        # `MCC_GATEWAY_OPERATOR_API_KEY: "op-key"` typed directly into the
        # agent service's own `environment:` block, no indirection at all).
        leaked_by_key = FORBIDDEN_KEY_NAMES & effective.keys()
        assert leaked_by_key == set(), f"{path}::{service} still defines forbidden keys: {leaked_by_key}"

        also_check_no_env_file = yaml.safe_load(current_text)["services"][service]
        assert "env_file" not in also_check_no_env_file, (
            f"{path}::{service} must not use blanket env_file after the fix"
        )

    def test_fixed_effective_env_still_has_required_agent_credential(self, path, service):
        """Non-degenerate positive control: the fix must not have also
        deleted the credential the agent genuinely needs -- checked by key
        presence with a non-empty value (resolved or literal), not by
        matching a specific synthetic value, since some of these files
        interpolate from env and others hardcode a literal demo value."""
        current_text = (ROOT / path).read_text(encoding="utf-8")
        effective = _effective_service_env(current_text, service, SYNTHETIC_ENV)
        agent_keys_present = {
            k: v for k, v in effective.items()
            if k in ("MCC_GATEWAY_API_KEY", "MCC_EGRESS_API_KEY")
            and v not in ("", "<<REQUIRED_VAR_MISSING>>")
        }
        assert agent_keys_present, f"{path}::{service} lost its own required agent credential"

    def test_non_vacuity_historical_vulnerable_config_leaked_the_marker(self, path, service):
        """Proves this check actually detects the original bug: run the
        IDENTICAL assertion against the file content at the confirmed
        finding's own commit and show a privileged key WAS present in the
        effective environment there (by value where the file used
        indirection, by key name where it hardcoded the value directly)."""
        historical_text = _historical_text(path)
        effective = _effective_service_env(historical_text, service, SYNTHETIC_ENV)
        leaked_by_value = {k: v for k, v in effective.items() if v in PRIVILEGED_MARKERS.values()}
        leaked_by_key = FORBIDDEN_KEY_NAMES & effective.keys()
        assert leaked_by_value or leaked_by_key, (
            f"non-vacuity failure: the historical {path}::{service} at "
            f"{CONFIRMED_FINDING_COMMIT} was expected to leak a privileged "
            f"credential (confirming this check would have caught the "
            f"original bug) but did not -- the check itself may be broken"
        )
