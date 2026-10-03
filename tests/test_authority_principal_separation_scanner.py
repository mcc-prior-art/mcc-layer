"""Repository-wide architecture guard: ROLE_AGENT services must never hold
ROLE_AUTHORITY_SECRET credentials, across every Docker Compose file in the
repository -- not just the ones a specific finding named.

This generalizes ``tests/test_agent_operator_credential_separation.py``'s
per-file checks into a scanner so that a *new* compose file, or a *new*
service added to an existing one, is caught automatically if it reintroduces
the pattern -- it does not need this test file to be updated to know about
it. The only way a ROLE_AGENT service may legitimately hold a
ROLE_AUTHORITY_SECRET is an entry in ``KNOWN_COMBINED_ROLE_EXCEPTIONS``
below, each with a reviewable reason -- removing or narrowing an exception
needs no change here; *adding* one is a visible, deliberate diff.

Role classification is intentionally not a single-variable grep: a service
is classified ROLE_AGENT by name heuristic (contains "agent", case
insensitive) and then its EFFECTIVE merged environment (env_file content +
explicit `environment:`, with `${...}` interpolation resolved) is checked
against the authority-secret key list -- the same effective-environment
machinery ``test_agent_operator_credential_separation.py`` already
validates against the historical, confirmed-vulnerable commit.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Tuple

import pytest
import yaml

from tests.test_agent_operator_credential_separation import (
    FORBIDDEN_KEY_NAMES,
    SYNTHETIC_ENV,
    _effective_service_env,
)

ROOT = Path(__file__).resolve().parents[1]

# Every documented, reviewed exception to "ROLE_AGENT holds no
# ROLE_AUTHORITY_SECRET" in this repository, as of this scan. Each entry is a
# conscious design choice (a single-process demo simulating the full
# ESCALATE->approval lifecycle without a second terminal), not an oversight
# -- and each is marked in its own compose file with a matching comment (see
# the "KNOWN, OUT-OF-SCOPE RELATED FINDING" comments in those three files).
KNOWN_COMBINED_ROLE_EXCEPTIONS: Dict[Tuple[str, str], str] = {
    ("docker-compose.pilot.yml", "mcc-agent"): (
        "governed_agent_compose_demo.py actively self-approves via "
        "MCC_EGRESS_OPERATOR_API_KEY by design, for a no-second-terminal demo"
    ),
    ("docker-compose.notify-pilot.yml", "pilot-agent"): (
        "notify_pilot_agent.py actively self-approves via "
        "MCC_GATEWAY_OPERATOR_API_KEY by design, for a no-second-terminal demo"
    ),
    ("docker-compose.reference-agent.yml", "reference-agent"): (
        "reference_agent_runner.py actively self-approves via "
        "MCC_GATEWAY_OPERATOR_API_KEY by design, for a no-second-terminal demo"
    ),
}


def _discover_compose_files():
    seen = set()
    for pattern in ("docker-compose*.yml", "docker-compose*.yaml"):
        for path in ROOT.glob(pattern):
            seen.add(path)
        for path in (ROOT / "deploy").rglob(pattern):
            seen.add(path)
    return sorted(seen)


def _agent_services(compose_path: Path):
    doc = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    services = (doc or {}).get("services") or {}
    for name in services:
        if "agent" in name.lower():
            yield name


def _all_agent_service_cases():
    cases = []
    for compose_path in _discover_compose_files():
        rel = str(compose_path.relative_to(ROOT))
        for service in _agent_services(compose_path):
            cases.append((rel, service))
    return cases


ALL_AGENT_SERVICES = _all_agent_service_cases()


def test_scanner_found_the_expected_agent_services():
    """Non-vacuity: the discovery step itself must find a non-trivial,
    expected set of agent services -- if this list were accidentally empty
    (e.g. a glob pattern typo), every test below would vacuously pass."""
    found = set(ALL_AGENT_SERVICES)
    expected_minimum = {
        ("deploy/pilot/docker-compose.yml", "reference-egress-agent"),
        ("docker-compose.voltagent.yml", "voltagent-agent"),
        ("docker-compose.pilot-voltagent.yml", "voltagent-agent"),
        ("docker-compose.pilot-clinic-voltagent.yml", "clinic-agent"),
        ("docker-compose.pilot.yml", "mcc-agent"),
        ("docker-compose.notify-pilot.yml", "pilot-agent"),
        ("docker-compose.reference-agent.yml", "reference-agent"),
    }
    missing = expected_minimum - found
    assert missing == set(), f"scanner failed to discover known agent services: {missing}"


@pytest.mark.parametrize("rel_path,service", ALL_AGENT_SERVICES)
def test_agent_service_holds_no_undocumented_authority_secret(rel_path, service):
    compose_text = (ROOT / rel_path).read_text(encoding="utf-8")
    effective = _effective_service_env(compose_text, service, SYNTHETIC_ENV)
    leaked_keys = FORBIDDEN_KEY_NAMES & effective.keys()
    leaked_values = {k for k, v in effective.items() if v in SYNTHETIC_ENV.values() and k in FORBIDDEN_KEY_NAMES}
    leaked = leaked_keys | leaked_values

    exception_reason = KNOWN_COMBINED_ROLE_EXCEPTIONS.get((rel_path, service))
    if exception_reason is None:
        assert leaked == set(), (
            f"{rel_path}::{service} (ROLE_AGENT) holds authority-plane secret(s) "
            f"{leaked} with no documented exception in "
            f"KNOWN_COMBINED_ROLE_EXCEPTIONS -- either this is a new instance of "
            f"the credential-separation bug (fix it) or it is a deliberate "
            f"combined-role design (add a reviewed, reasoned entry here)"
        )
    else:
        # A documented exception must still be TRUE (not stale): the service
        # must actually hold the secret the exception claims, so a future fix
        # that removes the secret is required to also remove the exception
        # entry, not leave a dangling, inaccurate allowlist entry behind.
        assert leaked, (
            f"{rel_path}::{service} no longer holds any authority-plane secret "
            f"-- its KNOWN_COMBINED_ROLE_EXCEPTIONS entry ({exception_reason!r}) "
            f"is now stale and should be removed"
        )


def test_every_exception_entry_still_refers_to_an_existing_service():
    """Catches the opposite staleness: an exception entry for a service that
    has since been renamed or removed."""
    discovered = set(ALL_AGENT_SERVICES)
    for key in KNOWN_COMBINED_ROLE_EXCEPTIONS:
        assert key in discovered, f"stale exception entry, service no longer found: {key}"
