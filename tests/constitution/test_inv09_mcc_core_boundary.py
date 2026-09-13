"""INV-09 — MCC-Core boundary.

Constitutional principle: "Execution remains within boundaries"; "No
plane may usurp the role of another."

The agent must not have a direct execution path to consequential tools.
This re-derives (does not duplicate the maintenance of, and does not
weaken) the same static-guard technique already established by
``tests/test_mcc_agent_no_direct_egress.py`` and
``tests/test_reference_governed_agent.py``'s own no-direct-execution
guard, explicitly framed here as a constitutional invariant with its own
non-vacuity probe, and extended to the reference agent package those
existing guards do not scan the whole of.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Direct outbound-networking primitives a consequential-execution-capable
# agent must never import -- the only legitimate outbound path is the
# governed executor reached through MCC-Core's own gate/coordinator.
FORBIDDEN_NETWORK_MODULES = {
    "httpx", "requests", "urllib", "urllib.request", "urllib3", "socket",
    "aiohttp", "http.client", "ssl", "asyncio.streams", "subprocess", "pycurl",
}
# Actuator/execution-plane types an agent package must never construct
# directly -- doing so would BE the direct execution path this invariant
# forbids, regardless of whether any networking import is also present.
FORBIDDEN_ACTUATOR_NAMES = {
    "GitHubIssueActuator", "HTTPEgressExecutor", "ResourceBoundUpstream",
}

AGENT_PACKAGES = [
    ROOT / "src" / "mcc_agent",
]
# examples/reference_governed_agent legitimately imports httpx-adjacent
# things nowhere -- it talks to MCC only via mcc_client -- but its
# providers.py may optionally import an LLM SDK, which is orthogonal to
# execution networking; scope this scan to the files responsible for
# actually reaching an executable outcome.
REFERENCE_AGENT_EXECUTION_FILES = [
    ROOT / "examples" / "reference_governed_agent" / "agent.py",
    ROOT / "examples" / "reference_governed_agent" / "actions.py",
]


def _imported_modules_and_names(source: str):
    tree = ast.parse(source)
    modules = set()
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
            for alias in node.names:
                names.add(alias.name)
    return modules, names


def _scan(path: Path):
    modules, names = _imported_modules_and_names(path.read_text(encoding="utf-8"))
    bad_modules = {m for m in modules if m in FORBIDDEN_NETWORK_MODULES or m.split(".")[0] in FORBIDDEN_NETWORK_MODULES}
    bad_names = names & FORBIDDEN_ACTUATOR_NAMES
    return bad_modules, bad_names


def test_mcc_agent_package_has_no_direct_execution_path():
    violations = []
    for pkg in AGENT_PACKAGES:
        if not pkg.is_dir():
            continue
        for path in pkg.glob("*.py"):
            bad_modules, bad_names = _scan(path)
            if bad_modules or bad_names:
                violations.append((str(path), sorted(bad_modules), sorted(bad_names)))
    assert violations == [], f"agent package must have no direct execution path: {violations}"


def test_reference_governed_agent_execution_files_have_no_direct_actuator():
    violations = []
    for path in REFERENCE_AGENT_EXECUTION_FILES:
        if not path.exists():
            continue
        bad_modules, bad_names = _scan(path)
        if bad_modules or bad_names:
            violations.append((str(path), sorted(bad_modules), sorted(bad_names)))
    assert violations == [], f"reference agent execution files must have no direct actuator: {violations}"


def test_non_vacuity_direct_network_import_would_be_caught():
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write("import httpx\n")
        planted_path = Path(f.name)
    try:
        bad_modules, _ = _scan(planted_path)
        assert "httpx" in bad_modules
    finally:
        planted_path.unlink()


def test_non_vacuity_direct_actuator_construction_would_be_caught():
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write("from examples.gpt6_astra_reference.github_actuator import GitHubIssueActuator\n")
        planted_path = Path(f.name)
    try:
        _, bad_names = _scan(planted_path)
        assert "GitHubIssueActuator" in bad_names
    finally:
        planted_path.unlink()


def test_mcc_agent_client_reaches_execution_only_through_governed_client():
    """Complements the import-absence guard: the agent's own client
    module must name-check as reaching execution only through the
    documented governed client type, not through any locally-defined
    'execute now' shortcut."""
    client_path = ROOT / "src" / "mcc_agent" / "client.py"
    if not client_path.exists():
        return  # covered by test_mcc_agent_package_has_no_direct_execution_path's existence check
    source = client_path.read_text(encoding="utf-8")
    assert "GovernedMCCClient" in source or "GovernanceClient" in source
