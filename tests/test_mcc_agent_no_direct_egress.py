"""Static guard: the agent package exposes no direct external execution path.

The governed agent must submit proposals + approval material to MCC-Core and
nothing else — only the existing governed HTTPS executor may perform the external
request. This test fails if any forbidden networking/HTTP-client import is added
to ``src/mcc_agent`` (so the agent can never grow its own outbound call), and
confirms the supported client surface advertises no direct-execute method.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1] / "src" / "mcc_agent"

# Modules the agent package must never import directly (it has no executor and
# performs no outbound networking of its own).
FORBIDDEN = {
    "httpx", "requests", "urllib", "urllib.request", "urllib3", "socket",
    "aiohttp", "http.client", "ssl", "asyncio.streams", "subprocess",
    "pycurl",
}


def _agent_sources():
    return sorted(PKG.glob("*.py"))


def test_agent_package_exists():
    assert PKG.is_dir() and _agent_sources(), "mcc_agent package not found"


@pytest.mark.parametrize("path", [p for p in (PKG.glob("*.py") if PKG.is_dir() else [])],
                         ids=lambda p: p.name)
def test_no_forbidden_network_imports(path):
    tree = ast.parse(path.read_text(), filename=str(path))
    bad = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if alias.name in FORBIDDEN or root in FORBIDDEN:
                    bad.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            root = mod.split(".")[0]
            if mod in FORBIDDEN or root in FORBIDDEN:
                bad.append(mod)
    assert not bad, f"{path.name} imports forbidden networking modules: {bad}"


def test_supported_client_has_no_direct_execute_method():
    # The supported client exposes propose(submit)/approve/execute_after_approval,
    # never a method that performs the external request directly.
    from mcc_agent.client import EmbeddedGovernanceClient, GovernanceClient

    for name in ("send", "request", "http", "fetch", "call_external", "raw_execute"):
        assert not hasattr(GovernanceClient, name)
    methods = {m for m in dir(EmbeddedGovernanceClient) if not m.startswith("_")}
    # The only execution entry points are governed (submit / execute_after_approval).
    assert "submit" in methods and "execute_after_approval" in methods
    assert "approve" in methods


def test_agent_exposes_no_executor_or_signing_key():
    from mcc_agent import GovernedAgent
    public = {a for a in dir(GovernedAgent) if not a.startswith("_")}
    for forbidden in ("executor", "signing_key", "private_key", "http", "session"):
        assert forbidden not in public
