"""V05 (part 2): per-agent credential provisioning + the agent-side loader.

The provisioner (gateway/agent_provisioning.py) runs only in the trusted
provisioning boundary. These tests pin its contract:

* each principal's credential lands ONLY in that principal's own directory
  (mode 0400), never in another's, and the registry holds hashes only;
* the registry it writes is exactly what the gateway's strict registry
  accepts, and each key resolves to its own principal (never another);
* reuse across restarts, single-principal rotation, and fail-closed refusal of
  every ambiguity (duplicate principal, shared directory, a foreign credential
  in a directory, empty input);
* the CLI never prints a raw key;
* the agent-side loader refuses missing/ambiguous identity and a provisioning
  map in the agent's environment.
"""
from __future__ import annotations

import json
import os
import stat

import pytest

from gateway.agent_identity import AgentCredentialRegistry
from gateway.agent_provisioning import (
    CREDENTIAL_FILE_NAME,
    AgentCredentialFileError,
    agent_credential_from_env,
    load_agent_credential,
    main,
    provision,
)


def _setup(tmp_path, principals=("agent/a", "agent/b")):
    agents = [(p, str(tmp_path / "creds" / p.split("/")[1])) for p in principals]
    return str(tmp_path / "registry.json"), agents


def test_each_principal_gets_only_its_own_credential_and_registry_holds_hashes(tmp_path):
    reg, agents = _setup(tmp_path)
    issued = provision(registry_path=reg, tenant_id="t1", agents=agents)
    assert set(issued) == {"agent/a", "agent/b"}

    creds = {p: load_agent_credential(os.path.join(d, CREDENTIAL_FILE_NAME)) for p, d in agents}
    assert {p: c.principal_id for p, c in creds.items()} == {"agent/a": "agent/a", "agent/b": "agent/b"}
    assert creds["agent/a"].api_key != creds["agent/b"].api_key
    for p, d in agents:
        files = os.listdir(d)
        assert files == [CREDENTIAL_FILE_NAME]                      # nothing else in the agent's dir
        mode = stat.S_IMODE(os.stat(os.path.join(d, CREDENTIAL_FILE_NAME)).st_mode)
        assert mode == 0o400
        other = [c for q, c in creds.items() if q != p][0]
        assert other.api_key not in open(os.path.join(d, CREDENTIAL_FILE_NAME)).read()

    text = open(reg).read()
    for c in creds.values():
        assert c.api_key not in text                                 # hashes only
    registry = AgentCredentialRegistry.from_file(reg)
    for p, c in creds.items():
        res = registry.resolve(c.api_key, tenant_id="t1")
        assert res.agent is not None and res.agent.principal_id == p  # each key -> its own principal
        assert registry.resolve(c.api_key, tenant_id="other").agent is None


def test_rerun_reuses_credentials_and_rotate_replaces_exactly_one(tmp_path):
    reg, agents = _setup(tmp_path)
    provision(registry_path=reg, tenant_id="t1", agents=agents)
    read = lambda: {p: load_agent_credential(os.path.join(d, CREDENTIAL_FILE_NAME)).api_key for p, d in agents}
    first = read()
    provision(registry_path=reg, tenant_id="t1", agents=agents)
    assert read() == first
    provision(registry_path=reg, tenant_id="t1", agents=agents, rotate=frozenset({"agent/a"}))
    after = read()
    assert after["agent/b"] == first["agent/b"] and after["agent/a"] != first["agent/a"]
    registry = AgentCredentialRegistry.from_file(reg)
    assert registry.resolve(first["agent/a"], tenant_id="t1").agent is None   # old key no longer registered
    assert registry.resolve(after["agent/a"], tenant_id="t1").agent.principal_id == "agent/a"


@pytest.mark.parametrize("bad", [
    "duplicate_principal", "shared_directory", "foreign_credential", "empty", "unknown_rotate", "padded_tenant",
])
def test_ambiguity_fails_closed(tmp_path, bad):
    reg, agents = _setup(tmp_path)
    kwargs = dict(registry_path=reg, tenant_id="t1", agents=agents)
    if bad == "duplicate_principal":
        kwargs["agents"] = [agents[0], ("agent/a", str(tmp_path / "x"))]
    elif bad == "shared_directory":
        kwargs["agents"] = [agents[0], ("agent/b", agents[0][1])]
    elif bad == "foreign_credential":
        provision(registry_path=reg, tenant_id="t1", agents=[("agent/b", agents[0][1])])
    elif bad == "empty":
        kwargs["agents"] = []
    elif bad == "unknown_rotate":
        kwargs["rotate"] = frozenset({"agent/zz"})
    elif bad == "padded_tenant":
        kwargs["tenant_id"] = " t1"
    with pytest.raises(ValueError):
        provision(**kwargs)


def test_cli_never_prints_a_raw_key(tmp_path, capsys):
    reg, agents = _setup(tmp_path)
    argv = ["--registry", reg, "--tenant-id", "t1"]
    for p, d in agents:
        argv += ["--agent", f"{p}={d}"]
    assert main(argv) == 0
    out = capsys.readouterr()
    for p, d in agents:
        key = load_agent_credential(os.path.join(d, CREDENTIAL_FILE_NAME)).api_key
        assert key not in out.out and key not in out.err
    assert main(argv + ["--agent", f"agent/a={tmp_path}/other"]) == 1     # duplicate principal -> refused


# ------------------------------------------------------------- agent-side loader

def _cred(tmp_path, doc):
    p = tmp_path / "credential.json"
    p.write_text(doc if isinstance(doc, str) else json.dumps(doc))
    return str(p)


GOOD = {"tenant_id": "t1", "principal_id": "agent/a", "credential_id": "c1", "api_key": "k-a"}


def test_loader_returns_one_principal_and_redacts_the_key(tmp_path):
    cred = agent_credential_from_env({"MCC_AGENT_CREDENTIAL_FILE": _cred(tmp_path, GOOD)})
    assert cred.principal_id == "agent/a" and cred.api_key == "k-a"
    assert "k-a" not in repr(cred)


@pytest.mark.parametrize("doc", [
    None, "not-json", "[]", {**GOOD, "api_key": ""}, {**GOOD, "principal_id": " agent/a"},
    {k: v for k, v in GOOD.items() if k != "tenant_id"}, {**GOOD, "other_agents": {"agent/b": "k"}},
    {**GOOD, "api_key": 7},
])
def test_loader_fails_closed(tmp_path, doc):
    env = {} if doc is None else {"MCC_AGENT_CREDENTIAL_FILE": _cred(tmp_path, doc)}
    with pytest.raises(AgentCredentialFileError):
        agent_credential_from_env(env)


def test_a_provisioning_map_in_the_agent_environment_is_refused(tmp_path):
    env = {"MCC_AGENT_CREDENTIAL_FILE": _cred(tmp_path, GOOD),
           "MCC_AGENT_API_KEYS": json.dumps({"agent/a": "k-a", "agent/b": "k-b"})}
    with pytest.raises(AgentCredentialFileError, match="never be given to an agent"):
        agent_credential_from_env(env)
