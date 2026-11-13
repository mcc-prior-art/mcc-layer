"""Test-fixture helper for V05 per-agent identity (part 2).

Fixtures migrate from "one shared tenant key, caller-asserted actor" to
EXPLICIT per-agent credentials. The agent key a fixture's clients already
send becomes that agent's registered credential, and the mount's shared
tenant key becomes a separate value no request uses (the gateway refuses a
shared key that is also registered).

Identity ATTACKS (another agent, shared key, unknown or revoked key) are
covered in tests/test_v05_agent_identity_http.py. Fixtures here model honest
agents, each presenting its own credential.
"""
from __future__ import annotations

from gateway.agent_identity import AgentCredentialRegistry, AuthenticatedAgent, hash_agent_key


def shared_tenant_key(agent_key: str) -> str:
    """A mount-level shared tenant key distinct from every agent key."""
    return f"{agent_key}::shared-tenant-key-unused"


def registry(tenant_id: str, agents: dict) -> AgentCredentialRegistry:
    """``agents`` maps principal_id -> raw agent key (all in ``tenant_id``)."""
    return AgentCredentialRegistry.from_config({"agents": [
        {"credential_id": f"cred-{i}", "tenant_id": tenant_id, "principal_id": principal,
         "key_sha256": hash_agent_key(key), "status": "active"}
        for i, (principal, key) in enumerate(sorted(agents.items()))]})


def registry_config(tenant_id: str, agents: dict) -> dict:
    return {"agents": [
        {"credential_id": f"cred-{i}", "tenant_id": tenant_id, "principal_id": principal,
         "key_sha256": hash_agent_key(key), "status": "active"}
        for i, (principal, key) in enumerate(sorted(agents.items()))]}


def agent(tenant_id: str, principal_id: str) -> AuthenticatedAgent:
    """The trusted identity a direct (in-process) library caller passes for
    an agent it has authenticated itself -- the library trust boundary."""
    return AuthenticatedAgent(tenant_id, principal_id, f"test-cred:{principal_id}")


def derived_agent_key(base_key: str, principal_id: str) -> str:
    """Deterministic per-agent test credential for out-of-process gateway
    harnesses: each principal gets its OWN key, distinct from the mount's
    shared tenant key ``base_key`` (which is never registered)."""
    return f"{base_key}::agent::{principal_id}"


def write_registry_file(path, tenant_id: str, agents: dict) -> str:
    """Write a registry JSON (hashes only) for ``MCC_AGENT_CREDENTIALS_CONFIG``."""
    import json
    with open(path, "w", encoding="utf-8") as f:
        json.dump(registry_config(tenant_id, agents), f)
    return str(path)
