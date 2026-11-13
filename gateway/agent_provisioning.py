"""V05 (part 2): per-agent credential provisioning and the agent-side loader.

Trust boundary
--------------
``python -m gateway.agent_provisioning`` runs ONLY inside the trusted
provisioning boundary (a one-shot init container, an operator workstation or
a secrets pipeline), never inside an agent container. For every principal it
writes ONE credential file into that principal's OWN directory (in the Docker
pilots: a named volume mounted read-only into that agent's container and no
other) and writes the gateway's registry with SHA-256 hashes only.

* No process except the provisioner ever sees more than one raw key, and no
  agent container ever receives the provisioning map, another agent's
  credential, the tenant's shared key, or the registry of raw keys.
* Existing credential files are REUSED (persistent volumes survive restarts);
  ``--rotate PRINCIPAL`` replaces one principal's key. The registry is
  rewritten every run, so a rotated key's predecessor stops authenticating as
  soon as the gateway reloads the registry (today: at gateway start).
* Raw keys are never printed or logged; only credential ids are.

Agent side
----------
:func:`load_agent_credential` reads the ONE credential file an agent was
given (``MCC_AGENT_CREDENTIAL_FILE``). It fails closed on anything ambiguous:
a missing/unreadable/malformed file, unknown or missing fields, or an empty
value. The agent's principal comes from this file, never from a caller-chosen
setting.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import sys
import tempfile
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .agent_identity import AgentCredentialRegistry, hash_agent_key

CREDENTIAL_FILE_NAME = "credential.json"
CREDENTIAL_FIELDS = frozenset({"tenant_id", "principal_id", "credential_id", "api_key"})


class AgentCredentialFileError(ValueError):
    """The agent credential file is missing, unreadable or ambiguous."""


@dataclass(frozen=True)
class AgentCredential:
    tenant_id: str
    principal_id: str
    credential_id: str
    api_key: str

    def __repr__(self) -> str:  # never render the key
        return (f"AgentCredential(tenant_id={self.tenant_id!r}, principal_id="
                f"{self.principal_id!r}, credential_id={self.credential_id!r}, api_key=<redacted>)")


def _validate_credential(doc) -> AgentCredential:
    if not isinstance(doc, dict) or set(doc) != CREDENTIAL_FIELDS:
        raise AgentCredentialFileError(
            f"credential file must contain exactly {sorted(CREDENTIAL_FIELDS)}")
    for field in sorted(CREDENTIAL_FIELDS):
        value = doc[field]
        if not isinstance(value, str) or not value or value != value.strip():
            raise AgentCredentialFileError(f"credential field {field!r} must be a non-empty, unpadded string")
    return AgentCredential(doc["tenant_id"], doc["principal_id"], doc["credential_id"], doc["api_key"])


def load_agent_credential(path: Optional[str]) -> AgentCredential:
    """Load the ONE credential this agent was provisioned with (fail-closed)."""
    if not path or not str(path).strip():
        raise AgentCredentialFileError("MCC_AGENT_CREDENTIAL_FILE is not set")
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as exc:
        raise AgentCredentialFileError(f"cannot read agent credential file: {type(exc).__name__}") from None
    return _validate_credential(doc)


def agent_credential_from_env(env=None) -> AgentCredential:
    """The agent-side entry point. A provisioning MAP in the agent's
    environment (``MCC_AGENT_API_KEYS``) is refused outright: an agent must
    never be handed other principals' credentials, even to filter them."""
    env = os.environ if env is None else env
    if (env.get("MCC_AGENT_API_KEYS") or "").strip():
        raise AgentCredentialFileError(
            "MCC_AGENT_API_KEYS must never be given to an agent; provision one "
            "credential file per agent (MCC_AGENT_CREDENTIAL_FILE)")
    return load_agent_credential(env.get("MCC_AGENT_CREDENTIAL_FILE"))


# ---------------------------------------------------------------- provisioning

_SLUG = re.compile(r"[^A-Za-z0-9]+")


def _write_private(path: str, data: str, mode: int, owner: Optional[Tuple[int, int]]) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".provision.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        if owner is not None:
            os.chown(tmp, *owner)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def provision(*, registry_path: str, tenant_id: str, agents: List[Tuple[str, str]],
              rotate: frozenset = frozenset(), owner: Optional[Tuple[int, int]] = None) -> Dict[str, str]:
    """Ensure each ``(principal_id, directory)`` holds exactly its own
    credential, then write the hash-only registry. Returns principal ->
    credential_id (never a key). Fail-closed on any ambiguity."""
    if not tenant_id or tenant_id != tenant_id.strip():
        raise ValueError("tenant_id must be a non-empty, unpadded string")
    if not agents:
        raise ValueError("at least one --agent PRINCIPAL=DIR is required")
    principals = [p for p, _ in agents]
    dirs = [os.path.realpath(d) for _, d in agents]
    if len(set(principals)) != len(principals):
        raise ValueError("duplicate principal")
    if len(set(dirs)) != len(dirs):
        raise ValueError("two principals share one credential directory")
    unknown_rotate = set(rotate) - set(principals)
    if unknown_rotate:
        raise ValueError(f"--rotate names an unprovisioned principal: {sorted(unknown_rotate)}")

    entries, issued = [], {}
    for principal, directory in agents:
        if not principal or principal != principal.strip():
            raise ValueError("principal_id must be a non-empty, unpadded string")
        os.makedirs(directory, exist_ok=True)
        os.chmod(directory, 0o700)
        if owner is not None:
            os.chown(directory, *owner)
        path = os.path.join(directory, CREDENTIAL_FILE_NAME)
        credential = None
        if os.path.exists(path) and principal not in rotate:
            credential = load_agent_credential(path)
            if credential.tenant_id != tenant_id or credential.principal_id != principal:
                raise ValueError(f"existing credential in {directory} belongs to another "
                                 "principal/tenant; refusing to reuse it")
        if credential is None:
            slug = _SLUG.sub("-", principal).strip("-") or "agent"
            credential = AgentCredential(tenant_id, principal,
                                         f"{slug}-{secrets.token_hex(4)}", secrets.token_urlsafe(32))
            _write_private(path, json.dumps({
                "tenant_id": credential.tenant_id, "principal_id": credential.principal_id,
                "credential_id": credential.credential_id, "api_key": credential.api_key}),
                0o400, owner)
        entries.append({"credential_id": credential.credential_id, "tenant_id": tenant_id,
                        "principal_id": principal, "key_sha256": hash_agent_key(credential.api_key),
                        "status": "active"})
        issued[principal] = credential.credential_id

    config = {"agents": entries}
    AgentCredentialRegistry.from_config(config)          # the gateway's own strict validation
    _write_private(registry_path, json.dumps(config, indent=2), 0o444, None)
    return issued


def _parse_agent(spec: str) -> Tuple[str, str]:
    principal, sep, directory = spec.partition("=")
    if not sep or not principal or not directory:
        raise argparse.ArgumentTypeError("expected PRINCIPAL=DIRECTORY")
    return principal, directory


def _parse_owner(spec: str) -> Tuple[int, int]:
    uid, sep, gid = spec.partition(":")
    if not sep:
        raise argparse.ArgumentTypeError("expected UID:GID")
    return int(uid), int(gid)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Provision per-agent credentials (trusted boundary only).")
    ap.add_argument("--registry", required=True, help="hash-only registry for MCC_AGENT_CREDENTIALS_CONFIG")
    ap.add_argument("--tenant-id", required=True)
    ap.add_argument("--agent", action="append", type=_parse_agent, default=[],
                    metavar="PRINCIPAL=DIR", help="one per agent; DIR is that agent's own credential directory")
    ap.add_argument("--rotate", action="append", default=[], metavar="PRINCIPAL")
    ap.add_argument("--owner", type=_parse_owner, help="UID:GID that owns each credential file (the agent's runtime user)")
    args = ap.parse_args(argv)
    try:
        issued = provision(registry_path=args.registry, tenant_id=args.tenant_id, agents=args.agent,
                           rotate=frozenset(args.rotate), owner=args.owner)
    except (ValueError, OSError) as exc:
        print(f"FAILED: agent credential provisioning refused: {exc} (fail-closed)", file=sys.stderr)
        return 1
    for principal, credential_id in issued.items():
        print(f"provisioned {principal}: credential_id={credential_id} (key written to its own directory only)")
    print(f"registry: {len(issued)} agent(s) -> {args.registry} (hashes only)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
