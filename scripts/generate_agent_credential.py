#!/usr/bin/env python3
"""Provision a per-agent credential (V05 remediation, part 2).

Generates a random agent key, adds its SHA-256 hash to the gateway's agent
credential registry (``MCC_AGENT_CREDENTIALS_CONFIG``), and prints the RAW key
once. Give the raw key to that agent only (it sends it as ``X-API-Key``). The
gateway stores only the hash.

    python scripts/generate_agent_credential.py --config secrets/agents.json \\
        --tenant-id pilot --principal-id agent/payments-bot

Rotation: run again for the same principal (a principal may hold several
active credentials), deploy the new key to the agent, then revoke the old
one:

    python scripts/generate_agent_credential.py --config secrets/agents.json \\
        --revoke <credential_id>

The gateway reads the registry at startup. Restart it (or roll the instances)
after a change, so a revocation takes effect.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway.agent_identity import AgentCredentialRegistry, hash_agent_key  # noqa: E402


def _load(path: Path) -> dict:
    if not path.exists():
        return {"agents": []}
    config = json.loads(path.read_text(encoding="utf-8"))
    AgentCredentialRegistry.from_config(config)          # refuse to edit an invalid file
    return config


def _write(path: Path, config: dict) -> None:
    AgentCredentialRegistry.from_config(config)          # never write an invalid registry
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", required=True, help="path of the agent credential registry JSON")
    ap.add_argument("--tenant-id", help="the gateway's MCC_GATEWAY_TENANT_ID")
    ap.add_argument("--principal-id", help="the agent's identity (must equal its actor / mandate subject)")
    ap.add_argument("--credential-id", help="optional stable id (default: generated)")
    ap.add_argument("--revoke", metavar="CREDENTIAL_ID", help="mark an existing credential revoked")
    args = ap.parse_args(argv)

    path = Path(args.config)
    config = _load(path)
    if args.revoke:
        hits = [e for e in config["agents"] if e["credential_id"] == args.revoke]
        if not hits:
            print(f"no credential {args.revoke!r} in {path}", file=sys.stderr)
            return 2
        hits[0]["status"] = "revoked"
        _write(path, config)
        print(f"revoked {args.revoke}; restart the gateway for it to take effect")
        return 0
    if not args.tenant_id or not args.principal_id:
        ap.error("--tenant-id and --principal-id are required to provision a credential")
    raw_key = secrets.token_urlsafe(32)
    credential_id = args.credential_id or f"cred-{secrets.token_hex(6)}"
    config["agents"].append({
        "credential_id": credential_id, "tenant_id": args.tenant_id,
        "principal_id": args.principal_id, "key_sha256": hash_agent_key(raw_key), "status": "active",
    })
    _write(path, config)
    print(f"credential_id={credential_id}")
    print(f"tenant_id={args.tenant_id}")
    print(f"principal_id={args.principal_id}")
    print(f"agent key (shown ONCE; give it to this agent only, as X-API-Key): {raw_key}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
