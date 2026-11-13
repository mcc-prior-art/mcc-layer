"""V05 (part 2): write the gateway's per-agent credential registry for the
deployable VoltAgent / AXFlow clinic pilots.

Reads ``MCC_AGENT_API_KEYS`` (JSON ``{principal_id: raw_key}``, supplied by the
operator in the git-ignored ``.env.pilot``) and writes ONLY SHA-256 hashes to
``--out`` (mode 0600), the file ``MCC_AGENT_CREDENTIALS_CONFIG`` points at.
Regenerated on every gateway start, so rotation = edit ``.env.pilot`` + restart.

Fail-closed: a missing, malformed or empty mapping, an empty key, or one key
shared by two principals exits non-zero and the gateway does not start.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile

from gateway.agent_identity import AgentCredentialRegistry, hash_agent_key


def build_config(raw: str, tenant_id: str) -> dict:
    try:
        keys = json.loads(raw)
    except ValueError as exc:
        raise ValueError("MCC_AGENT_API_KEYS is not valid JSON") from exc
    if not isinstance(keys, dict) or not keys:
        raise ValueError("MCC_AGENT_API_KEYS must be a non-empty JSON object {principal_id: key}")
    entries = []
    for i, (principal, key) in enumerate(sorted(keys.items())):
        if not isinstance(key, str) or not key:
            raise ValueError(f"empty or non-string key for {principal!r}")
        entries.append({"credential_id": f"pilot-agent-{i + 1}", "tenant_id": tenant_id,
                        "principal_id": principal, "key_sha256": hash_agent_key(key),
                        "status": "active"})
    config = {"agents": entries}
    AgentCredentialRegistry.from_config(config)  # same strict validation as the gateway
    return config


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--tenant-id", default=os.environ.get("MCC_GATEWAY_TENANT_ID") or "pilot")
    args = ap.parse_args(argv)
    try:
        config = build_config(os.environ.get("MCC_AGENT_API_KEYS", ""), args.tenant_id)
    except ValueError as exc:
        print(f"FAILED: agent credential registry not written: {exc} (fail-closed)", file=sys.stderr)
        return 1
    out_dir = os.path.dirname(os.path.abspath(args.out))
    fd, tmp = tempfile.mkstemp(dir=out_dir, prefix=".agent_credentials.")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, args.out)
    print(f"agent credential registry: {len(config['agents'])} agent(s) -> {args.out} (hashes only)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
