#!/usr/bin/env python3
"""Generate the local pilot keys and trust configs for the Docker Compose pilot.

Writes everything into ``deploy/pilot/secrets/`` (git-ignored):

    gateway_signing.pem        decision-token signing key (gateway)
    approver_signing.pem       approval-mandate issuer key (ESCALATE loop)
    mandate_issuer_signing.pem a mandate issuer key (sign pilot mandates with this)
    evaluator_{1..N}.pem       N independent consensus evaluator keys
    trust.pilot.json           mandate trust set (PUBLIC keys only)
    consensus_trust.json       consensus evaluator trust set (PUBLIC keys only)

Private keys are mode 0600 and never leave ``secrets/``; only PUBLIC keys go into
the JSON trust configs. Nothing here is committed (see deploy/pilot/.gitignore).
The gateway loads these via the paths in deploy/pilot/.env.

Usage:
    python deploy/pilot/generate_pilot_config.py [--evaluators N] [--force]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SECRETS = HERE / "secrets"
sys.path.insert(0, str(ROOT / "src"))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from mcc_core import SigningKey  # noqa: E402


def _write_key(path: Path, force: bool) -> SigningKey:
    if path.exists() and not force:
        sys.exit(f"refusing to overwrite existing key: {path} (use --force)")
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    if path.exists():
        path.unlink()
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    return SigningKey.from_pem_file(str(path), path.stem)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evaluators", type=int, default=3)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    if args.evaluators < 1:
        sys.exit("--evaluators must be >= 1")

    SECRETS.mkdir(parents=True, exist_ok=True)
    os.chmod(SECRETS, 0o700)

    gateway = _write_key(SECRETS / "gateway_signing.pem", args.force)
    approver = _write_key(SECRETS / "approver_signing.pem", args.force)
    mandate_issuer = _write_key(SECRETS / "mandate_issuer_signing.pem", args.force)
    evaluators = [_write_key(SECRETS / f"evaluator_{i + 1}.pem", args.force)
                  for i in range(args.evaluators)]

    # Mandate trust set: PUBLIC key of the pilot mandate issuer.
    trust = {
        "issuers": [
            {
                "issuer_id": "pilot-mandate-issuer",
                "enabled": True,
                "keys": [{"kid": mandate_issuer.kid,
                          "public_key_b64": mandate_issuer.public_key_b64(),
                          "not_after": None}],
            }
        ]
    }
    (SECRETS / "trust.pilot.json").write_text(json.dumps(trust, indent=2), encoding="utf-8")

    # Consensus trust set: PUBLIC keys of the independent evaluators.
    consensus = {
        "issuers": [
            {"issuer_id": f"evaluator-{i + 1}", "enabled": True,
             "keys": [{"kid": e.kid, "public_key_b64": e.public_key_b64(), "not_after": None}]}
            for i, e in enumerate(evaluators)
        ]
    }
    (SECRETS / "consensus_trust.json").write_text(json.dumps(consensus, indent=2), encoding="utf-8")

    print(f"wrote pilot secrets to {SECRETS} (mode 0600 keys; trust configs hold PUBLIC keys only)")
    print(f"  gateway signing kid:  {gateway.kid}")
    print(f"  approver kid:         {approver.kid}")
    print(f"  mandate issuer kid:   {mandate_issuer.kid}")
    print(f"  evaluator kids:       {[e.kid for e in evaluators]}")
    print("\nNext: copy deploy/pilot/.env.example to deploy/pilot/.env, then "
          "`docker compose -f deploy/pilot/docker-compose.yml up --build`.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
