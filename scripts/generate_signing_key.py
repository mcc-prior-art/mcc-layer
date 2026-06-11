#!/usr/bin/env python3
"""Generate a persistent Ed25519 signing key for the MCC-Core runtime.

Usage:
    python scripts/generate_signing_key.py [output_path]

Writes a PKCS8 PEM (mode 0600) and prints the base64-encoded public key
for distribution to execution gate trust sets. Refuses to overwrite an
existing file.
"""

import base64
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "mcc_signing_key.pem"
    if os.path.exists(path):
        sys.exit(f"refusing to overwrite existing key: {path}")

    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)

    public_raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    print(f"written: {path} (mode 0600)")
    print(f"public key (base64): {base64.b64encode(public_raw).decode('ascii')}")


if __name__ == "__main__":
    main()
