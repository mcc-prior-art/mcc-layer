"""Ed25519 decision token signing and verification.

All authority-bearing artifacts in MCC-Core are signed with Ed25519.
Serialization is canonical (sorted keys, compact separators, ASCII)
so that signatures are deterministic and reproducible.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Dict

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SIGNATURE_FIELD = "sig"


def canonical_bytes(obj: Any) -> bytes:
    """Deterministic serialization used for every signed or hashed structure."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def hash_payload(payload: Dict[str, Any]) -> str:
    return sha256_hex(canonical_bytes(payload))


def hash_action(action: str) -> str:
    return sha256_hex(action.encode("utf-8"))


class SigningKey:
    """Ed25519 signing key bound to a key ID."""

    def __init__(self, private_key: Ed25519PrivateKey, kid: str) -> None:
        self._private_key = private_key
        self.kid = kid

    @classmethod
    def generate(cls, kid: str) -> "SigningKey":
        return cls(Ed25519PrivateKey.generate(), kid)

    @classmethod
    def from_pem_file(cls, path: str, kid: str) -> "SigningKey":
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("MCC signing key must be Ed25519")
        return cls(key, kid)

    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()

    def public_key_b64(self) -> str:
        raw = self.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return base64.b64encode(raw).decode("ascii")

    def sign_token(self, claims: Dict[str, Any]) -> Dict[str, Any]:
        """Return ``claims`` + ``kid`` + detached Ed25519 signature."""
        if SIGNATURE_FIELD in claims:
            raise ValueError("claims must not already contain a signature field")
        unsigned = {**claims, "kid": self.kid}
        signature = self._private_key.sign(canonical_bytes(unsigned))
        return {**unsigned, SIGNATURE_FIELD: base64.b64encode(signature).decode("ascii")}


def verify_token(token: Dict[str, Any], public_key: Ed25519PublicKey) -> bool:
    """Fail-closed signature check: True only for a valid Ed25519 signature."""
    try:
        unsigned = {k: v for k, v in token.items() if k != SIGNATURE_FIELD}
        signature = base64.b64decode(token[SIGNATURE_FIELD])
        public_key.verify(signature, canonical_bytes(unsigned))
        return True
    except Exception:
        return False


def public_key_from_b64(b64: str) -> Ed25519PublicKey:
    """Rebuild an Ed25519 public key from the raw base64 form used in
    ``/health`` and ``/export`` (the inverse of ``SigningKey.public_key_b64``)."""
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(b64))
