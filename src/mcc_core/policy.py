"""PolicyBundle: a policy source bound to a verifiable sha256 hash.

The bundle hash is embedded in every decision token, and the execution
gate rejects tokens whose policy hash does not match the locally
trusted bundle.
"""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Optional

from .signing import sha256_hex


class PolicyBundleError(Exception):
    """Raised when a policy bundle fails hash verification on load."""


class PolicyBundle:
    def __init__(self, policy_id: str, content: bytes) -> None:
        self.policy_id = policy_id
        self.content = content
        self.policy_hash = sha256_hex(content)

    @classmethod
    def from_file(
        cls,
        path: str,
        policy_id: Optional[str] = None,
        expected_hash: Optional[str] = None,
    ) -> "PolicyBundle":
        source = Path(path)
        bundle = cls(policy_id or source.name, source.read_bytes())
        if expected_hash is not None and not bundle.verify(expected_hash):
            raise PolicyBundleError(
                f"policy bundle hash mismatch for {path}: tampered bundle rejected"
            )
        return bundle

    def verify(self, expected_hash: str) -> bool:
        return secrets.compare_digest(self.policy_hash, expected_hash)
