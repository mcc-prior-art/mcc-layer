"""MCC-Core runtime security primitives.

The model proposes.
MCC-Core decides.
The gate enforces.
The audit chain records.
"""

from .audit import AuditLog
from .authority import (
    ActionPolicy,
    AuthorityDecision,
    AuthorityModel,
    Mandate,
    MandateRegistry,
)
from .core import EXECUTABLE_VERDICTS, DecisionEngine, TokenNotIssuable, Verdict
from .gate import ExecutionGate, GateResult
from .nonce import NonceRegistry
from .policy import PolicyBundle, PolicyBundleError
from .signing import (
    SigningKey,
    canonical_bytes,
    hash_action,
    hash_payload,
    sha256_hex,
    verify_token,
)

__all__ = [
    "ActionPolicy",
    "AuditLog",
    "AuthorityDecision",
    "AuthorityModel",
    "DecisionEngine",
    "EXECUTABLE_VERDICTS",
    "Mandate",
    "MandateRegistry",
    "ExecutionGate",
    "GateResult",
    "NonceRegistry",
    "PolicyBundle",
    "PolicyBundleError",
    "SigningKey",
    "TokenNotIssuable",
    "Verdict",
    "canonical_bytes",
    "hash_action",
    "hash_payload",
    "sha256_hex",
    "verify_token",
]
