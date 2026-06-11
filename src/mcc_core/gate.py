"""Fail-closed execution gate.

No verified decision token — no execution.

Verification order: signature and key trust first, then audience and
time window, then verdict, then scope binding (policy/action/payload
hashes), and the nonce is consumed last so that a token failing any
static check does not burn its nonce.

Any exception anywhere resolves to deny.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .core import Verdict
from .nonce import NonceRegistry
from .signing import hash_action, hash_payload, verify_token


@dataclass
class GateResult:
    allowed: bool
    reason: str


class ExecutionGate:
    def __init__(
        self,
        *,
        trusted_keys: Dict[str, Ed25519PublicKey],
        audience: str,
        nonce_registry: NonceRegistry,
        policy_hash: Optional[str] = None,
        nonce_ttl_seconds: int = 300,
    ) -> None:
        self.trusted_keys = trusted_keys
        self.audience = audience
        self.nonce_registry = nonce_registry
        self.policy_hash = policy_hash
        self.nonce_ttl_seconds = nonce_ttl_seconds

    async def verify(
        self,
        token: Any,
        *,
        action: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        now: Optional[int] = None,
    ) -> GateResult:
        try:
            return await self._verify(token, action=action, payload=payload, now=now)
        except Exception:
            return GateResult(False, "GATE_ERROR: fail-closed")

    async def _verify(
        self,
        token: Any,
        *,
        action: Optional[str],
        payload: Optional[Dict[str, Any]],
        now: Optional[int],
    ) -> GateResult:
        if not isinstance(token, dict) or not token:
            return GateResult(False, "NO_TOKEN: no verified decision token, no execution")

        public_key = self.trusted_keys.get(token.get("kid"))
        if public_key is None:
            return GateResult(False, "UNTRUSTED_KEY: unknown or revoked key id")

        if not verify_token(token, public_key):
            return GateResult(False, "INVALID_SIGNATURE: Ed25519 verification failed")

        if token.get("aud") != self.audience:
            return GateResult(False, "AUDIENCE_MISMATCH: token bound to another gate")

        ts = int(now if now is not None else time.time())
        nbf, exp = token.get("nbf"), token.get("exp")
        if not isinstance(nbf, int) or not isinstance(exp, int):
            return GateResult(False, "INVALID_TIME_WINDOW: missing nbf/exp")
        if ts < nbf:
            return GateResult(False, "TOKEN_NOT_YET_VALID: nbf in the future")
        if ts >= exp:
            return GateResult(False, "TOKEN_EXPIRED")

        if token.get("decision") not in (Verdict.ALLOW.value, Verdict.CONSTRAIN.value):
            return GateResult(False, "NON_EXECUTABLE_VERDICT: only ALLOW/CONSTRAIN execute")

        if self.policy_hash is not None and token.get("policy_hash") != self.policy_hash:
            return GateResult(False, "POLICY_HASH_MISMATCH: token issued under untrusted policy")

        if action is not None and token.get("action_hash") != hash_action(action):
            return GateResult(False, "ACTION_HASH_MISMATCH: token does not authorize this action")

        if payload is not None and token.get("payload_hash") != hash_payload(payload):
            return GateResult(False, "PAYLOAD_HASH_MISMATCH: payload differs from authorized one")

        if not await self.nonce_registry.consume(
            token.get("nonce"), ttl_seconds=self.nonce_ttl_seconds
        ):
            return GateResult(False, "NONCE_REJECTED: replay or registry unavailable (fail-closed)")

        return GateResult(True, "VERIFIED: execution authorized")
