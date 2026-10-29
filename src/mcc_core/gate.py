"""Fail-closed execution gate.

No verified decision token — no execution.

Verification order: signature and key trust first, then audience and
time window, then verdict, then scope binding (policy/action/payload
hashes), then generic operation binding, then PR-3 evidence-bound
execution ticket binding (exact digest match against ``evidence_digest``
when the token carries one), and the nonce is consumed last so that a
token failing any static check does not burn its nonce.

Evidence binding (PR-3, MCC-AT-003) performs only a deterministic
canonical-document hash comparison. It does not import, invoke, or
duplicate any semantic attestation verification, trust-store resolution,
or claim-policy logic — that ownership belongs entirely to PR-2's
``gateway.pre_execution_control.PreExecutionControl``, which already ran
once, before this token was ever issued. The gate proves only that the
evidence artifact presented at actuation time is byte-identical (under
canonical serialization) to the one Control verified and bound into the
token — never that the evidence's semantic claims are true.

Any exception anywhere resolves to deny.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .core import Verdict
from .nonce import NonceRegistry
from .signing import hash_action, hash_document, hash_payload, is_valid_digest, verify_token
from .trusted_time import LocalTimeSource, TimeTrustError, TrustedTimeSource


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
        min_nonce_ttl_seconds: int = 1,
        nonce_clock_skew_seconds: int = 30,
        time_source: Optional[TrustedTimeSource] = None,
    ) -> None:
        self.trusted_keys = trusted_keys
        self.audience = audience
        self.nonce_registry = nonce_registry
        self.policy_hash = policy_hash
        # The nonce record's TTL is derived per-token from the token's validity
        # window; ``nonce_ttl_seconds`` is the upper bound on that derived value
        # (it must be >= the token TTL so the nonce always outlives the token).
        self.max_nonce_ttl_seconds = nonce_ttl_seconds
        self.min_nonce_ttl_seconds = min_nonce_ttl_seconds
        self.nonce_clock_skew_seconds = nonce_clock_skew_seconds
        # Clock-skew hardening (PR #122 round 3): the default source of
        # ``now`` below when the caller (``coordinator.enforce()``, which
        # deliberately never passes an explicit ``now`` -- see
        # tests/test_velocity.py's static guard) does not supply one.
        # Defaults to this process's own clock (the pre-existing behavior)
        # when not configured. This is independent of, and does not alter,
        # ``EnforcementCoordinator``'s own ``now`` parameter or
        # ``VelocityRegistry``'s distinct (and deliberately untouched)
        # monotonic-vs-wall-clock semantics.
        self.time_source: TrustedTimeSource = time_source or LocalTimeSource()

    def _nonce_ttl(self, exp: int, now: int) -> int:
        """Derive the nonce record's TTL from the token's validity window.

        The nonce must outlive the token: if its record expired while the token
        were still valid, the same token could be replayed into the freed slot.
        So TTL = remaining token validity + a clock-skew margin, clamped to
        ``[min_nonce_ttl_seconds, max_nonce_ttl_seconds]``.
        """
        remaining = int(exp) - int(now) + self.nonce_clock_skew_seconds
        return max(self.min_nonce_ttl_seconds, min(self.max_nonce_ttl_seconds, remaining))

    async def verify(
        self,
        token: Any,
        *,
        action: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        binding: Optional[Dict[str, Any]] = None,
        evidence: Optional[Dict[str, Any]] = None,
        now: Optional[int] = None,
    ) -> GateResult:
        try:
            return await self._verify(
                token, action=action, payload=payload, binding=binding,
                evidence=evidence, now=now,
            )
        except Exception:
            return GateResult(False, "GATE_ERROR: fail-closed")

    async def _verify(
        self,
        token: Any,
        *,
        action: Optional[str],
        payload: Optional[Dict[str, Any]],
        binding: Optional[Dict[str, Any]],
        evidence: Optional[Dict[str, Any]],
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

        if now is not None:
            ts = int(now)
        else:
            try:
                ts = await self.time_source.now()
            except TimeTrustError as exc:
                return GateResult(False, f"{exc.reason}: {exc.detail}")
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

        # Generic operation binding: the executor's view of the operation
        # (actor, resource, transaction, idempotency key, or any signed claim)
        # must match what the token authorized. Only fields the caller asks to
        # check against a token that actually carries them are compared, so an
        # unbound (legacy) token is unaffected. Checked before the nonce so a
        # mismatch does not burn the nonce.
        if binding:
            for field, expected in binding.items():
                if expected is None:
                    continue
                authorized = token.get(field)
                # A token that does not carry this field is simply not bound on
                # it (an authentic None — the signature covers it, so it cannot
                # be stripped). Only enforce when the token actually asserts a
                # value and it differs from the operation being executed.
                if authorized is not None and authorized != expected:
                    return GateResult(
                        False,
                        f"BINDING_MISMATCH: {field} differs from authorized operation",
                    )

        # PR-3: strict evidence-bound execution ticket binding. Deliberately
        # NOT folded into the generic ``binding`` loop above, which tolerates
        # a legacy token simply not carrying a field: evidence binding must
        # be stricter in the other direction -- when the TOKEN asserts an
        # evidence_digest, a matching evidence artifact becomes mandatory,
        # not merely checked-if-present. A token with no evidence_digest
        # (every pre-PR-3 token, and every PR-3 token for an action with no
        # configured AttestationRequirement) is completely unaffected: no new
        # requirement is introduced for it. This performs only a
        # deterministic canonical-document hash comparison -- it does not
        # invoke, import, or duplicate any mcc_attestation verification or
        # claim-policy logic (that ownership stays with PR-2 Control, which
        # already ran once before this token was ever issued). Checked
        # before the nonce so a missing/wrong/malformed evidence artifact
        # never burns the token's one-time nonce.
        token_evidence_digest = token.get("evidence_digest")
        if token_evidence_digest is not None:
            # Defense-in-depth: DecisionEngine.issue_token already refuses to
            # sign a malformed evidence_digest, but the Gate does not trust
            # that every token it ever sees was produced by that exact code
            # path -- a valid Ed25519 signature only proves the claims were
            # not tampered with after signing, not that the signer's own
            # issuance-time validation ran. A well-formed-looking but
            # otherwise malformed claim (wrong prefix, wrong length,
            # uppercase/non-hex, or a non-string value) must fail closed here
            # too, before any evidence artifact is even considered and before
            # the nonce is consumed.
            if not is_valid_digest(token_evidence_digest):
                return GateResult(
                    False,
                    "EVIDENCE_INVALID: token's evidence_digest claim is malformed",
                )
            if evidence is None:
                return GateResult(
                    False,
                    "EVIDENCE_REQUIRED: token is evidence-bound; no evidence artifact supplied",
                )
            try:
                computed_digest = hash_document(evidence)
            except Exception:
                return GateResult(
                    False,
                    "EVIDENCE_INVALID: evidence artifact could not be canonicalized",
                )
            if computed_digest != token_evidence_digest:
                return GateResult(
                    False,
                    "EVIDENCE_DIGEST_MISMATCH: evidence artifact does not match the "
                    "digest bound into this token",
                )

        if not await self.nonce_registry.consume(
            token.get("nonce"), ttl_seconds=self._nonce_ttl(exp, ts)
        ):
            return GateResult(False, "NONCE_REJECTED: replay or registry unavailable (fail-closed)")

        return GateResult(True, "VERIFIED: execution authorized")
