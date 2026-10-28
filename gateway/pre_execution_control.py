"""Pre-Execution Attestation Control — PR-2.

The Control-side boundary that makes a PR-1 ``EvidenceAttestation`` a real
input to MCC-Control, without replacing any existing primitive:

    VALID AUTHORITY
        +
    REQUIRED VERIFIED ATTESTATION
        +
    DETERMINISTIC CONTROL POLICY
        =
    ELIGIBLE FOR DECISION-TOKEN ISSUANCE

This module adds deterministic policy interpretation *above* the PR-1
cryptographic/structural verifier (``mcc_attestation.verifier.verify_attestation``,
unchanged, still the only thing that performs signature/trust/binding
verification). It does not reimplement, weaken, or duplicate that
verification, and it does not replace ``MandateAuthority``, ``DecisionEngine``,
``ExecutionGate``, or ``EnforcementCoordinator`` — it sits *before*
``DecisionEngine.issue_token()`` in the existing authority-to-token path and
decides, deterministically, whether a required attestation is present and
valid for the exact action about to be authorized.

Core doctrine (unchanged from MCC-AT-001, preserved here):

    Intelligence assesses.
    Attestation makes the assessment attributable.
    Control verifies.
    Execution acts.

Control does not classify risk and does not decide whether an Attester's
semantic assessment is *true*. It deterministically verifies whether the
required trusted evidence and authority exist for this exact action, now.
If a trusted Attester asserts ``risk_class=low`` and trusted deterministic
policy accepts ``low``, Control proceeds even if the Attester turns out to
have been wrong about the real world — that is an attestation/policy
failure, not a Control bypass. See ``specs/MCC-AT-002.md``.

An ``EvidenceAttestation`` MUST NOT itself grant authority: this module
never substitutes for, and is always evaluated *alongside*, the existing
mandate/consensus authority check performed by the caller. A valid
attestation with no valid mandate still yields no executable authority (the
caller's existing authority check already denies before Control is ever
reached); a valid mandate with a missing/invalid *required* attestation
yields no executable authority either (``PreExecutionControl.evaluate``
below).

Nonce/replay: PR-1 deliberately carried ``nonce`` without consuming it. This
module closes that gap by reusing the *existing* ``mcc_core.nonce`` replay
primitive (no second replay algorithm), with the attestation nonce
domain-separated from the decision-token nonce via a key prefix
(``attestation:<attester_id>:<nonce>``) — the same registry instance the
gateway already uses for token replay protection can be shared safely,
because the two nonce spaces never collide at the key level.
"""

from __future__ import annotations

import copy
import fnmatch
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Tuple

from mcc_attestation import (
    AttestationStatus,
    AttestationVerificationResult,
    AttesterTrustStore,
    CheckStatus,
    EvidenceAttestation,
    verify_attestation,
)
from mcc_core.signing import hash_action, hash_document, hash_payload
from mcc_core.trusted_time import LocalTimeSource, TimeTrustError, TrustedTimeSource


class AttestationControlReason(str, Enum):
    """Machine-readable, fail-closed reason codes for a Control attestation
    decision. A closed enumeration — never an ad hoc string — so a caller
    (audit, HTTP response, test) can branch on it reliably."""

    #: No AttestationRequirement is configured for this action; existing
    #: (pre-PR-2) behavior is preserved unchanged.
    NOT_REQUIRED = "NOT_REQUIRED"
    #: Required attestation was supplied, cryptographically/structurally
    #: verified, correctly bound, and satisfied the deterministic claim
    #: policy; its nonce was consumed. Issuance may proceed.
    VERIFIED = "VERIFIED"

    ATTESTATION_REQUIRED = "ATTESTATION_REQUIRED"
    ATTESTATION_INVALID = "ATTESTATION_INVALID"
    ATTESTER_UNTRUSTED = "ATTESTER_UNTRUSTED"
    ATTESTATION_EVIDENCE_TYPE_MISMATCH = "ATTESTATION_EVIDENCE_TYPE_MISMATCH"
    ATTESTATION_ACTION_MISMATCH = "ATTESTATION_ACTION_MISMATCH"
    ATTESTATION_PAYLOAD_MISMATCH = "ATTESTATION_PAYLOAD_MISMATCH"
    ATTESTATION_SCOPE_MISMATCH = "ATTESTATION_SCOPE_MISMATCH"
    ATTESTATION_POLICY_MISMATCH = "ATTESTATION_POLICY_MISMATCH"
    ATTESTATION_NOT_YET_VALID = "ATTESTATION_NOT_YET_VALID"
    ATTESTATION_EXPIRED = "ATTESTATION_EXPIRED"
    ATTESTATION_CLAIM_POLICY_MISMATCH = "ATTESTATION_CLAIM_POLICY_MISMATCH"
    ATTESTATION_REPLAYED = "ATTESTATION_REPLAYED"
    ATTESTATION_REPLAY_UNAVAILABLE = "ATTESTATION_REPLAY_UNAVAILABLE"
    ATTESTATION_CONTROL_ERROR = "ATTESTATION_CONTROL_ERROR"
    #: PR #122 round 4: the trusted-time source could not vouch for `now`
    #: (unavailable / excessive skew / rollback) -- the attestation's own
    #: validity-window check below cannot be trusted, so it never runs.
    CLOCK_UNTRUSTED = "CLOCK_UNTRUSTED"


#: Reason codes that permit decision-token issuance to proceed. Every other
#: member of AttestationControlReason is fail-closed (no token).
_OK_REASONS = frozenset({AttestationControlReason.NOT_REQUIRED, AttestationControlReason.VERIFIED})


@dataclass(frozen=True)
class AttestationRequirement:
    """A trusted, declarative requirement: which actions require a PR-1
    attestation, what it must assert, and what it must be bound to.

    Action-policy-driven, not caller-driven: every field here comes from
    trusted Control configuration (mirrors ``mcc_core.authority.ActionPolicy``
    — an ``fnmatch`` glob over the action name, most-specific-first
    resolution). Neither the HTTP caller nor the attestation itself can widen
    or choose what this requirement expects.
    """

    #: fnmatch glob over the action name (e.g. "send_payment", "payment.*").
    action_pattern: str
    #: The evidence_type a trusted Attester must assert for this action.
    evidence_type: str
    #: Deterministic scope template, resolved via ``str.format(action=...,
    #: resource=...)`` — e.g. ``"payment:{resource}"``. No DSL: plain
    #: str.format over two fixed, trusted fields only. The caller/attestation
    #: never supplies or overrides this; it comes only from this requirement.
    scope_template: str
    #: Whether the attestation MUST bind to the exact final (post-mandate-
    #: constraint) payload via payload_hash. Defaults to True: exact-payload
    #: binding is the safer default per the critical exact-payload rule.
    require_payload_binding: bool = True
    #: Whether the attestation MUST bind to Control's own trusted
    #: policy_hash/policy_version for this decision.
    require_policy_binding: bool = False
    #: Deterministic required-claim policy: claim name -> allowed value
    #: tuple. Evaluated as a plain equality/membership check against the
    #: attestation's *signed* claims — never semantic reinterpretation.
    required_claims: Mapping[str, Tuple[Any, ...]] = field(default_factory=dict)

    def resolve_scope(self, *, action: str, resource: Optional[str]) -> str:
        return self.scope_template.format(action=action, resource=resource or "")


class AttestationRequirementRegistry:
    """The set of trusted AttestationRequirements Control resolves actions
    against. Fail-open-to-``None`` by design when unconfigured (matches the
    task's explicit backward-compatibility requirement): an action with no
    matching requirement is simply not gated by this module at all, and
    existing (pre-PR-2) behavior is unchanged for it. First matching pattern
    wins — configure most-specific patterns first, exactly like
    ``mcc_core.authority.AuthorityModel``."""

    def __init__(self, requirements: Optional[List[AttestationRequirement]] = None) -> None:
        self._requirements = list(requirements or [])

    def for_action(self, action: str) -> Optional[AttestationRequirement]:
        for requirement in self._requirements:
            if fnmatch.fnmatchcase(action, requirement.action_pattern):
                return requirement
        return None

    @classmethod
    def from_config(cls, items: Optional[List[Dict[str, Any]]]) -> "AttestationRequirementRegistry":
        """Build from a small declarative list, e.g.::

            [{"action": "send_payment", "evidence_type": "risk_assessment",
              "scope": "payment:{resource}",
              "required_claims": {"risk_class": ["low"]}}]

        Not a DSL: every field maps 1:1 onto :class:`AttestationRequirement`.
        """
        requirements = []
        for item in items or []:
            claims_cfg = item.get("required_claims") or {}
            required_claims = {name: tuple(values) for name, values in claims_cfg.items()}
            requirements.append(AttestationRequirement(
                action_pattern=item["action"],
                evidence_type=item["evidence_type"],
                scope_template=item["scope"],
                require_payload_binding=bool(item.get("require_payload_binding", True)),
                require_policy_binding=bool(item.get("require_policy_binding", False)),
                required_claims=required_claims,
            ))
        return cls(requirements)


@dataclass(frozen=True)
class ControlAttestationResult:
    """The result of Control's attestation-gate decision for one proposed
    issuance. Never a bare boolean: ``reason_code`` is a closed, testable
    enum, and ``verification`` carries the underlying PR-1 structured result
    (when verification was actually attempted) for audit.

    ``evidence_digest`` (PR-3) is the trusted digest of the EXACT complete
    signed ``EvidenceAttestation`` document Control itself verified --
    present if and ONLY IF ``reason_code == VERIFIED`` (a required
    attestation that passed every check, including replay consumption).
    It is ``None`` for ``NOT_REQUIRED`` (nothing was verified; there is
    nothing to bind) and for every failed reason_code -- a failed or
    unrequired attestation decision can never carry a digest an issuance
    path could mistake for trusted evidence. This is enforced structurally
    below, not by caller discipline."""

    ok: bool
    reason_code: AttestationControlReason
    reason: str
    verification: Optional[AttestationVerificationResult] = None
    evidence_digest: Optional[str] = None

    def __post_init__(self) -> None:
        if self.ok and self.reason_code not in _OK_REASONS:
            raise ValueError(
                f"ControlAttestationResult.ok=True is inconsistent with reason_code={self.reason_code}"
            )
        if not self.ok and self.reason_code in _OK_REASONS:
            raise ValueError(
                f"ControlAttestationResult.ok=False is inconsistent with reason_code={self.reason_code}"
            )
        if self.evidence_digest is not None and self.reason_code != AttestationControlReason.VERIFIED:
            raise ValueError(
                "ControlAttestationResult.evidence_digest MUST be None unless "
                f"reason_code is VERIFIED (got reason_code={self.reason_code})"
            )


def _map_verification_failure(result: AttestationVerificationResult) -> AttestationControlReason:
    """Translate a non-VERIFIED PR-1 :class:`AttestationVerificationResult`
    into a Control reason code. This inspects PR-1's *own* structured check
    list — it re-derives nothing about cryptographic validity; it only
    relabels which named step failed into Control's reason-code vocabulary.
    """
    if result.overall_status is AttestationStatus.UNSUPPORTED_SCHEMA:
        return AttestationControlReason.ATTESTATION_INVALID

    failing = next((c for c in result.checks if c.status is CheckStatus.FAIL), None)
    if failing is None:
        # Defensive: INVALID with no FAIL check recorded should not happen,
        # but never fabricate a VERIFIED-adjacent code for it.
        return AttestationControlReason.ATTESTATION_CONTROL_ERROR

    if failing.name == "attester_trust":
        return AttestationControlReason.ATTESTER_UNTRUSTED
    if failing.name == "evidence_type_authorization":
        return AttestationControlReason.ATTESTATION_EVIDENCE_TYPE_MISMATCH
    if failing.name == "validity_window":
        return (
            AttestationControlReason.ATTESTATION_NOT_YET_VALID
            if "not yet valid" in failing.detail
            else AttestationControlReason.ATTESTATION_EXPIRED
        )
    if failing.name == "action_binding":
        return AttestationControlReason.ATTESTATION_ACTION_MISMATCH
    if failing.name == "payload_binding":
        return AttestationControlReason.ATTESTATION_PAYLOAD_MISMATCH
    if failing.name == "scope_binding":
        return AttestationControlReason.ATTESTATION_SCOPE_MISMATCH
    if failing.name == "policy_binding":
        return AttestationControlReason.ATTESTATION_POLICY_MISMATCH
    # input_validation / structural_validation / signature_verification /
    # verifier_internal_error all collapse to ATTESTATION_INVALID -- each is
    # a structural or cryptographic defect in the attestation itself, not a
    # specific binding mismatch.
    return AttestationControlReason.ATTESTATION_INVALID


class PreExecutionControl:
    """Mediates whether a proposed action, whose authority has *already*
    been separately verified by the caller (mandate or consensus), is also
    ELIGIBLE for decision-token issuance under trusted attestation policy.

    Does not verify authority (that remains ``MandateAuthority`` /
    ``ConsensusVerifier`` — unchanged, unreplaced). Does not issue tokens
    (that remains ``DecisionEngine.issue_token`` — called by the caller only
    after this returns ``ok=True``). Does not itself execute anything.
    """

    def __init__(
        self,
        *,
        requirements: AttestationRequirementRegistry,
        trust_store: AttesterTrustStore,
        nonce_registry: Optional[Any],
        nonce_clock_skew_seconds: int = 30,
        max_nonce_ttl_seconds: int = 900,
        min_nonce_ttl_seconds: int = 1,
        time_source: Optional[TrustedTimeSource] = None,
    ) -> None:
        self.requirements = requirements
        self.trust_store = trust_store
        self.nonce_registry = nonce_registry
        self.nonce_clock_skew_seconds = nonce_clock_skew_seconds
        self.max_nonce_ttl_seconds = max_nonce_ttl_seconds
        self.min_nonce_ttl_seconds = min_nonce_ttl_seconds
        # Clock-skew hardening (PR #122 round 4): default source of `now`
        # for the attestation validity-window check below when the caller
        # does not supply one explicitly -- see trusted_time.py. Defaults
        # to this process's own clock (pre-existing behavior) when not
        # configured.
        self.time_source: TrustedTimeSource = time_source or LocalTimeSource()

    def _nonce_ttl(self, expires_at: int, now: int) -> int:
        """Derive the attestation nonce record's TTL from the attestation's
        own validity window plus a clock-skew margin, clamped to
        ``[min_nonce_ttl_seconds, max_nonce_ttl_seconds]`` -- the identical
        discipline ``mcc_core.gate.ExecutionGate._nonce_ttl`` already uses
        for decision-token nonces, applied here to the attestation's
        ``expires_at`` instead of the token's ``exp``. Never zero/negative,
        never unbounded."""
        remaining = int(expires_at) - int(now) + self.nonce_clock_skew_seconds
        return max(self.min_nonce_ttl_seconds, min(self.max_nonce_ttl_seconds, remaining))

    async def evaluate(
        self,
        *,
        action: str,
        forward_context: Dict[str, Any],
        resource: Optional[str],
        raw_attestation: Optional[Dict[str, Any]],
        policy_hash: Optional[str] = None,
        policy_version: Optional[str] = None,
        now: Optional[int] = None,
    ) -> ControlAttestationResult:
        """Decide whether ``action`` (already authority-approved by the
        caller, about to be issued a token over exactly ``forward_context``)
        is eligible for decision-token issuance under attestation policy.

        ``forward_context`` MUST be the exact final payload the caller is
        about to pass to ``DecisionEngine.issue_token`` — i.e. *after* any
        mandate CONSTRAIN rewrite, never the pre-constraint proposal. This
        method never trusts a caller-supplied "already verified" claim: it
        always calls PR-1's ``verify_attestation`` itself, on the raw
        attestation, regardless of what the caller believes.
        """
        try:
            requirement = self.requirements.for_action(action)
            if requirement is None:
                return ControlAttestationResult(
                    True, AttestationControlReason.NOT_REQUIRED,
                    f"no attestation requirement configured for action {action!r}",
                )

            if raw_attestation is None or not isinstance(raw_attestation, dict):
                return ControlAttestationResult(
                    False, AttestationControlReason.ATTESTATION_REQUIRED,
                    f"action {action!r} requires a verified pre-execution attestation "
                    f"(evidence_type={requirement.evidence_type!r}); none supplied",
                )

            # PR-3 TOCTOU fix: snapshot the raw attestation document into a
            # private copy IMMEDIATELY, before any verification and before the
            # single ``await`` point below (nonce consumption). ``raw_attestation``
            # is a caller-supplied mutable dict; without this snapshot, a
            # concurrent mutation of the caller's original object during that
            # await could let verify_attestation() (and the claim-policy check)
            # examine artifact A while evidence_digest ends up derived from a
            # mutated artifact B -- exactly the "token binds to a different
            # artifact than the one Control verified" failure MCC-AT-003 exists
            # to rule out (EBT-DIGEST-003). Every subsequent operation in this
            # method -- verification, claim inspection, the nonce key, and the
            # final digest -- reads only this snapshot, never the caller's
            # original object, so nothing that happens to that object after
            # this point can change what gets verified or digested.
            raw_attestation = copy.deepcopy(raw_attestation)

            if now is not None:
                now_i = int(now)
            else:
                try:
                    now_i = await self.time_source.now()
                except TimeTrustError as exc:
                    return ControlAttestationResult(
                        False, AttestationControlReason.CLOCK_UNTRUSTED,
                        f"{exc.reason}: {exc.detail}",
                    )
            expected_action_hash = hash_action(action)
            expected_payload_hash = (
                hash_payload(forward_context) if requirement.require_payload_binding else None
            )
            expected_scope = requirement.resolve_scope(action=action, resource=resource)
            expected_policy_hash = policy_hash if requirement.require_policy_binding else None
            expected_policy_version = policy_version if requirement.require_policy_binding else None

            # Step 7 of the required target order: Control itself invokes
            # PR-1's verifier -- never trusts a caller-supplied verified=True,
            # a caller-supplied AttestationVerificationResult, an unsigned
            # risk result, or a model's own confidence. Only this raw dict.
            result = verify_attestation(
                raw_attestation,
                trust_store=self.trust_store,
                expected_action_hash=expected_action_hash,
                expected_scope=expected_scope,
                now=now_i,
                expected_payload_hash=expected_payload_hash,
                expected_policy_hash=expected_policy_hash,
                expected_policy_version=expected_policy_version,
            )
            if not result.verified:
                return ControlAttestationResult(
                    False, _map_verification_failure(result),
                    f"attestation verification failed: {result.overall_status.value}"
                    + (f" -- {result.failures[-1]}" if result.failures else ""),
                    verification=result,
                )

            # Deterministic claim policy -- Control's own interpretation,
            # never delegated back into mcc_attestation.verifier. Re-parses
            # the already cryptographically-verified raw document (no crypto
            # redone; EvidenceAttestation.from_dict is pure structural
            # parsing, the same PR-1 primitive verify_attestation itself used
            # internally) purely to read the signed claims.
            attestation = EvidenceAttestation.from_dict(raw_attestation)
            for claim_name, allowed_values in requirement.required_claims.items():
                if claim_name not in attestation.claims:
                    return ControlAttestationResult(
                        False, AttestationControlReason.ATTESTATION_CLAIM_POLICY_MISMATCH,
                        f"required claim {claim_name!r} is absent from the attestation",
                        verification=result,
                    )
                value = attestation.claims[claim_name]
                if value not in allowed_values:
                    return ControlAttestationResult(
                        False, AttestationControlReason.ATTESTATION_CLAIM_POLICY_MISMATCH,
                        f"claim {claim_name!r}={value!r} is outside the deterministic allowed "
                        f"set {list(allowed_values)!r}",
                        verification=result,
                    )

            # Nonce consumption is LAST -- only after every static check
            # (crypto, trust, action/payload/scope/policy binding, claim
            # policy) has already passed, and immediately before returning
            # ok=True (the caller issues the token right after). A failure
            # anywhere above this point never reaches here, so it never
            # burns the nonce.
            if self.nonce_registry is None:
                return ControlAttestationResult(
                    False, AttestationControlReason.ATTESTATION_REPLAY_UNAVAILABLE,
                    "no attestation replay registry configured; fail-closed",
                    verification=result,
                )
            nonce_key = f"attestation:{attestation.attester_id}:{attestation.nonce}"
            ttl = self._nonce_ttl(attestation.expires_at, now_i)
            try:
                consumed = await self.nonce_registry.consume(nonce_key, ttl_seconds=ttl)
            except Exception:  # noqa: BLE001 -- any registry failure fails closed
                return ControlAttestationResult(
                    False, AttestationControlReason.ATTESTATION_REPLAY_UNAVAILABLE,
                    "attestation replay registry raised; fail-closed",
                    verification=result,
                )
            if not consumed:
                return ControlAttestationResult(
                    False, AttestationControlReason.ATTESTATION_REPLAYED,
                    "attestation nonce already consumed (replay); fail-closed",
                    verification=result,
                )

            # PR-3: the trusted evidence_digest is derived HERE, by Control,
            # from the exact raw attestation document it just finished
            # cryptographically verifying -- never from a caller-supplied
            # digest/verified flag (there is no such input to this method).
            # Digesting the raw dict (not a re-serialized reconstruction of
            # it) means the digest corresponds exactly to the bytes whose
            # Ed25519 signature was actually checked.
            evidence_digest = hash_document(raw_attestation)

            return ControlAttestationResult(
                True, AttestationControlReason.VERIFIED,
                "attestation verified, required claims satisfied, nonce consumed",
                verification=result, evidence_digest=evidence_digest,
            )
        except Exception as exc:  # noqa: BLE001 -- Control itself must never raise into the caller
            return ControlAttestationResult(
                False, AttestationControlReason.ATTESTATION_CONTROL_ERROR,
                f"unexpected Control error: {exc!r}",
            )


__all__ = [
    "AttestationControlReason",
    "AttestationRequirement",
    "AttestationRequirementRegistry",
    "ControlAttestationResult",
    "PreExecutionControl",
]
