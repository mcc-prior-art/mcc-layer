"""Thirty-nine targeted, hand-authored security-critical mutations (PR #71,
Workstream J; extended post-merge-review to close a disclosed mutation-
testing gap -- see the ``gate-*-fail-open`` block below; extended again by
PR-5 to cover the PR-1->4 attestation-to-execution chain, which the
original 26 entirely predate -- see the trailing block below that and
``docs/ATTESTATION_INDEPENDENT_ASSURANCE.md``'s gap matrix; extended once
more (Round 17/18, durable logical-operation safety) with
``idempotency-reserve-reopens-pending-states``, targeting the exact defect
class Astra's Round 16-18 inspections identified -- a mutation that
genuinely reopens execution eligibility for an unresolved (DISPATCH_OWNED/
UNKNOWN) operation, replacing an earlier Round 17 mutation the Round 18
inspection found could only be caught on a harmless state-label technicality
-- see ``docs/DURABLE_OPERATION_SAFETY.md``).

Unlike generic mutation testing (which mutates arbitrary operators across a
whole codebase and requires heavy tuning to separate meaningful mutants
from noise), each ``Defect`` here is a SPECIFIC, deliberately chosen
regression of a named security property this repository claims to hold --
the kind of one-line, plausible-looking, code-review-survivable change a
real regression could actually look like. Each targets an EXACT, unique
source substring (verified present exactly once before mutating, so a
future refactor that moves the code makes this fail loudly rather than
silently mutating nothing) and names the workstream test(s) expected to
catch it.

"100% detection" is the required outcome, not an assumption: this module
only DEFINES the defects; ``mutation/harness.py`` actually applies each one
to an isolated copy of the repository, runs the named detector tests
against that mutated copy, and reports pass/fail per defect. A defect
whose detector tests do NOT fail against the mutated code is a genuine,
reportable gap in this assurance suite's coverage -- never silently
dropped or reclassified as "not applicable" to make the score look better.

The 13 original defects (below) are one hand-picked mutation per security
property, spread across the whole runtime. The trailing ``gate-*-fail-open``
block is a DIFFERENT, complementary kind of coverage: an exhaustive,
systematic sweep of every single ``GateResult(False, ...)`` fail-closed
return in ``src/mcc_core/gate.py``'s ``ExecutionGate._verify``/``verify`` --
i.e. every site where a one-line ``False`` -> ``True`` edit would flip the
gate from deny to allow. It was added after a direct-verification
mutation-testing addendum found that 2 of these 14 sites (the ``verify()``
exception handler and the ``nbf``/``exp`` type-check) were not caught by a
reasonable hand-selected test oracle, even though the gate's own explicit
rejection reasons made the bug look "obviously" covered. Both gaps were
closed with new regression tests in ``tests/test_mcc_core.py``
(``test_gate_denies_when_verify_raises_unexpectedly`` and
``test_gate_denies_malformed_time_window``) before these defects were added,
so this module now proves -- not assumes -- that all 14 fail-open sites in
the gate are genuinely detected, permanently, in CI.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple


@dataclass(frozen=True)
class Defect:
    id: str
    description: str
    file_path: str  # repo-relative
    find: str        # exact, unique source substring
    replace: str      # the mutated substring
    detector_tests: Tuple[str, ...]  # pytest node ids / paths expected to fail


DEFECTS: List[Defect] = [
    Defect(
        id="gate-fail-open",
        description="The execution gate's fail-closed exception handler is flipped to fail-open on any error.",
        file_path="src/mcc_core/gate.py",
        find='        except Exception:\n            return GateResult(False, "GATE_ERROR: fail-closed")',
        replace='        except Exception:\n            return GateResult(True, "GATE_ERROR: MUTATED-fail-open")',
        detector_tests=("mutation/detectors.py::test_gate_exception_path_fails_closed",),
    ),
    Defect(
        id="signature-verify-always-true",
        description="Ed25519 signature verification always reports valid, regardless of the signature bytes.",
        file_path="src/mcc_core/signing.py",
        find="        public_key.verify(signature, canonical_bytes(unsigned))\n        return True\n    except Exception:\n        return False",
        replace="        public_key.verify(signature, canonical_bytes(unsigned))\n        return True\n    except Exception:\n        return True  # MUTATED",
        detector_tests=("assurance/tests/test_exclusive_execution_path.py::test_a7_forged_gate_identity_tampered_signature",
                         "assurance/tests/test_exclusive_execution_path.py::test_a5_agent_to_actuator_bypass_self_signed_forged_evaluator"),
    ),
    Defect(
        id="nonce-replay-allowed",
        description="In-memory nonce registry no longer rejects a nonce it has already seen (replay accepted).",
        file_path="src/mcc_core/nonce.py",
        find="        if nonce in self._seen:\n            return False",
        replace="        if False:  # MUTATED: replay check disabled\n            return False",
        detector_tests=("mutation/detectors.py::test_in_memory_nonce_registry_rejects_replay",),
    ),
    Defect(
        id="consensus-threshold-bypassed",
        description="Consensus verification treats any vote count as meeting the threshold.",
        file_path="src/mcc_core/consensus.py",
        find="        if len(allow_ids) >= self.policy.threshold:",
        replace="        if True:  # MUTATED: threshold check disabled",
        detector_tests=("assurance/tests/test_decision_authority_containment.py::test_c2_below_threshold_votes_denied",),
    ),
    Defect(
        id="consensus-veto-disabled",
        description="A trusted evaluator's DENY vote no longer vetoes consensus.",
        file_path="src/mcc_core/consensus.py",
        find="        if self.policy.veto_on_deny and deny_ids:",
        replace="        if False:  # MUTATED: veto disabled",
        detector_tests=("assurance/tests/test_decision_authority_containment.py::test_c3_trusted_deny_vote_vetoes_despite_sufficient_allow_votes",),
    ),
    Defect(
        id="consensus-vote-binding-disabled",
        description="Votes are accepted regardless of which action/payload/actor they were actually signed for.",
        file_path="src/mcc_core/consensus.py",
        find='            if (vote.get("action_hash") != expected_action\n                    or vote.get("payload_hash") != expected_payload\n                    or vote.get("actor") != actor):',
        replace='            if False:  # MUTATED: operation binding check disabled',
        detector_tests=("assurance/tests/test_exclusive_execution_path.py::test_a8_valid_token_direct_to_actuator_wrong_binding",
                         "assurance/tests/test_decision_authority_containment.py::test_c5_votes_bound_to_a_different_actor_rejected"),
    ),
    Defect(
        id="audit-before-actuation-bypassed",
        description="A failed pre-actuation audit write no longer blocks actuation (audit-before-actuation invariant broken).",
        file_path="src/mcc_core/coordinator.py",
        find="        if pre_ref is None:\n            # Cannot confirm the pre-actuation record -> indeterminate before\n            # execution -> fail closed and release everything reserved.",
        replace="        if False:  # MUTATED: audit-before-actuation guard disabled\n            # Cannot confirm the pre-actuation record -> indeterminate before\n            # execution -> fail closed and release everything reserved.",
        detector_tests=("mutation/detectors.py::test_coordinator_denies_when_pre_actuation_audit_write_fails",),
    ),
    Defect(
        id="canonical-action-body-excluded",
        description="The request body no longer contributes to the canonical action hash -- two requests with different bodies bind identically.",
        file_path="egress_proxy/canonical_action.py",
        find="    action.update(_encode_body(body))\n    return action",
        replace="    pass  # MUTATED: action.update(_encode_body(body)) removed\n    return action",
        detector_tests=("tests/test_egress_canonical.py::test_material_difference_changes_hash",),
    ),
    Defect(
        id="ssrf-allowed-hosts-bypassed",
        description="The destination allowed_hosts allowlist is no longer enforced.",
        file_path="egress_proxy/ssrf.py",
        find='    if policy.allowed_hosts is not None and host not in policy.allowed_hosts:\n        raise SSRFError(f"host {host!r} not in allowed_hosts")',
        replace='    if False:  # MUTATED: allowed_hosts check disabled\n        raise SSRFError(f"host {host!r} not in allowed_hosts")',
        detector_tests=("tests/test_egress_ssrf.py::test_allowed_hosts_enforced",),
    ),
    Defect(
        id="api-key-check-disabled",
        description="The actuator's client API key check accepts any key.",
        file_path="egress_proxy/app.py",
        find='    def require_api_key(x_api_key: str = Header(...)) -> str:\n        if x_api_key != cfg.api_key:\n            raise HTTPException(status_code=401, detail="INVALID_API_KEY")',
        replace='    def require_api_key(x_api_key: str = Header(...)) -> str:\n        if False:  # MUTATED: API key check disabled\n            raise HTTPException(status_code=401, detail="INVALID_API_KEY")',
        detector_tests=("assurance/tests/test_exclusive_execution_path.py::test_a2_stolen_endpoint_wrong_client_credential",),
    ),
    Defect(
        id="idempotency-duplicate-allowed",
        description="The in-memory idempotency registry no longer rejects a duplicate reservation of an already-executed (or in-flight, or UNKNOWN, or binding-conflicting) key.",
        file_path="src/mcc_core/idempotency.py",
        find=(
            '        state, generation, held_binding, _ = _decode(encoded)\n'
            '        if held_binding != binding:\n'
            '            return ReserveResult(ReserveStatus.BINDING_CONFLICT, "logical operation bound to a different "\n'
            '                                  "action/resource/payload", held_binding)\n'
            '        if state == IdempotencyState.EXECUTED:\n'
            '            return ReserveResult(ReserveStatus.DUPLICATE_EXECUTED, "operation already executed", held_binding)\n'
            '        if state == IdempotencyState.UNKNOWN:\n'
            '            return ReserveResult(ReserveStatus.DUPLICATE_UNKNOWN,\n'
            '                                  "operation outcome UNKNOWN; requires reconciliation, not retry", held_binding)\n'
            '        return ReserveResult(ReserveStatus.DUPLICATE_INFLIGHT, "operation already reserved", held_binding)'
        ),
        replace=(
            '        state, generation, held_binding, _ = _decode(encoded)\n'
            '        return ReserveResult(ReserveStatus.RESERVED, "MUTATED: duplicate check disabled", held_binding, fence=generation)'
        ),
        detector_tests=("tests/test_idempotency.py::test_duplicate_reservation_denied",),
    ),
    Defect(
        id="idempotency-reserve-reopens-pending-states",
        description=(
            "The idempotency registry's reserve() treats DISPATCH_OWNED, UNKNOWN, and "
            "in-flight RESERVED records as available for a fresh reservation (only EXECUTED "
            "is still protected) -- genuinely reopening execution eligibility for an operation "
            "whose actuation outcome is not yet durably confirmed, letting a fresh authorization "
            "actually reach and invoke the executor a second time. This replaces Round 17's "
            "'unsafe-release' mutation, which mutated the coordinator to call the (already "
            "correctly fenced) release() after dispatch -- release() itself refuses to act "
            "outside RESERVED regardless, so that mutation could only ever be caught on a "
            "harmless state-LABEL technicality (DISPATCH_OWNED instead of UNKNOWN), never by "
            "proving a real duplicate actuation -- see Round 18 requirement 8 and "
            "docs/DURABLE_OPERATION_SAFETY.md."
        ),
        file_path="src/mcc_core/idempotency.py",
        find=(
            '        if state == IdempotencyState.UNKNOWN:\n'
            '            return ReserveResult(ReserveStatus.DUPLICATE_UNKNOWN,\n'
            '                                  "operation outcome UNKNOWN; requires reconciliation, not retry", held_binding)\n'
            '        return ReserveResult(ReserveStatus.DUPLICATE_INFLIGHT, "operation already reserved", held_binding)'
        ),
        replace=(
            '        # MUTATED: DISPATCH_OWNED/UNKNOWN/in-flight RESERVED all reopened for reservation\n'
            '        generation = uuid.uuid4().hex\n'
            '        self._store[key] = (_encode(IdempotencyState.RESERVED, generation, binding), now + DEFAULT_RESERVATION_TTL_SECONDS)\n'
            '        return ReserveResult(ReserveStatus.RESERVED, "MUTATED: pending states reopened", held_binding, fence=generation)'
        ),
        detector_tests=(
            "tests/test_idempotency.py::test_unknown_blocks_reservation_pending_reconciliation",
            "tests/test_idempotency.py::test_concurrent_duplicate_exactly_one_winner",
            "tests/test_coordinator.py::test_no_second_actuator_invocation_after_ambiguous_first_attempt",
        ),
    ),
    Defect(
        id="challenge-replay-allowed",
        description=(
            "The in-memory challenge registry no longer rejects consuming an already-consumed "
            "challenge. InMemoryChallengeRegistry.consume has TWO independent single-use guards "
            "(the rec.state != ISSUED check, and the separate _consumed-set membership check); "
            "mutating only one alone is not observable (the other still fires first on a normal "
            "replay), so this defect disables both together, representing a single refactor that "
            "breaks single-use enforcement as a whole."
        ),
        file_path="src/mcc_core/challenge.py",
        find=(
            '        if rec.state == ChallengeState.ISSUED.value and rec.is_expired(now):\n'
            '            rec.state = ChallengeState.EXPIRED.value\n'
            '        if rec.state != ChallengeState.ISSUED.value:\n'
            '            return ConsumeResult(False, f"challenge not consumable in state {rec.state}", rec.state)\n'
            '        if challenge_id in self._consumed:\n'
            '            return ConsumeResult(False, "challenge already consumed (replay)",\n'
            '                                 ChallengeState.CONSUMED.value)'
        ),
        replace=(
            '        if rec.state == ChallengeState.ISSUED.value and rec.is_expired(now):\n'
            '            rec.state = ChallengeState.EXPIRED.value\n'
            '        if False:  # MUTATED: single-use state check disabled\n'
            '            return ConsumeResult(False, f"challenge not consumable in state {rec.state}", rec.state)\n'
            '        if False:  # MUTATED: _consumed-set check disabled\n'
            '            return ConsumeResult(False, "challenge already consumed (replay)",\n'
            '                                 ChallengeState.CONSUMED.value)'
        ),
        detector_tests=("tests/test_challenge.py::test_consume_exactly_once",),
    ),
    Defect(
        id="constraint-residual-violation-allowed",
        description="A constraint violation that clamping could not fully resolve is allowed through as CONSTRAIN instead of failing to DENY.",
        file_path="src/mcc_core/authority.py",
        find="            residual = _constraint_violations(constraints, constrained)\n            if residual:",
        replace="            residual = _constraint_violations(constraints, constrained)\n            if False:  # MUTATED: residual-violation guard disabled",
        detector_tests=("tests/test_authority.py::test_missing_constrained_field_cannot_be_constrained_so_denies",),
    ),
    # ------------------------------------------------------------------
    # Exhaustive gate.py fail-open sweep: every GateResult(False, ...) in
    # ExecutionGate._verify()/verify() gets its own False->True defect.
    # "gate-fail-open" above already covers the verify() except-handler
    # (site 1 of 14); the remaining 13 sites are below, in source order.
    # ------------------------------------------------------------------
    Defect(
        id="gate-no-token-fail-open",
        description="A missing/non-dict/empty token is treated as authorized instead of denied.",
        file_path="src/mcc_core/gate.py",
        find='        if not isinstance(token, dict) or not token:\n            return GateResult(False, "NO_TOKEN: no verified decision token, no execution")',
        replace='        if not isinstance(token, dict) or not token:\n            return GateResult(True, "NO_TOKEN: MUTATED-fail-open")',
        detector_tests=("tests/test_mcc_core.py::test_gate_denies_missing_token",),
    ),
    Defect(
        id="gate-untrusted-key-fail-open",
        description="A token signed by an unknown/revoked key id is treated as authorized instead of denied.",
        file_path="src/mcc_core/gate.py",
        find='        if public_key is None:\n            return GateResult(False, "UNTRUSTED_KEY: unknown or revoked key id")',
        replace='        if public_key is None:\n            return GateResult(True, "UNTRUSTED_KEY: MUTATED-fail-open")',
        detector_tests=("tests/test_mcc_core.py::test_gate_denies_unknown_kid",),
    ),
    Defect(
        id="gate-invalid-signature-fail-open",
        description="A token with an invalid Ed25519 signature is treated as authorized instead of denied (distinct from signature-verify-always-true: this mutates the GATE's handling of a correctly-computed False result, not signing.py's verification itself).",
        file_path="src/mcc_core/gate.py",
        find='        if not verify_token(token, public_key):\n            return GateResult(False, "INVALID_SIGNATURE: Ed25519 verification failed")',
        replace='        if not verify_token(token, public_key):\n            return GateResult(True, "INVALID_SIGNATURE: MUTATED-fail-open")',
        detector_tests=("tests/test_mcc_core.py::test_gate_denies_tampered_token",),
    ),
    Defect(
        id="gate-audience-mismatch-fail-open",
        description="A token bound to a different gate's audience is treated as authorized instead of denied.",
        file_path="src/mcc_core/gate.py",
        find='        if token.get("aud") != self.audience:\n            return GateResult(False, "AUDIENCE_MISMATCH: token bound to another gate")',
        replace='        if token.get("aud") != self.audience:\n            return GateResult(True, "AUDIENCE_MISMATCH: MUTATED-fail-open")',
        detector_tests=("tests/test_mcc_core.py::test_gate_denies_wrong_audience",),
    ),
    Defect(
        id="gate-invalid-time-window-fail-open",
        description="A token with a missing or non-integer nbf/exp is treated as authorized instead of denied. Previously an UNDETECTED survivor of the direct-verification mutation addendum -- closed by adding test_gate_denies_malformed_time_window.",
        file_path="src/mcc_core/gate.py",
        find='        if not isinstance(nbf, int) or not isinstance(exp, int):\n            return GateResult(False, "INVALID_TIME_WINDOW: missing nbf/exp")',
        replace='        if not isinstance(nbf, int) or not isinstance(exp, int):\n            return GateResult(True, "INVALID_TIME_WINDOW: MUTATED-fail-open")',
        detector_tests=("tests/test_mcc_core.py::test_gate_denies_malformed_time_window",),
    ),
    Defect(
        id="gate-not-yet-valid-fail-open",
        description="A token whose nbf is still in the future is treated as authorized instead of denied.",
        file_path="src/mcc_core/gate.py",
        find='        if ts < nbf:\n            return GateResult(False, "TOKEN_NOT_YET_VALID: nbf in the future")',
        replace='        if ts < nbf:\n            return GateResult(True, "TOKEN_NOT_YET_VALID: MUTATED-fail-open")',
        detector_tests=("tests/test_mcc_core.py::test_gate_denies_not_yet_valid_token",),
    ),
    Defect(
        id="gate-token-expired-fail-open",
        description="An expired token is treated as authorized instead of denied.",
        file_path="src/mcc_core/gate.py",
        find='        if ts >= exp:\n            return GateResult(False, "TOKEN_EXPIRED")',
        replace='        if ts >= exp:\n            return GateResult(True, "TOKEN_EXPIRED-MUTATED-fail-open")',
        detector_tests=("tests/test_mcc_core.py::test_gate_denies_expired_token",),
    ),
    Defect(
        id="gate-non-executable-verdict-fail-open",
        description="A signed DENY/ESCALATE verdict is executed instead of denied at the gate.",
        file_path="src/mcc_core/gate.py",
        find='        if token.get("decision") not in (Verdict.ALLOW.value, Verdict.CONSTRAIN.value):\n            return GateResult(False, "NON_EXECUTABLE_VERDICT: only ALLOW/CONSTRAIN execute")',
        replace='        if token.get("decision") not in (Verdict.ALLOW.value, Verdict.CONSTRAIN.value):\n            return GateResult(True, "NON_EXECUTABLE_VERDICT: MUTATED-fail-open")',
        detector_tests=("tests/test_mcc_core.py::test_gate_denies_signed_deny_verdict",),
    ),
    Defect(
        id="gate-policy-hash-mismatch-fail-open",
        description="A token issued under an untrusted/stale policy hash is treated as authorized instead of denied.",
        file_path="src/mcc_core/gate.py",
        find='        if self.policy_hash is not None and token.get("policy_hash") != self.policy_hash:\n            return GateResult(False, "POLICY_HASH_MISMATCH: token issued under untrusted policy")',
        replace='        if self.policy_hash is not None and token.get("policy_hash") != self.policy_hash:\n            return GateResult(True, "POLICY_HASH_MISMATCH: MUTATED-fail-open")',
        detector_tests=("tests/test_mcc_core.py::test_gate_denies_policy_hash_mismatch",),
    ),
    Defect(
        id="gate-action-hash-mismatch-fail-open",
        description="A token whose action_hash does not match the action actually being executed is treated as authorized instead of denied.",
        file_path="src/mcc_core/gate.py",
        find='        if action is not None and token.get("action_hash") != hash_action(action):\n            return GateResult(False, "ACTION_HASH_MISMATCH: token does not authorize this action")',
        replace='        if action is not None and token.get("action_hash") != hash_action(action):\n            return GateResult(True, "ACTION_HASH_MISMATCH: MUTATED-fail-open")',
        detector_tests=("tests/test_mcc_core.py::test_gate_denies_action_hash_mismatch",),
    ),
    Defect(
        id="gate-payload-hash-mismatch-fail-open",
        description="A token whose payload_hash does not match the payload actually being executed is treated as authorized instead of denied.",
        file_path="src/mcc_core/gate.py",
        find='        if payload is not None and token.get("payload_hash") != hash_payload(payload):\n            return GateResult(False, "PAYLOAD_HASH_MISMATCH: payload differs from authorized one")',
        replace='        if payload is not None and token.get("payload_hash") != hash_payload(payload):\n            return GateResult(True, "PAYLOAD_HASH_MISMATCH: MUTATED-fail-open")',
        detector_tests=("tests/test_mcc_core.py::test_gate_denies_payload_hash_mismatch",),
    ),
    Defect(
        id="gate-binding-mismatch-fail-open",
        description="A token whose bound operation fields (actor/resource/transaction/etc.) differ from the operation actually being executed is treated as authorized instead of denied.",
        file_path="src/mcc_core/gate.py",
        find='                if authorized is not None and authorized != expected:\n                    return GateResult(\n                        False,\n                        f"BINDING_MISMATCH: {field} differs from authorized operation",\n                    )',
        replace='                if authorized is not None and authorized != expected:\n                    return GateResult(\n                        True,\n                        f"BINDING_MISMATCH: MUTATED-fail-open ({field})",\n                    )',
        detector_tests=("tests/test_coordinator.py::test_binding_mismatch_blocks_before_execution",),
    ),
    Defect(
        id="gate-nonce-rejected-fail-open",
        description="A replayed nonce (or a nonce registry that is unavailable/errors) is treated as authorized instead of denied -- breaks both replay protection and the registry-down fail-closed guarantee.",
        file_path="src/mcc_core/gate.py",
        find='        if not await self.nonce_registry.consume(\n            token.get("nonce"), ttl_seconds=self._nonce_ttl(exp, ts)\n        ):\n            return GateResult(False, "NONCE_REJECTED: replay or registry unavailable (fail-closed)")',
        replace='        if not await self.nonce_registry.consume(\n            token.get("nonce"), ttl_seconds=self._nonce_ttl(exp, ts)\n        ):\n            return GateResult(True, "NONCE_REJECTED: MUTATED-fail-open")',
        detector_tests=("tests/test_mcc_core.py::test_gate_denies_replayed_nonce",
                         "tests/test_mcc_core.py::test_gate_fail_closed_when_redis_down"),
    ),

    # -- PR-5: twelve targeted defects closing the PR-1->4 attestation-to- --
    # -- execution chain gap the original 26 (all pre-dating PR-1) leave --
    # -- entirely uncovered. See docs/ATTESTATION_INDEPENDENT_ASSURANCE.md --
    # -- for the full gap matrix. Each targets one named security-critical --
    # -- decision from the PR-5 task specification's own candidate list. --

    Defect(
        id="attester-trust-check-disabled",
        description="MCC-AT-001 verifier no longer resolves the attester's (attester_id, kid) against the trust store -- any attester, trusted or not, is accepted.",
        file_path="src/mcc_attestation/verifier.py",
        find="        if anchor is None:",
        replace="        if False:  # MUTATED: attester trust check disabled",
        detector_tests=("assurance/tests/test_attestation_chain.py::test_a1_forged_attestation_untrusted_key_blocked_no_actuation",),
    ),
    Defect(
        id="attester-signature-verification-disabled",
        description="MCC-AT-001 verifier no longer checks the attestation's Ed25519 signature -- a forged/tampered attestation is accepted.",
        file_path="src/mcc_attestation/verifier.py",
        find="        if not verify_token(attestation.to_dict(), anchor.public_key):",
        replace="        if False:  # MUTATED: attestation signature check disabled",
        # NOTE: assurance/tests/test_attestation_chain.py::test_a2 (a claims
        # tamper) does NOT isolate this defect -- Control's SEPARATE claim-
        # policy check still rejects a claims tamper even with signature
        # verification fully disabled, so that E2E test alone would let this
        # mutant survive (confirmed by direct verification before this
        # detector was finalized). tests/test_mcc_attestation.py's own
        # PR-1 unit test asserts the SPECIFIC "signature_verification"
        # named check's status directly, at the pure verifier boundary,
        # unaffected by any Control-layer check -- the correct, precise
        # detector for this exact defect.
        detector_tests=("tests/test_mcc_attestation.py::test_03_forged_signature_is_invalid",),
    ),
    Defect(
        id="attestation-action-binding-disabled",
        description="MCC-AT-001 verifier no longer checks the attestation's action_hash -- evidence for one action authorizes any other.",
        file_path="src/mcc_attestation/verifier.py",
        find="        if attestation.action_hash != expected_action_hash:",
        replace="        if False:  # MUTATED: action binding check disabled",
        detector_tests=("assurance/tests/test_attestation_chain.py::test_b_wrong_action_binding_blocked_no_actuation",),
    ),
    Defect(
        id="attestation-payload-binding-disabled",
        description="MCC-AT-001 verifier no longer checks the attestation's payload_hash -- evidence for one payload authorizes a mutated one.",
        file_path="src/mcc_attestation/verifier.py",
        find="            if attestation.payload_hash != expected_payload_hash:",
        replace="            if False:  # MUTATED: payload binding check disabled",
        detector_tests=("assurance/tests/test_attestation_chain.py::test_c_wrong_payload_binding_blocked_no_actuation",),
    ),
    Defect(
        id="attestation-scope-binding-disabled",
        description="MCC-AT-001 verifier no longer checks the attestation's scope -- evidence valid for one trusted scope is reusable for another.",
        file_path="src/mcc_attestation/verifier.py",
        find="        if attestation.scope != expected_scope:",
        replace="        if False:  # MUTATED: scope binding check disabled",
        detector_tests=("assurance/tests/test_attestation_chain.py::test_d_wrong_scope_blocked_no_actuation",),
    ),
    Defect(
        id="attestation-expiry-check-disabled",
        description="MCC-AT-001 verifier no longer checks whether the attestation has expired -- stale evidence is accepted indefinitely.",
        file_path="src/mcc_attestation/verifier.py",
        find="        if now >= attestation.expires_at:",
        replace="        if False:  # MUTATED: expiry check disabled",
        detector_tests=("assurance/tests/test_attestation_chain.py::test_f_expired_evidence_blocked_no_actuation",),
    ),
    Defect(
        id="attestation-replay-consumption-ignored",
        description="PreExecutionControl no longer fails closed when the attestation nonce registry reports the nonce already consumed -- the same attestation authorizes execution twice.",
        file_path="gateway/pre_execution_control.py",
        find="            if not consumed:",
        replace="            if False:  # MUTATED: attestation replay check disabled",
        detector_tests=("assurance/tests/test_attestation_chain.py::test_g_attestation_replay_second_use_blocked",),
    ),
    Defect(
        id="evidence-digest-computed-from-caller-object-not-snapshot",
        description="PreExecutionControl reverts the PR-3 TOCTOU fix: derives evidence_digest from the caller-supplied (mutable, potentially concurrently-mutated) object instead of a private snapshot taken before verification.",
        file_path="gateway/pre_execution_control.py",
        find="            raw_attestation = copy.deepcopy(raw_attestation)",
        replace="            raw_attestation = raw_attestation  # MUTATED: TOCTOU snapshot removed",
        detector_tests=("tests/test_evidence_bound_execution_ticket.py::test_17_toctou_concurrent_mutation_during_nonce_consume_cannot_bind_mutated_artifact",),
    ),
    Defect(
        id="evidence-digest-omitted-from-issued-token",
        description="DecisionEngine.issue_token never binds evidence_digest into the signed token even when Control supplied one -- PR-3's evidence-bound execution ticket silently reverts to an unbound token.",
        file_path="src/mcc_core/core.py",
        find="        if evidence_digest is not None:",
        replace="        if False:  # MUTATED: evidence_digest never bound into the token",
        detector_tests=("tests/test_evidence_bound_execution_ticket.py::test_06a_issued_token_carries_the_exact_evidence_digest",),
    ),
    Defect(
        id="gate-evidence-digest-mismatch-ignored",
        description="ExecutionGate no longer rejects an evidence artifact whose digest does not match the token's bound evidence_digest -- a substituted or mutated artifact is accepted.",
        file_path="src/mcc_core/gate.py",
        find="            if computed_digest != token_evidence_digest:",
        replace="            if False:  # MUTATED: evidence digest mismatch ignored",
        detector_tests=("tests/test_evidence_bound_execution_ticket.py::test_09_gate_denies_evidence_substitution_even_when_independently_valid",
                         "tests/test_evidence_bound_execution_ticket.py::test_10_gate_denies_mutated_evidence"),
    ),
    Defect(
        id="attester-service-caller-controlled-field-permitted",
        description="The Independent Attester Service's request schema no longer rejects unknown/bypass-shaped fields -- a caller can attach self-declared trusted output (claims, sig, verified, ...) to the request.",
        file_path="src/mcc_attester_service/app.py",
        find='    model_config = ConfigDict(extra="forbid")',
        replace='    model_config = ConfigDict(extra="allow")  # MUTATED: caller-controlled fields permitted',
        detector_tests=("tests/test_attester_service.py::test_b_caller_cannot_supply_a_bypass_shaped_field",),
    ),
    Defect(
        id="attester-service-unauthenticated-call-permitted",
        description="The Independent Attester Service's service-to-service auth check is disabled -- any caller, authenticated or not, reaches the assessment provider and signer.",
        file_path="src/mcc_attester_service/app.py",
        find="        if not x_attester_auth or not secrets.compare_digest(x_attester_auth, auth_secret):",
        replace="        if False:  # MUTATED: auth check disabled",
        detector_tests=("tests/test_attester_service.py::test_g_missing_auth_header_rejected_before_provider_is_called",
                         "tests/test_attester_service.py::test_g_wrong_auth_header_rejected_before_provider_is_called"),
    ),
    # P2-A3: Automated Audit Integrity & Fail-Closed Enforcement -- the two
    # independent enforcement boundaries this task adds. See
    # docs/AUDIT_INTEGRITY_ENFORCEMENT.md.
    Defect(
        id="audit-integrity-dispatch-gate-disabled",
        description="EnforcementCoordinator.enforce()'s audit-integrity DISPATCH-boundary check is disabled -- actuation proceeds even when audit-chain integrity is UNVERIFIED/VERIFYING/UNHEALTHY.",
        file_path="src/mcc_core/coordinator.py",
        find='            if getattr(integrity_state, "value", integrity_state) != "HEALTHY":',
        replace="            if False:  # MUTATED: audit-integrity dispatch gate disabled",
        detector_tests=("tests/test_audit_integrity_enforcement.py::test_direct_coordinator_call_blocked_when_integrity_not_healthy",),
    ),
    Defect(
        id="audit-integrity-issuance-gate-disabled",
        description="GovernanceService._integrity_gate() always permits token issuance regardless of audit-chain integrity state -- the ISSUANCE-boundary half of the P2-A3 control is disabled.",
        file_path="gateway/governance_service.py",
        find="        if state == IntegrityState.HEALTHY:\n            return None",
        replace="        if True:  # MUTATED: audit-integrity issuance gate disabled\n            return None",
        detector_tests=("tests/test_audit_integrity_enforcement.py::test_mandate_issuance_blocked_when_integrity_not_healthy",),
    ),
]

DEFECT_IDS = tuple(d.id for d in DEFECTS)

assert len(DEFECT_IDS) == 41, f"expected exactly 41 targeted defects, found {len(DEFECT_IDS)}"
assert len(set(DEFECT_IDS)) == 41, "defect ids must be unique"

GATE_FAIL_OPEN_DEFECT_IDS = tuple(d.id for d in DEFECTS if d.id == "gate-fail-open" or d.id.startswith("gate-") and d.id.endswith("-fail-open"))
assert len(GATE_FAIL_OPEN_DEFECT_IDS) == 14, (
    f"expected exactly 14 gate.py fail-open sites (one per GateResult(False, ...) "
    f"call site in ExecutionGate._verify()/verify()), found {len(GATE_FAIL_OPEN_DEFECT_IDS)}"
)
