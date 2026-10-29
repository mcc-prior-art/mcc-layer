# Verifiable Delegation & Intent Binding

A **delegation** is a cryptographically verifiable, owner-signed authority
object distinct from a `Mandate` (`docs/SIGNED_MANDATES.md`). A mandate answers
*"may this subject take this action, within these bounds?"* with scopes that
the authority (`MandateAuthority`) is permitted to **clamp** on breach
(`CONSTRAIN`). A delegation answers a narrower, stricter question: *"did the
human owner, independently of the agent, consent to this exact transaction
shape, for this exact tenant and purpose, up to this exact cumulative
budget?"* — and a breach of any exact-binding field is a hard `DENY`, never a
silent rewrite.

This closes the specific gap the owner's Strategic Roadmap v1.2 and STRIDE
Threat Model v1.0 (`docs/security/`) flagged as **planned** against T-01, T-03,
T-05, T-06 and T-09: an agent could previously act under a mandate whose
*existence* implied consent, without an independently verifiable, owner-signed
consent artifact bound to the exact recipient/amount/currency/purpose of the
specific operation, and without an atomic cumulative ceiling scoped to that
one grant.

## Why an agent can never mint, expand, transfer, or replay its own authority

1. **Disjoint trust root.** `DelegationVerifier.trusted_owner_keys` is a
   dedicated `{kid: public_key}` map for *owner* identities only. It is never
   merged with `ExecutionGate`'s decision-signing trust, `MandateAuthority`'s
   issuer trust, or any key an agent holds. An agent cannot self-issue a
   delegation — it does not hold, and must never be given, an owner key.
2. **Exact fields, not scopes the authority may rewrite.** `recipient_scope`,
   `currency`, `purpose`, and `action_scope`/`resource_scope` are checked for
   an exact (or owner-chosen glob) match and denied on mismatch.
   `DelegationAuthority` never clamps a payload into a narrower shape the way
   `MandateAuthority`'s `CONSTRAIN` verdict does — binary ALLOW/DENY only.
3. **Payload-derived, not caller-asserted, binding.** `recipient`, `currency`,
   and `amount` are derived from the action's own canonical payload (the same
   payload whose hash is bound into the decision token), never from a
   separate parameter the caller could assert independently of what is
   actually dispatched. This is what prevents T-03 (tampering) — a caller
   cannot authorize against one value while a different value is executed.
4. **Fail-closed issuance.** `issue_delegation()` raises `ValueError` at
   signing time on an empty/malformed `purpose`, `action_scope`,
   `resource_scope`, `recipient_scope`, `currency`, non-positive `max_amount`,
   non-positive duration, or missing `consent_ref`. Every one of
   `DelegationAuthority`'s checks is therefore unconditional — there is no
   "empty scope means skip this check" path for an agent to exploit by
   requesting a sparsely-populated delegation.
5. **Atomic, replay-safe cumulative budget.** The delegation's spending
   ceiling is enforced through the *same* `VelocityRegistry` primitive PR #122
   hardened for cross-instance atomicity — scoped by `delegation_id`, not by
   actor — so no new accounting code path exists for an agent to find gaps in.

## Object

An Ed25519-signed claims object (`mcc_core.issue_delegation`):

| Field | Meaning |
|---|---|
| `delegation_id` | unique id; bound into the decision token (`mandate_id` slot) and the revocation registry |
| `owner_id` | the human/owner principal who signed — **not** the agent |
| `subject` | the agent/delegate the grant is issued to |
| `tenant_id` | exact tenant binding |
| `purpose` | exact classification of what the grant is for (e.g. `"invoice_payment"`) |
| `action_scope` / `resource_scope` | glob patterns, like a mandate |
| `recipient_scope` | glob pattern the payload's recipient must match |
| `currency` | exact currency the grant is denominated in |
| `max_amount` | the delegation's cumulative ceiling (not a per-transaction cap) |
| `nbf` / `exp` / `iat` | validity window and issuance time |
| `revocation_required` | whether a live revocation check is mandatory (default `True`) |
| `consent_ref` | an independently verifiable reference to the owner's consent evidence (e.g. a signed consent-capture receipt id) |
| `policy_hash` | optional trust-set/policy-version binding |
| `kid` / `sig` | Ed25519 signature metadata, under the **owner** trust root |

`REQUIRED_FIELDS` in `src/mcc_core/delegation.py` is the authoritative list;
`DelegationVerifier` rejects any delegation missing one as `MALFORMED_DELEGATION`.

## Verification order (fail-closed)

`DelegationVerifier.verify` runs, and denies on the first failure:

1. **signature & trusted owner** — `INVALID_DELEGATION_SIGNATURE` / `UNTRUSTED_OWNER`
2. **structural completeness** — `MALFORMED_DELEGATION`
3. **validity window** — `DELEGATION_NOT_YET_VALID` / `DELEGATION_EXPIRED`
4. **subject** — `SUBJECT_MISMATCH`
5. **tenant** — `TENANT_MISMATCH`
6. **action scope** — `ACTION_SCOPE_MISMATCH`
7. **resource scope** — `RESOURCE_SCOPE_MISMATCH` (unconditional)
8. **policy binding** — `POLICY_BINDING_MISMATCH`
9. **revocation** — `DELEGATION_REVOKED` / `REVOCATION_UNAVAILABLE` / `REVOCATION_REQUIRED`

`DelegationAuthority.authorize` then layers, also unconditional and also
fail-closed on any exception (`DELEGATION_ERROR`):

10. **purpose** — `PURPOSE_MISMATCH`
11. **recipient scope** — `RECIPIENT_SCOPE_MISMATCH`
12. **currency** — `CURRENCY_MISMATCH`
13. **amount** — `INVALID_AMOUNT` (non-numeric) / `AMOUNT_EXCEEDS_DELEGATION`

## Atomic cumulative budget

`delegation_velocity_limit(delegation)` builds a `VelocityLimit` named
`delegation:{delegation_id}`, aggregated by `("delegation",)` (never by
actor — the ceiling is a property of the *grant*, not of who happens to be
using it), with `window_seconds = max(1, exp - nbf)` so the budget spans
exactly the delegation's own validity window — it cannot "forget" earlier
spend while the delegation itself is still alive, and it cannot outlive the
delegation either.

The reservation is made through `EnforcementCoordinator`'s existing
`VelocityRegistry` (`InMemoryVelocityRegistry` for dev/tests,
`RedisVelocityRegistry` for durable cross-instance deployments) — the same
primitive PR #122 proved atomic under concurrent, cross-instance load. No new
accounting code path was introduced for this feature.

## Binding the authority to the decision token and execution

`GovernanceService.execute_with_delegation(...)`:

1. Canonicalizes the payload via the action's `ActionProfile` **first**.
2. Derives `recipient`, `currency`, and `amount` from that canonical payload —
   never from independently-supplied parameters (T-03 closure; see point 3
   above).
3. Resolves `purpose` and `tenant_id` as trusted, server-resolved parameters
   — never read from agent-supplied context.
4. Calls `DelegationAuthority.authorize(...)` against the canonical values.
5. Atomically reserves against the delegation's cumulative velocity limit.
6. Issues the decision token with `max_exp=delegation.exp` and
   `mandate_id=delegation_id` — the token can never outlive its delegation,
   and records which grant authorized it.
7. Runs the actuation through the same coordinator path (`gate → idempotency
   → velocity → audit-before-actuation → execute → finalize`) as every other
   execution path.
8. Releases the velocity reservation **only** when the final result is
   `BLOCKED` (pre-dispatch — no external effect occurred, so releasing is
   safe). It never releases on `EXECUTION_FAILED` or `UNKNOWN`: the external
   effect may have already happened, and releasing an ambiguous outcome's
   reservation could enable a genuine double-spend.

## A pre-existing defect this work found and fixed (not a security vulnerability)

While building the delegation velocity path, exercising `now=None` end to end
(the production shape — `EnforcementCoordinator.enforce()` is never called
with an explicit `now` outside tests; see the static guard in
`tests/test_velocity.py`) surfaced a correctness defect already present in the
merged PR #122 coordinator code: `VelocityRegistry.reserve()` and `.release()`
each independently resolve their own fresh clock reading when `now=None`.
Both registries correlate a release to its reservation by exact timestamp
equality, so `EnforcementCoordinator._release()` re-resolving a *fresh* `now`
at release time (instead of carrying back the exact value the reservation was
stored under) made the release silently no-op — it reported success but left
the reservation in place, leaking budget until the sliding window aged it out
naturally.

This is **not** a security vulnerability: it fails toward over-conservative
denial (a leaked reservation makes the *next* legitimate operation more
likely to be denied), never toward unauthorized execution. It is a genuine
availability/correctness defect, now fixed:

* `VelocityOutcome` carries the exact `now` each `reserve()` call resolved.
* `EnforcementCoordinator.enforce()` threads that per-reservation value
  through `reserved_limits` and passes it back, unchanged, to the matching
  `release()` call — instead of reusing the outer, separately-resolved `now`.

Regression coverage:
`tests/test_coordinator.py::test_velocity_release_matches_its_own_reservation_in_production_shape`
drives two limits through the coordinator with `now` omitted entirely
end-to-end (real wall-clock issuance and enforcement). Confirmed non-vacuous
by reverting only `src/mcc_core/velocity.py` and `src/mcc_core/coordinator.py`
(a narrowly-scoped `git stash` excluding the delegation feature itself) and
observing the test fail exactly as predicted before the fix, then pass again
once restored.

## STRIDE threat coverage (T-01, T-03, T-05, T-06, T-09)

Per `docs/security/MCC_CORE_THREAT_MODEL_v1.0.md`'s existing register. Status
is this PR's own honest assessment, not an independent certification.

| Threat | What this PR adds | Status | What is still open |
|---|---|---|---|
| **T-01** Spoofing (agent impersonates owner / forges consent) | Dedicated owner trust root disjoint from agent/mandate-issuer keys; `consent_ref` is a mandatory, signature-covered field | **Partially mitigated** | `consent_ref` is a *reference* this code verifies is present and bound into the signed claims — it does not itself independently verify that the referenced consent-capture event was genuinely a human action (e.g. a live biometric/2FA ceremony). Proving that requires an external, out-of-band consent-capture system this PR does not implement. |
| **T-03** Tampering (swap amount/payee/currency/action/payload after approval) | Recipient/currency/amount derived exclusively from the canonical payload the token's hash covers, never from a separately-asserted parameter; adversarial tests assert zero actuator invocations on every substitution attempt | **Fully mitigated for the delegation path** | Only covers paths that go through `execute_with_delegation`. The pre-existing `execute_with_mandate` path (and any direct `EnforcementCoordinator.enforce()` caller) is unchanged and was already covered by PR #121/#122's binding tests — not newly hardened by this PR. |
| **T-05** Repudiation (owner/agent/bank denies authorizing or performing) | Signed delegation + existing cryptographic audit chain; `delegation_id` recorded in every audit entry for the operation | **Partially mitigated** | A valid Ed25519 signature proves the owner's key signed the claims, not that the owner knowingly, contemporaneously reviewed *this* transaction. Non-repudiation against a compromised or coerced owner key, or a key signed once and reused unattended for many future transactions, is out of scope here — see `consent_ref` limitation under T-01. |
| **T-06** Information disclosure (leakage of credentials/PII/budget/policy) | No new disclosure surface: delegation claims carry only scopes/ids/consent-reference, never raw PHI/credentials; audit entries record `delegation_id` and hashes, not raw payload | **Not newly addressed; no regression** | Selective disclosure / zero-knowledge proof of delegation scope (so a verifier can confirm "within budget" without learning the exact ceiling or counterparty) remains **planned** (roadmap P3), exactly as the threat model states. This PR does not implement it. |
| **T-09** Elevation of privilege (agent widens purpose/amount/recipient/time/aggregate spend) | Every exact-binding field is unconditionally checked and denies on mismatch (no clamp); atomic cumulative ceiling scoped to the delegation, enforced via the PR #122-hardened `VelocityRegistry`; adversarial tests cover forgery, scope escalation, split-transaction spend, and concurrent cross-instance spend | **Fully mitigated for grants issued through this path** | Coverage is bounded by the trust assumption that the owner key itself is never compromised and that `trusted_owner_keys` is provisioned correctly in deployment config — this PR does not add owner-key custody/HSM integration, which remains an operational/deployment concern outside this code. |

## Architectural limitations (apply to all five threats above)

* **No live consent-capture ceremony.** This PR implements the verification
  and binding of a signed delegation claim; it does not implement (and does
  not claim to implement) the system that would capture the owner's
  real-time, informed consent before the claim is signed. `consent_ref` is a
  required field and its presence is enforced, but its *provenance* is
  outside this PR's code.
* **Owner-key custody is a deployment concern.** `trusted_owner_keys` must be
  provisioned, rotated, and protected by the deploying operator exactly as
  `trust.py`'s existing multi-issuer trust set is. This PR adds no new
  key-management tooling.
- **Single delegation per operation.** The current design does not model
  delegation *chains* (owner → sub-delegate → agent); `subject` is checked
  against exactly one grant. Multi-hop delegation, if ever required, is a
  distinct future design, not an extension of this object as-is.
* **Only the `execute_with_delegation` path is hardened by this PR.** Other
  execution paths (`execute_with_mandate`, direct coordinator callers) are
  unchanged.

## Evidence required for independent security sign-off

This PR's own test suite (unit + end-to-end adversarial, listed in
`tests/test_delegation.py` and `tests/test_delegation_governance_service.py`)
demonstrates the properties above against the code as written. It does
**not** by itself constitute independent sign-off. An independent reviewer
would additionally need:

1. Review of `trusted_owner_keys` provisioning in the actual deployment
   config used (this PR ships no deployment wiring for it beyond the
   `GovernanceService` constructor parameter).
2. Independent verification of the external consent-capture system that
   produces `consent_ref` values, which this PR treats as an opaque,
   already-verified reference.
3. A real-Redis, multi-process run of the concurrent-spending test
   (`tests/test_delegation_governance_service.py`'s Redis-gated case) in the
   target deployment topology, not just the in-memory-backend companion test
   that runs unconditionally in CI.
4. Review of key-custody/HSM practices for the owner signing key, which is
   outside this PR's code.
5. Confirmation that no other execution path in the codebase can reach the
   same actuator without going through either `execute_with_delegation` or
   `execute_with_mandate` (a topology/wiring review, not a unit-test claim).

No claim of complete security is made for this PR in isolation.
