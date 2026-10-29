# AXLOGIQ / MCC-Core — Threat Model v1.0 (STRIDE)

**Date:** 28 October 2026  
**Document status:** Proposed for independent review; NOT yet merged into the GitHub repository.  
**Proposed repository location:** `docs/security/MCC_CORE_THREAT_MODEL_v1.0.md`  
**Applies to:** MCC-Core Authority Plane, approval / mandate / consensus / attestation / Execution Gate / durable dispatch / audit and prospective signed delegation.  
**Related:** Strategic Engineering Roadmap v1.2; PR #119, #121, **current draft PR #122**; planned PR **#123** (number not yet allocated).

## 1. Security thesis and scope

MCC-Core enforces the distinction between an agent proposing an action and an independently verified right to execute that exact action. The security property is **No independently verified authority -> no execution**. Its trust model assumes integrity of the configured independent authorization and trust roots; it must not silently grant an agent those roots.

This model is a source-code and deployment design review, not a bank certification, service-level agreement, proof of adversary-invariant correctness, or a completed third-party penetration test.

**Protected assets:** signing and verifier keys, human / organizational consent and mandates, independent policy, authenticated identity and tenant, action and payload bindings, approvals and votes, TrustedTime and revocation, global limits, nonces, durable dispatch and idempotency state, executor network routes, receipts and tamper-evident audit evidence.

**Threat actors:** compromised or prompt-injected AI agent; agent framework or tool adapter; operator with stolen credentials; malicious insider; network or service-impersonation attacker; host/cloud operator; storage administrator; attacker controlling clock sources; collaborating signers; external counterparty providing false receipts.

**Trust boundaries (TB):**

- **TB-1 User / Owner -> Agent:** human identity, consent, exact delegation and purpose. Not fully implemented as a signed end-to-end delegation chain; planned PR #123.
- **TB-2 Agent -> Gateway / Authority Plane:** proposer-controlled payload, header and identity spoofing risk. Proposer must have no signing/approval capability.
- **TB-3 Authority Plane -> Signing / Trust / Clock:** independently owned keys, policies, revocation, time and evaluator quorum.
- **TB-4 Gate -> Durable State:** replay, approval consume, nonce/challenge, transaction binding and persistent one-way dispatch fence.
- **TB-5 Gate / Executor -> External Bank/API:** actual network side effect, exact outbound payload, verified external receipt and ambiguous results.
- **TB-6 MCC -> Audit / External Evidence:** integrity, append-only chain, external anchor independence and attribution limits.

## 2. Stable STRIDE threat register

The identifiers T-01 ... T-12 are stable project-wide references. **Implemented / partial / planned** statuses describe current known evidence and must be validated on the exact PR head; they are not third-party security certifications.

| ID | STRIDE category | Attack / violated invariant | Primary control / status | Required evidence / residual risk | PR mapping |
| --- | --- | --- | --- | --- | --- |
| **T-01** | **Spoofing** | Agent impersonates real owner and forges consent or changes delegated purpose | Existing actor/mandate binding; **signed owner-to-agent delegation planned** | Negative test: agent without owner signing key cannot create or expand signed consent; owner identity binding is not currently end-to-end proven | **#123 planned** |
| **T-02** | **Spoofing** | Fake bank/gateway/authority/evaluator service or forged approval credentials | Trusted keys, operator separation, signed approvals and votes; transport/workload identity deployment-dependent | Prove unauthenticated peer cannot issue valid mandate; test stolen, replaced and rotated key; mutual TLS is not implied by signatures | **#122 partial** |
| **T-03** | **Tampering** | Swap amount, payee, currency, action or final outbound payload after approval | Canonical hashing, exact payload/action binding, server-stored approval payload, Gate checks | Actuator-counted payload-substitution tests across every adapter; signed hash does not automatically prove destination or external bytes | **#121/#122; #123 extension** |
| **T-04** | **Tampering** | Spoof NTP/Redis time or roll clock back to accept expired approvals, mandates, votes or attestations | PR #122 draft TrustedTime/Redis TIME with skew/rollback detection; **authenticated UTC source NOT proven** | NTS or equivalent approved clock assurance, drift bounds, cross-instance and common-mode attacks, tested fail-closed; Redis TIME alone is not trusted UTC | **#122 partial / P0** |
| **T-05** | **Repudiation** | Owner, agent, bank or operator denies authorizing or performing transaction | Signed authority, cryptographic audit chain, verified receipts in supported integrations | Distinguish proof that key signed from proof a human knowingly consented; partner-side receipts and independent key custody necessary | **#123 planned / existing audit** |
| **T-06** | **Information disclosure** | Leakage of credentials, PII, customer budget or policy contents to agent/counterparty | Least privilege, redaction, scoped evidence; selective disclosure/ZKP **planned** | Verify data minimization across telemetry, exports, APIs and cache; ZKP never substitutes for consent/authorization | **#123 identity; P3 ZKP** |
| **T-07** | **Denial of service** | Flood gateway, Redis, time provider or Authority Plane; block business payments | Bounded operations and fail-closed; HA/Safe Degradation **planned** | Rate limiting, quotas, p99 under load, failover tests; safety may require blocking, not automatic approval | **#122 fail-closed / HA future** |
| **T-08** | **Elevation of privilege** | Compromised AI uses operator key or auto-approval to authorize its own proposal | Independent AuthorityPolicy, credential separation and separation of proposer/authorizer | Adversarial self-approval tests; reject agent-controlled policy config; check deployments not just library code | **#119/#122** |
| **T-09** | **Elevation of privilege** | Agent widens purpose, amount, merchant, recipient, time window or aggregate spend beyond delegation | Exact scoped mandate existing; owner-signed delegation + global cumulative budget **planned** | Forgeries, delegation-chain substitutions, simultaneous transactions and atomic budget exhaustion; prevent double spend | **#123 planned** |
| **T-10** | **Tampering** | State race resurrects invalidated approval, duplicate consume, or alters immutable transaction binding | Atomic Redis Lua compare-and-swap, single-use consume, immutable operation hashes | Real Redis multi-process races, failover and timeout tests, independent actual actuator count | **#121/#122** |
| **T-11** | **Denial of service / integrity** | After timeout or partition, client retries an already dispatched payment and duplicates side effects | Durable `DISPATCH_OWNED` / `UNKNOWN` semantics, idempotency, reconciliation | Distinguish pre-dispatch BLOCKED from post-dispatch UNKNOWN; no blind retry; validate cross-region durable state and receipts | **#103/#121/#122; HA future** |
| **T-12** | **Repudiation / Tampering** | External service falsely claims success or falsifies receipt; audit re-write inside compromised domain | Receipt binding in supported pilots, hash-chained audit, external checkpoints architecture | Independent trusted receipt sources and checkpoint stores; anchor compromise and partner dishonesty are residual risks | **existing pilot / Enterprise gate** |

### Scope-specific security assertions

1. A valid Ed25519 signature on a decision token establishes signature integrity under the trusted key, **not** that a human knowingly consented. T-01/T-05 requires explicit independently bound owner consent.
2. A signed request is not automatically delivered through an authenticated transport channel. T-02 requires workload identities and infrastructure controls beyond token signatures.
3. A ZKP can prove a constrained statement without disclosing a private value, but global balance accounting must still be atomic, independently controlled and replay-safe. T-09 is not solved by a proof alone.
4. Neither HA nor cached authorization may bypass current revocation, tenant, expiry, idempotency, nonce, budget or independent policy requirements. T-07/T-11 trade availability for safety when no trustworthy decision can be reached.

## 3. Trusted Time and anti-NTP-spoofing specification (T-04)

### Current implementation / actual evidence boundary

At checked PR #122 HEAD `bfc6ec1` (28 Oct 2026), the draft branch includes `src/mcc_core/trusted_time.py`: `LocalTimeSource` reads the process wall clock, while opt-in `RedisTimeSource` queries Redis `TIME` with timeouts, round-trip freshness, local-vs-Redis skew and rollback checks. Redis-backed pilot Compose files opt in to the shared time source. This is a **shared clock + drift detection**, not independent authentication of UTC. Current code does not implement authenticated NTP/NTS, HSM time or Google TrueTime. At this reviewed HEAD, time paths for consensus, challenge and attestation still require complete trust-boundary review, as do final actuation entry points.

### Required deployment architecture before finance-grade time claim

- Select and document at least two administratively independent, trusted upstream clock references where practicable, with independently monitored clock uncertainty; **NTS (RFC 8915)** is a standards-based option for authenticating NTP client-server synchronization. Simple agreement between clocks in one compromised trust domain is insufficient.
- Document OS service configuration (e.g., NTS-capable NTP daemon when selected), trust anchors, authentication status, synchronization state, maximum offset/error estimate, holdover policy, and alarm thresholds. Verify certificates and key rotation; do not invent a currently deployed NTS configuration.
- Redis TIME is an **application-level shared reference**, not an authentication service; require protected Redis transport and workload identity. Validate clock uncertainty, not just pairwise difference from a node that may itself be wrong.
- Hard fail on expired/stale samples, untrusted synchronization, rollback, contradictory references, invalid configuration (NaN/infinity/negative/out-of-bounds) and the inability to establish freshness for protected operations. Never fall back silently to uncontrolled local time.
- Define a **maximum permission-age uncertainty envelope** at validity-window boundaries (strict deny in the uncertain interval or conservative treatment); keep all revocation and nonce/fencing state authoritative.
- Keep monotonic duration counters separate from authenticated UTC validity decisions. Threat-model the exact point of actual executor dispatch, including latency between token issuance and physical transmission.

**Non-goals:** Google TrueTime is a specific database timing service, not a generic public satellite time feed; an HSM storing signing keys does not automatically establish UTC; Redis TIME alone does not prevent upstream NTP spoofing.

**Evidence gate:** replayable drift/rollback injection; NTS-disabled or spoofed upstream; multiple Gate instances; verified and expired token windows; actual elapsed time and actuator-counted tests; independent sign-off on configured sources and residual common-mode risk.

## 4. Failure modes, recovery and attribution (T-05/T-07/T-11/T-12)

| Failure moment | Correct classification | Mandatory action |
| --- | --- | --- |
| Authority unavailable or clock untrusted **before** dispatch ownership | `BLOCKED` or separate workflow `DEFERRED`; **no actuator invocation** | Queue *unexecuted proposal*, not authorized transaction; on recovery re-verify complete authority and all mutable limits. |
| Trust, audit or state unavailable before durable dispatch | `BLOCKED` | No grant; if a retry is permitted it must be newly authorized and keep exact logical-operation identity. |
| Timeout, lost acknowledgment or crash **after** durable dispatch commitment | `UNKNOWN` or durable `DISPATCH_OWNED` | Never silently retry. Reconcile against independently verified external evidence and retained idempotency state. |
| Verified externally bound receipt, durable success | `EXECUTED` | Preserve audit and reject duplicate operations. |
| Partition among quorum, Redis or trusted-clock instances | Deny/defer unless independent authority and single-use global state provably remain valid | No split-brain double-spend or fallback to lower-trust authorization. |

Human-in-the-loop may request an explanation or approve a **new** proposal, but it cannot reclassify an unresolved execution or bypass cryptographic authority. Append-only hash-chained logs prove internal linkage; non-repudiation of human consent and truthfulness of a bank receipt require independent evidence, reliable identity binding and protected key custody.

## 5. Threat-to-PR traceability and release gates

| PR / milestone | Threat IDs | Mandatory scope and evidence | Status |
| --- | --- | --- | --- |
| **#119 Independent Authority** | T-02, T-08 | Proposer cannot mint own authority, policy separate and fail-closed | Historical implemented baseline; inspect exact evidence |
| **#121 Durable safety and bindings** | T-03, T-10, T-11 | Payload binding, atomic state, durable op safety | Existing/hardening baseline; tests required |
| **#122 Security closure & clock** | **T-02, T-03, T-04, T-07, T-08, T-10, T-11** | Complete TrustedTime through all protected paths, Redis races, AuthorityPolicy deployment wiring, fail-closed and actual actuator-counted tests | **Draft/unmerged at checked HEAD; no independent sign-off** |
| **Planned #123 Verifiable Delegation** | **T-01, T-03, T-05, T-06, T-09** | Signed owner/delegation/intention, exact transaction scope, identity, revocation, atomic cumulative spending limits | Future PR; number is provisional |
| **HA/Privacy/Enterprise tracks** | T-04, T-05, T-06, T-07, T-09, T-11, T-12 | NTS/time assurance, recovery tests, zero-knowledge disclosures, trusted receipts, external security audit | Planned / independently verified evidence pending |

**PR #122 description template (insert only after this doc has been committed to repo):**

> **Threat Model Coverage:** [`docs/security/MCC_CORE_THREAT_MODEL_v1.0.md`](docs/security/MCC_CORE_THREAT_MODEL_v1.0.md) — T-02, T-03, T-04, T-07, T-08, T-10, T-11. This PR hardens atomic approval state, deployment-independent authority and clock validity boundaries. Tested evidence: [list actual CI run IDs, real Redis tests, actuator-counted E2E]. Residual risks: [explicit items]. No third-party certification claim.

**Proposed PR #123 description template (use once actual PR exists):**

> **Threat Model Coverage:** [`docs/security/MCC_CORE_THREAT_MODEL_v1.0.md`](docs/security/MCC_CORE_THREAT_MODEL_v1.0.md) — T-01, T-03, T-05, T-06, T-09. This PR implements signed consent/delegation and exact-operation intent binding, subject to demonstrated end-to-end identity and custody properties. Tested evidence: [actual signed-chain, forgery, scope-expansion, concurrent-spend tests]. Residual risks: [explicit items].

**Do not state that a PR *mitigates* an ID until the applicable path and negative tests have been independently reviewed.** The list above is intended coverage, not automatic sign-off. A future security report should maintain per-threat status as `CLOSED (evidence-linked)`, `PARTIAL`, `OPEN`, or `ACCEPTED RISK`, with owner and version.

## 6. Sources and design references

- Microsoft, *STRIDE methodology*: https://www.microsoft.com/en-us/securityengineering/sdl/practices/secure-by-design
- RFC 8915, *Network Time Security for NTP*: https://www.rfc-editor.org/rfc/rfc8915.html
- MCC-Core repository: https://github.com/mcc-prior-art/mcc-layer
- PR #122: https://github.com/mcc-prior-art/mcc-layer/pull/122
- MCC-Core code paths: `src/mcc_core/trusted_time.py`, `src/mcc_core/approvals.py`, `src/mcc_core/gate.py`, `src/mcc_core/mandate.py`, `src/mcc_core/consensus.py`, `src/mcc_core/challenge.py`, `gateway/governance_service.py`, `gateway/pre_execution_control.py`, `src/mcc_core/coordinator.py`.

**Review requirements:** repository owners decide merges; CI is self-administered evidence, not an external audit. Claims may be made only at the scope proven by available tests and deployment observations.
