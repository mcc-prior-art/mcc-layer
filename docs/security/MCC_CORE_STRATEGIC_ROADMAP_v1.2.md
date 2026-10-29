# AXLOGIQ / MCC-Core — Strategic Engineering Roadmap

**Version:** 1.2  
**Decision date:** 28 October 2026  
**Status:** Approved working engineering direction; roadmap items are not production claims  
**Scope:** MCC-Core, its Authority Plane, STRIDE security model, trusted time, operational safety and enterprise adoption

**PR #122 status snapshot (28 Oct 2026, latest checked HEAD `bfc6ec1`):** 10/10 GitHub Actions workflows successful; PR remains open/Draft/not merged. CI success does not constitute security sign-off. Clock-trust coverage of consensus, attestation, challenge and final-actuation paths requires explicit closure evidence before owner-approved merge.

## Strategic thesis

MCC-Core is a **universal Verifiable Execution Authority / independent Authority Plane** for autonomous AI systems. It cryptographically separates an agent's ability to propose an action from the independently verified right to execute it, before any financial, enterprise, cloud, or physical side effect.

**Non-negotiable rules:**

- Capability ≠ Authority. Autonomy ≠ Authorization. Proposal ≠ Permission.
- No independently verified authority → no execution.
- No bypass of independent authority for latency, availability, caching, failover, or compatibility.
- Distinguish verified engineering evidence from external certification and production operating history.

**Positioning:** Building an infrastructure component that could eventually become as fundamental to AI execution authorization as IAM is to access management and TLS is to protected communications is a *strategic aspiration*, not an achieved market status. The immediate aim is reproducible security, predictable latency, fault tolerance, verified integration and third-party assurance.

## Execution order and acceptance gates

| Priority | Workstream | Deliverables | Evidence / exit gate |
| --- | --- | --- | --- |
| **P0 — Current PR #122** | Security closure, including clock skew | Complete TrustedTime integration across approvals, mandates, decision tokens, Gate, consensus, attestation, challenge and final actuation. Prove fault handling, replay/expiry/race safety. | Independently inspect all critical production call paths; real-Redis, multi-instance and actuator-counted adversarial tests; full CI, TLA+, mutation testing; no unresolved known critical/high issue. No merge without owner's decision. |
| **P0 — Documentation & independent review** | **STRIDE Threat Model v1.0 + Trusted Time Assurance + Failure Modes** | Define actors, capabilities, trust boundaries, trusted-clock design/limitations, pre/post-dispatch state taxonomy and fault-handling runbooks. | Reviewer signs off attack assumptions; fault-injection matrix covers dependency loss, time drift, network partition, crash/recovery and unknown outcomes. Documentation is evidence-linked, not a security guarantee. |
| **P1 — Next planned PR (working label #123)** | **Verifiable Delegation & Intent Binding** | Signed delegation from authority owner to identified agent, with purpose, action, amount, currency, recipient, resource, expiry, revocation and transaction binding. Signed and independently verified user intent. | Negative controls prove that agent cannot mint, amend, expand or reuse delegated authority; exact transaction binding; atomic cumulative limits and replay protection; reproducible E2E evidence. GitHub assigns the actual PR number. |
| **P2 — Parallel engineering track** | **Low-Latency Authority Plane** | Benchmark harness and performance budget; local verification of signed proof where safe; safe delegation cache with bounded freshness and revocation-aware invalidation; precomputation/async evidence preparation *before* authorization. | Publish measured p50/p95/p99 authorization overhead, throughput and degradation under realistic concurrent financial workloads; correctness under cache races, stale state and clock failures. No invented latency SLA. |
| **P2 — Parallel engineering track** | **High Availability & Safe Degradation** | Multi-zone / active-active architecture, HA stateful services, auditable failover and recovery, redundancy of trusted time, health checks, queue-or-deny behavior, disaster recovery. | Chaos, network partition, region failover and replay tests; measurable RTO/RPO/SLO; exactly-once or conservative UNKNOWN semantics; no unsafe offline authorization or double spend. |
| **P3 — Requirements-driven** | **Privacy-Preserving Authority / ZKP** | Selective disclosure; ZKP feasibility for proving policy and budget compliance without revealing total user budget; privacy-preserving proofs linked to exact operation. | Formal statement and threat model, cryptographic review, soundness and replay tests, atomic global spent-state accounting, actual proof-generation/verification latency measurements. |
| **P3 — Interoperability / ecosystem** | **Agent Identity & Open Standards** | External agent identity verification, trust/attestation model, adapter research for Mastercard Verifiable Intent, Google AP2 and UCP; preserve adapter isolation from the trusted core. | Proven identity-binding and delegation chain, negative trust tests, cross-provider E2E, versioned contracts; no assumption that pilot support equals standards certification. |
| **Enterprise adoption gate** | **Independent evidence & partner pilots** | Third-party security assessment, documented deployment trust assumptions, bank/enterprise pilot integration, operator runbooks, reproducible benchmarks. | Independent findings addressed, monitored production-like exercise, proven performance and availability claims, explicit scope of certification. |


## v1.2 security-document governance and PR traceability

**Normative companion document to publish in GitHub:** `docs/security/MCC_CORE_THREAT_MODEL_v1.0.md` (currently prepared as a local draft, not yet committed). It includes a STRIDE threat catalog with stable IDs **T-01 ... T-12**, a data-flow and trust-boundary description, evidence status, adversarial test requirements and references to applicable code and PRs. Assign each finding a distinct ID; never renumber an existing ID after publication.

**Requirements for PR descriptions:** include a **Threat Model Coverage** subsection with the versioned, real repository link (only after the document is committed), implemented mitigations, regression tests, and residual risks. A passing PR must not claim to resolve threats that its code does not address. Current PR #122 maps primarily to **T-02, T-03, T-04, T-07, T-08, T-10 and T-11** (subject to final reviewer verification); planned PR #123 maps primarily to **T-01, T-06 and T-09** with additional coverage of T-03 and T-05. Proposed mappings are scope annotations, not security certification.

**Trusted Time / NTP-spoofing policy:** `RedisTimeSource` is a shared time reference and drift detector, **not** independently authenticated UTC. Specify the operating-system clock synchronization chain, whether NTP is unauthenticated, NTS-authenticated under RFC 8915, PTP or another approved source, key/certificate trust, source diversity, alerting and the maximum accepted uncertainty. Two clocks being consistent cannot exclude common-mode compromise. HSM-backed signing does not by itself authenticate time. NTS support is a proposed deployment safeguard, not a current MCC-Core feature. Maintain fail-closed behavior when configured time assurance is absent.

**PR timing:** do not update public PR descriptions with a link to a local-only document. First land the versioned threat model in the appropriate repository branch; then update PR #122's description and include the versioned link in future PR #123. The latter number is provisional until GitHub creates the PR.

## P0 security threat model and trust boundaries

**Protected assets:** human/organizational delegation; independent signing keys; authority policies; tenant identity; signed mandates and decision tokens; single-use counters and budget state; durable operation identity; actuator access; audit evidence; trust and time configuration.

| Attacker / scenario | Attack objective | Required controls and evidence | Residual trust boundary |
| --- | --- | --- | --- |
| **Compromised AI agent / prompt-injected planner** | Forge or expand authority, directly access actuator, manipulate payload or retry until allowed. | Strict proposal/authorizer separation; signed exact-operation binding; network-enforced actuator isolation; replay/idempotency tests; direct-outbound negative controls. | A compromised agent can still submit many valid proposals; resource abuse and rate limiting must be enforced separately. |
| **Malicious insider / stolen operator credentials** | Approve prohibited actions, alter policy, revoke logging, leak signing keys. | Least privilege, split duties, independent policy, optional N-of-M consensus, controlled signing keys, immutable/external audit evidence; key-rotation tests. | If a sufficiently privileged insider controls all authority keys, policies and audit anchors, software-only separation may fail. |
| **Network attacker / service impersonation** | Reorder/replay requests, tamper with approvals, intercept trust traffic. | Authenticated and encrypted transport, mutual service identity as appropriate, signed scoped authority, nonce/idempotency, channel/binding tests and network partition exercises. | Signed payloads do not automatically authenticate transport peers, secure credentials or block denial-of-service. |
| **Compromised cloud/host operator** | Exfiltrate keys, alter runtime code or storage, forge execution/audit. | Independent key custodianship, non-exportable HSM/KMS where applicable, workload identity and attestation, immutable checkpoints external to compromised domain, multi-domain recovery exercises. | No general protection is claimed where one adversary owns code execution, all keys and all external trust anchors. HSM/TEE integration is a future validation item, not an implemented guarantee. |
| **Compromised time / state infrastructure** | Accept expired authorizations, revive invalidated state, double-execute after partition. | Trusted Time Assurance, atomic CAS, durable idempotency, conservative revalidation, bounded freshness, fail-closed clock/registry handling. | Clock sources, synchronization and replicated single-use state must remain within documented trust assumptions. |

**Security assurance requirement:** every threat must have a named preventative or detective control, an adversarial test with non-vacuity/negative controls, and explicit out-of-scope/residual risks. ZKP is not a substitute for protection against compromised signing authority or cloud administrators. HA is not a substitute for integrity of authorization.

## P0 trusted time assurance specification

**Current code baseline (PR #122 candidate, not yet merged):** `LocalTimeSource` reads local wall time; opt-in `RedisTimeSource` queries Redis `TIME` and evaluates latency, local-vs-Redis skew, rollback and availability. Redis-backed pilot deployments select Redis clock. These checks reduce inter-instance drift, but comparing Redis TIME against a node's local clock is **not an independent attestation of correct UTC time**. A common-mode clock error remains possible. A default local clock still requires operational synchronization and is not proof of trusted time.

**Required architecture and evidence:**

1. Enumerate *every* protected time decision across approval, attestation, consensus, challenge, mandate, token issuance, Gate, and final actuator entry. Do not pass wall-clock values into monotonic velocity counters.
2. Specify clock trust model: authenticated time source(s), synchronization/health signals, measured uncertainty, maximum permitted drift, bounded sample age, rollback handling, detection of common-mode failure, and secure configuration. If independent UTC reference is unavailable, explicitly state the assumption and reject claims of strong UTC assurance.
3. Reject invalid configuration (NaN, infinity, negative and unsafe bounds). Ensure fail-closed behavior on stale/unavailable/contradictory time and never fall back silently to a weaker unvalidated source.
4. Preserve test-only synthetic clocks through isolated test interfaces; never permit proposer- or request-controlled production overrides.
5. Evaluate authenticated NTP via **NTS (RFC 8915)**, independent synchronization sources, NTP spoofing / common-mode-compromise defenses, PTP trust models and (where justified) hardware-backed timing or attestation in a **future deployment design**. Do not claim NTS, HSM-backed time, or Google TrueTime integration exists today.
6. Verify multi-gateway skew, delayed dispatch, expiry boundary, backward/forward jumps, redistribution/failover, reference loss and actuator-invocation counts under real elapsed time.

**Acceptance:** no stale/expired permission is treated as valid solely due to an untrusted local clock in a documented protected deployment; clock uncertainty and failure produce an auditable, deterministic deny/defer result. Specify actual clock error budget and source independent verification before promising finance-grade timing.

## P0 failure modes and recovery matrix

**Critical distinction:** `BLOCKED` and durable `UNKNOWN` are not interchangeable.

| Failure stage and event | Required behavior | Retry and recovery |
| --- | --- | --- |
| **Before authorization / Gate verification**: Authority Plane unreachable, time untrusted, policy or revocation state inaccessible. | **BLOCKED** (or operational **DEFERRED/QUEUED**, when a surrounding workflow safely records the unexecuted intent); **no actuator call**. | Re-evaluate against fresh independently verified authority after restoration. A queued proposal does not itself carry permission. |
| **After Gate but before dispatch ownership**: audit write/registry reservation fails, velocity unavailable, nonce/revocation check inconclusive. | **BLOCKED**, fail closed. Durable semantics must establish that no dispatch took place before treating a retry as safe. | Revalidate from the beginning; preserve idempotency, tenant and exact-operation binding. |
| **After durable dispatch commitment**: executor timeout, lost response, process crash or result-persistence failure. | **UNKNOWN** or durable **DISPATCH_OWNED**, with operation identity retained. Never report `EXECUTED` without verified receipt. | **No blind retry.** Independent reconciliation must establish the actual external outcome; an operator may initiate reconciliation but cannot waive authority or override single-use safeguards. |
| **Confirmed receipt and durable success**. | **EXECUTED** with cross-checked receipt/operation binding and audit. | Further identical operations blocked as duplicates unless explicitly distinct, newly authorized operations. |
| **Network partition / partial HA loss**. | Continue only where all required independent authority, current revocation, clock trust, global budget and single-use state remain verifiable. Otherwise block/defer. | Restore quorum/consistency, reconcile unresolved operations, resume through the normal Gate. No automatic fail-open. |

**Example:** if Gate loses connectivity to Authority Plane **before dispatch**, it must not call the external banking API. The workflow may mark the *proposal* as waiting for reauthorization; it is **not** a payment `UNKNOWN`. If connectivity or an execution receipt is lost **after committed dispatch**, the durable operation remains `UNKNOWN` or `DISPATCH_OWNED` until independent reconciliation. Human review is an escalation tool, **not a bypass**.

**Required operating artifacts:** RACI for incident response, explicit RTO/RPO/SLO hypotheses (measured, not promised), deduplication/replay protection across failover, queue retention/cancellation, reconciliation SLAs, immutable incident evidence, game-day runbooks and proof of safe recovery after network partitions.

## Enterprise evidence package and release sequencing

**Current PR #122** must close TrustedTime integration and security issues before merge; unresolved critical/high findings block sign-off. Maintain the owner-controlled merge decision. Do not broaden this PR with ZKP, payment adapters, caching, or new product features.

**Next, docs/spec phase:** publish a reviewer-ready version of this threat model and operational failure matrix. Link exact source paths, deterministic tests, CI runs and known limitations. Assign owners and change-control rules for policies and signing keys.

**Planned PR #123 (actual number assigned by GitHub):** Verifiable Delegation & Intent Binding. Must retain all PR #122 invariants, including single-use, trusted time, revocation, exact operation and durable state.

**Following engineering tracks:** (a) low-latency benchmark and safe proof caching, (b) HA and disaster recovery with real fault injection; progress both, without violating permission at execution time. **Then** ZKP and ecosystem adapters when measurable deployment requirements justify their complexity.

**Production readiness claim boundary:** until independent security assessment, real performance benchmarks, HA/failover tests and partner deployment evidence exist, describe MCC-Core as a reference/runtime engineering system with tested controls, **not** certified banking infrastructure, proven p99 SLA, or vulnerability-free execution security.

## Critical architectural constraints

### Latency
- Permit asynchronous *preparation* of attestations, credentials and candidate proofs; the final actuation boundary must synchronously verify current authorization.
- A cached **validated signature** is not sufficient authorization if revocation, nonce/single-use, budget, policy, tenant, payload or expiry can change. Cache design must protect these dimensions explicitly.
- Use benchmarks before public commitments; compare end-to-end overhead and tail latency under realistic contention.

### Privacy / ZKP
- A proof such as “this transaction is within remaining budget” must be bound to an independently authenticated commitment, exact transaction, agent, nonce, and versioned accounting state.
- Prevent parallel proofs from spending the same remaining budget twice with atomic reservation/settlement or equivalent anti-double-spend controls.
- ZKP does not replace authority, human consent, execution gating, or audit. It minimizes disclosure within that chain.

### High availability
- **Fail-closed does not mean single-instance:** build redundant trusted-authority services and state with documented failover.
- If independent authority or freshness cannot be proven, queue or deny new high-risk execution; do not silently fail open.
- Previously delegated limited authority can be used during outages only if its remaining validity, current revocation and global spending/single-use state can be verified under the chosen failure model. Otherwise block.

## Communications and claims

- The system has tested independent authorization, Ed25519-signed authority, replay prevention, durable execution-safety patterns, consensus, audit evidence, integration paths and adversarial tests. Describe scope and exact evidence.
- Historical GPT-6 Astra adversarial evidence: the documented 10-attempt live adaptive trial produced **0 unauthorized executions / 0 actuator invocations**; do not generalize this to all attacks or claim OpenAI endorsement.
- Current CI and self-administered assurance are **not** a third-party security audit, production certification, guaranteed zero vulnerabilities, or proven banking SLA.
- A plan, proof of concept, pilot and fully production-certified capability are different statuses; label each correctly.

## Development discipline

1. Finish and independently review PR #122 before merge; do not mix new product features into the hardening PR. Close remaining TrustedTime paths and demonstrate fail-closed operation before owner sign-off.
2. Produce and independently review the P0 Threat Model, Trusted Time Assurance and Failure Modes/Recovery Matrix as version-controlled evidence documents.
3. Create the next PR for delegated authority only after security closure; number #123 is provisional until GitHub assigns it.
4. Run performance and high-availability as mutually reinforcing engineering tracks; neither weakens the enforcement boundary.
5. Develop ZKP only with a sound, measurable use case and robust global accounting semantics.
6. All changes must have adversarial negative controls, reproducible test evidence, clear residual-risk disclosures and explicit owner-approved merging.

**Canonical product sentence:**  
*MCC-Core separates AI intelligence from execution authority. It independently verifies precisely scoped, cryptographically attributable permission at the point of action.*

**Canonical rule:**  
**No independently verified authority → no execution.**
