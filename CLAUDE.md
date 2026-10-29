# CLAUDE.md — MCC-Core / AXLOGIQ

## Project Identity

**Repository:** `mcc-prior-art/mcc-layer`  
**Organization:** AXLOGIQ Inc. (Delaware C-Corp)  
**Founder/Architect:** Alexandr Ponomariov (AX)  
**Purpose:** Public prior art record + reference implementation of MCC-Core — execution governance infrastructure for autonomous AI systems.

-----

## Core Doctrine

> **“Intent is not authority. Execution requires a verified decision.”**

The canonical four-line formula — never deviate from this wording:

```
The model proposes.
MCC-Core decides.
The gate enforces.
The audit chain records.
```

MCC-Core is **not** AI safety tooling.  
MCC-Core is **architectural maturity infrastructure** — the missing layer between AI agent intent and real-world execution.

-----

## Decision Logic

Four verdicts. No others.

|Verdict    |Meaning                                            |
|-----------|---------------------------------------------------|
|`ALLOW`    |Execution authorized, token signed                 |
|`DENY`     |Execution blocked, gate closed                     |
|`ESCALATE` |Requires human authorization before execution      |
|`CONSTRAIN`|Execution permitted within modified parameters only|

**Default behavior: fail-closed.** If MCC-Core does not issue a signed ALLOW token, the gate does not open. Ever.

-----

## Architecture

```
AI Agent → [Intent/Action Request]
              ↓
         MCC-Core
         ┌─────────────────────────────────┐
         │  Policy Evaluation Engine        │
         │  Ed25519 Decision Token Signing  │
         │  Nonce Registry (replay protect) │
         │  Revocation List Check           │
         └─────────────────────────────────┘
              ↓
         Execution Gate (fail-closed)
              ↓
         Append-Only Hash-Chain Audit Log
```

**Vertical products built on MCC-Core:**

- `MCC-I` — Infrastructure / Cloud
- `PayGuard AI` — Financial transaction governance
- `ProcureGuard AI` — Procurement governance
- `MCC-R` — Robotics
- `MCC-H` — Healthcare (future)

-----

## Technical Stack

**Language:** Python  
**Version:** v1.10.1-stable-professional  
**Signing:** Ed25519 (asymmetric) — not HMAC. Do not introduce HMAC references.  
**Audit log:** Append-only hash-chain with `fsync` on every write  
**Replay protection:** Redis-backed nonce registry  
**Policy:** `PolicyBundle` with hash verification  
**Serialization:** Canonical (deterministic field ordering before signing)

-----

## Naming & Terminology Rules

- Repository name: `mcc-prior-art` (not `mcc-prior-auth` — watch for this typo in footers/exhibits)
- Product name: **MCC-Core** (hyphenated, capital M, C, C)
- Company: **AXLOGIQ** (all caps)
- Signing: **Ed25519** — never write “HMAC” unless explicitly discussing a legacy comparison
- “Multi-Context Consensus” — do not expose in marketing without corresponding code implementation

-----

## Brand / Visual

|Token       |Value                                                              |
|------------|-------------------------------------------------------------------|
|Deep Indigo |`#0A0F1A`                                                          |
|AX Cyan     |`#00B8DB`                                                          |
|Primary font|Eurostile Next Bold (headings), Inter (body), JetBrains Mono (code)|

-----

## Positioning (LinkedIn / Public)

Primary positioning statement:

> **“Execution governance is not post-factum approval.”**

Secondary hook (Cowork context):

> **“Cowork executes. MCC decides whether it can.”**

Target audiences by product:

- **PayGuard AI** → CFO, Head of Risk, AML/Compliance officers
- **ProcureGuard AI** → CPO, Head of Procurement
- **MCC-I** → CTO, Head of Infrastructure
- **NIW case** → Framing: national interest infrastructure standard, analogous to TCP/IP / TLS

-----

## What This Repo Is

1. **Prior art record** — timestamped public documentation of MCC-Core architecture, published April 22, 2026
1. **Reference implementation** — Python codebase with 20+ tests demonstrating the governance layer
1. **Doctrine repository** — MCC-Core Doctrine Lines v1.0, four-role governance formula, Mermaid architecture diagrams

When editing docs or code, treat this repo as a **legal and commercial artifact**, not just a codebase.

-----

## Code Conventions

- All decision tokens must be Ed25519-signed before returning
- Gate functions must be **fail-closed** — default `DENY` on any exception
- Audit log entries must be written with `fsync` — no buffered writes
- Nonce must be checked before policy evaluation — reject replays early
- `PolicyBundle` hash must be verified on load — reject tampered bundles
- Tests must cover: ALLOW, DENY, ESCALATE, CONSTRAIN paths + replay rejection + revocation

-----

## Do Not

- Do not add dependencies without explicit approval
- Do not change the canonical four-line formula wording
- Do not use “HMAC” in signing-related code or docs
- Multi-Context Consensus 3/3 is now implemented in code (`src/mcc_core/consensus.py` — N-of-M signed evaluator votes, `docs/MULTI_CONTEXT_CONSENSUS.md`); referencing it is unblocked. Keep all claims aligned with the actual N-of-M implementation — do not over-state beyond what the code does
- Do not soften the fail-closed default — it is a design principle, not a configuration option

-----

## Forward Architecture Rules

Mandatory invariants for work that has **not** landed yet. They exist so future
extensions widen the system through the correct layer instead of bypassing the
governance boundary. Do not violate these even if a task seems to ask for it —
flag the conflict to AX first.

### 1. MCP Adapter Boundary

MCP (Model Context Protocol) may be added later **only** as an ingress adapter /
ecosystem entrypoint. It is a client surface, not an authority.

- MCP must **not** become an execution authority.
- MCP must **not** introduce its own executor.
- MCP must **not** call external upstream services directly.
- Any future `integrations/mcp/` code must reach execution **only** through
  `MccClient` / the MCC Gateway / the governed contract — the same boundary the
  VoltAgent and reference-agent integrations already use.

```
MCP Client / Tool Call
        ↓
MCP Adapter (ingress only)
        ↓
MCC Gateway / governed contract
        ↓
Policy / Authority / Decision
        ↓
Execution Gate
        ↓
Governed Executor
        ↓
Receipt + Audit
```

- `integrations/mcp/` must ship with a **static CI guard** modeled on
  `tests/test_mcc_agent_no_direct_egress.py`. The guard must fail on:
  - imports of `egress_proxy.executor`
  - use of `HTTPEgressExecutor`
  - direct HTTP clients used for upstream execution
  - any direct upstream-execute method that bypasses the MCC Gateway

### 2. Real-Clinic / PHI Compliance Gate

Mock clinic workflows (the AXFlow pilot) are **not** real-clinic production
workflows. Introducing a real clinic, real patient data, or PHI is a **separate
milestone gated on compliance**, never an ordinary product PR.

- Before any real clinic / real patient data / PHI is introduced, MCC-Core must
  pass a dedicated compliance gate covering: PHI, GDPR/HIPAA-like handling,
  consent, retention, deletion / right to erasure, legal responsibility, and
  clear production disclaimers.
- Clinical or diagnostic requests remain **denied by design**.
- Raw `patient_request`, raw payload, or PHI must **not** be written directly
  into the append-only audit hash-chain. (Append-only immutability conflicts
  with GDPR-style erasure rights if raw PHI is recorded directly.)
- Required future architecture **before** any PHI:
  - the audit chain stores only hash / token / redacted fields;
  - raw patient data lives in separate, deletable storage;
  - consent and retention rules govern that storage;
  - the audit proves *what* happened without exposing *who* it happened to.
- Until that gate passes, AXFlow is presented only as a clinic revenue / booking
  **workflow simulator** — not medical advice, not a medical device, not
  production-certified.

### 3. G7 / NIW Evidence Track Separation

G7 evidence is a **legal / NIW evidence track**, not an engineering PR track.

- The engineering roadmap answers *what the system can do*; G7 evidence answers
  *how the system is proven for NIW / USCIS*. Keep them synchronized but never
  merged into one PR scope.
- Do not mix G7 / NIW evidence artifacts into product or engineering PR scope
  unless AX explicitly asks for it.
- PR titles, descriptions, and milestone wording used in NIW / expert materials
  must stay synchronized with the **actual** GitHub PR titles and contents — a
  mismatch between an exhibit and the real PR is a reviewable discrepancy.

-----

## Repository File Map

```
mcc-layer/
├── CLAUDE.md                                           ← this file
├── README.md                                           ← primary public prior art document
├── pyproject.toml           ← root distribution `mcc-core` (PR #40; extended PR #50): packages `mcc` facade + `mcc_adapter_sdk` + `mcc_protocol` + curated GOVERNANCE-FREE subsets of mcc_core (signing/version/__init__) & mcc_compliance (capability_profile/models/__init__); depends on mcc-client + cryptography + prometheus-client; optional [gateway]/[dev]/[release]; no governance logic
├── setup.py                 ← PR #50 narrow packaging correction: custom build_py ships ONLY the governance-free modules of mcc_core/mcc_compliance (excludes gate/authority/consensus/coordinator/mandate/audit/nonce/policy/velocity/idempotency/challenge/approvals/profiles/redis_client/core + compliance runner/reporting/program/registry/adapters/certification/protocol/cli). Metadata stays in pyproject
├── mcc/                     ← stable public import namespace (PR #40): thin facade re-exporting mcc_client unchanged (from mcc import MCCClient); no local decisions/transport/signing; py.typed; _version.py = single-source version (PR #41, pyproject dynamic attr)
├── RELEASING.md             ← PR #41 release runbook: Trusted Publishing (OIDC, no tokens), version bump, preflight, TestPyPI/PyPI, emergency yank, failed-release recovery
├── MCC-Core_Decision_Boundary_Doctrine_2026-06-02.md   ← doctrine (protected)
├── MCC-Core_Doctrine_Lines_v1_0_2026-06-02.md          ← doctrine (protected)
├── MCC-Core_Non-Post-Execution_Principle_2026-06-02.md ← doctrine (protected)
├── RUNTIME_DEPLOYMENT.md    ← production notes: signing key, env vars, fail-closed ops
├── main.py                  ← runtime: OPA adapter + Ed25519 decision tokens
├── mcc.yaml                 ← declarative policy reference (thresholds = rego canon)
├── policies.yaml            ← declarative policy reference (thresholds = rego canon)
├── requirements.txt         ← runtime deps (incl. cryptography for Ed25519)
├── requirements-dev.txt     ← dev deps (pytest)
├── Dockerfile / docker-compose.yml
├── audit.jsonl              ← hash-chain audit log (genesis 2026-04-22)
├── test_vectors.json
├── .github/
│   └── workflows/
│       └── mcc-runtime-ci.yml ← CI: pytest + MCC invariant checks
├── src/
│   └── mcc_core/
│       ├── core.py            ← decision engine: ALLOW/DENY/ESCALATE/CONSTRAIN → signed token
│       ├── gate.py            ← fail-closed execution gate
│       ├── audit.py           ← append-only hash-chain log (fsync on every write); P2-A2: _read_last_entry() backward-seeks via _tail_last_nonblank_line() (O(tail), not O(file size)) instead of a full forward scan -- same lock, same re-read-under-lock, same fail-closed/rollback/AuditCorruptionError semantics; verify_chain() unchanged (full scan by design, see docs/AUDITLOG_OPTIMIZATION.md); P2-A3 adds exactly one new public method, verify_chain_safe() (verify_chain() inside the SAME inter-process lock append() uses) -- append()'s own hot path untouched
│       ├── audit_integrity.py ← P2-A3: Automated Audit Integrity & Fail-Closed Enforcement (docs/AUDIT_INTEGRITY_ENFORCEMENT.md) -- UNVERIFIED/VERIFYING/HEALTHY/UNHEALTHY state machine; AuditIntegrityMonitor (startup + periodic verify_once() via verify_chain_safe(), explicit trusted-bootstrap policy, freshness-grace staleness); dual-backend IntegrityStateRegistry (InMemory + Redis, monotonic-generation CAS, no silent fallback) mirroring nonce/challenge; enforced at two independent boundaries (GovernanceService._integrity_gate at issuance, EnforcementCoordinator.enforce()'s first statement at dispatch) via MCC_REQUIRE_AUDIT_INTEGRITY, both opt-in/backward-compatible (default None)
│       ├── nonce.py           ← replay protection: RedisNonceRegistry (multi-instance) + InMemory; env-selectable, no silent fallback
│       ├── idempotency.py     ← business-operation idempotency: RESERVED/EXECUTED/FAILED lifecycle, Redis+InMemory, fail-closed
│       ├── velocity.py        ← atomic velocity/aggregate limits (count, cumulative amount, new destinations); anti-splitting
│       ├── profiles.py        ← domain-neutral ActionProfile + PaymentProfile + InfraProfile + RoboticsProfile (canonical payload + auth_claims)
│       ├── coordinator.py     ← EnforcementCoordinator: a-h order (gate→[require_consensus]→[challenge-consume]→revocation→approval-consume→idem→velocity→audit→execute→finalize); P2-A3: optional integrity_monitor (default None) checked as enforce()'s VERY FIRST statement -- the dispatch-boundary fail-closed audit-integrity gate, independent of GovernanceService's own issuance-boundary gate
│       ├── mandate.py         ← signed, revocable mandates: issue/verify (fail-closed), MandateAuthority, revocation registry (Redis+InMemory)
│       ├── delegation.py      ← Verifiable Delegation & Intent Binding: owner-signed Delegation (exact purpose/action/resource/recipient/currency/amount/tenant/consent_ref binding; dedicated owner trust root, never merged with mandate-issuer/agent keys); DelegationVerifier (fail-closed, binary) + DelegationAuthority (ALLOW/DENY only, never clamps); delegation_velocity_limit/descriptor (reuses VelocityRegistry, scoped by delegation_id, window spans the grant's own validity)
│       ├── approvals.py       ← ESCALATE loop: ApprovalService + state machine + single-use signed approval mandate (Redis+InMemory)
│       ├── consensus.py       ← Multi-Context Consensus: N-of-M independent Ed25519-signed evaluator votes (pre-token authority step + mandatory enforcement; binds action/actor/payload/resource/policy_hash/nonce)
│       ├── challenge.py        ← consensus challenge: gateway-issued one-time nonce; single-use TTL-bound ChallengeService + registries (Redis+InMemory); consumed once before actuation (clients never generate the nonce)
│       ├── policy.py          ← PolicyBundle with hash verification
│       ├── authority.py       ← config mandate registry + action→authority→verdict (the formula in code)
│       └── signing.py         ← Ed25519 token signing/verification
│   └── mcc_evidence/          ← Governance Evidence Bundle Core (PR #42): observational, downstream of decision/gate/audit; NO executor/gate/nonce/actuator/transport imports. Reuses mcc_core.signing (canonical/sha/verify_token) + audit-linkage recompute
│       ├── schema.py          ← versioned bundle schema (mcc-evidence/1) + structured VerificationResult (integrity_valid/signer_verified/signer_trusted/authority_evidence_verified/overall_status) + EvidenceStatus (VERIFIED/DENIAL_VERIFIED/INTACT_UNTRUSTED_SIGNER/INVALID/UNSUPPORTED_SCHEMA)
│       ├── export.py          ← export_bundle: fail-closed, deterministic dir or .tar.gz; ALLOW carries signed token+receipt, DENY never fabricates a receipt; refuses inconsistent evidence
│       ├── verify.py          ← verify_bundle: offline; digests + manifest↔token bindings + audit-chain recompute + signature (trusted key) + exec/denial consistency; never mutates/executes
│       └── cli.py / __main__.py ← python -m mcc_evidence verify <bundle> (JSON + human; exit 0 VERIFIED/DENIAL_VERIFIED, 1 INTACT_UNTRUSTED_SIGNER, 2 INVALID, 3 UNSUPPORTED_SCHEMA); read-only, no network. NOT in the mcc-core wheel (PR #41 contract intact); extraction seam for a future standalone mcc-evidence dist
│   └── mcc_compliance/         ← Integration Contract Compliance & Certification Suite (PR #44): observational, downstream; NO new authorization/execution/bypass. Certifies an adapter vs a contract version through ONE framework-neutral boundary, driving a REAL in-process governed stack + ground-truth cross-checks. Reuses mcc_core.signing (digests/fingerprint) + mcc_client.contract (CONTRACT_VERSION/error taxonomy). Fail-closed. NOT in the mcc-core wheel
│       ├── protocol.py         ← framework-neutral ComplianceAdapter boundary (describe→AdapterMetadata, run_scenario→AdapterOutcome) + AdapterContext; experimental/internal
│       ├── models.py / registry.py ← result models + stable ComplianceErrorCode taxonomy; strict fail-closed vector-manifest load (dup-id/unknown-type/unsupported-version rejected, no implicit fallback) + adapter registry
│       ├── runner.py / certification.py ← deterministic runner (real stack, ground-truth receipts+audit cross-check, replay probe) + fail-closed certification (all mandatory must pass; % informational) + stable fingerprint (excludes timestamp)
│       ├── reporting.py / cli.py / __main__.py ← JSON + Markdown + certification.json (no secrets/paths); python -m mcc_compliance certify --adapter <a> --contract-version <v> (exit 0 CERTIFIED / 1 NOT_CERTIFIED / 2 ERROR)
│       ├── adapters.py         ← conforming reference + voltagent adapters (SAME generic boundary; no special-case). VoltAgent = conforming reference INTEGRATION, not the reference specification
│       ├── program.py          ← Certified Adapter Program (PR #46): certify(adapter, contract_version)→CertificationResult derived SOLELY from the compliance result (no self-attestation, no wall-clock); deterministic evidence_digest (sha256 over adapter id+version/contract/vector-set/ordered scenarios/invariants/status); build_manifest/verify_manifest for certifications/manifest.json (regenerate+canonical-compare→tamper/stale/regression detection); link_capability_profile (PR #47 trust-ladder linkage, report-only). No governance/Gate/signing/network
│       ├── capability_profile.py ← Governance Capability Profile (PR #47): DECLARATIVE, framework-neutral, versioned. validate_profile (pure-Python schema+semantic, fail-closed; stable ProfileErrorCode) + canonicalize_profile/profile_digest (reuse mcc_core.signing). Vocabulary single-sourced from mcc_client.contract.REQUIRED_SECURITY_INVARIANTS (baseline) + closed optional set (escalation/constrain/evidence-bundle). "declared<validated<certified<authorized" never conflated; capability support ≠ execution permission. No runtime governance change
│       ├── vectors/v1/manifest.json ← 18 versioned golden vectors for contract v1.0 (IC-V1-*: allow/deny/constrain/escalate/malformed/no-auth/expired/replay/scope/actor/policy-hash/signature/tamper/bypass/audit/unknown-verdict/adapter-error); each maps to a normative invariant; immutable once released
│       ├── sdk_reference_adapter.py ← PR #51: SdkReferenceAdapter — reference mcc_adapter_sdk.Adapter (fixture, NOT a framework integration) expressing the four-verdict reference behaviour on the SDK; reuses reference_governed_agent.actions payload builder (identical proposals→identical verdicts). Purely translational
│       ├── sdk_bridge.py ← PR #51: SdkComplianceAdapter — the Adapter SDK is the CANONICAL certification ingress. Bridges any mcc_adapter_sdk.Adapter into the EXISTING ComplianceAdapter boundary (ONE engine, no 2nd pipeline): per vector, exercises the adapter's SDK surface via AdapterRunner+CanonicalIngressPipeline (evaluate through the governed mcc_client), then drives governed execution via the SAME governed path the reference agent uses (harness executes, not the adapter). Fail-closed; no gate/authority/signing imports
│       └── sdk_certification.py ← PR #51: stable API certify_sdk_adapter/run_sdk_certification/write_certification + deterministic docs (certification.json[schema-versioned] / evidence.json[report.stable_dict] / certification-report.md); reuses program.certify(include_timestamp=False) + reporting; NO wall-clock/random-ids/paths → byte-reproducible. Exposed via mcc_compliance.__init__; CLI `certify-sdk`
│   └── mcc_protocol/           ← Canonical Governance Protocol & Canonical Ingress Pipeline (PR #49): RECONCILED with PR #43 — ONE normative wire contract, no parallel hierarchy, no semantic drift. PROTOCOL_VERSION IS CONTRACT_VERSION; reuses check_version_compatibility + ContractErrorCode + mcc_client.Verdict/Decision + PR#47 capability vocabulary + mcc_core.signing (pure hash only). Pure in-process library; NOT a 2nd gateway/engine/auth path; NO gate/authority/consensus/executor/signing-authority imports. NOT in the mcc-core wheel
│       ├── proposal.py         ← CanonicalProposal: the normative governance REQUEST (additive — SDK had none). Full field set (contract_version/proposal_id/trace_id/correlation_id/adapter+framework identity/actor/principal/action/resource/scope/authority+policy+risk context/action_hash/nonce/issued+expires/payload/metadata). create() fills defaults; validate() fail-closed; action_hash is a proposal-integrity/trace hash (NOT the Gate's authoritative binding)
│       ├── decision.py         ← GovernanceDecision: response ENVELOPE that WRAPS (never replaces) mcc_client.Decision + Decision Token by reference; verdicts are mcc_client.Verdict; reason_codes ⊆ ContractErrorCode. from_decision(proposal, decision)
│       ├── version.py          ← PROTOCOL_VERSION == CONTRACT_VERSION; negotiate() delegates to check_version_compatibility (unknown major fails closed, no downgrade)
│       ├── registry.py         ← AdapterRegistry/AdapterDescriptor: INFORMATIONAL only (id/framework/version/supported protocol versions/capabilities[PR#47 vocab]/conformance ref); grants NO authority, no certification/trust decision. Distinct from mcc_compliance.registry (test-factory registry)
│       ├── pipeline.py         ← CanonicalIngressPipeline: the ONE mandatory in-process pipeline (schema→protocol→version-negotiation→adapter-registry→capability→enrichment→policy-context→routing), fail-closed throughout; reaches the gateway ONLY via an injected Router (mcc_client) — imports no gateway/gate internals; never authorizes/evaluates/signs
│       ├── observability.py    ← PipelineMetrics: bounded-cardinality Prometheus on an ISOLATED registry (requests/verdicts/failures[stage+code]/routing/latency/version usage); no payload/secret in labels; instrumentation only
│       └── errors.py           ← IngressStage + IngressError: NO new stable taxonomy — every failure classifies into ContractErrorCode (fail-closed to CONTRACT_FIELD_INVALID/INTERNAL_ERROR); stage is an observability label only
│   └── mcc_adapter_sdk/        ← Adapter SDK (PR #50): the small, stable, PUBLIC façade third parties use to build adapters WITHOUT importing gateway/gate/authority/policy/audit/runtime/signing internals. Thin over mcc_protocol; reuses CanonicalProposal/GovernanceDecision/pipeline/AdapterRegistry/Verdict/Decision/ContractErrorCode/capability vocab/version-compat + mcc_core.signing (pure hash only). Purely translational: NO authorize/allow/approve/execute/enforce/evaluate_policy/issue_token/sign_token. SHIPPED in the mcc-core wheel (curated, engine-free)
│       ├── metadata.py         ← AdapterMetadata: immutable, deterministic to_dict + reproducible digest, fail-closed; capabilities⊆PR#47 vocab; protocol+contract version reuse; unsupported→ContractErrorCode
│       ├── context.py          ← AdapterContext: immutable, canonical/deterministic, bounded extension (reject unserializable), NO secrets in repr()/evidence (only key names)
│       ├── adapter.py          ← Adapter ABC (describe/to_proposal/to_response + optional sample_request) + make_proposal helper (binds identity+context; fail-closed). Purely translational
│       ├── runner.py           ← AdapterRunner + AdapterRunResult: native→proposal→ONLY CanonicalIngressPipeline→GovernanceDecision→native; fail-closed (translation/pipeline/response failure→no native_response); preserves Decision/Token/Verdict; no bypass/authorize/execute
│       ├── registration.py     ← register_adapter + AdapterRegistration: reuses mcc_protocol.AdapterRegistry; informational only, dup-id/incompatible-version rejected, deterministic
│       ├── validation.py       ← validate_adapter + AdapterValidationReport: STRUCTURAL only (metadata/methods/version/serialization/proposal-production/registry); wording "structurally valid / SDK compatible / VALIDATION_PASSED" — NEVER certified/trusted/compliant/approved
│       ├── evidence.py         ← generate_adapter_evidence: deterministic, sanitized (no secrets/token/random ids/wall-clock), reproducible → artifacts/adapter-sdk/; DISTINCT from Compliance/Certification evidence
│       └── errors.py / _version.py ← AdapterSDKError (carries ContractErrorCode; fail-closed) + SDK_VERSION == mcc._version single source
│   └── mcc_agent/             ← governed agent pilot (proposes only; no executor/signing key/outbound HTTP)
│       ├── agent.py           ← GovernedAgent: goal→planner→submit→[ESCALATE approve]→AgentResult
│       ├── planner.py         ← DeterministicPlanner: goal→ActionProposal (credential-free; pilot goals)
│       ├── client.py          ← GovernanceClient protocol + EmbeddedGovernanceClient (reuses GovernedMCCClient + HTTPEgressExecutor + per-action pilot AuthorityModel); propose/decide/approve/execute
│       ├── models.py / errors.py ← typed ActionProposal/GovernanceOutcome/AgentResult + structured errors
│       ├── demo.py            ← runnable pilot: 9 scenarios (+ --verdicts four-verdict staged demo) vs a real loopback pilot-api + reproducible evidence
│       └── version.py         ← pilot release metadata (PILOT_RELEASE_NAME = "MCC-Core Pilot v0.1", PILOT_VERSION = "0.1.0-pilot")
├── pilot_api/                 ← the EXTERNAL pilot API the agent acts upon (separate service; deterministic state, /operations evidence, strict schemas; no governance)
│   └── app.py                 ← /leads /campaigns/{id}/budget /notifications /tasks /webhooks /operations /health
├── pilot_notify/              ← Real Governed Executor Pilot: mock notification service + receipt-verifying governed-executor adapter (EXECUTED only on a confirmed receipt matching payload+correlation_id; plugs into GovernanceService.upstream — no governance duplicated)
│   ├── service.py             ← mock external notification service (POST /send_notification -> receipt; /receipts; /health)
│   └── governed_upstream.py   ← receipt_verifying_upstream adapter (raises unless 2xx + received + correlation + payload-hash match -> fail-closed non-EXECUTED)
├── clinic_service/            ← AXFlow Clinic pilot (PR #38): mock external CLINIC service the governed executor calls (catch-all POST /{action_type} -> bound receipt; /health; reuses receipt_verifying_upstream — no governance duplicated)
│   └── service.py             ← records each clinic action, returns receipt (received + correlation_id + payload_sha256 + status); 8 known actions; reset/recorded helpers
├── gateway/                   ← the gate as an HTTP service
│   ├── app.py                 ← POST /evaluate; /verify; /export; mounts governance HTTP routes
│   ├── pilot_policy.py        ← hardcoded authority + velocity (PILOT_VELOCITY) config for the first pilot client; also the AXFlow clinic mandate/policies (clinic.book/message/discount[max 20%]/priority[max 1]; refund/complaint→ESCALATE; medical_advice_request→DENY)
│   ├── trust.py               ← multi-issuer trust set: Ed25519 public keys, rotation, disable/revoke, fail-closed startup
│   ├── governance_service.py  ← wiring (no decision logic): trust→authority→token→coordinator→audit→upstream; also execute_with_delegation (Verifiable Delegation: canonicalize→derive recipient/currency/amount from the canonical payload only→DelegationAuthority.authorize→atomic velocity reserve→token with max_exp=delegation.exp→coordinator run→release ONLY on BLOCKED); P2-A3: optional integrity_monitor (default None) + _integrity_gate() mirroring _attestation_gate, called before issue_token in execute_with_mandate/execute_with_delegation/execute_with_consensus -- the issuance-boundary fail-closed audit-integrity gate
│   └── governance_api.py      ← thin HTTP: /mandates/*, /approvals/*, /trust/*; agent vs operator auth; strict schemas; build_governance_service also wires _build_delegation_verifier (MCC_DELEGATION_OWNER_TRUST_CONFIG → a DEDICATED owner TrustSet, disjoint from trust_set/consensus trust; unconfigured → delegation disabled, fail-closed)
│   └── app.py /ready          ← readiness probe: Redis reachable + trust/verifier/signing loaded (fail-closed 503)
├── sdk/python/                ← supported, independently-installable Python client SDK (package `mcc_client` v0.1.0; pyproject + py.typed + README)
│   └── src/mcc_client/        ← MCCClient (evaluate→verdict; explicit governed execute), models (Verdict/Decision/…; unknown-enum rejected), transport (httpx; safe-only retries; typed errors), exceptions (full hierarchy). Client not policy engine; no local decisions/signing/bypass/direct-executor
│       └── contract.py        ← PR #43 normative layer (reconcile, NOT parallel models): CONTRACT_VERSION 1.0 + fail-closed check_version_compatibility; stable ContractErrorCode/ErrorCategory taxonomy mapped from the MCCError hierarchy; deterministic conformance_manifest() for PR #44. Pure (no I/O/network/authorization); reuses Verdict/Decision as the canonical models
├── pilot/                     ← supported pilot runtime package (thin surface; no governance logic)
│   ├── client.py              ← MCCGatewayClient: typed HTTP SDK (propose→verdict, approvals, consensus; governed /…/execute only)
│   └── outbound_executor.py   ← OutboundHTTPExecutor: the governed side effect (real POST; refuses unsigned/ungoverned)
├── egress_proxy/              ← enforced outbound HTTP egress proxy (enforcement adapter; embeds the runtime, no parallel engine)
│   ├── app.py                 ← POST /v1/http/execute + /v1/approvals/* + /health + /ready; build_app(settings) factory; four outcomes
│   ├── canonical_action.py    ← flat canonical HTTP action + hash_payload binding; reconstruct; clamp-stable (no stale body hash)
│   ├── ssrf.py                ← destination safety: scheme/creds/port + loopback/link-local/multicast/private/CGNAT rejection; global-only default
│   ├── secure_transport.py    ← strict TLS context (+ in-memory CA / mTLS client identity via 0600 temp) + IP-pinned httpcore backend (SNI, peer-IP) + redirect validation/stripping
│   ├── credentials.py         ← governed credential references: scope binding, in-memory/env providers, typed redacted material; secrets resolved only in the executor
│   ├── executor.py            ← HTTPEgressExecutor: the ONLY outbound call (verified token; HTTPS-only; pinned TLS; per-hop credential resolution + mTLS; safe redirects; redacted audit)
│   ├── runtime.py             ← embeds GovernedMCCClient (egress AuthorityModel + registries-from-env); no decision logic
│   ├── observability.py       ← instrumentation only (never decides): correlation ids, stable ErrorCode taxonomy + safe messages, redacted structured events, bounded-cardinality Prometheus Metrics (isolated registry), optional/no-op OTel span (export failures swallowed+counted)
│   ├── app.py /livez /metrics ← liveness (process-only) + Prometheus /metrics; /ready validates Redis+audit-durable+consensus+credential provider (fail-closed 503); X-MCC-Correlation-Id propagated
│   ├── config.py / models.py  ← EgressSettings (trusted config) + strict request/response schemas (HTTPExecuteResponse.error_code = stable ErrorCode)
├── deploy/
│   ├── observability/         ← operational assets: prometheus.yml (scrape), alerts.yml (audit/Redis/replay/consensus/credential/TLS/executor/DENY/readiness/telemetry), INCIDENT_RUNBOOK.md (detection→containment→recovery→evidence→rollback; RULE ZERO: never bypass MCC-Core)
│   └── pilot/                 ← pilot Docker Compose deployment (gateway + Redis + echo upstream)
│       ├── Dockerfile / docker-compose.yml ← fail-closed startup; health + /ready readiness gate
│       ├── .env.example / .gitignore ← API keys only; secrets/ + .env git-ignored
│       ├── generate_pilot_config.py ← generate signing/evaluator keys + trust configs (public keys only)
│       ├── pilot_driver.py    ← runbook driver: four verdicts + consensus execute over HTTP via the SDK
│       ├── echo_upstream.py   ← governed-but-external echo service for the demo
│       ├── Dockerfile.egress  ← egress proxy image (src+gateway+egress_proxy+examples)
│       ├── egress_agent.py    ← compose reference agent: proves direct egress blocked, governed egress works
│       └── RUNBOOK.md         ← deterministic: startup, config, each path, audit inspection, teardown
├── config/
│   └── trust.pilot.example.json ← pilot multi-issuer trust config example (public keys only)
├── interceptors/              ← MVP: where an action physically passes through the gate
│   └── egress_proxy.py        ← the ONE interceptor (owns the path → DENY means DENY); optional EnforcementCoordinator path
├── policies/
│   └── mcc.rego               ← canonical policy source (OPA)
├── server/
│   └── app.py                 ← DEPRECATED legacy runtime (no decision tokens)
├── examples/                  ← demo scripts and execution profiles
│   ├── _demo_server.py        ← deterministic embedded-uvicorn lifecycle (DemoServer/DemoServers): server.started readiness + should_exit + bounded join + verify-not-alive; prevents the interpreter-finalization SIGSEGV (exit 139); daemon-thread termination never relied upon; free_port() (distinct ephemeral ports — no hardcoded demo ports → no smoke port-race)
│   ├── egress_proxy_demo.py   ← live E2E: agent → proxy → upstream (ALLOW reaches, DENY blocked)
│   ├── transaction_governance_demo.py ← live E2E: idempotency dedup + cumulative ceiling through gateway+coordinator proxy
│   ├── governance_http_demo.py ← live E2E HTTP: mandate execute/revoke + ESCALATE approve→single-use over the real gateway
│   ├── pilot_reference_integration.py ← reference: agent outbound HTTP via real runtime; ALLOW/DENY/ESCALATE/CONSTRAIN-re-consensus; no bypass
│   ├── enforced_egress_agent.py ← reference: outbound HTTP only via the egress proxy; four outcomes + replay/tamper/no-bypass over HTTP
│   ├── reference_governed_agent/ ← framework-neutral reference governed agent (SDK-only; no framework, no direct execution route)
│   └── adapter_sdk/           ← PR #50 Adapter SDK examples: minimal_adapter.py (runnable full lifecycle: declare→translate→pipeline→decision→native→validate→evidence; no exec/creds/side-effects) + reference_http_adapter.py (the ONE migrated adapter — framework-neutral HTTP on the SDK, preserves GenericHttpAdapter behaviour)
│       ├── agent.py            ← ReferenceGovernedAgent: propose→evaluate→(approve)→governed execute→verify (mcc_client only)
│       ├── providers.py        ← ReasoningProvider: DeterministicProvider (default, offline) + OptionalLLMProvider (opt-in; failure→ProviderError, never a bypass)
│       ├── operator.py         ← Operator: ProgrammaticOperator (tests) + CLIOperator (human prompt) — decide only, never executes
│       ├── authorizers.py      ← ConsensusAuthorizer: obtains N-of-M evaluator votes for executable verdicts (gate still verifies)
│       ├── evidence.py         ← PR #43: agent_evidence/export_agent_evidence — the contract's Audit→portable evidence step; converts SDK Decision+ExecutionResult → mcc_evidence EvidenceInput (reuses PR #42; observational, no new logic)
│       ├── actions.py / models.py ← send_notification payload builder + NL parser; typed ProposedAction/AgentRunResult/ProviderError
│       ├── cli.py / _localstack.py ← CLI demo (four scenarios) + private in-process governed stack harness (not the agent)
│       └── README.md / Dockerfile ← package doc (invariants, quick-start) + self-contained demo image
├── integrations/
│   └── voltagent/            ← Real VoltAgent Governed Integration (first real third-party framework; reuses the PR #35 contract; NOT MCP)
│       ├── src/agent.ts / tools/governed-notification.ts ← VoltAgent Agent + the ONE governed tool (operator-less client; no direct external route)
│       ├── src/mcc-client.ts / schemas.ts ← gateway-contract HTTP client + governed-path orchestration; strict zod proposal + trusted-identity binding
│       ├── src/model.ts / demo.ts / e2e-runner.ts ← provider config + deterministic offline model; runnable NL demo; Docker E2E runner (markers)
│       ├── tests/            ← vitest: schemas/no-bypass (offline) + integration (spawns the REAL MCC stack); globalSetup launches mcc_side/testserver
│       ├── mcc_side/evaluator_quorum.py ← independent N-of-M evaluator quorum (holds keys; signs only executable decisions over the gateway's authoritative payload)
│       ├── mcc_side/generate_config.py / testserver.py ← evaluator keyset (+ optional persistent gateway signing key) + in-process real stack for the TS tests
│       ├── mcc_side/operator_cli.py ← pilot ESCALATE operator step (approve+execute in the gateway container; never the agent)
│       ├── src/pilot-cli.ts   ← pilot scenario runner (readiness-gated; one governed scenario per invocation; records ESCALATE state)
│       ├── src/clinic-schemas.ts / tools/clinic-action.ts ← AXFlow clinic (PR #38): strict zod clinic proposal + trusted-identity binding + the ONE governed clinic tool (delegates to governAction; no direct clinic call)
│       ├── src/clinic-model.ts / clinic-agent.ts / clinic-cli.ts ← deterministic offline patient-intent classifier + AXFlow clinic Agent + one-scenario runner (allow/deny/constrain/escalate; records ESCALATE state)
│       ├── src/interop-originate.ts ← PR #48e interoperability originator: runs the REAL native @voltagent/core Agent offline (deterministic model; reuses createDeterministicModel + schemas/buildProposal) whose tool CAPTURES the proposal (does NOT run the TS governed path) + prints it as JSON for the Python VoltAgentAdapter; explicit process.exit (VoltAgent keeps the loop alive). Governance stays on the shared Python→Gateway path
│       ├── docker/Dockerfile.mcc / Dockerfile.agent ← Python (gateway+quorum+notify+clinic+config) + Node (agent) images
│       └── README.md         ← integration doc: VoltAgent vs MCC boundary, verdicts, receipt verification, bypass prevention, diagram
├── docker-compose.voltagent.yml ← one-command VoltAgent stack (config-init → redis + mock-notification + gateway[consensus+receipt] + quorum + agent)
├── docker-compose.pilot-voltagent.yml ← deployable VoltAgent pilot (persistent audit+config volumes, persistent gateway signing key, network-isolated agent) — distinct from the egress docker-compose.pilot.yml
├── docker-compose.pilot-clinic-voltagent.yml ← AXFlow Clinic business pilot (PR #38): reuses the VoltAgent pilot patterns; mock clinic-service as the governed upstream; isolated project `axflow-clinic` + clinic-* volumes; agent has no network path to clinic-service
├── Makefile                  ← operator pilot commands (pilot-* + clinic-pilot-* : up/ready/allow/deny/constrain/escalate/approve/audit-verify/restart-check/demo/down)
├── .env.pilot.example        ← pilot config template (git-ignored .env.pilot; no secrets; fail-closed defaults)
├── scripts/
│   ├── generate_signing_key.py ← Ed25519 key generator (PKCS8 PEM, mode 0600)
│   ├── release_checks.py       ← PR #41 release engineering (testable, no publish): inspect/validate wheel+sdist content contract, PEP 503 name normalize, PEP 440 check, PyPI/TestPyPI duplicate-version guard (200/404), manual-release input confirmation; CLI for CI
│   ├── redis_nonce_smoke.py    ← E2E: two gates share one Redis → cross-instance replay rejected
│   ├── redis_governance_smoke.py ← E2E: cross-instance idempotency dedup + aggregate ceiling on real Redis
│   ├── redis_mandate_smoke.py  ← E2E: cross-instance mandate revocation on real Redis
│   ├── redis_approval_smoke.py ← E2E: cross-instance single-use approval consume on real Redis
│   ├── redis_challenge_smoke.py ← E2E: cross-instance challenge issue + single-use consume on real Redis
│   ├── redis_governance_http_smoke.py ← E2E: cross-instance revocation + single-use through GovernanceService on real Redis
│   ├── smoke_stress.sh        ← stress harness: each affected demo x N runs; fails on exit 139 / hang / non-zero (no retries/masking)
│   └── smoke_test.sh
├── docs/                      ← architecture, security model, decision token spec
│   ├── MVP_GATEWAY.md         ← MVP: authority model, gateway service, the one interceptor
│   ├── TRANSACTION_GOVERNANCE.md ← the five protections: nonce, idempotency, binding, velocity, aggregate
│   ├── SIGNED_MANDATES.md     ← signed/revocable mandate spec: trust model, lifecycle, revocation, deployment
│   ├── VERIFIABLE_DELEGATION.md ← Verifiable Delegation & Intent Binding: owner-signed Delegation vs Mandate, dedicated owner trust root, exact-binding (never-clamped) verification order, atomic cumulative budget via VelocityRegistry, pre-existing coordinator velocity-release defect found+fixed by this work, STRIDE T-01/T-03/T-05/T-06/T-09 coverage table (fully/partially mitigated/open), architectural limitations, evidence needed for independent sign-off
│   ├── HA_SAFE_DEGRADATION.md ← P2-B High Availability & Safe Degradation: where globally-consistent state is actually required (nonce/revocation/budget/idempotency/dispatch-ownership), the tests/ha/ real-process fault-injection lab, the fault matrix with an explicit real-vs-simulated-vs-approximated column (STRIDE T-04/T-07/T-10/T-11), no src/ changes (pure evidence against the existing fail-closed contract), honest "Known limits" (no true multi-host partition, no Docker exercise, split-brain unproven, no RTO/RPO/SLO claims)
│   ├── AUDITLOG_OPTIMIZATION.md ← P2-A2 (production code change, unlike P2-A/P2-B): AuditLog._read_last_entry()'s O(n) full-file forward scan replaced by an O(tail) backward-seek read; exception-behavior parity (incl. the one disclosed scope narrowing -- historical non-last-line corruption no longer incidentally detected by the hot path, still caught by verify_chain()); differential equivalence test methodology (27 tests, old-vs-new over a fuzz corpus + bounded-bytes-read proof); real before/after measurements at 3 file sizes with commit SHAs (up to 473x read speedup, 33x end-to-end, raw-fsync floor unchanged); adversarial regression suite (10 tests: real concurrent processes, real SIGKILL crash/restart, corruption, storage errors, lock contention, stale cache); PASS/FAIL/NOT-PROVEN exit-gate matrix; §7's proposed-but-not-implemented integrity-verification control is now implemented -- see AUDIT_INTEGRITY_ENFORCEMENT.md
│   ├── AUDIT_INTEGRITY_ENFORCEMENT.md ← P2-A3: automated audit-chain integrity verification + mandatory fail-closed enforcement. UNVERIFIED/VERIFYING/HEALTHY/UNHEALTHY state machine; why periodic re-verification is REQUIRED (not optional) for HEALTHY to stay meaningful + honest detection-latency bound; explicit trusted-bootstrap policy; dual-backend (InMemory/Redis, monotonic-generation CAS) multi-worker registry design; the two independent enforcement boundaries (issuance + dispatch) and why both are needed; MCC_REQUIRE_AUDIT_INTEGRITY config + fail-closed startup; honest Limitations section
│   ├── ESCALATE_APPROVAL.md   ← ESCALATE state machine + operator workflow + service boundary
│   ├── INFRA_PROFILE.md       ← non-payment (infrastructure) profile: domain neutrality demonstrated
│   ├── ROBOTICS_PROFILE.md    ← robotics profile: domain neutrality demonstrated a second time
│   ├── GOVERNANCE_HTTP_API.md ← HTTP API reference, trust config, rotation/revocation, auth boundary, threat model
│   ├── GOVERNANCE_EVIDENCE_BUNDLE.md ← PR #42: portable offline-verifiable evidence bundle — what it proves/does-not-prove, trust assumptions, structured status, ALLOW/DENY evidence, tamper detection, sensitive-data/retention, schema compatibility, operational limitations (NOT independently installable yet)
│   ├── INTEGRATION_CONTRACT.md ← PR #43: NORMATIVE framework-neutral integration contract (v1.0) — RFC-2119 language, pinned "spec is normative / existing models are the canonical implementation artifacts / adapters incl. VoltAgent conform but do not define it", Mermaid sequence diagram, 5 stages, versioning+compat, lifecycle state table, stable error taxonomy, traceability + invariant-ownership matrices, negative guarantees, conformance+change-control; reuses mcc_client models (NO parallel wire models)
│   ├── contract/conformance-manifest.json ← PR #43: deterministic machine-readable manifest for PR #44 (contract id/version, verdicts, authorization artifacts, error taxonomy, required invariants, validation entry points, golden-vector location); generated by mcc_client.contract.conformance_manifest(), drift-guarded by tests
│   ├── CANONICAL_GOVERNANCE_PROTOCOL.md ← PR #49: the official Canonical Governance Protocol + Canonical Ingress Pipeline. Reconciliation-with-PR#43 table (ONE wire contract, no drift), CanonicalProposal/GovernanceDecision lifecycles, 8 pipeline stages, adapter registry, version negotiation, unified observability, CI-enforced architecture guards, evidence, extension rules + adapter developer guide (quick-start). GovernanceDecision WRAPS (never replaces) mcc_client.Decision + Decision Token
│   ├── MULTI_CONTEXT_CONSENSUS.md ← N-of-M signed evaluator consensus: votes, policy, /consensus HTTP, deployment
│   ├── CONSENSUS_CHALLENGE.md ← gateway-issued one-time nonce: challenge handshake, single-use consume, binding/rejection table, MCC_REQUIRE_CHALLENGE
│   ├── unified-governance-runtime.md ← one runtime: architecture + state-machine + 3 sequence diagrams, path table, modified-payload→new-consensus invariant
│   ├── enforced-http-egress-proxy.md ← egress proxy: architecture/lifecycle/4 sequences, canonicalization+hash binding, SSRF, Docker network model + honest limits
│   ├── secure-https-egress.md ← HTTPS hardening: HTTPS-only mode, TLS verification, SSRF model, DNS-rebinding IP pinning, safe redirects, audit evidence
│   ├── credential-references-mtls.md ← governed credential refs + optional mTLS: provider interface, scope binding, resolution order, redaction, redirect credential behavior
│   ├── OBSERVABILITY.md       ← operational readiness: correlation model, error-code taxonomy, bounded metrics reference, liveness/readiness semantics, safe-logging rules, OTel config, alert install, incident response, evidence collection, preserved security invariants
│   ├── MIGRATION_NOTES.md     ← backward-compatibility + migration notes for the governance layers
│   ├── CI_MAINTENANCE.md      ← CI hygiene: GitHub Actions Node 20→24 migration, action version table, runner requirements, workflow least-privilege/persist-credentials, diagnosing deprecated-action warnings
│   ├── PILOT_VOLTAGENT_DEPLOYMENT.md ← deployable VoltAgent pilot: architecture, trust boundaries, config, scenarios, audit persistence, fail-closed, demo script
│   ├── PILOT_AXFLOW_CLINIC.md ← AXFlow Clinic Revenue Agent (PR #38): first productized BUSINESS pilot; PR#35→38 progression, clinic schema, four verdicts as clinic decisions, no-bypass, run/audit, NOT medical-advice/device/production-certified disclaimer
│   ├── PACKAGING_AND_SDK.md  ← PR #40: install (pip install mcc-core / editable), the stable `mcc` facade public API, quick start, back-compat with mcc_client, security invariants (readme of the mcc-core dist)
│   ├── ADAPTER_SDK.md        ← PR #50: the public Adapter SDK — purpose, trust boundary + CI architecture guards, adapter lifecycle, metadata/context/registration/validation/evidence, version compat, migration guide, packaging decision (curated engine-free wheel), explicit "SDK validation is NOT certification"
│   ├── security/              ← versioned, point-in-time security governance docs; published as-approved and never edited in place — status changes go in a separately dated addendum (docs-only handoff PR, post-PR#122-merge)
│   │   ├── MCC_CORE_STRATEGIC_ROADMAP_v1.2.md ← approved Strategic Engineering Roadmap v1.2 (28 Oct 2026): P0–P3 workstreams + acceptance gates, trusted-time assurance spec, failure-modes/recovery matrix, threat-model governance/PR traceability
│   │   ├── MCC_CORE_THREAT_MODEL_v1.0.md      ← STRIDE threat model v1.0 (28 Oct 2026): stable T-01…T-12 register, 6 trust boundaries, trusted-time/anti-NTP-spoofing spec, failure/recovery/attribution table, threat-to-PR traceability + PR description templates
│   │   ├── PR122_POST_MERGE_ADDENDUM.md       ← post-merge status update (29 Oct 2026) to the two docs above: PR #122 actually merged (`fdd7fe0`, final head `ee896c1`), Round 4–6 TrustedTime/dispatch-staleness/mandate-exp-clamp closure evidence, updated threat-to-control-to-test traceability; does not edit or re-date the originals
│   │   ├── PR124_P1_COMPLETION_ADDENDUM.md    ← post-merge status update (29 Oct 2026): P1 (Verifiable Delegation & Intent Binding, PR #124) merged at `9f1c8a7` (head `357dfdd`); scope-accurate STRIDE T-01/T-03/T-05/T-06/T-09 status table (do not generalize beyond the delegation path); P2-A/P2-B named next, not claimed complete; does not edit or re-date the originals
│   │   └── README.md                          ← index; relationship to the pre-existing, differently-scoped docs/THREAT_MODEL.md, docs/SECURITY_MODEL.md, docs/ROADMAP.md
│   └── exhibits/              ← NIW exhibits (protected)
├── certifications/
│   └── manifest.json         ← PR #46 committed Certified Adapter Program manifest: only genuinely-CERTIFIED official adapters (reference + voltagent), each binding adapter id+version/contract/vector-set/status/covered-invariants/evidence_digest; deterministically ordered + schema-versioned; regenerated + verified in CI (verify-manifest) — hand-editing a status/digest fails CI
├── schemas/
│   ├── governance-capability-profile-v1.schema.json ← PR #47 published JSON Schema (draft-07) for the Governance Capability Profile; capability enums drift-guarded against the Python registry (test); the pure-Python validator is authoritative for cross-field invariants
│   └── adapter-certification-v1.schema.json ← PR #51 published JSON Schema (draft-07) for the deterministic certification.json (schema_version 1, certification_ingress adapter-sdk); the sdk_certification writer is authoritative
├── proof/
└── tests/
    ├── conftest.py
    ├── test_mcc_core.py       ← 42 tests: four verdict paths, replay, expiry,
    │                            fail-closed (Redis/OPA down), audit chain
    ├── test_authority.py      ← mandate-driven verdicts, constraint binding, expiry, deny-by-default
    ├── test_gateway.py        ← /evaluate + signed token through the gate, observe/inline, verify/export
    ├── test_egress_proxy.py   ← action mapping + fail-closed enforcement (proxy owns the path)
    ├── test_nonce.py          ← RedisNonceRegistry: atomic claim, cross-instance + concurrent replay, TTL bounds, fail-closed
    ├── test_idempotency.py    ← RESERVED/EXECUTED lifecycle, exactly-one winner, restart persistence, stale recovery, fail-closed
    ├── test_velocity.py       ← cumulative ceiling/anti-splitting, count + new-destination caps, concurrency safety, fail-closed
    ├── test_transaction_binding.py ← actor/resource/transaction + beneficiary/amount/currency substitution denied; non-payment compat
    ├── test_coordinator.py    ← a-h ordering, replay, shared idempotency key, audit-before-actuation, execution-failure recovery; test_velocity_release_matches_its_own_reservation_in_production_shape (regression for a pre-existing PR #122 coordinator defect found by this work: reserve()/release() each resolve their OWN fresh now when now=None (the universal production shape) and correlate by exact timestamp, so re-resolving a fresh now at release silently no-ops instead of carrying back the reservation's own now; fails toward over-conservative denial, never unauthorized execution; non-vacuity confirmed via a narrowly-scoped revert of only velocity.py+coordinator.py)
    ├── test_mandate.py        ← signed mandates: forged/expired/revoked/wrong-subject/scope-widening/backend-unavailable; MandateAuthority; actuation revocation
    ├── test_delegation.py     ← Verifiable Delegation & Intent Binding (37 tests, unit-level): non-vacuity baseline, forgery/tampering/malformed, scope escalation (action/resource/recipient/currency/amount/purpose incl. boundary-at-ceiling), transfer prevention + cross-tenant + policy-hash mismatch, expiry, revocation (revoked/no-registry/backend-unavailable), issuance-time fail-closed validation (parametrized over malformed fields), untrusted time source, atomic cumulative budget (split-transaction + per-delegation scope isolation)
    ├── test_delegation_governance_service.py ← Verifiable Delegation E2E through the real GovernanceService.execute_with_delegation (15 tests): baseline + unconfigured-delegation block, forgery, payload substitution (recipient/amount/currency derived from canonical payload only), cross-tenant, expired, replay, revocation race, backend failures (revocation + velocity), blocked-reservation-release-enables-legitimate-retry, concurrent cross-instance spending (real-Redis gated + in-memory companion) — asserts zero actuator invocations on every negative case
    ├── test_delegation_builder.py ← build_governance_service wiring for the delegation owner trust root: MCC_DELEGATION_OWNER_TRUST_CONFIG unconfigured → delegation disabled; configured → DelegationVerifier built; disjoint from both the gateway's mandate/approval trust_set and the consensus evaluator trust config (even when both are configured simultaneously)
    ├── ha/                     ← P2-B High Availability & Safe Degradation fault-injection lab (real processes, real Redis; no src/ changes)
    │   ├── _redis_lab.py       ← RealRedisServer (genuine redis-server OS process: start/kill/restart on an ephemeral port); KillRedisOnFirstCall (proxy that really kills the real server as a side effect of its first call, then genuinely attempts the now-failing real call); ForgedClockRedisClient (the one deliberately-mocked primitive — forges only RedisTimeSource's TIME reply); build_coordinator/payment_token/killer_executor helpers
    │   ├── _crash_worker.py    ← real OS subprocess (python -m tests.ha._crash_worker) that SIGKILLs itself either right after a real idempotency.reserve() succeeds (--crash-point reserve) or inside the executor callback enforce() only invokes after durable dispatch-ownership commit (--crash-point dispatch)
    │   └── test_fault_matrix.py ← 12 tests, real-redis-gated: pre-dispatch crash+TTL-recovery, post-dispatch-ownership crash→never-double-dispatch→reconciliation→still-never-double-dispatch→fresh-op-still-works, audit-chain-integrity-after-recovery, real redis-server kill/restart (mid-operation fail-closed + full recovery), get_state fails-closed-not-not-found under real outage, cross-connection revocation-visibility race, cross-connection concurrent aggregate-spend ceiling, forged-clock fail-closed, audit-write-failure release+retry, iptables-DROP network-partition approximation (real rule, real bounded timeout, real cleanup+recovery-reverification) — every assertion counts actual actuator invocations, never just a status string
    ├── test_approvals.py      ← ESCALATE loop: full execution, single-use replay, denial terminal, substitution, policy drift, backend failure
    ├── test_infra_profile.py  ← infrastructure profile: canonical payload, substitution denied, constraint convention, full E2E, core-stays-agnostic
    ├── test_robotics_profile.py ← robotics profile (2nd non-payment domain): zone/force constraints, restricted-zone DENY, full E2E, core-stays-agnostic
    ├── test_trust.py          ← multi-issuer trust set: resolution, rotation, disable/revoke/expiry, malformed config, pilot fail-closed startup
    ├── test_mandate_http.py   ← mandate HTTP: verify/execute/revoke, strict schemas, operator boundary, no-bypass (upstream unreached when blocked)
    ├── test_approval_http.py  ← approval HTTP: ESCALATE scenarios (approve/deny/single-use/substitution/policy-drift/expiry/concurrency/backend-down)
    ├── test_consensus.py      ← N-of-M consensus: unanimity/threshold/veto, forged/duplicate/mismatched/expired votes + resource/policy_hash/nonce binding fail-closed
    ├── test_consensus_http.py ← consensus HTTP: verify + execute, below-threshold/veto/forged → BLOCKED (upstream unreached)
    ├── test_consensus_enforcement.py ← mandatory consensus at the coordinator: valid 3-of-3 actuates; every invalid/incomplete case BLOCKED before executor runs
    ├── test_consensus_enforcement_http.py ← mandatory consensus E2E HTTP: valid 3-of-3 reaches downstream; missing/<3/veto/duplicate/untrusted/bad-sig/expired/mismatch/replay denied + upstream unreached; cross-path (mandate execute) also fails closed
    ├── test_consensus_builder.py ← build_governance_service wiring: MCC_REQUIRE_CONSENSUS without trust config refuses startup (no fail-open); with config enables the coordinator gate; challenge service always built + MCC_REQUIRE_CHALLENGE
    ├── test_challenge.py      ← consensus challenge service/registry: strong unique nonce, single-use consume, unknown/expired/reused/mismatch fail-closed, concurrency single-winner
    ├── test_challenge_coordinator.py ← coordinator consumes the challenge once before actuation; challenge_consumed before pre_actuation; unknown/expired/nonce/actor/resource mismatch BLOCKED
    ├── test_challenge_http.py ← challenge E2E HTTP: gateway-issued nonce; valid flow reaches downstream once; reused/expired/unknown + every binding mismatch denied; client-supplied nonce w/o challenge denied
    ├── test_challenge_redis.py ← multi-instance challenge: cross-instance visibility + single-use consume (no double-spend), TTL expiry, backend-down fail-closed
    ├── test_pilot_client.py   ← pilot HTTP SDK: four verdicts, /ready, audit verify, approvals, consensus challenge/verify/execute; no direct-execute method
    ├── test_pilot_startup.py  ← pilot fail-closed startup (no trust / no verifier refused) + /ready Redis-required helpers
    ├── test_pilot_driver.py   ← runbook driver: consensus execute over the SDK reaches upstream; votes bind to nonce + policy hash
    ├── examples/test_pilot_reference_integration.py ← outbound-HTTP reference: four paths + re-consensus + no-bypass + Redis fail-closed
    ├── _egress_harness.py     ← egress test harness: live upstream + evaluator pool + build_app driver
    ├── _tls_harness.py        ← deterministic local CA + cert minter + HTTPS server runner (offline TLS tests)
    ├── test_egress_canonical.py ← canonicalization/hash binding: equivalence-stable, tamper-sensitive, clamp re-canonicalizes
    ├── test_egress_ssrf.py    ← SSRF: loopback/private/link-local/multicast/IPv6/CGNAT/metadata/rebinding/creds/scheme/port fail-closed
    ├── test_egress_https.py   ← HTTPS: valid TLS executes; expired/self-signed/untrusted/wrong-host rejected; HTTP rejected; peer-IP pin; mixed DNS
    ├── test_egress_redirects.py ← redirects: downgrade/private/creds/loop/max rejected; cross-origin sensitive-header stripping
    ├── examples/test_enforced_egress.py ← E2E egress: ALLOW/DENY/ESCALATE+approval/CONSTRAIN-re-consensus, replay, tamper, no-bypass, Redis fail-closed
    ├── examples/test_egress_governance_audit.py ← audit-before-execution, extended-but-verifiable chain, payload-hash binding
    ├── _tls_harness.py        ← (extended) local CA/cert minter + HTTPS + stdlib mTLS servers
    ├── test_egress_credentials.py ← credential scope binding, resolution, header injection, redaction, cross-origin stripping
    ├── test_egress_mtls.py    ← optional mTLS via refs: valid; missing/mismatched cert+key; invalid CA; server-trust/SSRF still enforced; temp cleanup
    ├── test_egress_observability.py ← correlation generate/validate/reject, redaction, bounded metric labels, telemetry-failure isolation, liveness≠readiness, correlation→header/audit, secret never in metrics/logs/response/ready/audit, audit-before-execution
    ├── test_demo_server.py    ← demo-server lifecycle: shutdown requested + thread joined + none survive, cleanup on exception, startup-failure reported, shutdown-timeout fails explicitly, no thread leak, success→exit 0, failure→non-zero
    ├── test_smoke_ports.py    ← PR #39 port-race guard: free_port() returns distinct bindable ports; the 5 smoke demos use free_port and hardcode no fixed listen port (regression guard for the smoke_stress flake)
    ├── test_audit_tail_read.py ← P2-A2 differential equivalence (27 tests): a test-only reference forward-scan vs. the optimized backward-seek _tail_last_nonblank_line(), over empty/blank-only/single-entry/many-trailing-blank/non-ASCII-UTF-8/chunk-boundary-straddling/corrupted-last-line/large-file/200-trial-fuzz cases; a bytes-read-instrumented proof the read is genuinely O(tail) on a ~2MB file; pins the one disclosed scope difference (historical non-last-line corruption no longer incidentally detected, still caught by verify_chain())
    ├── test_audit_optimization_regression.py ← P2-A2 adversarial regression (10 tests, real OS processes/real SIGKILL via tests/_audit_fault_worker.py, not in-process simulation): concurrent real-process appends never corrupt the chain, concurrent reads during concurrent writes stay consistent, crash-before-fsync recovery, crash-while-holding-lock auto-releases, corrupted-last-line fails closed (not a silent chain restart), verify_chain() still detects tampering anywhere, simulated ENOSPC rolls back to the exact pre-attempt size, lock-timeout behavior unchanged, stale in-memory prev_hash never used for a real write, governed-stack actuator-call counts unaffected
    ├── test_audit_integrity.py ← P2-A3 (30 tests): state machine (UNVERIFIED/VERIFYING/HEALTHY/UNHEALTHY incl. a slow-pass VERIFYING observation), explicit trusted-bootstrap policy (missing/empty file), freshness/staleness (stale HEALTHY -> UNHEALTHY; untrusted-clock fail-closed), trusted recovery (explicit new pass required, never silent), InMemory + modelled-Redis registry CAS semantics (stale-generation rejected, malformed record, backend-down -> IntegrityBackendUnavailable), multi-worker visibility across a shared modelled Redis, append()-never-triggers-a-full-scan guard (PR #128 O(tail) invariant preserved), periodic verification runs on a worker thread (never blocks the event loop), real concurrent append() vs verify_once() under genuine thread+lock contention
    ├── test_audit_integrity_enforcement.py ← P2-A3 (18 tests): both enforcement boundaries end-to-end through the REAL GovernanceService/EnforcementCoordinator -- issuance (execute_with_mandate, execute_with_consensus, the shared _integrity_gate directly) and dispatch (direct EnforcementCoordinator.enforce() call, proving the "direct API bypass" is still blocked); every BLOCKED case asserts zero actuator/issue_token calls; non-vacuity companions (integrity_monitor=None, the pre-P2-A3 baseline) proving the identical scenario would otherwise execute; restart-with-corrupted-file-blocks-before-any-execution; healthy-ALLOW-executes-exactly-once + idempotency/UNKNOWN semantics unaffected; backward-compatibility spot-checks (default integrity_monitor is None)
    ├── _audit_fault_worker.py ← P2-A2 real-subprocess worker for the adversarial regression suite above: modes append / hold-lock / crash-before-fsync (SIGKILLs itself at the real os.fsync() call)
    ├── test_mcc_agent.py      ← governed agent E2E: ALLOW/DENY/ESCALATE(+invalid approvals)/CONSTRAIN, replay/nonce/idempotency, Redis fail-closed, SSRF/malformed, audit-before-exec, bypass, real external execution, state-unchanged-after-blocked
    ├── test_mcc_agent_no_direct_egress.py ← static guard: no forbidden networking imports in src/mcc_agent (incl. subprocess); no direct-execute surface
    ├── test_pilot_release.py  ← Pilot v0.1 release matrix: version metadata, clean/fail-closed startup, four verdicts, audit-evidence completeness, audit-before-exec, chain verify, no-exec-before-auth, constrained-payload-executed, Redis replay (gated)
    ├── test_governed_executor_pilot.py ← Real Governed Executor Pilot E2E: ALLOW->genuine EXECUTED (confirmed receipt), DENY/ESCALATE(approve)/CONSTRAIN, replay, altered payload, expired, missing-auth, invalid approval, Redis outage, audit-write-failure, mismatched receipt != EXECUTED, no direct bypass (real gateway + gate + audit + receipt)
    ├── test_reference_governed_agent.py ← Reference Governed Agent (20 tests): four verdict flows→genuine EXECUTED, forged/expired/mismatched approval fail-closed, ESCALATE preserves original payload, CONSTRAIN executes only clamped payload, altered-votes rejected, receipt-verification fail-closed, Redis outage, audit verify, no-direct-execution static guard, provider invariants
    ├── test_integration_contract.py ← PR #43 integration-contract scenario gaps (9 tests) through the REAL gateway via mcc_client: invalid signature / expired authorization / replay / invalid policy hash / gateway-unavailable all fail-closed (no execution, tool never called), audit-evidence generation→offline verify (PR #42 bundle VERIFIED + tamper→INVALID), DENY no fabricated receipt, framework-neutral public API guard
    ├── test_integration_contract_layer.py ← PR #43 normative-layer reconcile (46 tests, offline): version compat vectors + fail-closed, error-taxonomy vectors + full MCCError mapping + fail-closed-to-INTERNAL, decision golden vectors through the EXISTING Decision.from_response, conformance-manifest determinism + no-drift + self-consistency, backward-compat (frozen top-level exports + facade parity), reconcile guards (no parallel models, no I/O, framework-neutral, spec pins normative statement)
    ├── contract_vectors/       ← PR #43 framework-neutral golden vectors (decisions/versions/errors JSON) — offline, checkout-independent; replayable by an external adapter author and by PR #44
    ├── test_compliance_suite.py ← PR #44 compliance & certification (35 tests, offline): strict manifest validation (dup-id/unknown-type/version-mismatch/no-fallback), reference + VoltAgent CERTIFIED through the SAME boundary, 8 deliberately non-compliant doubles rejected (always-allow fabrication, bypass, malformed, exception, mandatory-skip, unknown-verdict, wrong-version, missing-audit), deterministic + timestamp-independent fingerprint (changes with adapter/vectors/contract version), report cleanliness (no secrets/paths), CLI exit codes 0/1/2, framework-neutral vectors
    ├── test_certified_adapter_program.py ← PR #46 Certified Adapter Program (22 tests, offline): reference + VoltAgent CERTIFIED; non-conforming NOT_CERTIFIED + never in manifest; version binding (unsupported→fail-closed); determinism + dict/scenario-order independence; tamper/stale detection (edited digest/counts/forged CERTIFIED entry rejected; changed adapter-version/scenario/contract/vector-set changes digest); boundary integrity (framework-neutral, self-attestation ignored, no network/signing/gate/execution)
    ├── test_sdk_certification.py ← PR #51 Adapter-SDK certification (9 tests): SdkReferenceAdapter CERTIFIED through the SDK ingress (18/18 vectors via the ONE existing engine); all outputs deterministic (certification.json/evidence.json/certification-report.md byte-identical across runs; no wall-clock); certification.json conforms to the versioned schema; non-conforming SDK adapter→NOT_CERTIFIED; SDK-exclusive ingress guard (bridge imports mcc_adapter_sdk, never gate/authority/consensus/signing); certify_sdk_adapter is the stable public API; existing ComplianceAdapter path still certifies (backward-compat)
    ├── test_capability_profile.py ← PR #47 Governance Capability Profile (32 tests, offline): baseline == contract invariants; schema-enum↔registry drift guard; valid/minimal/full/unsupported/voltagent fixtures; each invalid fixture→its stable code (overlap/unknown/version/false-cert/constraint); missing-baseline/duplicate/unknown-field/identity fail-closed; canonicalization order-independence + digest determinism; certification linkage trust-ladder (self_declared=false, identity-mismatch→REJECTED); CLI 0/1/2 + no stack trace
    ├── capability_profiles/    ← PR #47 framework-neutral profile fixtures (4 valid incl. non-normative voltagent example + 4 invalid), offline; drive the validator + CLI tests
    ├── interoperability/       ← PR #48 Multi-Adapter Interoperability Proof (48a foundation): ONE shared out-of-process MCC Gateway (real HTTP), a framework-neutral AdapterProof boundary, the 7 common governance scenarios (ALLOW/DENY/REPLAY/MISMATCH/AUDIT/GATEWAY_UNAVAILABLE/INVALID_OR_EXPIRED), a deterministic evidence bundle, and AST bypass guards. 48a ships adapter 5/5 (Generic HTTP over real httpx→bound gateway); real framework adapters LangGraph (48b), AutoGen (48c), CrewAI (48d), VoltAgent (48e) all landed — matrix COMPLETE (5 adapters × 7 scenarios; 4 real ecosystems + neutral HTTP). Frameworks pin mutually-incompatible deps (crewai pydantic<2.13 vs autogen pydantic>=2.13) so each is proven in its OWN isolated CI job over the identical shared path; the 5/5 matrix is the union of jobs
    │   ├── _gateway_process.py ← the ONE shared Gateway booted as a real subprocess (env-configured: consensus trust + require-consensus/challenge + isolated audit + receipt-verifying notify upstream); reuses gateway.app + build_governance_service (no parallel governance)
    │   ├── harness.py          ← SharedGovernedGateway (spawns+health-gates the subprocess; plays evaluators for consensus votes) + AdapterProof protocol + run_common_scenarios (7 scenarios via real mcc_client over HTTP)
    │   ├── evidence.py         ← deterministic multi_adapter_matrix builder + capability→evidence map + fail-closed structural validation (missing scenario/provenance/audit/unproven-capability → FAIL)
    │   ├── adapters/generic_http.py ← FRAMEWORK-NEUTRAL HTTP INTEGRATION (canonical proposal, real transport boundary; no framework)
    │   ├── adapters/langgraph_adapter.py ← PR #48b REAL FRAMEWORK INTEGRATION (2/5): builds+invokes a native langgraph.graph.StateGraph→CompiledStateGraph offline, extracts the node's proposal, normalizes to canonical. Isolated optional dep (requirements-langgraph.txt); registered only if langgraph importable; dedicated interop-langgraph CI job installs it + fails if absent/not-exercised
    │   ├── adapters/autogen_adapter.py ← PR #48c REAL FRAMEWORK INTEGRATION (3/5): runs a native autogen_core.RoutedAgent on a SingleThreadedAgentRuntime offline (Microsoft AutoGen v0.4+, autogen-agentchat/core 0.7.5), the message-handler emits the proposal, normalizes to canonical. Isolated optional dep (requirements-autogen.txt); registered only if autogen_core importable; dedicated interop-autogen CI job installs it + fails if absent/not-exercised
    │   ├── adapters/crewai_adapter.py ← PR #48d REAL FRAMEWORK INTEGRATION (4/5): builds+runs a native crewai.flow.flow.Flow (@start/@listen steps) via the framework's own kickoff entrypoint offline (crewai 1.15.5), the final step emits the proposal, normalizes to canonical. Opts out of CrewAI telemetry/tracing/OTel BEFORE importing crewai (native run stays offline). Isolated optional dep (requirements-crewai.txt); registered only if crewai importable; dedicated interop-crewai CI job installs it + fails if absent/not-exercised
    │   ├── adapters/voltagent_adapter.py ← PR #48e REAL FRAMEWORK INTEGRATION (5/5 — completes the matrix): VoltAgent is Node/TS, so exercised across a language boundary — runs the real @voltagent/core Agent (2.8.1) in a Node subprocess (integrations/voltagent/src/interop-originate.ts, deterministic offline model; native agent selects its governed tool, subprocess emits the proposal as JSON), normalizes to canonical. Registered only if node + @voltagent/core + tsx present (else ImportError→skip); dedicated Node-based interop-voltagent CI job (setup-node + npm ci) installs it + fails if absent/not-exercised. Uses subprocess (NOT a governance bypass — the Node side only originates the proposal, never executes)
    │   ├── schemas/multi_adapter_matrix.schema.json ← committed JSON Schema for the evidence matrix
    │   ├── test_matrix.py / test_shared_governance_path.py ← 14 tests: 7/7 scenarios, one shared gateway+policy-hash, real-HTTP boundary, capability-evidence, audit verify, evidence hygiene (no secrets/paths) + AST guards (adapters can't import governance internals / mint decisions / execute locally)
    │   └── test_canonical_ingress.py ← PR #49 evidence: every registered PR#48 adapter → mcc_protocol.CanonicalProposal → the ONE CanonicalIngressPipeline → the real shared gateway (over HTTP) → GovernanceDecision (wrapping the authoritative Decision+token); asserts all traverse the IDENTICAL 8-stage pipeline + one protocol version; writes artifacts/protocol/canonical_ingress_evidence.json (secret-free)
    ├── adapter_sdk/            ← PR #50 Adapter SDK tests (offline + one gateway-backed): metadata (immutable/deterministic/version+capability fail-closed), adapter interface (translation, no authoritative verbs, abstract enforcement), AdapterContext (bounded/unserializable-rejected/no-secrets-in-repr), AdapterRunner (mandatory 8-stage pipeline, no bypass, fail-closed translation/pipeline/response, Decision+Token+Verdict preserved), registration (informational/dup+version reject/deterministic), validation (structural, deterministic, NEVER certification) + evidence (deterministic/sanitized/nondeterministic-ids excluded), architecture guards (no gate/authority/policy/audit/executor/gateway/private-signing imports; pure-hash-only; no authorize/execute surface; no parallel models; curated __all__), import-boundary regression (fresh-interpreter: importing mcc_protocol/mcc_adapter_sdk loads NO engine/suite; `from mcc_core import ExecutionGate` still works), reference migration (generic-http on SDK preserves behaviour + traverses real gateway; interop untouched)
    ├── protocol/               ← PR #49 Canonical Governance Protocol tests (54, offline): CanonicalProposal shape/determinism/fail-closed + tamper, GovernanceDecision envelope (wraps Decision, verdicts=mcc_client.Verdict, reason_codes⊆ContractErrorCode), version negotiation (reuses PR#43, unsupported/malformed fail closed), AdapterRegistry (fail-closed, no authority surface), ingress pipeline (ordered stages, router-never-called-on-rejection, gateway-down/expired/capability fail closed, enrichment doesn't touch binding), observability (isolated registry, no secret leak), reconciliation guards (single version axis, same Verdict/Decision objects, one canonicalization/taxonomy), architecture guards (no gate/authority/consensus/executor/signing-authority imports; pure-hash-only from mcc_core.signing; no local authorize/execute/sign surface; gateway only via injected router)
    ├── test_voltagent_quorum.py ← VoltAgent integration MCC-side (7 tests): evaluator quorum signs only executable decisions over the gateway's authoritative payload; ALLOW→genuine EXECUTED, DENY/ESCALATE quorum-refuses, CONSTRAIN clamped-only, forged receipt not-EXECUTED, replay/tamper rejected (real gateway + quorum). TS tests live under integrations/voltagent/tests/
    ├── test_pilot_deployment.py ← VoltAgent pilot deployment (9 tests): fail-closed WITHOUT valid execution authority (no/forged votes, forged approval mandate, untrusted external mandate) + bypass topology (agent has no network path to the external service, holds no operator key; only the gateway bridges the two networks; inline+redis fail-closed). Documents why MCC_ENV=pilot mandate-trust is N/A (consensus + gateway-minted approvals instead)
    ├── test_axflow_clinic_pilot.py ← AXFlow Clinic business pilot (PR #38, 9 tests): four verdicts through the REAL gateway+quorum+receipt-verifying executor→mock clinic (ALLOW book→EXECUTED, DENY medical advice, CONSTRAIN discount 90→20 + priority 3→1 with receipt bound to clamped payload, ESCALATE refund single-use+replay/complaint), direct-bypass-without-authority denied, forged receipt never EXECUTED, compose topology proves agent has no path to clinic-service
    ├── test_mcc_facade.py     ← PR #40 public API contract: `mcc` re-exports mcc_client identically, __all__ parity, facade defines no logic of its own, no misleading local authorize/MCC API, client surface unchanged
    ├── test_version_contract.py ← PR #41: mcc.__version__ == importlib.metadata.version("mcc-core"), PEP 440 valid, single source = mcc._version, client_version distinct = mcc_client version
    ├── test_release_guard.py  ← PR #41: duplicate-version index guard (200 exists / 404 absent / 500 propagates), release input+version confirmation, PEP 440/503, wheel+sdist content validators fail closed (vendored client, missing py.typed, shipped tests/secrets, version mismatch)
    ├── test_artifact_contract.py ← PR #41: build real sdist+wheel, exactly-one-each, content contract, wheel ships only mcc+py.typed, genuine clean install of the built wheel OUTSIDE the checkout (mcc.__file__ in venv, identical MCCClient, runtime==metadata version)
    ├── test_mcc_client_sdk.py ← Python SDK: real-HTTP integration (four verdicts + audit verify vs gateway.app) + controlled-transport units (fail-closed, unknown verdict, timeout/transport, DENY/ESCALATE never execute, CONSTRAIN authoritative payload, replay, ambiguous exec, no unsafe retry, idempotency/correlation propagation)
    ├── examples/test_egress_credentials_governed.py ← secrets resolved only after authorization + durable audit; never in response/audit
    └── opa_test_vectors.json
```

If actual structure differs — update this map, do not guess.

-----

## Before You Change Anything — Self-Check

Before editing any file, answer these four questions:

1. **Does this touch a NIW-sensitive file?** (README.md, DOCTRINE.md, any dated exhibit) → Stop. Ask AX explicitly before proceeding.
1. **Does this introduce HMAC anywhere?** → No. Ed25519 only.
1. **Does this contain the string `mcc-prior-auth`?** → Fix to `mcc-prior-art` before saving.
1. **Does this soften or remove fail-closed behavior?** → No. This is non-negotiable architecture.

If any answer is yes — pause and flag to AX before proceeding.

-----

## Pre-Commit Checklist

Run before every commit:

```bash
# 1. Tests pass
pytest tests/ -v

# 2. No HMAC references introduced
grep -r "HMAC\|hmac" src/ && echo "STOP: HMAC found" || echo "OK"

# 3. No typo in repo name
grep -r "mcc-prior-auth" . && echo "STOP: typo found" || echo "OK"

# 4. No unbuffered audit writes (fsync must be present)
grep -r "fsync" src/audit.py || echo "STOP: fsync missing"

# 5. No fail-open gates (check for default ALLOW on exception)
grep -r "except.*ALLOW\|except.*allow" src/gate.py && echo "STOP: fail-open detected" || echo "OK"
```

All checks green → commit is safe.

-----

## NIW-Protected Files

These files are part of the legal prior art record for AX’s EB-2 NIW petition. They carry timestamps and must not be silently modified:

|File                           |Status     |Rule                                                 |
|-------------------------------|-----------|-----------------------------------------------------|
|`README.md`                    |🔒 Protected|No structural changes without explicit approval      |
|`DOCTRINE.md`                  |🔒 Protected|Wording is legally significant — no paraphrasing     |
|Any file with `Exhibit` in name|🔒 Protected|Do not touch                                         |
|`diagrams/architecture.mmd`    |⚠️ Sensitive|Changes must preserve all four verdict paths visually|

**When in doubt: read, analyze, suggest — but do not write.**

-----

## Advisor Mode

After completing any task, briefly note:

- One thing that could be improved in the code or docs
- One thing that could be automated

This is not optional. AX uses this to find gaps he hasn’t seen yet.