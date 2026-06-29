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

## Repository File Map

```
mcc-layer/
├── CLAUDE.md                                           ← this file
├── README.md                                           ← primary public prior art document
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
│       ├── audit.py           ← append-only hash-chain log (fsync on every write)
│       ├── nonce.py           ← replay protection: RedisNonceRegistry (multi-instance) + InMemory; env-selectable, no silent fallback
│       ├── idempotency.py     ← business-operation idempotency: RESERVED/EXECUTED/FAILED lifecycle, Redis+InMemory, fail-closed
│       ├── velocity.py        ← atomic velocity/aggregate limits (count, cumulative amount, new destinations); anti-splitting
│       ├── profiles.py        ← domain-neutral ActionProfile + PaymentProfile + InfraProfile + RoboticsProfile (canonical payload + auth_claims)
│       ├── coordinator.py     ← EnforcementCoordinator: a-h order (gate→[require_consensus]→[challenge-consume]→revocation→approval-consume→idem→velocity→audit→execute→finalize)
│       ├── mandate.py         ← signed, revocable mandates: issue/verify (fail-closed), MandateAuthority, revocation registry (Redis+InMemory)
│       ├── approvals.py       ← ESCALATE loop: ApprovalService + state machine + single-use signed approval mandate (Redis+InMemory)
│       ├── consensus.py       ← Multi-Context Consensus: N-of-M independent Ed25519-signed evaluator votes (pre-token authority step + mandatory enforcement; binds action/actor/payload/resource/policy_hash/nonce)
│       ├── challenge.py        ← consensus challenge: gateway-issued one-time nonce; single-use TTL-bound ChallengeService + registries (Redis+InMemory); consumed once before actuation (clients never generate the nonce)
│       ├── policy.py          ← PolicyBundle with hash verification
│       ├── authority.py       ← config mandate registry + action→authority→verdict (the formula in code)
│       └── signing.py         ← Ed25519 token signing/verification
├── gateway/                   ← the gate as an HTTP service
│   ├── app.py                 ← POST /evaluate; /verify; /export; mounts governance HTTP routes
│   ├── pilot_policy.py        ← hardcoded authority + velocity (PILOT_VELOCITY) config for the first pilot client
│   ├── trust.py               ← multi-issuer trust set: Ed25519 public keys, rotation, disable/revoke, fail-closed startup
│   ├── governance_service.py  ← wiring (no decision logic): trust→authority→token→coordinator→audit→upstream
│   └── governance_api.py      ← thin HTTP: /mandates/*, /approvals/*, /trust/*; agent vs operator auth; strict schemas
│   └── app.py /ready          ← readiness probe: Redis reachable + trust/verifier/signing loaded (fail-closed 503)
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
│   ├── egress_proxy_demo.py   ← live E2E: agent → proxy → upstream (ALLOW reaches, DENY blocked)
│   ├── transaction_governance_demo.py ← live E2E: idempotency dedup + cumulative ceiling through gateway+coordinator proxy
│   ├── governance_http_demo.py ← live E2E HTTP: mandate execute/revoke + ESCALATE approve→single-use over the real gateway
│   ├── pilot_reference_integration.py ← reference: agent outbound HTTP via real runtime; ALLOW/DENY/ESCALATE/CONSTRAIN-re-consensus; no bypass
│   └── enforced_egress_agent.py ← reference: outbound HTTP only via the egress proxy; four outcomes + replay/tamper/no-bypass over HTTP
├── scripts/
│   ├── generate_signing_key.py ← Ed25519 key generator (PKCS8 PEM, mode 0600)
│   ├── redis_nonce_smoke.py    ← E2E: two gates share one Redis → cross-instance replay rejected
│   ├── redis_governance_smoke.py ← E2E: cross-instance idempotency dedup + aggregate ceiling on real Redis
│   ├── redis_mandate_smoke.py  ← E2E: cross-instance mandate revocation on real Redis
│   ├── redis_approval_smoke.py ← E2E: cross-instance single-use approval consume on real Redis
│   ├── redis_challenge_smoke.py ← E2E: cross-instance challenge issue + single-use consume on real Redis
│   ├── redis_governance_http_smoke.py ← E2E: cross-instance revocation + single-use through GovernanceService on real Redis
│   └── smoke_test.sh
├── docs/                      ← architecture, security model, decision token spec
│   ├── MVP_GATEWAY.md         ← MVP: authority model, gateway service, the one interceptor
│   ├── TRANSACTION_GOVERNANCE.md ← the five protections: nonce, idempotency, binding, velocity, aggregate
│   ├── SIGNED_MANDATES.md     ← signed/revocable mandate spec: trust model, lifecycle, revocation, deployment
│   ├── ESCALATE_APPROVAL.md   ← ESCALATE state machine + operator workflow + service boundary
│   ├── INFRA_PROFILE.md       ← non-payment (infrastructure) profile: domain neutrality demonstrated
│   ├── ROBOTICS_PROFILE.md    ← robotics profile: domain neutrality demonstrated a second time
│   ├── GOVERNANCE_HTTP_API.md ← HTTP API reference, trust config, rotation/revocation, auth boundary, threat model
│   ├── MULTI_CONTEXT_CONSENSUS.md ← N-of-M signed evaluator consensus: votes, policy, /consensus HTTP, deployment
│   ├── CONSENSUS_CHALLENGE.md ← gateway-issued one-time nonce: challenge handshake, single-use consume, binding/rejection table, MCC_REQUIRE_CHALLENGE
│   ├── unified-governance-runtime.md ← one runtime: architecture + state-machine + 3 sequence diagrams, path table, modified-payload→new-consensus invariant
│   ├── enforced-http-egress-proxy.md ← egress proxy: architecture/lifecycle/4 sequences, canonicalization+hash binding, SSRF, Docker network model + honest limits
│   ├── secure-https-egress.md ← HTTPS hardening: HTTPS-only mode, TLS verification, SSRF model, DNS-rebinding IP pinning, safe redirects, audit evidence
│   ├── credential-references-mtls.md ← governed credential refs + optional mTLS: provider interface, scope binding, resolution order, redaction, redirect credential behavior
│   ├── OBSERVABILITY.md       ← operational readiness: correlation model, error-code taxonomy, bounded metrics reference, liveness/readiness semantics, safe-logging rules, OTel config, alert install, incident response, evidence collection, preserved security invariants
│   ├── MIGRATION_NOTES.md     ← backward-compatibility + migration notes for the governance layers
│   ├── CI_MAINTENANCE.md      ← CI hygiene: GitHub Actions Node 20→24 migration, action version table, runner requirements, workflow least-privilege/persist-credentials, diagnosing deprecated-action warnings
│   └── exhibits/              ← NIW exhibits (protected)
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
    ├── test_coordinator.py    ← a-h ordering, replay, shared idempotency key, audit-before-actuation, execution-failure recovery
    ├── test_mandate.py        ← signed mandates: forged/expired/revoked/wrong-subject/scope-widening/backend-unavailable; MandateAuthority; actuation revocation
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