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
- Do not reference “Multi-Context Consensus 3/3” until the consensus implementation exists in code
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
│       ├── profiles.py        ← domain-neutral ActionProfile + payment-specific PaymentProfile (canonical payload + auth_claims)
│       ├── coordinator.py     ← EnforcementCoordinator: the explicit a-h execution order (gate→idem→velocity→audit→execute→finalize)
│       ├── policy.py          ← PolicyBundle with hash verification
│       ├── authority.py       ← mandate registry + action→authority→verdict (the formula in code)
│       └── signing.py         ← Ed25519 token signing/verification
├── gateway/                   ← MVP: the gate as an HTTP service
│   ├── app.py                 ← POST /evaluate {identity,action,context,+binding}; /verify; /export; inline|observe
│   └── pilot_policy.py        ← hardcoded authority + velocity (PILOT_VELOCITY) config for the first pilot client
├── interceptors/              ← MVP: where an action physically passes through the gate
│   └── egress_proxy.py        ← the ONE interceptor (owns the path → DENY means DENY); optional EnforcementCoordinator path
├── policies/
│   └── mcc.rego               ← canonical policy source (OPA)
├── server/
│   └── app.py                 ← DEPRECATED legacy runtime (no decision tokens)
├── examples/                  ← demo scripts and execution profiles
│   ├── egress_proxy_demo.py   ← live E2E: agent → proxy → upstream (ALLOW reaches, DENY blocked)
│   └── transaction_governance_demo.py ← live E2E: idempotency dedup + cumulative ceiling through gateway+coordinator proxy
├── scripts/
│   ├── generate_signing_key.py ← Ed25519 key generator (PKCS8 PEM, mode 0600)
│   ├── redis_nonce_smoke.py    ← E2E: two gates share one Redis → cross-instance replay rejected
│   ├── redis_governance_smoke.py ← E2E: cross-instance idempotency dedup + aggregate ceiling on real Redis
│   └── smoke_test.sh
├── docs/                      ← architecture, security model, decision token spec
│   ├── MVP_GATEWAY.md         ← MVP: authority model, gateway service, the one interceptor
│   ├── TRANSACTION_GOVERNANCE.md ← the five protections: nonce, idempotency, binding, velocity, aggregate
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