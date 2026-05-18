# MCC-Core

<p align="center">
  <strong>Execution Governance Infrastructure for Autonomous AI Systems</strong>
</p>

<p align="center">
  <strong>Autonomy without verifiable control is not intelligence.</strong>
</p>

<p align="center">
  <a href="https://axlogiq.com"><img alt="AXLOGIQ Corporate" src="https://img.shields.io/badge/AXLOGIQ-Corporate-00B8DB?style=for-the-badge"></a>
  <a href="https://axlogiq.ai"><img alt="MCC-Core Technical Product" src="https://img.shields.io/badge/MCC--Core-Technical_Runtime-15388A?style=for-the-badge"></a>
  <a href="https://axlogiq.org"><img alt="Public Architecture Record" src="https://img.shields.io/badge/Public-Architecture_Record-0A0F1A?style=for-the-badge"></a>
</p>

<p align="center">
  <img alt="Status" src="https://img.shields.io/badge/Status-Public_Reference_Architecture-8A9AB0?style=flat-square">
  <img alt="Runtime Law" src="https://img.shields.io/badge/Runtime_Law-No_Verified_Decision_No_Execution-00B8DB?style=flat-square">
  <img alt="Posture" src="https://img.shields.io/badge/Posture-Fail_Closed-FF5C7A?style=flat-square">
  <img alt="OPA/Rego" src="https://img.shields.io/badge/Policy-OPA%2FRego-39D98A?style=flat-square">
</p>

---

As AI systems move from generation to execution, a new infrastructure layer becomes necessary — one that verifies identity, policy, risk, and context before action is allowed.

MCC-Core implements the execution governance boundary for autonomous systems. It verifies identity, policy, risk, context, constraints, token validity, replay state, auditability, and policy-engine output before issuing a signed decision token.

**Intent is not authority.**  
**Execution requires a verified decision.**  
**No verified decision — no execution.**

---

## Public Status

MCC-Core is published as a **public reference architecture and prototype implementation** for technical review, simulation, OPA/Rego integration testing, and enterprise PoC design.

It is not presented as a certified production safety system, government-approved product, formally audited system, production-certified policy enforcement platform, or production-proven industry standard.

---

## Web Presence

AXLOGIQ separates company identity, technical product reference, and public architecture record across three domains.

| Domain | Role |
|---|---|
| [axlogiq.com](https://axlogiq.com) | Corporate landing — company-level positioning, founder profile, platform vision, and high-level execution governance narrative. |
| [axlogiq.ai](https://axlogiq.ai) | MCC-Core technical product site — decision tokens, fail-closed gates, replay protection, OPA/Rego adapter, and audit model. |
| [axlogiq.org](https://axlogiq.org) | Public architecture record — timestamped record of the MCC doctrine, architecture, authorship, positioning, and reference repository. |

---

## What MCC-Core Is

MCC-Core is the technical runtime/reference implementation of **MCC — Meta-Cognitive Control**.

MCC is an execution governance boundary for autonomous AI systems.

It sits between AI-generated intent and real-world execution, evaluating identity, policy-engine output, risk, context, constraints, token validity, replay state, and auditability before issuing a verified decision.

If execution is not authorized, it does not happen.

---

## Why MCC-Core Exists

AI systems are crossing from advisory into operational.

The risk is not only that a model may produce a wrong answer.

The deeper risk is that AI-generated intent may become real-world execution without a separate authority decision.

In operational environments, the final risk point is not the prompt.

The final risk point is execution.

Examples of execution surfaces:

- agent sends an external email
- workflow updates production data
- tool-using model runs shell commands
- payment agent initiates a transfer
- software agent deletes files
- AI agent calls a privileged API
- robot performs a physical movement
- automation modifies enterprise infrastructure

MCC-Core exists to make execution governance explicit, verifiable, auditable, and enforceable.

---

## Core Thesis

The model proposes.  
MCC-Core evaluates.  
The gate enforces.

Proposal is not permission.  
Model output is not authorization.  
Neural confidence is not a license to act.

Every autonomous system requires a verifiable boundary between intent and execution.

That boundary is MCC.

---

## Architecture

MCC-Core separates proposal from authority.

Agents, workflows, services, or users may request an action, but execution only happens after a verifiable decision is produced, scoped, signed, audited, and enforced at the gate.

```text
Intent Sources
     ↓
MCC-Core Decision Boundary
     ↓
Signed Decision Token
     ↓
Execution Gate
     ↓
Controlled Execution
```

---

## Architecture Layers

```text
L0 — Identity & Trust Fabric
Foundation layer for workload identity, trust anchors, key material, and policy trust state.

L1 — Intent Sources
AI models, agents, users, workflows, services, controllers, and applications propose actions.

L2 — MCC-Core Decision Boundary
Evaluates identity, policy, risk, context, payload, scope, constraints, approvals, nonce state, token validity, and auditability.

L3 — Enforcement Layer
Execution gate verifies signed decision tokens before allowing action.

L4 — Controlled Execution
External tools, APIs, workflows, operational systems, or actuators execute only after verified authorization.
```

---

## Runtime Flow

```text
Evaluate → Decide → Tokenize → Enforce → Audit
```

1. **Evaluate** identity, policy, risk, context, constraints, and replay state.
2. **Decide** with an explicit execution outcome.
3. **Tokenize** the decision into a signed, scoped, time-limited decision token.
4. **Enforce** at the execution gate.
5. **Audit** before actuation.

---

## Decision Outcomes

MCC-Core converts autonomous intent into explicit execution outcomes.

Every intent resolves to one of four decisions:

| Outcome | Meaning |
|---|---|
| `ALLOW` | Execution is authorized within verified scope, policy, payload, identity, and time window. |
| `DENY` | Execution is blocked. Missing, invalid, risky, stale, unavailable, or unverifiable authority fails closed. |
| `ESCALATE` | Execution requires additional approval, human review, quorum, or privileged authorization. |
| `CONSTRAIN` | Execution may proceed only under explicit limits such as amount, speed, duration, destination, or scope. |

No ambiguity at execution time.

---

## Runtime Law

```text
No verified decision — no execution.
```

Execution invariants:

```text
No identity — no execution
No policy — no execution
No verified decision — no execution
No valid decision token — no execution
No audit — no trust
Used nonce — deny
Policy mismatch — deny
OPA unavailable — deny
Expired token — deny
Fail closed by default
```

---

## OPA / Rego Policy Adapter

Policy evaluation is integrated.

Execution authority remains separate.

The current MCC-Core reference runtime includes a real OPA/Rego adapter.

OPA evaluates policy. MCC-Core binds the policy result into execution authority with runtime context, token validity, replay protection, constraints, and audit-before-actuation.

When enabled, MCC-Core calls OPA at:

```text
/v1/data/mcc/decision
```

and converts the policy result into:

```text
ALLOW / DENY / ESCALATE / CONSTRAIN
```

If OPA is unavailable, times out, returns invalid output, omits a result, or returns an invalid decision, MCC-Core fails closed to `DENY`.

```text
OPA decides policy.
MCC-Core governs execution authority.
The execution gate enforces the verified decision.
```

---

## Decision Token

Authority is a verifiable object, not an assumption.

A signed decision token binds execution authority to a verified, scoped, time-limited decision.

The gate does not infer permission.

It verifies authority.

Example decision token payload:

```json
{
  "iss": "mcc/node-a",
  "kid": "mcc-node-a-key-1",
  "sub": "agent/payment-worker",
  "aud": "execution-gate-1",
  "action": "create_payment",
  "payload_hash": "sha256:...",
  "action_hash": "sha256:...",
  "policy_id": "prod/v1",
  "policy_hash": "sha256:...",
  "policy_ref": "mcc.rego/send_payment/escalate",
  "nonce": "single-use-uuid",
  "nbf": 1760000000,
  "exp": 1760000060,
  "constraints": {
    "max_amount_usd": 500
  },
  "audit_ref": "audit://..."
}
```

The JSON payload above is not authority by itself. It becomes enforceable only when it is canonically serialized, signed by a trusted MCC authority key, and verified by the execution gate.

Reference signature envelope:

```text
decision_token = canonical_payload + signature
signature      = Sign(canonical_payload, trusted_mcc_authority_key)
verify         = Verify(signature, canonical_payload, trusted_key_set)
```

Token fields:

| Field | Purpose |
|---|---|
| `iss` | MCC authority issuing the decision token. |
| `kid` | Trusted signing key identifier. |
| `sub` | Actor requesting or executing the action. |
| `aud` | Intended execution gate. |
| `action` | Runtime action being authorized. |
| `payload_hash` | Binds the decision to the exact payload. Tampering invalidates authority. |
| `action_hash` | Binds authority to the specific action being executed. |
| `policy_id` | Policy identifier used during evaluation. |
| `policy_hash` | Ensures policy state at decision time matches gate-side verification. |
| `policy_ref` | Links the execution decision to the evaluated policy branch. |
| `nonce` | Single-use replay protection. Used nonce — deny. |
| `nbf` / `exp` | Short validity window. Stale or premature tokens cannot authorize execution. |
| `constraints` | Explicit limits attached to the decision. |
| `audit_ref` | Links the decision to append-only audit evidence. |

---

## Security Model

MCC-Core follows a fail-closed posture.

Uncertainty does not authorize execution.

Every verification failure results in denial.

### Deny by Default

Missing, ambiguous, stale, invalid, unavailable, or unverifiable authority state denies execution.

There is no permissive fallback.

### Policy Engine Fail-Closed

OPA timeout, unreachable service, missing result, invalid JSON, or invalid decision resolves to `DENY`.

### Signature Verification

Decision tokens are verified against trusted authority keys.

Invalid, revoked, or unknown keys deny execution.

### Replay Protection

Single-use nonces prevent token reuse.

Distributed deployments require shared nonce state.

### Canonical Binding

Payload, action, policy, identity, and audience binding prevent request substitution and scope drift.

### Policy Trust Set

Only accepted policy versions authorize execution.

Mismatch, revocation, or expiry resolves to denial.

---

## Audit Model

Audit before actuation.

Always.

The execution flow records an audit event before the actuator, external tool, API, or operational system is invoked.

Audit evidence is append-only and hash-chain friendly.

Reference audit sequence:

```text
1  VERIFY_POLICY
2  VERIFY_TOKEN
3  EXECUTION_ATTEMPT
4a EXECUTION_REJECTED
4b EXECUTION_SUCCEEDED
4c EXECUTION_FAILED
4d EXECUTION_EXCEPTION
```

---

## Why Not Just Use OPA, SPIFFE, IAM, or Existing Policy Engines?

MCC-Core is not a policy engine, identity system, agent framework, observability layer, or functional safety system.

It is the execution decision boundary that turns identity, policy, risk, context, constraints, token validity, replay protection, and audit evidence into one enforceable runtime decision before real-world execution.

MCC-Core does not ask only:

```text
Is this allowed by policy?
```

It asks:

```text
Is this actor authorized to execute this exact action,
with this payload,
under this policy,
in this context,
within this time window,
with a valid token,
unused nonce,
enforceable constraints,
and audit evidence before execution?
```

---

## Complementary Positioning

MCC-Core is complementary to existing identity, policy, access-control, observability, and safety systems.

It is not presented as a replacement for OPA, SPIFFE/SPIRE, IAM, RBAC/ABAC, agent frameworks, observability platforms, functional safety systems, E-stops, safety PLCs, compliance controls, or regulated approval mechanisms.

It is positioned as an execution governance boundary that can integrate with those systems and bind their signals into a verified runtime decision before execution.

| System | Role | MCC-Core Position |
|---|---|---|
| OPA / Rego | Policy evaluation | MCC-Core uses policy evaluation as an input and binds it to execution authority. |
| SPIFFE / SPIRE | Workload identity | Identity is necessary but not sufficient for authorizing a specific action. |
| IAM / RBAC / ABAC | Access control | Access is not execution governance. MCC-Core evaluates concrete execution attempts at runtime. |
| Agent frameworks | Planning and orchestration | Agent frameworks propose and route actions. MCC-Core gates execution. |
| Observability | Logs, traces, monitoring | Logging after execution is too late. MCC-Core controls whether execution is allowed. |
| Functional safety systems | Hardware limits and emergency control | MCC-Core does not replace certified safety systems. It governs AI action authority before execution. |

---

## Design Doctrine

Ten principles of verifiable execution governance:

### 1. Intent is not authority

A generated plan, model output, API call, workflow step, or agent decision is not automatically authorized to execute.

### 2. Execution requires a verified decision

Before execution, the system must produce a verifiable authority decision based on identity, policy, risk, context, constraints, approval state, and token validity.

### 3. Fail closed by default

Missing, ambiguous, stale, invalid, mismatched, expired, or unverifiable state denies execution.

Uncertainty is not permission.

### 4. Bind decisions to scope

Authority must be bound to action, payload, policy, identity, audience, constraints, time window, and nonce.

### 5. Audit before actuation

Execution attempts must be recorded in an append-only audit chain before the actuator, external tool, API, or operational system is invoked.

### 6. Separate proposal from authority

The system that proposes an action should not automatically possess execution authority.

Proposal and authorization are separate concerns.

### 7. Internal does not mean authorized

An internal agent, service, workflow, or controller may still be compromised, misconfigured, unauthorized, or operating outside approved scope.

### 8. Used nonce — deny

Token nonces are single-use.

Replay attempts are denied at the gate regardless of token validity in all other dimensions.

### 9. Override is not bypass

Emergency recovery paths must be explicitly authorized, signed, time-limited, nonce-protected, operator-bound, and auditable.

### 10. Make uncertainty non-permissive

When the system cannot verify the authority state, it should not allow execution by default.

Uncertainty resolves to denial.

---

## Reference Repository Structure

Recommended repository structure:

```text
mcc-core/
├── README.md
├── docker-compose.yml
├── server/
│   └── app.py
├── policies/
│   └── mcc.rego
├── tests/
│   └── smoke_test.sh
├── examples/
│   └── decision_request.json
└── docs/
    └── architecture.md
```

---

## Reference Runtime Scope

This README intentionally does not claim a Docker Compose runtime unless `docker-compose.yml` is present in the repository.

The repository should be evaluated against the runtime artifacts actually present in the public record, including source files, policy files, tests, examples, documentation, and release history.

If a Docker Compose runtime is added later, it should be documented in a separate revision with matching files and commands.

---

## Example Decision Request

```json
{
  "actor": "agent/payment-worker",
  "action": "create_payment",
  "payload": {
    "amount_usd": 750,
    "recipient": "vendor_123"
  },
  "context": {
    "environment": "production",
    "risk_level": "medium"
  }
}
```

Possible result:

```json
{
  "decision": "ESCALATE",
  "reason": "payment exceeds autonomous threshold",
  "constraints": {
    "requires_human_approval": true
  }
}
```

---

## Public Technical Review Status

This repository is maintained as a public technical record and reference implementation for MCC-Core.

The purpose of this repository is to document the architecture, runtime model, doctrine, and prototype behavior of MCC-Core as an execution governance boundary for autonomous AI systems.

Technical comments, independent review, and expert analysis may reference this repository as a fixed public artifact.

The core doctrine is intentionally stable:

```text
Intent is not authority.
Execution requires a verified decision.
No verified decision — no execution.
Fail closed by default.
```

Changes that affect the doctrine, authority model, runtime law, or fail-closed posture should be treated as architecture-level revisions, not routine contributions.

---


## Accurate Positioning

MCC-Core should be described precisely.

### Accurate descriptions

- AXLOGIQ’s execution governance architecture/product direction
- MCC-Core public reference architecture and reference implementation
- Execution governance model for autonomous AI systems
- Verifiable decision boundary between intent and action
- Architectural draft and open protocol direction
- Technical prototype for review, simulation, and discussion
- Public technical record — Alexandr Ponomariov / AXLOGIQ

### Inaccurate descriptions

Do not describe MCC-Core as:

- certified production safety system
- government-approved or government-endorsed
- adopted by xAI or any named organization
- independently audited or formally verified
- industry standard or certified compliance product
- patent granted
- production-proven at scale

---

## Project Identity

**Company / Project Identity:** AXLOGIQ  
**Architecture / Product Direction:** MCC — Meta-Cognitive Control  
**Technical Runtime:** MCC-Core  
**Founder & Architect:** Alexandr Ponomariov  
**Status:** Public reference architecture / prototype  
**Initial Public Prior-Art Release:** April 22, 2026  
**Public Architecture Record:** May 2026  
**Repository:** github.com/mcc-prior-art/mcc-layer  
**Public Record:** axlogiq.org  
**Technical Product Site:** axlogiq.ai  
**Corporate Site:** axlogiq.com  

---

## Footer Principle

**Autonomy without verifiable control is not intelligence.**

**Intent is not authority.**

**No verified decision — no execution.**

---

## License

Rights and licensing are defined by the applicable repository license and project documentation.

---

**VERIFY EVERY INTENT. CONTROL EVERY ACTION. BUILD TRUSTED AUTONOMY.**
