# MCC-Core: Execution Governance Infrastructure

**Public technical record established:** May 2026  
**Author:** Alexandr Ponomariov / AXLOGIQ Inc.  
**Repository:** https://github.com/mcc-prior-art/mcc-layer  
**Version:** `v1.5.0` | **Date:** `2026-05-25`

---

<p align="center">
  <strong>Verified execution authority for autonomous AI systems.</strong>
</p>

<p align="center">
  <strong>Intent is not authority. Memory is not authority.<br>
  Execution requires a verified decision token.</strong>
</p>

<p align="center">
  <a href="https://www.axlogiq.com">
    <img alt="AXLOGIQ Corporate" src="https://img.shields.io/badge/AXLOGIQ-CORPORATE-00B8DB?style=for-the-badge">
  </a>
  <br>
  <a href="https://axlogiq.ai">
    <img alt="MCC-Core Technical Runtime" src="https://img.shields.io/badge/MCC--CORE-TECHNICAL_RUNTIME-15388A?style=for-the-badge">
  </a>
  <br>
  <a href="https://axlogiq.org">
    <img alt="Public Architecture Record" src="https://img.shields.io/badge/PUBLIC_ARCHITECTURE-RECORD-111827?style=for-the-badge">
  </a>
</p>

<p align="center">
  <img src="docs/exhibits/AXLOGIQ_Governance_v2.png" alt="AXLOGIQ Execution Governance Infrastructure" width="100%">
</p>

<p align="center">
  <a href="docs/exhibits/README.md"><strong>View MCC-I Exhibits G3–G4.1 →</strong></a>
  ·
  <a href="docs/exhibits/AXLOGIQ_Governance_v2.png"><strong>View Governance Exhibit →</strong></a>
</p>

---

## Executive Summary

**MCC-Core** is a public reference architecture and minimal reference runtime for verified execution governance in autonomous AI systems.

As AI systems move from generating answers to executing actions, the critical infrastructure problem changes.

The question is no longer only:

> Can the model reason?

The execution question is:

> Is this exact action authorized to execute, under this policy, by this actor, in this context, at this time?

MCC-Core defines the verified boundary between AI-generated intent and authorized execution by verifying identity, policy, risk, context, constraints, memory freshness, token validity, replay state, and auditability before an action is allowed.

Core principle:

> Intent is not authority.  
> Memory is not authority.  
> Execution requires a verified decision token.  
> No verified decision token — no execution.

MCC-Core produces explicit execution outcomes:

- **ALLOW**
- **DENY**
- **ESCALATE**
- **CONSTRAIN**

When execution is authorized, MCC-Core issues a signed, scoped, time-limited, replay-protected decision token.

The execution gate does not infer permission. It verifies authority.

This repository contains the public reference architecture, doctrine, runtime model, MCC-I infrastructure vertical, exhibit materials, and MCC-Core API Server reference direction.

Current status: **Public reference architecture + minimal runnable reference implementation for local testing and technical review.**

This is not a certified production system, a formally audited security product, or a government-approved solution.

---

## Boundary Note

MCC-Core is not an AI model, not an agent framework, and not a certified production safety system.

It is a public reference architecture and prototype runtime for evaluating whether proposed autonomous actions are authorized to execute.

MCC-Core does not replace enterprise security, compliance, legal review, or operational controls.

It defines the execution decision boundary before action.

---

## Quick Start

Clone the repository:

```bash
git clone https://github.com/mcc-prior-art/mcc-layer.git
cd mcc-layer
```

Run the minimal runtime proof:

```bash
python examples/mcc_runtime_proof.py
```

Expected behavior:

```text
WITHOUT MCC:
EXECUTED: user deleted

WITH MCC:
BLOCKED: Destructive action blocked
```

This demonstrates the core boundary: an action may be proposed, but execution is blocked unless MCC-Core authorizes it.

Run the API server locally:

```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

Run with OPA and Redis through Docker Compose:

```bash
docker compose up --build
```

Evaluate a proposed action:

```bash
curl -X POST http://localhost:8000/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "actor": "infra_agent",
    "action": "terraform_apply",
    "target": "production_cluster",
    "environment": "production"
  }'
```

Example response:

```json
{
  "outcome": "ESCALATE",
  "reason_code": "STALE_MEMORY_CONTEXT_MISMATCH",
  "token_issued": false,
  "execution_allowed": false,
  "audit_recorded": true
}
```

Possible governance outcomes:

```text
ALLOW / DENY / ESCALATE / CONSTRAIN
```

If authority cannot be verified, MCC-Core fails closed.

---

## Category Statement

AXLOGIQ Inc. builds execution governance infrastructure for autonomous systems.

MCC-Core is not a generic AI safety layer.

MCC-Core is a verified execution authority layer.

It governs whether autonomous systems are authorized to act before execution occurs.

Correct category:

- Execution Governance Infrastructure
- Verified Execution Authority
- Decision Boundary for Autonomous Systems
- Public Reference Architecture for AI execution control

Not the category:

- Generic AI safety slogan
- AI ethics layer
- Content moderation layer
- Agent framework
- Monitoring dashboard only
- Logging system only

The core distinction:

> AI safety asks: Can the model be trusted?  
> MCC-Core asks: Who authorized this action?

The model may propose.  
MCC-Core evaluates.  
The execution gate enforces.  
The audit trail proves.

---

## Productization Directions

MCC-Core is the foundational execution governance engine.

AXLOGIQ commercializes MCC-Core through domain-specific agent systems while preserving MCC-Core as the common execution governance engine across verticals.

Clients can adopt ready-to-use agent systems while MCC-Core remains the embedded verified execution authority layer underneath.

### AXLOGIQ Agent Systems

| Product / Vertical | Domain | Primary Responsibility | Key Principle |
|---|---|---|---|
| **ProcureGuard AI** | Procurement | Vendor decisions, purchase orders, change orders, cost control | No procurement action without a verified decision token |
| **InfraGuard AI / MCC-I** | Infrastructure & Cloud | CI/CD, IAM, Terraform, Kubernetes, shell commands, production changes | Memory is not authority |
| **PayGuard AI** | Finance & Payments | Invoice approval, payouts, payment workflows, financial execution | Critical financial actions require verified execution governance |

All agents are powered by the same MCC-Core engine.

Strategic principle:

> Build the agent to prove the layer. Sell the layer to scale beyond the agent.

---

## Relationship to Exhibits

The principle **Memory Is Not Authority** is formally documented in:

- [MCC-I Exhibits G3–G4.1](docs/exhibits/README.md)

The exhibit package includes:

- **Corporate Governance Exhibit** — AXLOGIQ category and authorship positioning
- **G3 — Memory–Authority Boundary** — the core principle
- **G4 — Stale Memory Production Deploy** — practical production deployment risk
- **G4.1 — Technical Prevention Layer** — technical validation and execution-blocking model

These exhibits serve as public reference architecture demonstrating why verified execution authority is required for infrastructure and cloud operations.

---

## MCC-I — Infrastructure & Cloud

**MCC-I** is the infrastructure and cloud execution governance vertical powered by MCC-Core.

**InfraGuard AI** is the productized agent system for the MCC-I vertical.

It governs:

- Terraform
- Kubernetes
- IAM changes
- CI/CD pipelines
- Cloud APIs
- Shell commands
- Production changes
- Infrastructure automation
- Privileged operational actions

Key principle:

> An agent may remember the past.  
> MCC-I authorizes the present.  
> Memory without a token is not permission.  
> No verified decision token — no infrastructure change.

Infrastructure agents can be useful.

But if an agent can deploy, delete, escalate privileges, rotate keys, alter policies, modify production, or trigger cloud operations, execution authority must be explicit, current, and verifiable.

MCC-I exists to make infrastructure autonomy governable.

---

## Memory Is Not Authority

Agent memory creates a new execution risk.

An autonomous agent may remember previous actions, prior approvals, historical tickets, deployment patterns, user preferences, successful workflows, or past operational decisions.

But memory is context.

Memory is not authority.

> An agent may remember the past.  
> MCC authorizes the present.

Memory without a valid decision token is not permission.

In infrastructure, payments, procurement, cloud operations, and other high-impact environments, remembered context must not become execution authority.

A valid action requires current verification of:

- Identity
- Policy
- Environment
- Risk
- Approval state
- Execution scope
- Auditability
- Token validity
- Nonce / replay state
- Memory freshness

The memory may inform evaluation. It cannot authorize execution.

For infrastructure and cloud operations, this principle becomes MCC-I:

> An agent may remember the past.  
> MCC-I authorizes the present.  
> No verified decision token — no infrastructure change.

---

## Runtime Law

No verified decision token — no execution.

Execution invariants:

- No identity → no execution
- No policy → no execution
- No verified decision token → no execution
- No valid decision token → no execution
- Memory without a valid token → deny
- Stale context → deny or escalate
- Used nonce → deny
- Expired token → deny
- Invalid signature → deny
- Missing audit path → deny
- Fail closed by default

MCC-Core does not treat model confidence as authorization.

MCC-Core does not treat memory as authorization.

MCC-Core does not treat prior successful execution as current permission.

Every action must be evaluated under current policy, current context, and current authority.

---

## Core Thesis

The model proposes.  
MCC-Core evaluates.  
The gate enforces.  
The audit proves.

Proposal is not permission.  
Model output is not authorization.  
Neural confidence is not a license to act.  
Memory is not authority.

Every autonomous system requires a verifiable boundary between intent and execution.

---

## Execution Boundary

MCC-Core separates proposed intent from authorized execution.

A proposed action is evaluated against:

- Actor identity
- System identity
- Policy state
- Risk profile
- Execution context
- Memory freshness
- Action scope
- Approval requirements
- Token validity
- Nonce state
- Auditability

The result is a governed execution decision.

| Outcome | Meaning |
|---|---|
| **ALLOW** | The action is authorized to execute under current policy and context. |
| **DENY** | The action is not authorized and must not execute. |
| **ESCALATE** | The action may be valid, but requires human or higher-authority approval. |
| **CONSTRAIN** | The action may proceed only under explicit limits or modified conditions. |

Execution occurs only after a valid decision is issued and enforced.

---

## Reference Flow

```text
Intent
  ↓
MCC-Core Evaluation
  ↓
Verified Decision
  ↓
Signed Decision Token
  ↓
Execution Gate
  ↓
Authorized Execution
  ↓
Audit Record
```

The action does not execute because the agent proposed it.

The action executes only if the execution gate receives a valid, verified decision token.

---

## Technical Model

MCC-Core is designed around a simple execution-control model:

1. **Intent is proposed**  
   An AI agent, workflow, service, user, automation, or external system proposes an action.

2. **MCC-Core evaluates authority**  
   MCC-Core evaluates the proposed action against identity, policy, context, risk, memory freshness, approval state, token state, and auditability.

3. **A decision is produced**  
   MCC-Core returns ALLOW, DENY, ESCALATE, or CONSTRAIN.

4. **A decision token may be issued**  
   If the action is authorized, MCC-Core issues a signed, scoped, time-limited, replay-protected decision token.

5. **The execution gate enforces**  
   The execution gate verifies the token before any action is allowed.

6. **Audit is recorded**  
   Every decision and execution attempt is recorded for traceability.

The architecture is intentionally simple:

> No verified decision token — no execution.

---

## Example Decision Request

Example action:

```text
action: terraform_apply
target: production_cluster
environment: production
actor: infra_agent
memory_policy: infra-policy-v3
current_policy: infra-policy-v4
memory_ctx: ctx_91f3a8
current_ctx: ctx_b72c19
```

Detected mismatch:

```text
policy_version_mismatch
context_hash_mismatch
```

Decision:

```text
OUTCOME: ESCALATE
token_issued: false
execution_allowed: false
```

Meaning:

The agent may remember a previous approval, but remembered approval does not authorize a current production action.

MCC-I requires current verification.

No valid decision token is issued.

Execution is blocked.

---

## MCC-Core API Server Direction

The MCC-Core API Server reference direction supports:

- Request evaluation
- Policy-aware decisioning
- Structured outcomes
- Decision token issuance
- Fail-closed behavior
- Audit-before-actuation
- Replay prevention
- Runtime testing
- Integration review

Representative endpoint direction:

```text
POST /evaluate
```

Representative decision response:

```json
{
  "outcome": "ESCALATE",
  "reason_code": "STALE_MEMORY_CONTEXT_MISMATCH",
  "token_issued": false,
  "execution_allowed": false,
  "audit_recorded": true
}
```

This repository is intended for local testing, simulation, technical review, and enterprise PoC design.

---

## Core Components

MCC-Core is organized around a small set of execution-governance components:

- **Policy Engine** — evaluates whether a proposed action is allowed under current policy.
- **Decision Token** — represents signed, scoped, time-limited execution authority.
- **Execution Gate** — verifies the decision token before allowing execution.
- **Audit Log** — records decisions and execution attempts for traceability.
- **Replay Protection** — prevents reuse of expired or previously consumed authority.
- **Escalation Logic** — routes high-risk or ambiguous actions to human or higher-authority review.

Recommended reading path:

1. Start with the README for the category and execution model.
2. Review the MCC-I exhibits for the memory-authority boundary.
3. Run the Quick Start proof.
4. Inspect the runtime proof and API evaluation flow.

---

## Accurate Positioning

Correct descriptions:

- AXLOGIQ’s execution governance architecture
- MCC-Core public reference architecture and reference implementation
- Verified decision boundary between intent and action
- Execution governance infrastructure for autonomous AI systems
- Public technical record — Alexandr Ponomariov / AXLOGIQ Inc.
- Prototype runtime for technical review, simulation, local testing, and integration design
- Verified execution authority layer for autonomous systems

Do not describe as:

- Certified production safety system
- Government-approved or endorsed
- Independently audited or formally verified
- Production-proven at scale
- Guaranteed prevention system
- Replacement for enterprise security, legal, compliance, or operational controls
- Generic AI safety product

---

## What MCC-Core Is Not

MCC-Core is not:

- A frontier AI model
- An agent framework
- A chatbot
- A generic AI safety slogan
- A content moderation layer
- A monitoring dashboard only
- A logging tool only
- An ERP system
- A payment processor
- A cloud provider
- A contract management system
- A certified safety product

MCC-Core is the execution governance boundary before action.

---

## What MCC-Core Is

MCC-Core is:

- An execution governance boundary
- A verified decision layer
- A pre-execution authority mechanism
- A policy-aware control point
- A token-gated execution model
- An audit-before-actuation pattern
- A fail-closed runtime architecture
- A public reference architecture for autonomous execution control

MCC-Core does not replace the model.

MCC-Core governs whether model-proposed actions are authorized to execute.

---

## Public Technical Record

This repository functions as a public technical record for:

- MCC — Meta-Cognitive Control
- MCC-Core
- MCC-I
- Memory–Authority Boundary
- Verified Execution Authority
- Execution Governance Infrastructure
- AXLOGIQ Inc. architecture doctrine
- Reference implementation direction
- Exhibit documentation

Key exhibit package:

- [MCC-I Exhibits G3–G4.1](docs/exhibits/README.md)

Key corporate governance exhibit:

- [AXLOGIQ Governance v2](docs/exhibits/AXLOGIQ_Governance_v2.png)

---

## Project Identity

- Company: **AXLOGIQ Inc.**
- Architecture: **MCC — Meta-Cognitive Control**
- Technical Runtime: **MCC-Core**
- Infrastructure Vertical: **MCC-I**
- Productized Infrastructure Agent: **InfraGuard AI**
- Procurement Agent System: **ProcureGuard AI**
- Finance & Payments Agent System: **PayGuard AI**
- Founder & Architect: **Alexandr Ponomariov**
- Repository: `github.com/mcc-prior-art/mcc-layer`
- Corporate Site: `www.axlogiq.com`
- Technical Product Site: `axlogiq.ai`
- Public Architecture Record: `axlogiq.org`

---

## Official Resources

- Corporate: `https://www.axlogiq.com`
- Technical Product: `https://axlogiq.ai`
- Public Architecture Record: `https://axlogiq.org`
- GitHub Reference: `https://github.com/mcc-prior-art/mcc-layer`
- MCC-I Exhibits: `docs/exhibits/README.md`

---

## Founder & Architect

**Alexandr Ponomariov**  
Founder & Architect, **AXLOGIQ Inc.**  
Architect of **MCC — Meta-Cognitive Control**  
Creator of **MCC-Core reference runtime**

---

## Canonical Doctrine

```text
Intent is not authority.
Memory is not authority.
Proposal is not permission.
Model output is not authorization.
Neural confidence is not a license to act.

Execution requires a verified decision token.
No verified decision token — no execution.

The model proposes.
MCC-Core evaluates.
The gate enforces.
The audit proves.

Easy to integrate.
Hard to bypass.
Fail closed by default.
Audit before actuation.
```

---

## Claim Hygiene

This repository describes a public reference architecture and prototype implementation for technical review, simulation, local testing, enterprise PoC design, and integration review.

It does not claim:

- Production certification
- Government approval
- Certified safety status
- Formal audit completion
- Production deployment at scale
- Guaranteed prevention of all failures
- Replacement for enterprise security, legal, compliance, or operational controls

MCC-Core and MCC-I are presented as public reference architecture and prototype / technical review materials.

---

## Status

Prepared: **May 2026**  
Classification: **Public Reference Architecture**  
Status: **Prototype / Technical Review**

---

## Footer Principle

Autonomy without verifiable control is not intelligence.

Intent is not authority.

Memory is not authority.

Execution requires a verified decision token.

No verified decision token — no execution.

---

**VERIFY THE DECISION. CONTROL THE EXECUTION. AUDIT THE OUTCOME.**
