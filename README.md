# MCC-Core

<p align="center">
  <strong>Execution Governance Infrastructure for Autonomous AI Systems</strong>
</p>

<p align="center">
  <strong>Autonomy without verifiable control is not intelligence.</strong>
</p>

<p align="center">
  <strong>Intent is not authority. Memory is not authority. Execution requires a verified decision.</strong>
</p>

<p align="center">
  <a href="https://axlogiq.com"><img alt="AXLOGIQ Corporate" src="https://img.shields.io/badge/AXLOGIQ-Corporate-00B8DB?style=for-the-badge"></a>
  <a href="https://axlogiq.ai"><img alt="MCC-Core Technical Product" src="https://img.shields.io/badge/MCC--Core-Technical_Runtime-15388A?style=for-the-badge"></a>
  <a href="https://axlogiq.org"><img alt="Public Architecture Record" src="https://img.shields.io/badge/Public-Architecture_Record-0A0F1A?style=for-the-badge"></a>
</p>

<p align="center">
  <img alt="Status" src="https://img.shields.io/badge/status-public_reference_architecture-blue.svg">
  <img alt="Runtime Law" src="https://img.shields.io/badge/runtime_law-no_verified_decision_no_execution-00B8DB.svg">
  <img alt="Posture" src="https://img.shields.io/badge/posture-fail_closed-FF5C7A.svg">
  <img alt="Execution" src="https://img.shields.io/badge/execution-token_required-15388A.svg">
  <img alt="Audit" src="https://img.shields.io/badge/audit-before_actuation-0A0F1A.svg">
</p>

---

## Executive Summary

MCC-Core is a public reference architecture and minimal reference runtime for verified execution governance in autonomous AI systems.

As AI systems move from generating answers to executing actions, the critical infrastructure problem changes.

The question is no longer only: **Can the model reason?**

The execution question is:

> Is this exact action authorized to execute, under this policy, by this actor, in this context, at this time?

MCC-Core defines the verified boundary between AI-generated intent and authorized execution by verifying identity, policy, risk, context, constraints, token validity, replay state, memory state, and auditability before action is allowed.

**Core principle:**

> Intent is not authority.  
> Memory is not authority.  
> Execution requires a verified decision.  
> No verified decision — no execution.

MCC-Core produces explicit execution outcomes: **ALLOW / DENY / ESCALATE / CONSTRAIN**.

When execution is authorized, MCC-Core issues a signed, scoped, time-limited, replay-protected decision token.

The execution gate does not infer permission. It verifies authority.

This repository contains the public reference architecture, doctrine, runtime model, MCC-I infrastructure vertical, exhibit materials, and MCC-Core API Server v0.1 reference direction.

Current status: Public reference architecture + minimal runnable reference implementation for local testing and technical review.

This is not a certified production system, a formally audited security product, or a government-approved solution.

---

## Productization Directions

MCC-Core is the foundational **execution governance engine**.

AXLOGIQ commercializes MCC-Core through domain-specific agent systems while preserving MCC-Core as the common execution governance engine across verticals.

Clients can adopt ready-to-use agent systems while MCC-Core remains the embedded verified execution authority layer underneath.

### AXLOGIQ Agents

| Agent | Domain | Primary Responsibility | Key Principle |
|---|---|---|---|
| **ProcureGuard AI** | Procurement | Vendor decisions, purchase orders, change orders, cost control | No procurement action without a verified decision token |
| **InfraGuard AI** | Infrastructure & Cloud / MCC-I | CI/CD, IAM, Terraform, Kubernetes, shell commands, production changes | Memory is not authority |
| **PayGuard AI** | Finance & Payments | Invoice approval, payouts, payment workflows, financial execution | Critical financial actions require verified execution governance |

All agents are powered by the **same MCC-Core** engine.

**Principle:**  
Build the agent to prove the layer. Sell the layer to scale beyond the agent.

### Relationship to Exhibits

The principle **"Memory Is Not Authority"** is formally documented in:

- [docs/exhibits/README.md](docs/exhibits/README.md) — MCC-I Exhibits G3–G4
  - **G3** — Defines the core principle
  - **G4** — Concrete example of stale memory risk in production deployment

These exhibits serve as public reference architecture demonstrating why verified execution authority is required for infrastructure and cloud operations.

---

## MCC-I — Infrastructure & Cloud

MCC-I is the infrastructure and cloud execution governance vertical powered by MCC-Core.

InfraGuard AI is the productized agent system for the MCC-I vertical.

It governs Terraform, Kubernetes, IAM changes, CI/CD, cloud APIs, shell commands, and production changes before execution.

**Key principle:**

> An agent may remember the past.  
> MCC-I authorizes the present.  
> Memory without a token is not permission.  
> No verified decision — no infrastructure change.

Infrastructure agents can be useful.

But if an agent can deploy, delete, escalate privileges, rotate keys, alter policies, modify production, or trigger cloud operations, execution authority must be explicit, current, and verifiable.

MCC-I exists to make infrastructure autonomy governable.

---

## Memory Is Not Authority

Agent memory creates a new execution risk.

An autonomous agent may remember previous actions, prior approvals, historical tickets, deployment patterns, user preferences, successful workflows, or past operational decisions.

But memory is context.  
**Memory is not authority.**

> An agent may remember the past.  
> MCC authorizes the present.

Memory without a token is not permission.

In infrastructure, payments, procurement, cloud operations, and other high-impact environments, remembered context must not become execution authority.

A valid action requires current verification of identity, policy, environment, risk, approval state, execution scope, auditability, and token validity.

The memory may inform evaluation. It cannot authorize execution.

For infrastructure and cloud operations, this principle becomes MCC-I:

> An agent may remember the past.  
> MCC-I authorizes the present.  
> No verified decision — no infrastructure change.

---

## Runtime Law

**No verified decision — no execution.**

Execution invariants:

- No identity → no execution
- No policy → no execution
- No verified decision → no execution
- No valid decision token → no execution
- Memory without a valid token → deny
- Stale context → deny or escalate
- Used nonce → deny
- Expired token → deny
- Invalid signature → deny
- Missing audit path → deny
- Fail closed by default

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

- actor identity
- system identity
- policy state
- risk profile
- execution context
- memory freshness
- action scope
- approval requirements
- token validity
- nonce state
- auditability

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

## Accurate Positioning

**Correct descriptions:**

- AXLOGIQ’s execution governance architecture
- MCC-Core public reference architecture and reference implementation
- Verified decision boundary between intent and action
- Execution governance infrastructure for autonomous AI systems
- Public technical record — Alexandr Ponomariov / AXLOGIQ
- Prototype runtime for technical review, simulation, local testing, and integration design

**Do not describe as:**

- Certified production safety system
- Government-approved or endorsed
- Independently audited or formally verified
- Production-proven at scale
- Guaranteed prevention system
- Replacement for enterprise security, legal, compliance, or operational controls

---

## What MCC-Core Is Not

MCC-Core is not:

- a frontier AI model
- an agent framework
- a chatbot
- a generic AI safety slogan
- a monitoring dashboard only
- a logging tool only
- an ERP system
- a payment processor
- a cloud provider
- a contract management system
- a certified safety product

MCC-Core is the execution governance boundary before action.

---

## Project Identity

- **Company:** AXLOGIQ Inc.
- **Architecture:** MCC — Meta-Cognitive Control
- **Technical Runtime:** MCC-Core
- **Infrastructure Vertical:** MCC-I
- **Productized Infrastructure Agent:** InfraGuard AI
- **Procurement Agent System:** ProcureGuard AI
- **Finance & Payments Agent System:** PayGuard AI
- **Founder & Architect:** Alexandr Ponomariov
- **Repository:** github.com/mcc-prior-art/mcc-layer
- **Corporate Site:** axlogiq.com
- **Technical Product Site:** axlogiq.ai
- **Public Architecture Record:** axlogiq.org

---

## Canonical Doctrine

```text
Intent is not authority.
Memory is not authority.
Proposal is not permission.
Model output is not authorization.
Neural confidence is not a license to act.
Execution requires a verified decision.
No verified decision — no execution.
```

```text
The model proposes.
MCC-Core evaluates.
The gate enforces.
The audit proves.
```

```text
Easy to integrate.
Hard to bypass.
Fail closed by default.
Audit before actuation.
```

---

## Footer Principle

Autonomy without verifiable control is not intelligence.

Intent is not authority.  
Memory is not authority.  
Execution requires a verified decision.  
No verified decision — no execution.

---

VERIFY THE DECISION. CONTROL THE EXECUTION. AUDIT THE OUTCOME.
