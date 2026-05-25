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

The question is no longer only:

> Can the model reason?

The execution question is:

> Is this exact action authorized to execute, under this policy, by this actor, in this context, at this time?

MCC-Core defines the verified boundary between AI-generated intent and authorized execution.

**Core principle:**

> Intent is not authority.  
> Memory is not authority.  
> Execution requires a verified decision.  
> No verified decision — no execution.

---

## Why MCC-Core Exists

Autonomous AI systems increasingly operate across software, infrastructure, finance, procurement, operations, and real-world workflows.

They may generate plans, call tools, trigger APIs, approve workflows, modify systems, recommend purchases, initiate deployments, or act through agents.

But intelligence alone does not create authority.

A model may reason correctly.  
An agent may remember previous actions.  
A workflow may appear valid.  
A tool call may be technically possible.

None of that means execution is authorized.

MCC-Core exists to separate **intent** from **authority**.

It introduces a verifiable execution decision boundary before action occurs.

The model proposes.  
MCC-Core evaluates.  
The gate enforces.  
The audit proves.

---

## Core Thesis

Every autonomous system requires a verifiable boundary between intent and execution.

Proposal is not permission.  
Model output is not authorization.  
Neural confidence is not a license to act.  
Memory is not authority.

MCC-Core treats execution as a governed event, not as a direct consequence of model output.

Before an action executes, MCC-Core evaluates:

- Who or what is requesting the action
- What action is being proposed
- Which policy applies
- Whether the context is current
- Whether the action is within scope
- Whether risk requires escalation
- Whether a valid decision token exists
- Whether the action can be audited before actuation

If the decision is not verified, execution does not happen.

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

MCC-Core is designed around a simple rule:

> The system must be easy to integrate and hard to bypass.

---

## Memory Is Not Authority

Agent memory creates a new class of execution risk.

An autonomous agent may remember:

- Previous approvals
- Prior tickets
- Past deployments
- Historical vendor decisions
- Earlier user instructions
- Old operational states
- Prior successful actions
- Repeated workflow patterns

But memory is context.

**Memory is not authority.**

An agent may remember the past.  
MCC-Core authorizes the present.

Memory without a valid decision token is not permission.

This matters because autonomous systems do not only reason from prompts. They increasingly reason from accumulated context, logs, embeddings, prior actions, workflow history, and long-term memory.

That memory may be useful.

It may also be stale, incomplete, misapplied, or no longer authorized.

MCC-Core prevents remembered context from becoming implicit execution authority.

---

## Decision Outcomes

MCC-Core evaluates proposed actions and returns a governed decision outcome.

| Outcome | Meaning |
|---|---|
| **ALLOW** | The action is authorized under current identity, policy, context, and risk conditions. |
| **DENY** | The action is not authorized and must not execute. |
| **ESCALATE** | The action may be valid but requires human or higher-authority review before execution. |
| **CONSTRAIN** | The action may proceed only under explicit limitations, reduced scope, or modified parameters. |

These outcomes allow autonomous systems to act with controlled execution authority rather than uncontrolled tool access.

---

## Reference Architecture

MCC-Core sits between autonomous intent and execution.

```text
User / Agent / Workflow / Model
        |
        v
Proposed Intent
        |
        v
MCC-Core Decision Boundary
        |
        |-- Evaluate identity
        |-- Evaluate policy
        |-- Evaluate risk
        |-- Evaluate context
        |-- Evaluate memory freshness
        |-- Evaluate token validity
        |-- Evaluate auditability
        |
        v
ALLOW / DENY / ESCALATE / CONSTRAIN
        |
        v
Signed Decision Token
        |
        v
Verified Execution Gate
        |
        v
Authorized Action
        |
        v
Audit Log
```

The execution gate does not execute because an agent asked.

It executes only when a valid verified decision exists.

---

## Execution Flow

MCC-Core follows a simple execution governance pattern:

```text
Evaluate → Decide → Tokenize → Enforce → Audit
```

### 1. Evaluate

The proposed action is evaluated against identity, policy, risk, context, and execution constraints.

### 2. Decide

MCC-Core returns one of four outcomes:

```text
ALLOW / DENY / ESCALATE / CONSTRAIN
```

### 3. Tokenize

If execution is permitted or constrained, MCC-Core issues a decision token containing the verified decision state.

### 4. Enforce

The execution gate checks the token before allowing tool, API, workflow, infrastructure, financial, or operational execution.

### 5. Audit

Every decision and execution attempt is recorded before actuation.

No audit path means no trusted execution path.

---

## Productization Directions

MCC-Core is the foundational **execution governance engine**.

AXLOGIQ commercializes MCC-Core through domain-specific agent systems while preserving MCC-Core as the common execution governance engine across verticals.

Clients can adopt MCC-powered systems as practical agent products, while MCC-Core remains the underlying execution authority layer.

### AXLOGIQ Agent Systems

| Agent System | Vertical | Primary Responsibility | Key Principle |
|---|---|---|---|
| **ProcureGuard AI** | Procurement | Vendor decisions, purchase orders, change orders, cost control | No action without a verified decision token |
| **InfraGuard AI** | MCC-I / Infrastructure & Cloud | CI/CD, IAM, Terraform, Kubernetes, shell commands, production changes | Memory is not authority |
| **PayGuard AI** | Finance & Payments | Invoice approval, payouts, payment workflows, financial execution | Critical financial actions require verified execution governance |

All agent systems are powered by the same MCC-Core engine.

**Strategic principle:**

> Build the agent to prove the layer.  
> Sell the layer to scale beyond the agent.

This allows AXLOGIQ to demonstrate MCC-Core through concrete products while preserving the long-term infrastructure opportunity.

---

## MCC-I — Infrastructure & Cloud

MCC-I is the infrastructure and cloud execution governance vertical powered by MCC-Core.

The productized agent system for this vertical is **InfraGuard AI**.

MCC-I governs high-impact infrastructure actions before they execute, including:

- Terraform changes
- Kubernetes operations
- IAM modifications
- CI/CD deployments
- Cloud API calls
- Shell commands
- Production configuration changes
- Cost-impacting infrastructure actions
- Security-sensitive operational workflows

**Key principle:**

> An agent may remember the past.  
> MCC-I authorizes the present.  
> Memory without a token is not permission.  
> No verified decision — no infrastructure change.

Infrastructure agents can be useful.

But if an agent can deploy, delete, escalate privileges, rotate keys, alter policies, modify production, or trigger cloud operations, execution authority must be explicit, current, and verifiable.

MCC-I exists to make infrastructure autonomy governable.

---

## Relationship to Exhibits

The principle **"Memory Is Not Authority"** is formally documented in the MCC-I exhibit set.

- [docs/exhibits/README.md](docs/exhibits/README.md) — MCC-I Exhibits G3–G4
  - **G3** — Defines the core principle: Memory Is Not Authority
  - **G4** — Demonstrates stale memory risk in production deployment scenarios

These exhibits serve as public reference architecture demonstrating why verified execution authority is required for infrastructure and cloud operations.

They support the broader MCC-Core doctrine:

> Intent is not authority.  
> Memory is not authority.  
> Execution requires a verified decision.

---

## Example Decision Request

A typical MCC-Core decision request asks whether a proposed action should be allowed to execute.

```json
{
  "actor": {
    "id": "agent.infraguard.production",
    "type": "autonomous_agent"
  },
  "action": {
    "type": "terraform_apply",
    "target": "production_cluster",
    "scope": "infrastructure_change"
  },
  "context": {
    "environment": "production",
    "risk_level": "high",
    "memory_reference": "previous_deployment_pattern",
    "ticket_id": "OPS-1842"
  },
  "policy": {
    "required_approval": true,
    "allow_production_apply": false,
    "stale_memory_execution": "deny"
  }
}
```

A possible MCC-Core response:

```json
{
  "outcome": "ESCALATE",
  "reason_code": "PRODUCTION_CHANGE_REQUIRES_APPROVAL",
  "decision": "Action cannot execute automatically in production.",
  "token_issued": false,
  "audit_required": true
}
```

The agent may have remembered a previous deployment pattern.

But memory is not authority.

No verified decision token means no execution.

---

## Example Enforcement Rule

A downstream execution gate should enforce MCC-Core decisions before allowing action.

```python
def execute_action(action, decision_token):
    if decision_token is None:
        raise PermissionError("No verified decision token — no execution.")

    if not verify_signature(decision_token):
        raise PermissionError("Invalid decision token — deny.")

    if is_expired(decision_token):
        raise PermissionError("Expired decision token — deny.")

    if is_nonce_used(decision_token):
        raise PermissionError("Replay detected — deny.")

    if decision_token.outcome not in ["ALLOW", "CONSTRAIN"]:
        raise PermissionError("Decision outcome does not authorize execution.")

    audit_before_actuation(action, decision_token)

    return perform_authorized_action(action, decision_token.constraints)
```

The execution gate does not trust model output.

It trusts only a valid, current, verified decision.

---

## Design Principles

MCC-Core is designed around the following principles:

### 1. Intent is not authority

A model, agent, workflow, or user may propose an action.

Proposal alone does not authorize execution.

### 2. Memory is not authority

Stored context, prior approvals, previous workflows, and remembered outcomes cannot become implicit permission.

### 3. Execution requires a verified decision

Every meaningful action requires an explicit decision before execution.

### 4. Fail closed by default

If identity, policy, token, context, signature, nonce, or audit state cannot be verified, the system denies execution.

### 5. Audit before actuation

The decision path must be recorded before the action executes.

### 6. Authority must be current

Past approval does not automatically authorize present execution.

### 7. Governance must be enforceable

Policy is not enough unless the execution gate can enforce it.

---

## What MCC-Core Is

MCC-Core is:

- A public reference architecture for execution governance
- A minimal reference runtime for verified decision enforcement
- A decision boundary between autonomous intent and authorized action
- A governance layer for AI agents, workflows, tools, APIs, and operational systems
- A technical record of MCC — Meta-Cognitive Control
- A prototype implementation for simulation, enterprise PoC, integration design, and technical review

---

## What MCC-Core Is Not

MCC-Core is not currently:

- A certified production safety system
- A government-approved control system
- A formally verified runtime
- An independently audited security product
- A production-proven system at enterprise scale
- A replacement for existing security, compliance, IAM, SIEM, ERP, DevOps, or financial control systems

MCC-Core is a reference architecture and prototype runtime intended to demonstrate a missing control boundary:

> Verified execution authority for autonomous systems.

---

## Accurate Positioning

**Correct descriptions:**

- AXLOGIQ’s execution governance architecture
- MCC-Core public reference architecture and reference implementation
- Verified decision boundary between intent and action
- Execution governance infrastructure for autonomous AI systems
- Public technical record — Alexandr Ponomariov / AXLOGIQ
- Prototype runtime for technical review, simulation, and integration design

**Do not describe as:**

- Certified production safety system
- Government-approved or endorsed system
- Independently audited security product
- Formally verified runtime
- Production-proven at scale
- Guaranteed prevention system
- Replacement for enterprise security, legal, compliance, or operational controls

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
