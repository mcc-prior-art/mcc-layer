# MCC-Core

<p align="center">
  <strong>Execution Governance Infrastructure for Autonomous AI Systems</strong>
</p>

<p align="center">
  <strong>Intent is not authority. Execution requires a verified decision.</strong>
</p>

<p align="center">
  <a href="https://axlogiq.com"><img alt="AXLOGIQ Corporate" src="https://img.shields.io/badge/AXLOGIQ-Corporate-00B8DB?style=for-the-badge"></a>
  <a href="https://axlogiq.ai"><img alt="MCC-Core Technical Product" src="https://img.shields.io/badge/MCC--Core-Technical_Runtime-15388A?style=for-the-badge"></a>
  <a href="https://axlogiq.org"><img alt="Public Architecture Record" src="https://img.shields.io/badge/Public_Architecture_Record-May_2026-111827?style=for-the-badge"></a>
</p>

---

## Public Reference Record

**Original public prior-art date:** 2026-04-22  
**Current public release package:** v1.5.0 / May 2026  
**Commit:** `52e1`  
**Author:** Alexandr Ponomariov / AXLOGIQ Inc.  
**Repository:** https://github.com/mcc-prior-art/mcc-layer  

MCC-Core is a public reference architecture and early implementation for a fail-closed execution governance layer between AI intent and real-world action.

The purpose of this repository is to document the technical structure, terminology, design principles, and implementation direction of MCC-Core as a public technical record.

---

## Core Principle

AI systems can generate intent.

They can propose actions.

They can reason, plan, optimize, and call tools.

But intent is not authority.

MCC-Core defines the verified decision boundary between an AI-generated proposal and authorized execution.

> The model proposes.  
> MCC-Core evaluates.  
> The execution gate enforces.  
> No verified decision — no execution.

---

## What MCC-Core Is

MCC-Core is an execution governance layer for autonomous AI systems.

It is designed to evaluate proposed actions before execution and return one of four controlled outcomes:

- `ALLOW`
- `DENY`
- `ESCALATE`
- `CONSTRAIN`

The system is intended to sit between AI intent sources and real-world execution surfaces such as APIs, cloud systems, procurement systems, payment workflows, infrastructure operations, enterprise tools, or other action-capable environments.

MCC-Core is not a model.

MCC-Core is not an agent framework.

MCC-Core is not a generic AI safety slogan.

MCC-Core is a decision boundary.

---

## Why MCC-Core Exists

Autonomous AI systems are moving from generation to execution.

That shift creates a new infrastructure problem:

AI output is not enough.

Reasoning is not enough.

Confidence is not enough.

A system that can act needs a verifiable control boundary before action.

Without such a boundary, autonomous systems may execute actions that are unauthorized, unsafe, out of policy, economically harmful, irreversible, or insufficiently auditable.

MCC-Core addresses this gap by separating:

```text
Intent generation
from
Execution authority
```

The central rule is simple:

```text
No verified decision — no execution.
```

---

## Execution Governance Boundary

MCC-Core evaluates whether an action proposed by an AI system should be allowed to execute.

The proposed action is evaluated against identity, policy, risk, context, constraints, approval requirements, replay protection, and auditability.

A verified decision is then issued.

Execution gates only allow action when a valid decision is present.

```text
AI / Agent / Workflow
        |
        v
Proposed Intent
        |
        v
MCC-Core Evaluation
        |
        v
ALLOW / DENY / ESCALATE / CONSTRAIN
        |
        v
Verified Decision Token
        |
        v
Execution Gate
        |
        v
Authorized Action
        |
        v
Audit Record
```

---

## Reference Architecture

MCC-Core is structured around the following conceptual layers:

### L0 — Identity and Trust Fabric

Establishes the identity of users, services, agents, tools, workloads, and execution environments.

Examples include:

- Service identity
- Agent identity
- User identity
- Environment identity
- Key material
- Trust anchors
- Authentication context

### L1 — Intent Sources

Sources that propose actions.

Examples include:

- AI agents
- LLM workflows
- Automation tools
- Enterprise workflows
- API clients
- Human operators
- Scheduled jobs

At this layer, proposed action is only intent.

It is not permission.

### L2 — MCC-Core Decision Boundary

Evaluates whether a proposed action may execute.

Evaluation may include:

- Identity validation
- Policy evaluation
- Risk scoring
- Context analysis
- Scope checking
- Threshold checking
- Human escalation requirements
- Constraint generation
- Replay protection
- Audit readiness

MCC-Core returns a structured decision:

```text
ALLOW
DENY
ESCALATE
CONSTRAIN
```

### L3 — Enforcement Layer

The execution gate verifies the MCC-Core decision before allowing an action to proceed.

If the decision is missing, invalid, expired, replayed, or inconsistent, the gate fails closed.

### L4 — Controlled Execution

Only authorized actions reach the execution surface.

Examples include:

- Cloud APIs
- Infrastructure commands
- Procurement systems
- Payment workflows
- CRM systems
- Ticketing systems
- Enterprise software
- External APIs
- Operational tools

---

## Decision Outcomes

### ALLOW

The action is permitted to execute under the current policy, identity, risk, and context.

### DENY

The action is not permitted to execute.

Typical reasons may include policy violation, invalid identity, unauthorized scope, forbidden operation, untrusted target, excessive risk, or missing audit requirements.

### ESCALATE

The action may be legitimate but requires human review or higher authority before execution.

Typical reasons may include high-value transactions, sensitive operations, production infrastructure changes, privileged access, irreversible actions, or ambiguous context.

### CONSTRAIN

The action may proceed only under modified limits.

Examples:

- Reduce transaction amount
- Limit scope
- Require safer execution mode
- Restrict target environment
- Apply budget cap
- Require staged rollout
- Remove unsafe parameters

---

## Fail-Closed Principle

MCC-Core follows a fail-closed execution model.

If the system cannot verify authority, it does not allow execution.

Examples of fail-closed conditions:

- Missing decision
- Missing policy
- Missing identity
- Invalid token
- Expired token
- Replayed nonce
- Invalid signature
- Policy evaluation error
- Audit failure
- Untrusted execution context
- Unsupported action type

The default posture is:

```text
If authority cannot be verified, execution is denied.
```

---

## Canonical Invariants

MCC-Core is built around the following invariants:

```text
No identity — no execution.
No policy — no execution.
No verified decision — no execution.
No valid token — no execution.
No audit — no trust.
Used nonce — deny.
Expired token — deny.
Invalid signature — deny.
Fail closed by default.
```

These invariants are the foundation of the MCC-Core execution governance model.

---

## Reference Flow

A typical MCC-Core execution flow:

```text
1. An AI agent proposes an action.
2. The proposed action is submitted to MCC-Core.
3. MCC-Core evaluates identity, policy, risk, context, and constraints.
4. MCC-Core returns ALLOW, DENY, ESCALATE, or CONSTRAIN.
5. If allowed, MCC-Core issues a verified decision token.
6. The execution gate verifies the token.
7. The action executes only if the token is valid.
8. The decision and execution attempt are recorded in the audit log.
```

---

## Example Decision Request

```json
{
  "actor": {
    "id": "agent.procurement.001",
    "type": "ai_agent",
    "role": "procurement_agent"
  },
  "action": {
    "type": "purchase_order.create",
    "amount": 12500,
    "currency": "USD",
    "vendor": "approved_vendor_42",
    "project_id": "project_alpha"
  },
  "context": {
    "environment": "pilot",
    "budget_remaining": 50000,
    "approval_threshold": 10000,
    "policy_bundle": "procurement_policy_v1"
  }
}
```

---

## Example Decision Response

```json
{
  "decision": "ESCALATE",
  "reason_code": "AMOUNT_EXCEEDS_AUTO_APPROVAL_THRESHOLD",
  "policy_reference": "procurement_policy_v1.approval_threshold",
  "risk_level": "medium",
  "requires_human_approval": true,
  "execution_allowed": false,
  "audit_required": true
}
```

In this example, the proposed action may be legitimate, but it exceeds the automatic approval threshold.

The correct outcome is not necessarily `DENY`.

The correct outcome is `ESCALATE`.

This distinction is central to execution governance.

---

## Example Constraint Response

```json
{
  "decision": "CONSTRAIN",
  "reason_code": "ACTION_ALLOWED_WITH_LIMITED_SCOPE",
  "policy_reference": "cloud_policy_v1.production_change_limit",
  "constraints": {
    "environment": "staging_only",
    "max_instances": 2,
    "requires_post_execution_review": true
  },
  "execution_allowed": true,
  "audit_required": true
}
```

In this example, the action is not fully denied.

It is allowed only within a safer execution boundary.

---

## Audit Model

MCC-Core treats auditability as part of execution authority.

A decision that cannot be recorded and reviewed is not a reliable authority boundary.

The audit model is intended to support:

- Decision traceability
- Policy reference
- Reason codes
- Actor identity
- Action metadata
- Decision outcome
- Execution attempt
- Token verification result
- Timestamped records
- Hash-chain integrity

The audit trail helps establish what was proposed, what was decided, why it was decided, and whether execution was authorized.

---

## Hash-Chain Audit

A hash-chain audit structure can be used to make decision records tamper-evident.

Each audit entry may include the hash of the previous entry.

Conceptually:

```text
entry_hash = hash(previous_hash + decision_record)
```

This creates a chain of decision records where later entries depend on earlier entries.

If an earlier record is modified, the chain no longer validates.

---

## Decision Token Model

MCC-Core may issue signed decision tokens after evaluation.

A decision token can bind together:

- Actor identity
- Action type
- Action scope
- Decision outcome
- Policy reference
- Risk classification
- Constraints
- Expiration time
- Nonce
- Audit reference
- Signature

The execution gate verifies the decision token before allowing execution.

If the token is missing, expired, replayed, malformed, or invalid, execution is denied.

---

## Replay Protection

Replay protection prevents a previously valid decision from being reused outside its intended context.

Replay protection may include:

- Nonce registry
- Token expiration
- Action binding
- Actor binding
- Scope binding
- Audit reference binding

A valid decision should authorize only the specific action it was created for.

---

## Policy Evaluation

MCC-Core can evaluate actions against policy bundles.

Policies may define:

- Allowed actions
- Denied actions
- Escalation thresholds
- Required approvals
- Budget limits
- Vendor restrictions
- Environment restrictions
- Role permissions
- Risk rules
- Constraint rules

Policy evaluation should be deterministic, auditable, and fail closed.

If policy cannot be evaluated, execution should not proceed.

---

## Integration Pattern

MCC-Core is designed to be integrated as a governance boundary before execution.

Typical integration pattern:

```text
Agent or workflow proposes action
        |
        v
Application calls MCC-Core
        |
        v
MCC-Core evaluates and returns decision
        |
        v
Execution gate verifies decision
        |
        v
Tool/API/operation executes only if authorized
```

This pattern can be applied to:

- AI agents
- Workflow automation
- API gateways
- Enterprise software
- Procurement workflows
- Cloud operations
- CI/CD pipelines
- Infrastructure automation
- Financial operations
- Human-in-the-loop approval systems

---

## Productization Directions

MCC-Core can support multiple execution governance use cases.

Examples include:

### ProcureGuard AI

Agentic procurement control system with MCC-Core embedded.

Use cases:

- Purchase order control
- Vendor policy enforcement
- Budget enforcement
- Change order review
- Approval escalation
- Procurement audit trail

### MCC-I

Infrastructure and cloud execution governance.

Use cases:

- Cloud API control
- CI/CD approval gates
- Terraform and Pulumi governance
- Kubernetes operation control
- IAM change review
- Production deployment constraints
- Cost guardrails

### PayGuard

Payment and financial execution governance.

Use cases:

- Payment authorization control
- Transaction threshold enforcement
- Vendor verification
- Escalation for high-risk payments
- Audit-before-payment
- Financial workflow constraints

These product directions use MCC-Core as the embedded execution governance engine.

The customer-facing product may be an agentic system, while MCC-Core remains the verified decision boundary inside the system.

---

## What MCC-Core Is Not

MCC-Core is not a production-certified safety system.

MCC-Core is not government-approved.

MCC-Core is not a certified compliance product.

MCC-Core is not a finished SaaS platform.

MCC-Core is not a replacement for legal, security, compliance, or operational review.

MCC-Core is not a claim that autonomous AI systems become safe merely by adding one component.

MCC-Core is a public reference architecture and early implementation for execution governance.

---

## Current Status

MCC-Core is published as a public reference architecture and early implementation.

It is intended for:

- Technical review
- Simulation
- Prior-art documentation
- Architecture discussion
- Enterprise PoC discussion
- Integration design
- Reference implementation testing

It is not production-hardened.

It is not certified.

It is not government-approved.

It is not a certified safety system.

It should not be used as the sole control mechanism for production, safety-critical, financial, medical, legal, defense, or high-risk systems without independent engineering, security, compliance, and legal review.

---

## Design Position

MCC-Core is based on a simple architectural separation:

```text
Reasoning is not authorization.
Intent is not authority.
Execution requires a verified decision.
```

The purpose of MCC-Core is to make execution authority explicit, verifiable, enforceable, and auditable.

---

## Repository Purpose

This repository documents MCC-Core as a public technical record.

The repository preserves:

- Core terminology
- Execution governance framing
- Decision boundary model
- Fail-closed principle
- Decision outcome model
- Audit model
- Token-based authority pattern
- Reference implementation direction
- Public prior-art timeline
- Productization direction

The repository is intended to show the technical structure of MCC-Core as of the current public release package.

---

## Author

**Alexandr Ponomariov**  
Founder & Architect, AXLOGIQ Inc.  
Architect of MCC — Meta-Cognitive Control  
Creator of MCC-Core reference runtime  
Creator of ProcureGuard AI product concept  

---

## AXLOGIQ

AXLOGIQ Inc. builds execution governance infrastructure for autonomous AI systems.

Web presence:

- Corporate: https://axlogiq.com
- Technical Product: https://axlogiq.ai
- Public Architecture Record: https://axlogiq.org
- GitHub Reference: https://github.com/mcc-prior-art/mcc-layer

---

## Canonical Doctrine

```text
Intent is not authority.
Proposal is not permission.
Model output is not authorization.
Execution requires a verified decision.
No verified decision — no execution.
The model proposes. MCC-Core decides. The gate enforces.
Autonomy without verifiable control is liability at scale.
```

---

## License and Use

This repository is published as a public reference architecture and early implementation record.

Use of this material should preserve the distinction between:

- Public reference architecture
- Prototype implementation
- Technical review material
- Production-certified system

MCC-Core is not presented as a certified production safety system.

---

## Final Statement

MCC-Core defines a verifiable execution governance boundary for autonomous AI systems.

AI may generate intent.

MCC-Core evaluates authority.

The execution gate enforces the verified decision.

No verified decision — no execution.
