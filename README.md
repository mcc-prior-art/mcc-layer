# AXLOGIQ MCC-Core

## Meta-Cognitive Control Layer for Autonomous Execution

**MCC-Core** is an execution governance layer for autonomous AI systems.

It defines a verifiable decision boundary between autonomous intent and real-world execution.

> Intent is not authority.  
> Execution requires a verified decision.  
> No verified decision — no execution.

MCC-Core is not another agent framework.  
It is the control boundary that determines whether an AI-generated intent may become authorized execution.

---

## Status

**Current status:** public reference architecture + reference implementation.

This repository is intended for:

- architectural review
- protocol discussion
- simulation
- enterprise PoC design
- agent execution governance research
- robotics / physical AI control-boundary exploration

This repository should **not** be treated as:

- a certified safety system
- a production-certified platform
- a replacement for IAM, safety PLCs, policy engines, legal review, or compliance systems
- a guarantee of safe autonomous behavior

MCC-Core is a reference implementation and architectural draft for verified execution authority.

---

## Core Doctrine

```text
Intent is not authority.
Execution requires a verified decision.
No verified decision — no execution.
```

Modern AI systems are moving from language into action.

They can call tools, operate APIs, modify files, trigger workflows, send messages, move data, initiate payments, update production systems, coordinate agents, and interact with physical environments.

That creates a new architectural failure mode:

```text
The system that proposes an action may also be able to execute it.
```

MCC-Core separates proposal from authority.

```text
The model proposes.
MCC evaluates.
Only verified decisions execute.
```

---

## What MCC-Core Is

MCC-Core is a meta-control layer above autonomous AI systems and below execution surfaces.

It evaluates whether an autonomous intent is allowed to become an authorized action.

MCC-Core combines:

- identity
- policy
- risk
- context
- constraints
- approval state
- nonce / replay protection
- signed decision tokens
- append-only audit
- enforcement gating
- fail-closed execution behavior

The result is an explicit decision:

```text
ALLOW / DENY / ESCALATE / CONSTRAIN
```

When execution is authorized, MCC-Core issues or validates a scoped, signed, TTL-bound authority artifact.

Without a valid authority artifact, execution remains closed.

---

## What MCC-Core Is Not

MCC-Core is not:

- a chatbot wrapper
- a prompt filter
- a jailbreak detector
- a model-safety feature
- an agent framework
- an agent control plane
- an orchestration engine
- an IAM replacement
- a policy-engine replacement
- a monitoring dashboard
- a certified functional safety system
- a legal, medical, financial, or operational authority by itself

MCC-Core uses lower-stack systems as inputs.

It does not replace them.

It defines the final execution decision boundary above them.

---

## MCC-Core and MCC-R

This repository uses the following terminology:

```text
MCC-Core  = universal execution governance layer
MCC-R     = robotics / physical AI implementation profile
MCC Layer = architectural category / control boundary
```

MCC-Core is the general architecture.

MCC-R is a robotics and physical AI profile built on top of MCC-Core principles.

Other future profiles may include:

```text
MCC-F   = finance / payment execution profile
MCC-I   = infrastructure / cloud execution profile
MCC-H   = healthcare operations profile
MCC-L   = legal operations profile
```

The common principle remains the same:

```text
No verified decision — no execution.
```

---

## Why MCC-Core Exists

Autonomous AI systems increasingly operate beyond conversation.

They may:

- call tools
- execute code
- access databases
- modify files
- send emails
- trigger workflows
- operate APIs
- initiate payments
- change infrastructure
- update production systems
- coordinate multiple agents
- interact with robots
- control industrial systems
- handle sensitive operational workflows

In these environments, a prompt-level response is no longer the final risk point.

The final risk point is execution.

MCC-Core exists to govern the transition from:

```text
AI-generated intent
```

to:

```text
authorized execution
```

The critical question is:

```text
May this intent become execution?
```

---

## Architecture Position

MCC-Core sits between autonomous intent sources and execution surfaces.

```text
Business / Legal / Operational Authority
                |
                v
        MCC-Core Decision Boundary
                |
                v
AI Models · Agents · Workflows · Control Planes
Policy Engines · IAM · Risk Engines · Observability
                |
                v
Execution Surfaces
Cloud · APIs · Databases · Payments · Email
Robotics · Industrial Systems · Critical Infrastructure
```

Lower-stack systems may propose, route, evaluate, observe, or enforce.

MCC-Core determines whether execution authority exists.

---

## Canonical Execution Flow

```text
AI Model / Agent / Workflow
        |
        v
Proposed Intent
        |
        v
MCC-Core Decision Boundary
        |
        +--> Identity Verification
        +--> Policy Evaluation
        +--> Risk & Context Evaluation
        +--> Constraint Resolution
        +--> Approval State Check
        +--> Nonce / Replay Check
        +--> Audit Binding
        |
        v
Meta-Decision
ALLOW / DENY / ESCALATE / CONSTRAIN
        |
        v
Decision Token
Signed · scoped · TTL-bound · auditable
        |
        v
Execution Gate
        |
        v
Execution Surface
Cloud · API · Database · Payment · Email · Robot · Industrial System
```

The enforcement layer executes only when a verified decision token exists.

---

## Decision Outcomes

Every proposed action is evaluated into one of four outcomes.

| Outcome | Meaning |
|---|---|
| `ALLOW` | The action is authorized and may proceed. |
| `DENY` | The action is blocked. |
| `ESCALATE` | Human, supervisory, legal, financial, clinical, security, or higher-level approval is required. |
| `CONSTRAIN` | The action may proceed only under reduced, scoped, monitored, or modified limits. |

These outcomes make execution explicit, enforceable, auditable, and reviewable.

---

## Core Invariants

```text
No identity — no execution.
No policy — no execution.
No verified decision — no execution.
No valid decision token — no execution.
No audit — no trust.
Used nonce — deny.
Expired token — deny.
Revoked key — deny.
Policy mismatch — deny.
Fail-closed by default.
```

These invariants define the MCC execution boundary.

---

## Current Reference Implementation

The current reference implementation demonstrates the MCC-Core execution authority model.

Implemented capabilities include:

- signed decision tokens
- Ed25519 signature verification
- canonical JSON / optional CBOR serialization
- payload hash binding
- action hash binding
- policy hash binding
- policy trust set validation
- local policy hash consistency checks
- nonce / replay protection
- optional Redis-backed distributed nonce registry
- append-only audit log
- hash-chained audit entries
- audit-before-actuation flow
- fail-closed execution gate
- key rotation
- key revocation
- token revocation
- recovery tokens
- safe-state behavior
- constrained execution
- attestation placeholder
- OPA integration placeholder that fails closed
- self-test suite

The reference implementation is designed for simulation, review, PoC work, and integration planning.

It is not a certified production safety system.

---

## Reference Runtime File

Expected primary runtime file:

```text
mcc_core_v1_10_1_stable_professional.py
```

Run:

```bash
python3 mcc_core_v1_10_1_stable_professional.py
```

Expected behavior:

```text
MCC-Core v1.10.1-stable-professional — Self-Test Suite
...
All tests passed.
Append-only audit enabled.
Distributed nonce registry ready for Redis.
PolicyTrustSet strict key_id verification.
Local policy hash consistency check enabled.
OPA placeholder fails closed.
```

---

## High-Level Component Model

### 1. Intent Source

The intent source may be:

- LLM
- agent
- workflow
- user
- application
- automation system
- robot controller
- external API
- enterprise service

All intent sources are treated as untrusted until verified.

```text
Internal does not mean authorized.
```

### 2. MCC-Core Decision Boundary

The MCC-Core decision boundary evaluates:

- who or what is requesting execution
- what action is requested
- what payload is attached
- what policy applies
- what risk level is present
- what constraints must be enforced
- whether approval is required
- whether the token is valid
- whether the nonce was already used
- whether the audit chain is healthy
- whether the execution surface may proceed

The decision boundary returns:

```text
ALLOW / DENY / ESCALATE / CONSTRAIN
```

### 3. Decision Token

A decision token is a signed authority artifact.

It binds execution to:

- issuer
- key ID
- subject
- audience
- action
- payload hash
- action hash
- constraints
- policy ID
- policy hash
- nonce
- issued-at timestamp
- not-before timestamp
- expiration timestamp
- audit reference
- signature

A valid decision token is required before execution.

```text
No valid token — no execution.
```

### 4. Execution Gate

The execution gate verifies the decision token and enforces the decision.

It checks:

- signature validity
- key trust
- audience binding
- token expiry
- not-before time
- revocation status
- nonce replay
- policy trust set
- local policy hash consistency
- payload hash
- action hash
- constraints
- attestation state
- audit chain state
- safe-state restrictions

If verification fails, execution is denied.

If verification succeeds, execution may proceed under the approved scope.

### 5. Audit Log

The audit log is append-only and hash-chained.

The execution flow follows an audit-before-actuation rule:

```text
1. Verify token.
2. Append EXECUTION_ATTEMPT.
3. If rejected, append EXECUTION_REJECTED.
4. If allowed, call actuator.
5. Append EXECUTION_SUCCEEDED / EXECUTION_FAILED / EXECUTION_EXCEPTION.
```

Existing audit entries are never mutated.

Corrections and finalization events must be appended as new entries.

---

## Security Model

MCC-Core assumes that autonomous intent is not authority.

The reference security model includes:

- deny-by-default behavior
- fail-closed execution
- signature verification
- canonical payload binding
- action hash binding
- policy hash binding
- nonce replay protection
- token TTL
- key revocation
- token revocation
- policy trust set validation
- append-only audit
- hash-chain integrity checks
- safe-state restrictions
- recovery token workflow

The design goal is to make execution authority explicit, verifiable, and reviewable.

---

## Policy Model

MCC-Core does not require policy to originate inside MCC.

Policy may come from:

- OPA / Rego
- Cedar
- YAML policy definitions
- IAM / RBAC / ABAC systems
- compliance requirements
- business approval matrices
- risk engines
- safety rules
- domain-specific governance systems

MCC-Core consumes signed, versioned, auditable policy inputs and converts them into execution decisions.

```text
Policy source may be external.
Execution authority must be verified by MCC.
```

A production-grade policy supply chain should include:

- policy authoring
- review and approval
- signing
- versioning
- distribution
- revocation
- hash binding
- audit trail
- rollback strategy

The reference implementation demonstrates the required control behavior.

Production environments must choose the appropriate policy authoring, signing, distribution, storage, and revocation workflow.

---

## Nonce / Replay Protection

MCC-Core uses nonces to prevent replay.

A token nonce may be used only once.

```text
Used nonce — deny.
```

The reference implementation supports:

- local in-memory nonce registry
- optional Redis-backed distributed nonce registry

For distributed deployments, nonce verification must be atomic across enforcement nodes.

A production deployment should use a shared strongly consistent or operationally appropriate nonce store.

---

## Fail-Closed Behavior

MCC-Core is designed to fail closed.

Execution is denied when:

- signature is invalid
- key is unknown
- key is revoked
- token is expired
- token is not yet valid
- audience does not match
- token was revoked
- nonce was already used
- policy trust set is missing
- policy trust set is expired
- policy hash is not accepted
- local policy hash does not match token policy hash
- payload hash does not match
- action hash does not match
- constraints are violated
- attestation fails
- audit chain is compromised
- system is in restricted safe state
- OPA integration is configured but not implemented

The default behavior is denial.

```text
Uncertainty does not authorize execution.
```

---

## Audit-Before-Actuation

The reference implementation follows audit-before-actuation.

Before an actuator is called, an execution attempt is recorded.

After actuation, the result is appended.

This creates an auditable sequence:

```text
EXECUTION_ATTEMPT
EXECUTION_SUCCEEDED
```

or:

```text
EXECUTION_ATTEMPT
EXECUTION_REJECTED
```

or:

```text
EXECUTION_ATTEMPT
EXECUTION_FAILED
```

or:

```text
EXECUTION_ATTEMPT
EXECUTION_EXCEPTION
```

The audit log is append-only.

No existing entry is modified after creation.

---

## Example Decision Token Fields

A decision token may contain:

```json
{
  "iss": "mcc/node-a",
  "kid": "mcc-node-a-key-1",
  "sub": "agent/payment-worker",
  "aud": "execution-gate-1",
  "jti": "mcc-node-a-001",
  "iat": 1760000000,
  "nbf": 1760000000,
  "exp": 1760000060,
  "action": "create_payment",
  "payload_hash": "sha256:...",
  "action_hash": "sha256:...",
  "constraints": {
    "max_amount_usd": 1000,
    "requires_approval_above_usd": 500
  },
  "policy_id": "prod/v1",
  "policy_hash": "sha256:...",
  "audit_start_seq": 0,
  "req_attest": "medium",
  "nonce": "..."
}
```

The token must be signed by a trusted MCC authority key.

---

## Example Execution Request

```json
{
  "subject": "agent/payment-worker",
  "action": "create_payment",
  "payload": {
    "amount_usd": 750,
    "recipient": "vendor-123",
    "invoice_id": "INV-2026-001"
  },
  "context": {
    "environment": "production",
    "risk_level": "medium",
    "business_unit": "finance"
  }
}
```

Possible MCC-Core decision:

```json
{
  "outcome": "ESCALATE",
  "reason": "Payment exceeds autonomous approval threshold",
  "required_approval": "finance_controller",
  "audit_required": true
}
```

The execution gate does not execute until the required authority exists.

---

## Example Robotics / MCC-R Profile

MCC-R applies MCC-Core principles to robotics and physical AI.

A physical action may require:

- robot identity
- device trust
- operator authority
- policy match
- safety constraints
- action hash binding
- physical-zone context
- proximity context
- signed decision token
- valid nonce
- audit-before-actuation

Example controlled action:

```json
{
  "subject": "robot/arm-01",
  "action": "move",
  "payload": {
    "zone": "A3",
    "speed_mps": 0.3,
    "force_n": 5
  },
  "constraints": {
    "allowed_zone": "A3",
    "max_speed_mps": 0.4,
    "max_force_n": 10
  }
}
```

If the robot attempts to exceed the approved scope, the gate denies execution.

```text
No valid token — no actuation.
```

---

## Example Cloud / Infrastructure Profile

MCC-Core can also apply to software execution surfaces.

Example high-risk action:

```json
{
  "subject": "agent/devops-worker",
  "action": "delete_database",
  "payload": {
    "database": "production-main",
    "region": "us-east-1"
  },
  "context": {
    "environment": "production",
    "risk_level": "critical"
  }
}
```

Possible MCC-Core decision:

```json
{
  "outcome": "DENY",
  "reason": "Destructive production action is not authorized for autonomous execution"
}
```

or:

```json
{
  "outcome": "ESCALATE",
  "reason": "Two-key approval required for destructive infrastructure operation"
}
```

---

## Example Agent Tool-Use Profile

MCC-Core can serve as the execution gate before agent tools.

Example actions:

```text
send_email
call_api
update_database
create_payment
execute_bash
delete_file
orchestrate_agents
```

Example policy behavior:

| Action | MCC Outcome |
|---|---|
| `send_email` | `ALLOW` if scope and recipient policy match |
| `create_payment` | `ESCALATE` above threshold |
| `delete_file` | `DENY` in production unless explicitly authorized |
| `execute_bash` | `CONSTRAIN` or `DENY` depending on context |
| `orchestrate_agents` | `ESCALATE` for high-impact multi-agent actions |

Agent frameworks can plan actions.

MCC-Core decides whether those actions are authorized to execute.

```text
Agent proposes. MCC evaluates. Only verified decisions execute.
```

---

## Relationship to Existing Systems

MCC-Core is designed to work with existing infrastructure.

| Existing System | Role | MCC-Core Relationship |
|---|---|---|
| IAM | Identity and access management | MCC consumes identity signals but does not replace IAM. |
| OPA / Cedar | Policy evaluation | MCC may consume policy decisions or signed bundles. |
| SIEM | Security monitoring | MCC emits audit and decision events. |
| Agent Frameworks | Planning and orchestration | MCC gates execution after intent generation. |
| Workflow Engines | Business process execution | MCC verifies authority before high-impact steps. |
| Safety PLCs | Certified physical safety | MCC does not replace certified safety systems. |
| Observability | Metrics and traces | MCC provides decision-level execution evidence. |

MCC-Core is not the whole stack.

It is the decision boundary inside the stack.

---

## Design Principles

### 1. Intent is not authority

A generated plan, model output, API call, workflow step, or agent decision is not automatically authorized.

### 2. Execution requires a verified decision

Before execution, the system must produce a verifiable authority decision.

### 3. Fail closed by default

Missing, ambiguous, stale, invalid, mismatched, expired, or unverifiable state denies execution.

### 4. Bind decisions to scope

Authority must be bound to action, payload, policy, identity, audience, constraints, time, and nonce.

### 5. Audit before actuation

Execution attempts must be recorded before the actuator or external tool is invoked.

### 6. Preserve reviewability

Every decision should be explainable, inspectable, and traceable after the fact.

### 7. Separate proposal from authority

The system that proposes an action should not automatically possess execution authority.

---

## Limitations

This repository is a reference implementation and architecture draft.

Known limitations:

- not formally verified
- not independently audited
- not certified for functional safety
- not certified for regulated production environments
- not a replacement for legal or compliance review
- OPA integration is represented as a fail-closed placeholder
- attestation logic is simplified for demonstration
- distributed consensus is simplified for reference purposes
- production key management requires KMS / HSM / Vault-class infrastructure
- production audit storage should use durable tamper-evident storage
- production policy distribution requires a signed policy supply chain

These limitations are intentional and explicit.

The purpose of this repository is to define and demonstrate the execution governance boundary.

---

## Roadmap

Planned directions may include:

- clearer protocol specification
- language-neutral decision token schema
- reference HTTP API
- reference SDK
- OPA / Rego integration example
- Cedar policy integration example
- LangGraph execution-gate example
- agent tool-use gateway example
- Redis nonce registry example
- WORM-style audit storage adapter
- KMS / Vault signing adapter
- dashboard / decision viewer
- architecture diagrams
- whitepaper
- independent technical review
- external security review

Roadmap items are not claims of current production readiness.

---

## Suggested Repository Structure

```text
.
├── README.md
├── mcc_core_v1_10_1_stable_professional.py
├── docs/
│   ├── ARCHITECTURE.md
│   ├── SECURITY_MODEL.md
│   ├── DECISION_TOKEN.md
│   ├── POLICY_TRUST_SET.md
│   ├── AUDIT_MODEL.md
│   └── LIMITATIONS.md
├── examples/
│   ├── agent_tool_gateway.json
│   ├── robotics_profile.json
│   └── cloud_execution_profile.json
└── tests/
    └── README.md
```

---

## Public Positioning

MCC-Core belongs to the emerging category of execution governance for autonomous systems.

The core problem is not only whether AI can reason.

The core problem is whether AI-generated intent should be allowed to become execution.

```text
Reasoning creates intent.
MCC governs authority.
Execution requires verification.
```

---

## Immigration / Evidence Note

This repository may be used as a public technical artifact demonstrating original work in AI governance, autonomous systems control, and execution authority architecture.

It should be described accurately as:

```text
A public reference architecture and reference implementation for a verifiable execution governance layer for autonomous AI systems.
```

It should not be described as:

```text
A certified production safety system.
A deployed critical infrastructure control platform.
A completed compliance product.
A legally recognized industry standard.
```

Accurate positioning preserves credibility.

---

## Citation / Attribution

Project: **AXLOGIQ MCC-Core**  
Profile: **MCC-R — Robotics / Physical AI Reference Profile**  
Founder / Architect: **Alexandr Ponomariov**  
Organization: **AXLOGIQ**

Web presence:

- https://axlogiq.com
- https://axlogiq.ai
- https://axlogiq.org
- https://github.com/axlogiq

---

## License

License to be defined.

Until a license is selected, all rights are reserved by the author.

---

## Final Principle

MCC-Core is not a safety checkbox.

It is an execution governance layer for autonomous systems.

Because autonomous intent without verifiable control is not authority.

```text
Intent is not authority.
Execution requires a verified decision.
No verified decision — no execution.
```
