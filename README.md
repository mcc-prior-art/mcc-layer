<div align="center">

<h1>AXLOGIQ MCC Layer</h1>
<h3>Meta-Cognitive Control Layer</h3>

<p><strong>The control boundary between AI intent and execution.</strong></p>

<blockquote>
  <strong>Intent is not authority. Execution requires a decision.</strong>
</blockquote>

<p>
  MCC-Core is a meta-control layer above the AI / execution stack:
  models, agents, workflows, control planes, policy engines, IAM,
  observability and execution surfaces.
</p>

<p>
  No verified decision — no execution.
</p>

<br>

![Status](https://img.shields.io/badge/status-reference%20implementation-blue.svg)
![Protocol](https://img.shields.io/badge/protocol-open%20draft-cyan.svg)
![Boundary](https://img.shields.io/badge/boundary-above%20AI%20execution-purple.svg)
![Safety](https://img.shields.io/badge/safety%20certification-not%20certified-red.svg)

</div>

---

## Overview

**MCC Layer** is a meta-control layer for autonomous AI systems.

It governs the transition from AI intent to real-world execution.

Autonomous AI can propose actions, call tools, coordinate workflows, and interact with execution surfaces. But it must not self-authorize execution.

MCC-Core separates the proposer from the authority layer.

The model proposes.  
MCC evaluates.  
Execution only follows a verified authority artifact.

```text
Intent is not authority.
Execution requires a decision.
No verified decision — no execution.
```

MCC does not govern the chatbot.

MCC governs the transition from autonomous intent to authorized execution.

---

## Core Category

MCC Layer defines an **execution authority boundary** above autonomous AI systems.

It is not a model.

It is not a prompt wrapper.

It is not a chatbot safety layer.

It is not an IAM replacement.

It is not a policy engine.

It is not an agent control plane.

It is the meta-control boundary above them.

MCC evaluates whether autonomous intent may become authorized execution.

---

## What MCC Layer Controls

Autonomous systems increasingly operate across real execution surfaces:

- Cloud infrastructure
- APIs
- Databases
- Payments
- Emails
- Legal operations
- Healthcare operations
- Enterprise workflows
- Robotics
- Production systems

The critical question is not only:

```text
What did the AI intend?
```

The critical question is:

```text
May this intent become authorized execution?
```

MCC Layer exists to answer that question.

---

## Decision Outcomes

Every proposed action is evaluated into one of four outcomes:

| Outcome | Meaning |
|---|---|
| `ALLOW` | The action is authorized and may proceed. |
| `DENY` | The action is blocked. |
| `ESCALATE` | Human, supervisory, legal, security, financial, or domain approval is required. |
| `CONSTRAIN` | The action may proceed only under reduced or modified limits. |

This makes execution explicit, reviewable, enforceable, and auditable.

---

## Authority Artifact

The output of MCC is not a suggestion.

The output is an authority artifact.

A verified authority artifact may be represented as a signed, scoped, TTL-bound decision token.

Without a valid authority artifact, the enforcement gate remains closed.

```text
No verified decision — no execution.
No valid authority artifact — no execution.
```

A hardened authority artifact should bind:

- Subject identity
- Source identity
- Requested action
- Action hash
- Policy version
- Risk score
- Decision outcome
- Constraints
- Approval state
- Expiry timestamp
- Replay-protected nonce
- Audit reference
- Signature

---

## Canonical Flow

```text
AI Model / Agent / Workflow / Control Plane
        |
        v
Autonomous Intent
        |
        v
MCC Layer / MCC-Core
Meta-Control Decision Boundary
        |
        +--> Identity Verification
        +--> Policy Evaluation
        +--> Risk & Context Evaluation
        +--> Approval / Escalation State
        +--> Reversibility / Constraint Check
        +--> Audit Binding
        |
        v
ALLOW / DENY / ESCALATE / CONSTRAIN
        |
        v
Authority Artifact
        |
        v
Enforcement Gate
        |
        v
Execution Surface
```

The model proposes.

MCC evaluates.

The enforcement layer executes only after verified authority.

---

## Architecture Position

MCC Layer sits above the AI / execution stack and below business, legal, and corporate authority.

```text
Business / Legal / Board Authority
              |
              v
        MCC Layer / MCC-Core
   Meta-Control Decision Boundary
              |
              v
AI Models · Agents · Workflows · Control Planes
Policy Engines · IAM · Observability · Runtime Systems
              |
              v
Execution Surfaces
Cloud · APIs · Databases · Payments · Emails
Legal Ops · Healthcare Ops · Robotics · Production Systems
```

MCC does not replace lower-stack controls.

It uses them as inputs.

Policy engines evaluate rules.

IAM verifies access.

Control planes orchestrate agents.

Observability records system state.

MCC decides whether autonomous intent may become authorized execution.

---

## Architecture Diagram

If this repository includes the architecture diagram, place it at:

```text
assets/mcc-core-execution-governance-layer-v2.png
```

Then use:

```html
<p align="center">
  <img src="./assets/mcc-core-execution-governance-layer-v2.png"
       width="100%"
       alt="MCC-Core Execution Governance Layer v2.0 Architecture">
</p>
```

The diagram represents MCC-Core as a meta-control boundary above the AI / execution stack, not as a robotics-only architecture.

---

## Technical Canon

```text
No identity — no execution.
No policy — no execution.
No verified decision — no execution.
No valid authority artifact — no execution.
No audit — no trust.
```

These are the core invariants of MCC Layer.

---

## Core Invariants

MCC-Core is designed around strict execution invariants:

- **Intent is not authority**
- **The proposer is not the authority**
- **No identity — no execution**
- **No policy — no execution**
- **No verified decision — no execution**
- **No valid authority artifact — no execution**
- **No audit — no trust**
- **Used nonce — deny**
- **Expired token — deny**
- **Unresolved approval — escalate**
- **Unresolved risk — deny or escalate**
- **Fail-closed by default**

---

## Fail-Closed by Default

MCC-Core is designed around fail-closed behavior.

If identity cannot be verified, execution is denied.

If no policy matches, execution is denied.

If risk cannot be resolved, execution is denied or escalated.

If approval is required and missing, execution is escalated.

If the authority artifact is missing, expired, malformed, replayed, or invalid, execution is denied.

If audit binding fails, execution is denied.

```text
Unknown state = DENY
Missing proof = DENY
Invalid authority artifact = DENY
Expired artifact = DENY
Used nonce = DENY
No audit = DENY
```

The safest default is no execution.

---

## What MCC Layer Is

MCC Layer is:

- A decision boundary
- A meta-control layer
- An execution authority layer
- A policy-gated execution control model
- An open protocol draft
- A reference implementation
- A framework for verifiable execution authorization
- A way to separate AI intent from execution authority

The core idea is simple:

```text
The agent may intend.
The system must decide.
Only verified decisions execute.
```

---

## What MCC Layer Is Not

MCC Layer is not:

- A prompt filter
- A model-safety feature
- A chatbot wrapper
- An IAM replacement
- A policy engine replacement
- An observability replacement
- An agent framework
- An agent control plane
- A robot controller
- A certified functional safety system
- A guarantee of safe behavior
- A substitute for independent review

MCC Layer is an execution governance boundary.

Its purpose is to make execution authority explicit, enforceable, and auditable.

---

## MCC Layer vs Lower-Stack Controls

| Layer | What It Does | Why MCC Is Different |
|---|---|---|
| Model | Generates reasoning, plans, tool calls, and proposed actions. | Model output is not authority. |
| Agent framework | Orchestrates agent behavior and tool usage. | Orchestration is not final execution authority. |
| Control plane | Manages agents, workflows, runtime, and infrastructure. | Control does not equal authorization. |
| IAM | Verifies access and permissions. | Access alone does not answer risk, context, reversibility, or audit authority. |
| Policy engine | Evaluates rules. | Rules are inputs; MCC resolves the final execution boundary. |
| Observability | Records telemetry and logs. | Logging is not pre-execution authority. |
| Safety filter | Attempts to reduce harmful behavior. | MCC governs whether intent may become execution. |

---

## Example API

### `POST /evaluate`

Example request:

```bash
curl -X POST http://localhost:8080/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "subject_id": "agent-7b",
    "source": "autonomous_workflow",
    "action": "upload_to_external",
    "resource": "model_weights.bin",
    "context": {
      "environment": "production",
      "data_classification": "restricted",
      "customer_data": false,
      "approval_state": "missing"
    }
  }'
```

Example response:

```json
{
  "decision_id": "dec_01HX...",
  "outcome": "DENY",
  "rule": "R-EXFIL-001",
  "reason": "restricted model artifact cannot be uploaded to an external destination",
  "risk_score": 0.99,
  "authority_artifact": null,
  "execution_gate": "CLOSED",
  "audit_ref": "audit_01HX..."
}
```

---

## Example Decision Token

When execution is authorized, MCC may issue a signed authority artifact.

```json
{
  "decision_id": "dec_01HX...",
  "subject_id": "agent-001",
  "source": "workflow-17",
  "action": "send_email",
  "action_hash": "sha256:...",
  "resource": "customer-notification",
  "policy_version": "enterprise-policy-v1",
  "outcome": "ALLOW",
  "risk_score": 0.18,
  "constraints": {
    "recipient_domain": "approved",
    "max_recipients": 5,
    "requires_logging": true
  },
  "issued_at": "2026-05-12T12:00:00Z",
  "expires_at": "2026-05-12T12:00:10Z",
  "audit_ref": "audit_01HX...",
  "signature": "..."
}
```

The enforcement layer should reject execution without a valid authority artifact.

---

## Signing Model

The current reference implementation may use HMAC-signed artifacts for local development and demonstration.

Production deployments should use asymmetric signing and hardware-backed key management.

Recommended production direction:

- Ed25519 or ECDSA signatures
- KMS / HSM / Vault-backed keys
- Key rotation
- Short token TTL
- Replay-protected nonce registry
- Policy-version binding
- Action-hash binding
- Audit-reference binding

HMAC is acceptable for demonstration and controlled internal prototypes.

It should not be treated as the final production trust model for independently verifiable deployments.

---

## Example Policy Logic

The following policy is simplified for documentation.

Production policy bundles should use explicit priority resolution to avoid conflicting decisions.

```rego
package mcc.core

default decision := {
  "outcome": "DENY",
  "reason": "default_deny_no_matching_rule",
  "risk_score": 1.0,
  "constraints": {}
}

decision := {
  "outcome": "DENY",
  "reason": "restricted_artifact_external_upload_blocked",
  "risk_score": 0.99,
  "constraints": {}
} {
  input.action == "upload_to_external"
  input.resource == "model_weights.bin"
  input.context.environment == "production"
}

decision := {
  "outcome": "ESCALATE",
  "reason": "high_value_payment_requires_dual_approval",
  "risk_score": 0.88,
  "constraints": {
    "requires_dual_approval": true
  }
} {
  input.action == "initiate_payment"
  input.context.amount_usd > 100000
  input.context.approval_state != "dual_approved"
}

decision := {
  "outcome": "CONSTRAIN",
  "reason": "email_send_allowed_with_scope_limits",
  "risk_score": 0.32,
  "constraints": {
    "max_recipients": 5,
    "approved_domains_only": true
  }
} {
  input.action == "send_email"
  input.context.environment == "production"
}

decision := {
  "outcome": "ALLOW",
  "reason": "low_risk_action_authorized",
  "risk_score": 0.12,
  "constraints": {}
} {
  input.action == "read_status"
  input.context.environment != "restricted"
}
```

---

## Audit & Assurance

MCC decisions should be logged with tamper-evident audit records.

Each audit record should include:

- Decision ID
- Subject identity
- Source identity
- Requested action
- Action hash
- Resource
- Policy version
- Outcome
- Risk score
- Constraints
- Approval state
- Authority artifact reference
- Timestamp
- Previous audit hash
- Current audit hash

The goal is to make autonomous execution reviewable after the fact.

```text
No audit — no trust.
```

---

## Strategic Adoption Surface

MCC Layer is relevant anywhere autonomous intent touches real execution.

Potential adoption surfaces include:

- AI labs
- Enterprise agents
- Cloud platforms
- DevOps and production systems
- Financial operations
- Payments and treasury workflows
- Healthcare operations
- Legal operations
- Regulated enterprise workflows
- Robotics and physical AI
- Critical infrastructure operations

---

## Platform Modules

MCC-Core is the universal meta-control layer.

Vertical implementations package the same canon for specific execution surfaces.

| Module | Domain | Execution Surface |
|---|---|---|
| `MCC-Core` | Universal layer | Meta-control boundary above AI / execution stack |
| `MCC-R` | Robotics / Physical AI | Robots, cobots, AMRs, humanoids, industrial controllers |
| `MCC-F` | Finance | Payments, treasury actions, approvals, audit evidence |
| `MCC-Cloud` | Cloud / DevOps | APIs, infrastructure, databases, production systems |
| `MCC-LegalOps` | Legal / Compliance | Contracts, filings, regulated legal workflows |
| `MCC-HealthcareOps` | Healthcare operations | Patient workflows, admin workflows, regulated healthcare operations |
| `MCC-Enterprise` | Enterprise agents | Email, workflows, SaaS actions, internal tools |

Same canon.

Different enforcement surfaces.

---

## Foundation / Prior Art

MCC Layer prior-art work is published here:

```text
https://github.com/mcc-prior-art/mcc-layer
```

The public prior-art foundation establishes the core execution-governance principle:

```text
Intent is not authority.
Execution requires a decision.
No verified decision — no execution.
```

This repository should be read as an extension and refinement of that foundation toward a broader MCC-Core / MCC Layer architecture.

---

## Relationship to Safety Systems

MCC Layer is not a replacement for certified safety systems.

In physical domains such as robotics or industrial automation, MCC does not replace:

- Emergency stop circuits
- Safety PLCs
- Certified robot controllers
- Hardware interlocks
- Mechanical safety design
- ISO / IEC safety certification
- Safety-rated sensors
- Human safety procedures
- Formal verification
- Independent validation

MCC adds a verifiable execution governance layer above runtime execution.

It helps answer a different question:

```text
Was this action authorized, policy-compliant, risk-evaluated, constrained, approved, and auditable before execution?
```

---

## Certification Status

MCC-Core is not currently certified under IEC 61508, ISO 13849, ISO 10218, SOC 2, ISO 27001, or any equivalent safety, security, or compliance certification regime.

Any production deployment in safety-critical, regulated, financial, healthcare, industrial, or physical environments would require independent engineering, security, legal, compliance, and safety validation.

MCC-Core should be treated as an execution governance architecture, open protocol draft, and reference implementation — not as a certified safety or compliance product.

---

## Reference Implementation Status

MCC-Core is currently provided as a reference implementation and open protocol draft.

It is intended for:

- Research
- Prototyping
- Architecture review
- Integration experiments
- Execution-governance evaluation
- Enterprise AI control architecture discussion
- Robotics and physical AI governance discussion
- Board-level autonomy maturity review

It should not be treated as a certified production control system.

It should not be used as the sole safety, security, legal, or compliance mechanism for real-world deployments.

---

## Production Deployment Requirements

Production deployments should include independent engineering, security, legal, compliance, and safety validation.

Recommended production controls:

- mTLS
- SPIFFE / SPIRE identity
- Signed policy bundles
- Strong subject identity
- Source attribution
- Hardware-backed or cloud KMS-backed signing keys
- Asymmetric authority artifact signatures
- Replay-protected nonce registry
- Short-lived authority artifacts
- Immutable audit logging
- Tamper-evident hash chains
- WORM audit storage
- Policy versioning
- Key rotation
- Prometheus metrics
- Alerting
- SIEM export
- Independent security review
- Independent compliance review
- Domain-specific safety review where applicable

---

## Benchmarking Status

Public performance benchmarks are not yet included in this README.

Until benchmark results are published, MCC-Core should not be described as low-latency, high-throughput, or production-performance verified.

Planned benchmark targets:

- Decision latency
- Token verification latency
- Policy evaluation latency
- Concurrent request throughput
- p50 / p95 / p99 latency
- Audit logging overhead
- Fail-closed behavior under load

---

## Roadmap

Planned areas of development:

- Formal protocol specification
- MCC-Core reference server
- Authority artifact verification library
- Improved policy priority resolver
- Ed25519 / ECDSA token signing
- Replay-protected nonce registry
- Audit hash-chain hardening
- Docker-based local deployment
- Kubernetes deployment manifests
- Metrics and observability
- Simulation scenarios
- Enterprise policy templates
- Robotics module: MCC-R
- Finance module: MCC-F
- Cloud / DevOps module
- LegalOps module
- HealthcareOps module
- Board-ready evidence export
- Public benchmarking
- Independent security review
- Public protocol documentation

---

## Installation

Installation instructions depend on the current repository structure.

Recommended local development flow:

```bash
git clone https://github.com/axlogiq/mcc-layer.git
cd mcc-layer
```

If using Python:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If using Docker:

```bash
docker compose up
```

If using a local API server:

```bash
uvicorn server.app:app --host 0.0.0.0 --port 8080
```

> Replace these commands with the exact commands supported by the current repository implementation.

---

## Licensing

MCC-Core / MCC Layer is released under the MIT License for research, prototyping, and evaluation use unless otherwise stated in this repository.

Commercial, enterprise, production, closed-source integration, or managed deployment use may require a separate commercial license from AXLOGIQ.

For licensing and enterprise inquiries:

```text
founder@axlogiq.com
```

---

## Author

**Alexandr Ponomariov**  
Founder & CEO, **AXLOGIQ Inc.**  
Delaware C-Corp

Business & inquiries:  
https://axlogiq.com

Documentation & demo:  
https://axlogiq.ai

Open-source work:  
https://github.com/axlogiq

Contact:  
founder@axlogiq.com

---

## Final Principle

MCC Layer is not just safety.

It is architectural maturity for autonomous systems.

Because autonomy without verifiable execution authority is not intelligence.

It is risk waiting for scale.

```text
Intent is not authority.
Execution requires a decision.
No verified decision — no execution.
```
