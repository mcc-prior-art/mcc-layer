<div align="center">

<h1>AXLOGIQ MCC Layer</h1>
<h3>Meta-Cognitive Control Layer</h3>

<p><strong>The control boundary between AI intent and execution.</strong></p>

<blockquote>
  <strong>Intent is not authority. Execution requires a decision.</strong>
</blockquote>

<p>
  MCC-Core is a meta-control layer above the AI / execution stack:
  models, agents, control planes, policy engines, IAM, workflows,
  observability and execution surfaces.
</p>

<p>
  <strong>No verified decision — no execution.</strong>
</p>

<br>

![Status](https://img.shields.io/badge/status-reference%20implementation-blue.svg)
![Protocol](https://img.shields.io/badge/protocol-open%20draft-cyan.svg)
![Boundary](https://img.shields.io/badge/boundary-above%20AI%20execution-purple.svg)
![Certification](https://img.shields.io/badge/safety%20certification-not%20certified-red.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

</div>

---

## Overview

**MCC Layer** is a universal meta-control layer for autonomous AI systems.

It governs the transition from **AI intent** to **real-world execution**.

Autonomous AI can propose actions, call tools, coordinate workflows, move data, operate APIs, trigger payments, modify infrastructure, control robots, generate legal workflows, and interact with production systems.

But autonomous AI must not self-authorize execution.

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

MCC governs the final transition from autonomous intent to authorized execution.

---

## Foundation / Prior Art

The public MCC Layer prior-art repository is available here:

```text
https://github.com/mcc-prior-art/mcc-layer
```

The foundational principle is:

```text
Intent is not authority.
Execution requires a decision.
No verified decision — no execution.
```

This repository develops that principle into the broader **MCC-Core / MCC Layer** architecture:

```text
MCC Layer = universal execution governance boundary
MCC-Core  = reference meta-control implementation
MCC-R     = robotics-grade implementation
MCC-F     = finance-grade implementation
```

The goal is not to create another agent framework.

The goal is to define the missing control boundary between autonomous AI systems and execution authority.

---

## Why MCC Exists

Modern AI systems are moving from language into action.

They do not only answer questions.

They can:

- call tools
- write files
- send emails
- access databases
- trigger workflows
- operate APIs
- initiate payments
- control infrastructure
- coordinate agents
- modify production systems
- interact with physical environments

This creates a new architectural failure mode:

```text
The system that proposes an action may also be able to execute it.
```

That is the wrong boundary.

MCC introduces a higher-level decision boundary:

```text
AI may propose.
MCC must decide.
Execution requires verified authority.
```

---

## What MCC Layer Is

MCC Layer is a meta-control boundary above autonomous AI systems.

It evaluates whether autonomous intent may become authorized execution.

MCC combines:

- identity
- policy
- risk
- context
- approval state
- audit requirements
- reversibility
- constraints
- enforcement state

The result is not a prompt-level suggestion.

The result is a decision artifact:

```text
ALLOW / DENY / ESCALATE / CONSTRAIN
```

When execution is authorized, MCC issues a signed, scoped, TTL-bound authority token.

Without that token, the enforcement gate remains closed.

---

## What MCC Layer Is Not

MCC Layer is not:

- a chatbot wrapper
- a prompt filter
- a model-safety feature
- an IAM replacement
- a policy engine replacement
- an agent framework
- an agent control plane
- a workflow orchestrator
- a monitoring dashboard
- a certified safety system
- a guarantee of safe behavior

MCC uses lower-stack systems as inputs.

It does not replace them.

It defines the final decision boundary above them.

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
Cloud · APIs · Databases · Payments · Emails · Legal Ops
Healthcare Ops · Robotics · Production Systems
```

Lower-stack systems can evaluate, route, observe, or enforce.

MCC decides whether intent may become authorized execution.

The key question MCC answers is:

```text
May this intent become execution?
```

---

## Core Principle

```text
Intent is not authority.
Execution requires a decision.
No verified decision — no execution.
```

This principle applies across execution surfaces:

- cloud
- APIs
- databases
- payments
- email
- legal operations
- healthcare operations
- robotics
- production infrastructure
- enterprise agents
- autonomous workflows

---

## Decision Outcomes

Every proposed action is evaluated into one of four outcomes:

| Outcome | Meaning |
|---|---|
| `ALLOW` | The action is authorized and may proceed. |
| `DENY` | The action is blocked. |
| `ESCALATE` | Human, supervisory, legal, financial, clinical, security, or higher-level approval is required. |
| `CONSTRAIN` | The action may proceed only under reduced, modified, scoped, or monitored limits. |

These outcomes make execution explicit, enforceable, auditable, and reviewable.

---

## Canonical Execution Flow

```text
AI Model / Agent / Workflow / Control Plane
        |
        v
Proposed Intent
        |
        v
MCC Layer / MCC-Core
        |
        +--> Identity Verification
        +--> Policy Evaluation
        +--> Risk & Context Evaluation
        +--> Approval State Check
        +--> Reversibility Check
        +--> Audit Binding
        +--> Constraint Resolution
        |
        v
Meta-Decision:
ALLOW / DENY / ESCALATE / CONSTRAIN
        |
        v
Authority Artifact
Signed · scoped · TTL-bound · auditable
        |
        v
Enforcement Gate
        |
        v
Execution Surface
Cloud · Data · Payments · Email · Legal Ops · Healthcare Ops · Robotics · Production
```

The model proposes.

MCC evaluates.

The enforcement layer executes only when a verified authority artifact exists.

---

## Technical Canon

```text
No identity — no execution.
No policy — no execution.
No verified decision — no execution.
No valid authority token — no execution.
No audit — no trust.
Used nonce — deny.
Expired token — deny.
Fail-closed by default.
```

These invariants define the MCC execution boundary.

---

## MCC-Core Decision Boundary

MCC-Core evaluates every execution request against five core dimensions:

| Layer | Function | Purpose |
|---|---|---|
| `Identity` | Subject, source, scope, attestation | Determine who or what is requesting execution. |
| `Policy` | Signed rules, constraints, approvals | Determine whether the requested action is allowed. |
| `Risk / Context` | Blast radius, environment, data sensitivity, reversibility | Determine the operational and business risk. |
| `Meta-Decision` | ALLOW / DENY / ESCALATE / CONSTRAIN | Convert evaluation into an execution decision. |
| `Authority Artifact` | Signed token, TTL, audit reference, constraints | Provide verifiable authority to the enforcement layer. |

MCC-Core is the boundary.

Everything below it may propose, route, evaluate, or execute.

Only MCC-Core grants execution authority.

---

## Operational Model

MCC-Core is designed as an execution authority boundary, not as a heavy monolithic service that must block every internal micro-step of a system.

It governs the moment where autonomous intent becomes real execution authority.

---

### Performance Model

MCC-Core sits on the authority path, not necessarily on every low-level micro-action path.

The system should evaluate transitions where autonomous intent becomes execution authority:

- tool calls
- external API actions
- data movement
- payment initiation
- infrastructure changes
- privileged operations
- physical actions
- regulated workflows
- destructive commands
- production-impacting changes

For high-throughput environments, MCC-Core can support multiple execution patterns:

- synchronous decision gate for high-risk actions
- pre-compiled policies for low-latency evaluation
- short-lived authority tokens for scoped execution windows
- local enforcement gates for runtime verification
- cached decisions with strict TTL and scope binding
- batch evaluation for repeated low-risk actions
- async escalation for human approval workflows

MCC does not require every internal micro-step to round-trip through a remote service.

It requires that execution authority is verified before governed action crosses the boundary.

```text
No verified authority artifact — no execution.
```

---

### Policy and Risk Sources

MCC-Core is not intended to replace existing policy engines, IAM systems, risk engines, or compliance tooling.

It can use them as inputs.

Possible policy and risk sources include:

- OPA / Rego
- Cedar
- IAM / RBAC / ABAC systems
- signed policy bundles
- data classification systems
- DLP systems
- SIEM / SOC signals
- asset criticality registries
- runtime telemetry
- business approval systems
- domain-specific risk engines
- human approval state

The source of truth for policy may remain external.

The source of truth for final execution authority is the MCC decision boundary.

MCC-Core normalizes these inputs into a final execution decision:

```text
ALLOW / DENY / ESCALATE / CONSTRAIN
```

---

### Escalation Model

`ESCALATE` means that autonomous execution is not authorized yet.

The proposed action is routed to a human, supervisory, legal, financial, clinical, security, or domain authority depending on policy.

A typical escalation flow:

```text
Proposed intent
    |
    v
MCC decision: ESCALATE
    |
    v
Approval request created
    |
    v
Queue / notification / ticket / chat / dashboard
    |
    v
Authorized reviewer approves, denies, or modifies constraints
    |
    v
MCC issues updated decision
    |
    v
Authority token issued or execution remains blocked
    |
    v
Audit record finalized
```

Escalation systems may include:

- approval queues
- Slack / Teams notifications
- email approval flows
- ticketing systems
- SOC / compliance dashboards
- CFO / legal / clinical / engineering approval paths
- SLA timers
- quorum or two-key approval
- break-glass workflows with mandatory audit

Human approval does not bypass MCC.

Human approval becomes an input to a new MCC decision.

```text
Approval is not execution.
Approval must produce a verified authority artifact.
```

---

### Decision Model

The core MCC decision should be deterministic, policy-bound, and auditable.

The reference implementation may use rule-based policies such as YAML, OPA/Rego, Cedar, or other policy engines.

LLMs may be used as assistive components, but not as the final authority engine.

Acceptable LLM-assisted roles include:

- intent classification
- context summarization
- policy explanation
- anomaly description
- escalation brief generation
- suggested constraint generation
- human-review support

Non-acceptable production role:

```text
LLM directly authorizes execution without deterministic policy, audit, and authority-token validation.
```

The final execution decision should remain governed by explicit policy, verified identity, risk context, approval state, and audit requirements.

```text
LLM may advise.
MCC must decide.
Execution requires verified authority.
```

---

## Authority Artifact

The output of MCC is an authority artifact.

Depending on the implementation, this may be called:

- Decision Token
- Authority Token
- Verified Decision
- Execution Permit
- Signed Authorization Artifact

A hardened authority artifact should bind:

- decision ID
- subject identity
- action
- action hash
- policy version
- outcome
- constraints
- risk score
- approval state
- issued-at timestamp
- expiry timestamp
- short TTL
- replay-protected nonce
- audit reference
- signature

Example structure:

```json
{
  "decision_id": "dec_01HX...",
  "subject_id": "agent-7b",
  "action": "upload_to_external",
  "action_hash": "sha256:...",
  "policy_version": "mcc-policy-v1",
  "outcome": "DENY",
  "risk_score": 0.99,
  "constraints": {},
  "issued_at": "2026-05-12T12:00:00Z",
  "expires_at": "2026-05-12T12:00:05Z",
  "audit_ref": "audit_01HX...",
  "signature": "..."
}
```

If the authority artifact is missing, expired, malformed, replayed, or invalid, execution must not proceed.

```text
No valid authority artifact — no execution.
```

---

## Token Signing Model

The reference implementation may use HMAC-signed tokens for local development and demonstration.

Production deployments should use asymmetric signing and hardware-backed key management.

Recommended production direction:

- Ed25519 or ECDSA signatures
- KMS / HSM / Vault-backed keys
- key rotation
- short token TTL
- replay-protected nonce registry
- policy-version binding
- action-hash binding
- audit-reference binding

HMAC is acceptable for demonstration and controlled prototypes.

It should not be treated as the final production trust model for independently verifiable deployments.

---

## Fail-Closed by Default

MCC is designed around fail-closed behavior.

If identity cannot be verified, execution is denied.

If no policy matches, execution is denied.

If risk is unresolved, execution is denied or escalated.

If approval is missing, execution is denied or escalated.

If audit binding fails, execution is denied.

If the authority artifact is invalid, execution is denied.

```text
Unknown state = DENY
Missing proof = DENY
Invalid token = DENY
Expired token = DENY
Used nonce = DENY
No audit = DENY
```

The safest default is no execution.

---

## Example API

### `POST /evaluate`

Example request:

```bash
curl -X POST http://localhost:8080/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "subject_id": "agent-7b",
    "action": "upload_to_external",
    "payload": "model_weights.bin",
    "context": {
      "environment": "production",
      "data_classification": "restricted",
      "destination": "external"
    }
  }'
```

Example response:

```json
{
  "decision_id": "dec_01HX...",
  "outcome": "DENY",
  "rule": "R-EXFIL-001",
  "reason": "model_weight_exfiltration_detected",
  "risk_score": 0.99,
  "authority_token": null,
  "execution_gate": "CLOSED",
  "audit_ref": "audit_01HX..."
}
```

---

## Example Policy

The following Rego policy is simplified for documentation.

Production policy bundles should use explicit priority resolution to avoid conflicting decisions.

```rego
package mcc.core

default decision := {
  "outcome": "DENY",
  "reason": "default_deny_no_matching_rule",
  "risk_score": 1.0,
  "constraints": {}
}

# Block model weight exfiltration
decision := {
  "outcome": "DENY",
  "reason": "model_weight_exfiltration_detected",
  "risk_score": 0.99,
  "constraints": {}
} {
  input.action == "upload_to_external"
  contains(input.payload, "model_weights")
  input.context.environment == "production"
}

# Escalate high-value payment
decision := {
  "outcome": "ESCALATE",
  "reason": "payment_requires_dual_approval",
  "risk_score": 0.85,
  "constraints": {
    "requires_dual_approval": "true"
  }
} {
  input.action == "initiate_payment"
  input.amount_usd > 100000
}

# Constrain production data export
decision := {
  "outcome": "CONSTRAIN",
  "reason": "production_data_export_limited",
  "risk_score": 0.55,
  "constraints": {
    "max_rows": "1000",
    "redaction_required": "true",
    "audit_level": "enhanced"
  }
} {
  input.action == "export_data"
  input.context.environment == "production"
  input.context.data_classification == "customer_data"
}

# Allow low-risk internal workflow
decision := {
  "outcome": "ALLOW",
  "reason": "low_risk_internal_action",
  "risk_score": 0.10,
  "constraints": {
    "ttl_seconds": "30"
  }
} {
  input.action == "create_internal_ticket"
  input.context.environment != "production"
}
```

---

## Audit & Assurance

MCC decisions should be logged with tamper-evident audit records.

Each audit record should include:

- decision ID
- subject identity
- requested action
- action hash
- policy version
- outcome
- risk score
- constraints
- authority artifact reference
- timestamp
- previous audit hash
- current audit hash

The goal is to make autonomous execution reviewable after the fact.

```text
No audit — no trust.
```

---

## Execution Surfaces

MCC applies wherever autonomous intent can affect real execution.

Examples:

| Surface | Examples |
|---|---|
| Cloud / DevOps | infrastructure changes, deployments, secrets, APIs, databases |
| Finance | payments, treasury, approvals, trading workflows |
| Data | exports, deletion, PII handling, external transfers |
| Email / Communications | outbound emails, legal notices, regulated communication |
| Legal Ops | contract workflows, filings, approvals, document release |
| Healthcare Ops | regulated workflows, patient operations, non-clinical administration |
| Robotics / Physical AI | robots, cobots, AMRs, humanoids, industrial controllers |
| Enterprise Agents | multi-agent workflows, tool calls, enterprise automation |
| Production Systems | destructive commands, privilege escalation, system changes |

MCC controls the boundary before these surfaces are reached.

---

## Platform Modules

MCC-Core is the universal meta-control layer.

Vertical implementations package the same canon for specific execution surfaces:

| Module | Domain | Execution Surface |
|---|---|---|
| `MCC-R` | Robotics / Physical AI | Robots, cobots, AMRs, humanoids, industrial controllers |
| `MCC-F` | Finance | Payments, treasury actions, approvals, trading workflows |
| `MCC-Cloud` | Cloud / DevOps | APIs, databases, infrastructure, production systems |
| `MCC-LegalOps` | Legal / Compliance | Contracts, filings, document workflows, legal approvals |
| `MCC-HealthcareOps` | Regulated operations | Healthcare administration and governed operational workflows |
| `MCC-Enterprise` | Enterprise agents | Tool use, workflows, approvals, internal automation |

Same canon.

Different enforcement surfaces.

---

## MCC Layer vs Lower-Stack Controls

MCC is not a replacement for lower-stack controls.

It sits above them.

| Lower-Stack Control | What It Does | MCC Position |
|---|---|---|
| Prompt safety | Reduces harmful model outputs | MCC governs execution authority, not just output text. |
| IAM | Determines access rights | MCC evaluates whether this intent should become execution now. |
| Policy engine | Evaluates rules | MCC combines policy with identity, risk, context, audit, approval and reversibility. |
| Agent framework | Plans and routes actions | MCC decides whether the proposed action may execute. |
| Control plane | Orchestrates agents and tools | MCC governs the final handoff into execution. |
| Observability | Records and monitors behavior | MCC creates the decision artifact before execution. |
| Safety filters | Reduce unsafe behavior | MCC defines a fail-closed authority boundary. |

The lower stack can propose.

MCC decides.

---

## Reference Implementation Status

MCC-Core is currently provided as a reference implementation and open protocol draft.

It is intended for:

- research
- prototyping
- architecture review
- integration experiments
- execution-governance evaluation
- enterprise AI governance discussion
- autonomous systems control-boundary design

It should not be treated as a certified safety system.

It should not be used as the sole control mechanism for safety-critical, financial, legal, regulated, or physical-world production environments.

---

## Production Deployment Requirements

Production deployments should include independent engineering, security, legal, compliance, and safety validation where applicable.

Recommended production controls:

- mTLS
- SPIFFE / SPIRE identity
- signed policy bundles
- hardware attestation where applicable
- Vault, KMS, or HSM-backed signing keys
- asymmetric authority-token signatures
- replay-protected nonce registry
- short-lived tokens
- immutable audit logging
- tamper-evident hash chains
- WORM audit storage
- policy versioning
- key rotation
- Prometheus metrics
- alerting
- SIEM export
- independent security review
- domain-specific compliance review
- functional safety review where physical systems are involved

---

## Certification Status

MCC-Core is not currently certified under IEC 61508, ISO 13849, ISO 10218, SOC 2, ISO 27001, or any equivalent certification regime.

Any production deployment in safety-critical, regulated, financial, legal, healthcare, industrial, or physical environments would require independent assessment, certification review, and validation by qualified bodies.

MCC-Core should be treated as an execution-governance architecture and reference implementation, not as a certified product.

---

## Benchmarking Status

Public performance benchmarks are not yet included in this README.

Until benchmark results are published, MCC-Core should not be described as low-latency, high-throughput, or production-performance verified.

Planned benchmark targets:

- decision latency
- policy evaluation latency
- token signing latency
- token verification latency
- concurrent request throughput
- p50 / p95 / p99 latency
- audit logging overhead
- fail-closed behavior under load

---

## Roadmap

Planned areas of development:

- formal protocol specification
- improved policy priority resolver
- authority token verification library
- Ed25519 / ECDSA token signing
- replay-protected nonce registry
- audit hash-chain hardening
- Docker-based local deployment
- Kubernetes deployment manifests
- Helm chart
- metrics and observability
- SIEM export
- simulation examples
- enterprise integration examples
- cloud execution adapters
- finance workflow adapters
- robotics runtime adapters
- legal / regulated workflow adapters
- public benchmarking
- protocol documentation
- independent security review

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

MCC-Core is released under the MIT License for research, prototyping, and evaluation use.

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

MCC Layer is not a safety checkbox.

It is an architectural maturity layer for autonomous systems.

Because autonomy without verifiable control is not intelligence.

It is risk waiting for scale.

```text
Intent is not authority.
Execution requires a decision.
No verified decision — no execution.
```
