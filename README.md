<div align="center">

<img src="https://github.com/axlogiq/mcc-r/raw/main/assets/mcc-r-banner.jpg"
     width="100%"
     alt="MCC-R — Meta-Cognitive Control for Robotics">

<h1>MCC-R</h1>
<h3>Meta-Cognitive Control for Robotics</h3>

<p><strong>Execution Governance Layer for Robotic and Physical AI Systems</strong></p>

<blockquote>
  <strong>No verified decision — no execution.</strong>
</blockquote>

<p>
  MCC-R defines a verifiable decision boundary between autonomous intent and physical action.
  <br>
  Based on the <strong>MCC-CORE Execution Governance Framework v2.0</strong>.
</p>

<p>
  The model may propose. MCC-R decides. Only verified decisions execute.
</p>

<br>

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
![Status](https://img.shields.io/badge/status-reference%20implementation-blue.svg)
![Protocol](https://img.shields.io/badge/protocol-open%20draft-cyan.svg)
![Safety](https://img.shields.io/badge/safety%20certification-not%20certified-red.svg)

</div>

---

# MCC-R — Meta-Cognitive Control for Robotics

**MCC-R** is an open execution-governance protocol draft and reference implementation for robotic and physical AI systems, extending the public MCC Layer prior-art foundation into robotics and physical AI.

It is designed to sit between autonomous AI intent and real-world execution.

A robot, agent, workflow, or physical system does not execute an action merely because an AI model proposed it.

Execution requires a verified decision.

MCC-R evaluates identity, policy, risk, context, constraints, and audit requirements before any action is allowed to pass into the execution layer.

---

## Foundation / Prior Art

MCC-R extends the public MCC Layer prior-art work into robotics and physical AI execution governance.

The foundational MCC Layer repository is available here:

```text
https://github.com/mcc-prior-art/mcc-layer
```

The MCC Layer establishes the core execution-governance principle:

```text
Intent is not authority.
Execution requires a decision.
No verified decision — no execution.
```

MCC-R applies that principle to robotic and physical AI systems by introducing robotics-specific execution controls:

- Robot identity
- Physical execution gates
- Decision Tokens
- Action hashing
- Policy binding
- Short-lived authorization
- Replay protection
- Risk and context evaluation
- Audit references
- Fail-closed execution behavior

The relationship is simple:

```text
MCC Layer = general execution governance boundary
MCC-R     = robotics-focused execution governance extension
```

MCC-R should be read as a robotics-specific reference implementation and architectural extension of the MCC Layer prior-art foundation.

---

## Architecture Overview

MCC-R is built on the **MCC-CORE Execution Governance Layer v2.0**, a universal decision-boundary framework for autonomous systems.

This repository provides a robotics-focused reference implementation of that architecture.

```text
┌─────────────────────────────────────────────────────────────┐
│                     LAYER 4                                 │
│               CONTROLLED EXECUTION                          │
│  Only verified and enforced decisions reach physical action │
└─────────────────────────────────────────────────────────────┘
                            ▲
                            │
┌─────────────────────────────────────────────────────────────┐
│                     LAYER 3                                 │
│                 ENFORCEMENT LAYER                           │
│  Execution Gate enforces verified decisions in real time.   │
│  All actions are controlled, monitored, and logged.          │
└─────────────────────────────────────────────────────────────┘
                            ▲
                            │
┌─────────────────────────────────────────────────────────────┐
│                     LAYER 2                                 │
│            MCC-CORE DECISION BOUNDARY                       │
│  Evaluates every request against identity, policy, risk,    │
│  context, constraints, and audit requirements.              │
│                                                             │
│  OUTCOMES: ALLOW · DENY · ESCALATE · CONSTRAIN              │
│  FAIL-CLOSED BY DEFAULT                                     │
└─────────────────────────────────────────────────────────────┘
                            ▲
                            │
┌─────────────────────────────────────────────────────────────┐
│                     LAYER 1                                 │
│                   INTENT SOURCES                            │
│  AI Models · Users · Agents · Workflows · Applications      │
│  Every intent is untrusted until verified.                  │
└─────────────────────────────────────────────────────────────┘
                            ▲
                            │
┌─────────────────────────────────────────────────────────────┐
│                     LAYER 0                                 │
│               IDENTITY & TRUST FABRIC                       │
│  Hardware root of trust · mTLS / SPIFFE · OIDC / OAuth 2.1  │
│  Device attestation · Cryptographic identity chain          │
└─────────────────────────────────────────────────────────────┘
```

---

## Core Principle

```text
Intent is not authority.
Execution requires a decision.
No verified decision — no execution.
```

Autonomous systems are moving from reasoning into action.

They will operate tools, call APIs, control robots, move assets, trigger workflows, and interact with physical environments.

That transition creates a new architectural requirement:

**A decision boundary between intelligence and execution.**

MCC-R is that boundary for robotics and physical AI.

---

## What MCC-R Does

MCC-R provides a structured control layer for evaluating whether an autonomous system should be allowed to execute a proposed action.

It introduces:

- Identity-aware execution control
- Policy-gated authorization
- Risk and context evaluation
- Decision outcomes
- Signed Decision Tokens
- Replay protection
- Constraint enforcement
- Audit references
- Fail-closed behavior
- Integration with existing physical safety systems

MCC-R is not a robot controller.

MCC-R is not a replacement for certified safety systems.

MCC-R is an execution governance layer.

---

## Decision Outcomes

Every proposed action is evaluated into one of four outcomes:

| Outcome | Meaning |
|---|---|
| `ALLOW` | The action is authorized and may proceed. |
| `DENY` | The action is blocked. |
| `ESCALATE` | Human, supervisory, or higher-level approval is required. |
| `CONSTRAIN` | The action may proceed only under reduced or modified limits. |

This makes execution explicit, reviewable, enforceable, and auditable.

---

## Canonical Execution Flow

```text
AI Model / Agent / Robot Planner
        |
        v
Proposed Action
        |
        v
MCC-R Decision Boundary
        |
        +--> Identity Check
        +--> Policy Evaluation
        +--> Risk & Context Evaluation
        +--> Constraint Resolution
        +--> Audit Binding
        |
        v
Decision: ALLOW / DENY / ESCALATE / CONSTRAIN
        |
        v
Decision Token
        |
        v
Enforcement Layer
        |
        v
Controlled Execution
```

The model proposes.

MCC-R evaluates.

The execution layer enforces.

---

## Technical Canon

```text
No identity — no execution.
No policy — no execution.
No verified decision — no execution.
No valid token — no physical action.
No audit — no trust.
```

These are the core invariants of MCC-R.

They are intended to make execution governance explicit, deterministic, and observable.

---

## Decision Token

Every executable decision may be represented as a signed **Decision Token**.

A Decision Token binds the decision to the action, subject, policy, risk context, constraints, expiry, and audit trail.

A typical Decision Token includes:

```json
{
  "decision_id": "dec_01HX...",
  "robot_id": "robot-001",
  "subject_id": "agent-001",
  "action": "move",
  "action_hash": "sha256:...",
  "policy_version": "robot-safety-v1",
  "outcome": "ALLOW",
  "risk_score": 0.12,
  "constraints": {
    "max_speed_mps": 0.5,
    "heartbeat_ms": 2000
  },
  "issued_at": "2026-05-12T12:00:00Z",
  "expires_at": "2026-05-12T12:00:05Z",
  "audit_ref": "audit_01HX...",
  "signature": "..."
}
```

The execution layer should reject actions without a valid Decision Token.

```text
No valid token — no physical action.
```

---

## Decision Token Contains

A hardened Decision Token should bind:

- Signature
- Decision payload
- Outcome
- Constraints
- Short TTL
- Replay-protected nonce
- Subject identity
- Robot identity
- Policy hash
- Action hash
- Audit reference
- Issued-at timestamp
- Expiry timestamp

---

## Token Signing Model

The current reference implementation may use HMAC-signed tokens for local development and demonstration.

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

## Core Invariants

MCC-R is designed around strict execution invariants:

- **No identity — no execution**
- **No policy — no execution**
- **No verified decision — no execution**
- **No valid token — no physical action**
- **No audit — no trust**
- **Used nonce — deny**
- **Expired token — deny**
- **Fail-closed by default**

---

## Fail-Closed by Default

MCC-R is designed around fail-closed behavior.

If identity cannot be verified, execution is denied.

If no policy matches, execution is denied.

If the decision token is missing, expired, malformed, replayed, or invalid, execution is denied.

If audit binding fails, execution is denied.

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

### `POST /decide`

Example request:

```bash
curl -X POST http://localhost:8080/decide \
  -H "Content-Type: application/json" \
  -d '{
    "robot_id": "robot-001",
    "subject_id": "agent-001",
    "action": "move",
    "params": {
      "direction": "forward",
      "speed_mps": 0.5
    },
    "robot_state": {
      "balance_score": 0.92,
      "velocity_mps": 0.2,
      "human_distance_m": 3.5,
      "payload_kg": 4.0
    }
  }'
```

Example response:

```json
{
  "decision_id": "dec_01HX...",
  "outcome": "ALLOW",
  "reason": "movement_safe",
  "risk_score": 0.1,
  "constraints": {
    "max_speed_mps": 0.5,
    "heartbeat_ms": 2000
  },
  "decision_token": "signed-token-value",
  "audit_ref": "audit_01HX..."
}
```

---

## Example Safety Policy

The following Rego policy is simplified for documentation.

Production policy bundles should use explicit priority resolution to avoid conflicting decisions.

```rego
package mcc_r.safety

default decision := {
  "outcome": "DENY",
  "reason": "default_deny_no_matching_rule",
  "risk_score": 1.0,
  "constraints": {}
}

# Safe movement
decision := {
  "outcome": "ALLOW",
  "reason": "movement_safe",
  "risk_score": 0.10,
  "constraints": {
    "max_speed_mps": "0.5",
    "heartbeat_ms": "2000"
  }
} {
  input.action == "move"
  input.robot_state.balance_score >= 0.75
  input.robot_state.velocity_mps <= 0.5
  input.robot_state.human_distance_m >= 2.0
}

# Human nearby — constrain speed
decision := {
  "outcome": "CONSTRAIN",
  "reason": "human_nearby_reduce_speed",
  "risk_score": 0.45,
  "constraints": {
    "max_speed_mps": "0.2",
    "heartbeat_ms": "500"
  }
} {
  input.action == "move"
  input.robot_state.human_distance_m < 2.0
  input.robot_state.human_distance_m >= 1.0
}

# Human too close — escalate
decision := {
  "outcome": "ESCALATE",
  "reason": "human_too_close_requires_supervision",
  "risk_score": 0.85,
  "constraints": {
    "requires_human_approval": "true"
  }
} {
  input.action == "move"
  input.robot_state.human_distance_m < 1.0
}

# Payload limit exceeded
decision := {
  "outcome": "DENY",
  "reason": "payload_limit_exceeded",
  "risk_score": 1.0,
  "constraints": {}
} {
  input.action == "carry_payload"
  input.robot_state.payload_kg > 20
}
```

---

## Audit & Assurance

MCC-R decisions should be logged with tamper-evident audit records.

Each audit record should include:

- Decision ID
- Subject identity
- Robot identity
- Requested action
- Action hash
- Policy version
- Outcome
- Risk score
- Constraints
- Token reference
- Timestamp
- Previous audit hash
- Current audit hash

The goal is to make autonomous execution reviewable after the fact.

```text
No audit — no trust.
```

---

## Integration Model

MCC-R is designed to integrate with existing runtime and safety infrastructure.

Possible integration points:

- Robot controllers
- Runtime buses
- Agent frameworks
- Industrial automation systems
- PLC / SCADA environments
- Cobots
- AMRs / AGVs
- Humanoid robotics stacks
- Physical AI systems
- Cloud robotics platforms
- Simulation environments
- ROS 2 adapters
- Custom domain controllers

MCC-R should sit before execution.

It should evaluate proposed actions before they reach physical actuation.

---

## Relationship to Certified Safety Systems

MCC-R is not a replacement for certified functional safety systems.

It does not replace:

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

MCC-R is designed to complement these systems by adding a verifiable execution governance layer above runtime execution.

It helps answer a different question:

```text
Was this action authorized, policy-compliant, risk-evaluated, constrained, and auditable before execution?
```

---

## Certification Status

MCC-R is not currently certified under IEC 61508, ISO 13849, ISO 10218, or any equivalent functional safety certification regime.

Any production deployment in safety-critical or physical environments would require independent safety assessment, certification review, and validation by qualified bodies.

MCC-R should be treated as an execution governance architecture and reference implementation, not as a certified safety product.

---

## What MCC-R Is Not

MCC-R is not:

- A certified safety system
- A replacement for E-stop
- A replacement for safety PLCs
- A robot operating system
- A robotics control stack
- A motion planner
- A perception system
- A formal verification engine
- A guarantee of safe behavior
- A substitute for independent safety review

MCC-R is an execution governance layer.

Its purpose is to make execution decisions explicit, enforceable, and auditable.

---

## What MCC-R Is

MCC-R is:

- A decision boundary
- A governance layer
- A policy-gated execution control model
- A reference implementation
- An open protocol draft
- A framework for verifiable execution authorization
- A way to separate AI intent from execution authority

The core idea is simple:

```text
The agent may intend.
The system must decide.
Only verified decisions execute.
```

---

## Security Model

MCC-R assumes that autonomous intent is not trusted by default.

Every proposed action should be evaluated before execution.

Security assumptions:

- AI model output is not authority
- Agent intent is not authority
- Workflow intent is not authority
- Runtime request is not authority
- Identity must be verified
- Policy must be matched
- Risk must be evaluated
- Tokens must be valid
- Audit must be preserved

Execution is treated as a governed event, not a side effect of model output.

---

## Reference Implementation Status

MCC-R is currently provided as a reference implementation and open protocol draft.

It is intended for:

- Research
- Prototyping
- Architecture review
- Integration experiments
- Execution-governance evaluation
- Robotics safety architecture discussion

It should not be treated as a certified functional safety system.

It should not be used as the sole safety mechanism for real-world robots.

---

## Production Deployment Requirements

Production deployments should include independent engineering, security, and safety validation.

Recommended production controls:

- mTLS
- SPIFFE / SPIRE identity
- Signed policy bundles
- Hardware attestation
- Vault, KMS, or HSM-backed signing keys
- Asymmetric Decision Token signatures
- Replay-protected nonce registry
- Short-lived tokens
- Immutable audit logging
- Tamper-evident hash chains
- WORM audit storage
- Policy versioning
- Key rotation
- Prometheus metrics
- Alerting
- SIEM export
- Independent security review
- Independent functional safety review

---

## Roadmap

Planned areas of development:

- Formal protocol specification
- Improved policy priority resolver
- Decision Token verification library
- Ed25519 / ECDSA token signing
- Replay-protected nonce registry
- Audit hash-chain hardening
- Docker-based local deployment
- Kubernetes deployment manifests
- Helm chart
- Metrics and observability
- Simulation examples
- Robotics runtime adapters
- ROS 2 integration examples
- Enterprise policy templates
- Independent security review
- Benchmarking
- Public protocol documentation

---

## Benchmarking Status

Public performance benchmarks are not yet included in this README.

Until benchmark results are published, MCC-R should not be described as low-latency, high-throughput, or production-performance verified.

Planned benchmark targets:

- Decision latency
- Token verification latency
- Policy evaluation latency
- Concurrent request throughput
- p50 / p95 / p99 latency
- Audit logging overhead
- Fail-closed behavior under load

---

## Installation

Installation instructions depend on the current repository structure.

Recommended local development flow:

```bash
git clone https://github.com/axlogiq/mcc-r.git
cd mcc-r
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

MCC-R is released under the MIT License for research, prototyping, and evaluation use.

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

MCC-R is not just a safety feature.

It is an architectural maturity layer for autonomous systems.

Because autonomy without verifiable control is not intelligence.

It is risk waiting for scale.

```text
Intent is not authority.
Execution requires a decision.
No verified decision — no execution.
```
