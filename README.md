# AXLOGIQ MCC-Core

## Meta-Cognitive Control Layer for Autonomous Execution

**MCC-Core** is a verifiable execution governance layer for autonomous AI systems.

It defines the control boundary between autonomous intent and real-world execution.

**Intent is not authority.**  
**Execution requires a verified decision.**  
**No verified decision — no execution.**

MCC-Core is not another agent framework.

It is the authority layer that determines whether an AI-generated intent, agent action, workflow request, tool call, infrastructure operation, payment instruction, or autonomous system command may become authorized execution.

---

## Canonical Positioning

**AXLOGIQ builds MCC — Meta-Cognitive Control, an execution governance layer for autonomous AI systems.**

MCC sits between AI-generated intent and real-world execution, evaluating identity, policy, risk, and context before issuing a verified decision.

If execution is not authorized, it does not happen.

**Intent is not authority. Execution requires a verified decision.**

---

## Project Identity

| Term | Meaning |
|---|---|
| **AXLOGIQ** | Company / project identity behind MCC |
| **MCC** | Meta-Cognitive Control; the execution governance layer |
| **MCC Layer** | Architectural category / universal control boundary |
| **MCC-Core** | Reference implementation and technical runtime |
| **MCC-R** | Robotics / physical AI implementation profile |
| **MCC-F** | Finance / payment execution profile |
| **MCC-I** | Infrastructure / cloud execution profile |
| **MCC-H** | Healthcare operations profile |
| **MCC-L** | Legal operations profile |

The common doctrine remains the same:

**No verified decision — no execution.**

---

## Status

Current status:

**Public reference architecture + reference implementation.**

This repository is intended for architectural review, protocol discussion, simulation, enterprise PoC design, agent execution governance research, robotics / physical AI control-boundary exploration, and public technical record of the MCC-Core execution governance model.

This repository should not be treated as a certified safety system, production-certified platform, government-approved system, independently audited system, formally verified security product, completed compliance product, replacement for IAM / safety PLCs / policy engines / legal review / compliance systems, or guarantee of safe autonomous behavior.

MCC-Core is a reference implementation and architectural draft for verified execution authority.

It defines and demonstrates the execution governance boundary.

It does not guarantee safe autonomous behavior.

---

## Executive Summary

Autonomous AI systems are moving from language into action.

They can call tools, operate APIs, modify files, send emails, trigger workflows, update databases, write code, initiate payments, change infrastructure, coordinate agents, interact with robots, and affect physical or operational environments.

Existing stacks often focus on reasoning, orchestration, monitoring, policy evaluation, identity, or access control.

MCC-Core focuses on the missing boundary:

> **May this intent become execution?**

The answer must be explicit, verifiable, scoped, auditable, and enforceable.

MCC-Core introduces that boundary.

---

## Core Doctrine

**Intent is not authority.**

A generated plan, model output, API call, workflow step, agent decision, or autonomous command is not automatically authorized to execute.

**Execution requires a verified decision.**

Before execution, the system must produce a verifiable authority decision based on identity, policy, risk, context, constraints, approval state, nonce / replay state, token validity, and auditability.

**No verified decision — no execution.**

If execution authority cannot be verified, execution remains closed.

---

## The Problem

AI systems are crossing from advisory behavior into operational authority.

The risk is not only that a model may produce a wrong answer.

The deeper risk is that AI-generated intent may become real-world execution without a separate authority decision.

Examples:

- an agent sends an external email
- a workflow updates production data
- a tool-using model runs shell commands
- a payment agent initiates a transfer
- a software agent deletes files
- a robot performs a physical movement
- a multi-agent system coordinates high-impact action
- an automation modifies enterprise infrastructure
- an AI agent calls a privileged API
- an autonomous workflow changes customer records
- a cloud agent mutates production infrastructure

In these cases, the final risk point is no longer the model response.

**The final risk point is execution.**

---

## The MCC-Core Answer

MCC-Core introduces an execution governance boundary.

It evaluates proposed actions before they reach execution surfaces.

Every proposed action resolves to one of four outcomes:

| Outcome | Meaning |
|---|---|
| **ALLOW** | The action is authorized and may proceed within verified scope. |
| **DENY** | The action is blocked. Execution remains closed. |
| **ESCALATE** | Human, supervisory, legal, financial, clinical, security, or higher-level approval is required. |
| **CONSTRAIN** | The action may proceed only under explicit limits or modified scope. |

If execution is allowed, MCC-Core issues or validates a scoped, signed, TTL-bound authority artifact.

If verification fails, execution remains closed.

**No verified decision — no execution.**

---

## Architecture

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
Robotics · Industrial Systems · Operational Infrastructure
```

Lower-stack systems may propose, route, evaluate, observe, or enforce.

MCC-Core determines whether execution authority exists.

MCC-Core does not create legal, financial, clinical, or operational authority by itself.

It verifies whether execution authority exists according to external business, legal, operational, policy, identity, and risk inputs.

See:

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md)
- [`docs/DECISION_TOKEN.md`](docs/DECISION_TOKEN.md)
- [`docs/OPA_INTEGRATION.md`](docs/OPA_INTEGRATION.md)
- [`docs/RELATIONSHIP_TO_EXISTING_SYSTEMS.md`](docs/RELATIONSHIP_TO_EXISTING_SYSTEMS.md)
- [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md)

---

## Current Reference Implementation

The current reference implementation demonstrates the MCC-Core execution authority model.

Implemented or demonstrated capabilities may include signed decision tokens, Ed25519 signature verification, canonical JSON / optional CBOR serialization, payload hash binding, action hash binding, policy hash binding, policy trust set validation, local policy hash consistency checks, nonce / replay protection, optional Redis-backed distributed nonce registry, append-only audit log, hash-chained audit entries, audit-before-actuation flow, fail-closed execution gate, key rotation, key revocation, token revocation, recovery tokens, safe-state behavior, constrained execution, attestation placeholder, OPA/Rego policy adapter with fail-closed evaluation, and a self-test suite.

The current runtime includes a real OPA/Rego adapter. When `MCC_USE_OPA=true`, MCC-Core calls OPA at `/v1/data/mcc/decision` and converts the policy result into `ALLOW / DENY / ESCALATE / CONSTRAIN`.

OPA unavailability, timeout, invalid output, missing result, or invalid decision fails closed to `DENY`.

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
OPA/Rego adapter enabled with fail-closed evaluation.
```

If this file or exact output is not present in the current repository state, treat this section as the intended reference runtime interface and operating target.

---

## Public Technical Record

This repository may serve as a public technical record of the MCC-Core architecture, reference implementation, terminology, and execution governance model.

It should be described accurately as:

> A public reference architecture and reference implementation for a verifiable execution governance layer for autonomous AI systems.

It should not be described as a certified production safety system, deployed critical infrastructure control platform, completed compliance product, legally recognized industry standard, government-approved system, independently audited security product, or production-proven platform at scale.

---

## Foundation / Prior Art

The public MCC Layer prior-art repository is available here:

```text
https://github.com/mcc-prior-art/mcc-layer
```

The foundational principle is:

```text
Intent is not authority.
Execution requires a verified decision.
No verified decision — no execution.
```

This repository develops that principle into the broader MCC-Core / MCC Layer architecture.

The goal is not to create another agent framework.

The goal is to define the missing control boundary between autonomous AI systems and execution authority.

---

## Web Presence

- AXLOGIQ Corporate: https://axlogiq.com
- MCC-Core Technical Product: https://axlogiq.ai
- Public Architecture Record: https://axlogiq.org
- GitHub Organization: https://github.com/axlogiq
- Prior-Art Repository: https://github.com/mcc-prior-art/mcc-layer

---

## Citation / Attribution

Project: **AXLOGIQ MCC-Core**  
Category: **Meta-Cognitive Control Layer for Autonomous Execution**  
Founder / Architect: **Alexandr Ponomariov**  
Organization / Project Identity: **AXLOGIQ**  
Public technical record: **AXLOGIQ / MCC-Core / May 2026**

---

## License

This repository is licensed under the **MCC Evaluation License 1.0**.

The materials are publicly available for **Non-Production Use**, including research, evaluation, testing, internal experimentation, architectural review, protocol discussion, and prior-art documentation.

**Production Use is not granted under this license** and requires separate commercial terms.

No express or implied patent license is granted.

All rights not expressly granted are reserved.

See [`LICENSE`](LICENSE) for the full license text.

---

## Final Principle

MCC-Core is not a safety checkbox.

It is an execution governance layer for autonomous systems.

Because autonomous intent without verifiable control is not authority.

**Intent is not authority.**  
**Execution requires a verified decision.**  
**No verified decision — no execution.**
