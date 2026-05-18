# MCC-Core Architecture

## Purpose

MCC-Core defines the control boundary between autonomous intent and real-world execution.

It separates proposal from authority.

The model, agent, workflow, user, service, or controller may propose an action.

MCC-Core determines whether the proposed action may become authorized execution.

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

## Architectural Position

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

---

## Layers

### Layer 0 — Identity & Trust Fabric

Identity, key management, attestation, trust roots, integrity checks, and authority lifecycle.

### Layer 1 — Intent Sources

AI models, agents, users, workflows, applications, APIs, services, and controllers.

Intent is treated as untrusted until verified.

### Layer 2 — MCC-Core Decision Boundary

Identity verification, policy evaluation, risk and context analysis, constraint resolution, approval state, nonce/replay checks, and audit binding.

### Layer 3 — Enforcement Layer

Execution Gate verifies decision tokens, enforces constraints, connects to runtime systems, and blocks unauthorized actions.

### Layer 4 — Controlled Execution

APIs, cloud infrastructure, enterprise workflows, databases, financial systems, robotics, physical AI, and operational systems.

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
Payload mismatch — deny.
Action mismatch — deny.
Uncertainty — deny.
Fail closed by default.
```

---

## Design Principles

1. Intent is not authority.
2. Execution requires a verified decision.
3. Fail closed by default.
4. Bind decisions to scope.
5. Audit before actuation.
6. Preserve reviewability.
7. Separate proposal from authority.
8. Treat internal systems as untrusted until verified.
9. Make authority portable but bounded.
10. Make uncertainty non-permissive.
