# Relationship to Existing Systems

## Summary

MCC-Core is not designed to replace existing identity, policy, access-control, observability, orchestration, or safety systems.

It is designed to sit above them as an execution decision boundary that binds identity, policy, risk, context, constraints, signed authority, replay protection, and audit-before-actuation into one enforceable runtime decision.

---

## Positioning Matrix

| Existing System | What It Does | What MCC-Core Adds |
|---|---|---|
| **OPA / Cedar** | Policy evaluation | MCC-Core uses policy as an input, then governs whether a specific action may execute with signed authority, constraints, nonce protection, and audit evidence. |
| **SPIFFE / SPIRE** | Workload identity | MCC-Core consumes workload identity, but identity alone does not authorize a specific action in a specific context. |
| **IAM / RBAC / ABAC** | Access control | MCC-Core evaluates runtime execution attempts and can deny, escalate, or constrain even when a subject has general access. |
| **Agent Frameworks** | Planning and tool orchestration | MCC-Core is the authority gate before tool execution, not the planner or orchestrator. |
| **Observability / SIEM** | Logs, traces, metrics, detection | MCC-Core controls whether execution is allowed to happen before the action occurs. |
| **Functional Safety Systems** | Hardware limits, safety PLCs, emergency stops, certified safety controls | MCC-Core does not replace certified safety systems. Functional safety systems govern hardware limits; MCC-Core governs AI action authority. |

---

## Core Distinction

OPA can decide policy.

SPIFFE can prove workload identity.

IAM can define access.

Observability can record behavior.

Functional safety systems can enforce hardware safety limits.

**MCC-Core governs whether a proposed AI-generated action is authorized to execute.**

MCC-Core does not ask only:

> “Is this allowed by policy?”

It asks:

> “Is this actor authorized to execute this exact action, with this payload, under this policy, in this context, within this time window, with a valid token, unused nonce, enforceable constraints, and audit evidence before execution?”

That execution envelope is the missing layer.
