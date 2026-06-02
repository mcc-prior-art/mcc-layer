# MCC-Core Decision Boundary Doctrine

File: `MCC-Core_Decision_Boundary_Doctrine.md`  
Status: Foundational Doctrine Layer  
Company: AXLOGIQ Inc.  
Context: MCC-Core / Execution Governance Infrastructure

**The Last Line Before Money Moves.**

---

## 1. Doctrine Position

This document defines the foundational decision-boundary doctrine of MCC-Core.

It must not be mixed with:

- `FORMULA-1_MCC-Core.md` — guardrails vs execution authority;
- `AXLOGIQ_MCC-Core_to_MCC-I_Bridge_Formula_May_2026.md` — bridge from MCC-Core to MCC-I;
- `MCC-I` — the Infrastructure & Cloud vertical packaging of MCC-Core.

This doctrine defines the core principle behind MCC-Core itself:

**the boundary where autonomous intent becomes authorized execution.**

---

## 2. Canon

Intent is potential.  
Decision is boundary.  
Execution is consequence.

---

## 3. Primary Enterprise Line

A proposal is not permission.

---

## 4. Meaning

Autonomous systems can generate intent, propose actions, simulate outcomes, and prepare execution paths.

But a proposed action is not authorized merely because an agent produced it.

A proposal is not permission.  
Intent is not authority.  
Model output is not authorization.

MCC-Core governs the boundary where autonomous intent attempts to become authorized execution.

Potential actions remain non-authoritative until a verified decision is produced.

After the verified decision boundary, an action either proceeds through a signed decision token, verified execution gate, and audit chain — or it does not occur.

---

## 5. Decision Boundary

MCC-Core evaluates whether a proposed autonomous action is allowed to cross the execution boundary.

The evaluation may include:

- identity;
- policy;
- risk;
- context;
- reversibility;
- scope;
- authority;
- auditability;
- execution constraints.

The result is one of four accountable outcomes:

- `ALLOW` — execution is authorized;
- `DENY` — execution is blocked;
- `ESCALATE` — higher authority or human review is required;
- `CONSTRAIN` — execution is permitted only within verified limits.

Example: `$1M transfer` → `ESCALATE` to CFO. `Delete production database` → `DENY`. `Read user data` → `CONSTRAIN` to read-only scope.

No action crosses the execution boundary without a verified decision.

---

## 6. Core Enforcement Principle

No verified decision — no execution.

This is the operating principle of MCC-Core.

The model may propose.  
The agent may plan.  
The workflow may prepare.  
The system may simulate.

But execution requires a verified decision.

---

## 7. Mandatory Evaluation Path

The decision boundary is valid only if execution-capable systems are structurally required to pass through it.

MCC-Core must not rely on voluntary agent compliance.

An autonomous agent may propose an action, but it must not hold direct execution authority over tools, APIs, infrastructure, workflows, financial systems, operational systems, or physical actuators.

All execution-capable paths must be routed through an `ExecutionGate` that requires a valid `VerifiedDecisionToken` issued by MCC-Core.

If an agent can bypass MCC-Core and execute directly, the system is not MCC-governed.

This is not a doctrine failure by MCC-Core.  
It is an integration failure by the system.

A boundary that can be bypassed is not a boundary.

No verified path — no trusted execution.

---

## 8. Bypass Resistance Principle

MCC-governed systems must be designed so that direct execution paths are unavailable, blocked, sandboxed, or treated as critical integration failures.

Execution-capable adapters must not expose raw tool access to agents.

The agent may access:

- proposal interfaces;
- planning interfaces;
- simulation interfaces;
- request-for-execution interfaces.

The agent must not access:

- direct production APIs;
- direct infrastructure credentials;
- direct payment rails;
- direct destructive commands;
- direct actuator controls;
- direct workflow mutation endpoints.

Execution rights belong to the gate, not to the agent.

Agents may propose.  
MCC-Core decides.  
The ExecutionGate enforces.

No direct tool access — only gated execution.

---

## 9. Verified Execution Path

A valid MCC-governed execution path follows this sequence:

1. An agent, model, workflow, user, or system proposes an action.
2. The proposed action enters a `PreExecutionState`.
3. MCC-Core evaluates the proposal against identity, policy, risk, context, reversibility, scope, authority, auditability, and execution constraints.
4. MCC-Core returns one accountable outcome: `ALLOW`, `DENY`, `ESCALATE`, or `CONSTRAIN`.
5. If execution is authorized, MCC-Core issues a `VerifiedDecisionToken`.
6. The `ExecutionGate` verifies the token before allowing execution.
7. The action executes only within the authorized scope.
8. The result is recorded in an immutable audit chain.

If any required step is missing, execution must fail closed.

---

## 10. Framing Protection

This doctrine is not a claim that quantum mechanics proves MCC.

It is an engineering and operational analogue: the boundary between possibility and consequence.

MCC is not physics. It is accounting.  
We do not measure reality. We authorize transactions.

The language of potential, boundary, and consequence should be used as architectural framing, not as a physical, mystical, or metaphysical claim.

Avoid direct “superposition” terminology in code, README, enterprise-facing technical materials, and investor documents.

Use decision-boundary language instead.

Preferred terms:

- `PreExecutionState`
- `DecisionBoundary`
- `MandatoryEvaluationPath`
- `VerifiedDecisionToken`
- `ExecutionGate`
- `ExecutionConsequence`
- `AuditChain`

Avoid:

- “quantum proof”
- “superposition layer”
- “collapse of reality”
- “consciousness creates execution”
- “measurement proves governance”

---

## 11. Practical Use

### Banner

Use the short formula:

Intent is potential.  
Decision is boundary.  
Execution is consequence.

A proposal is not permission.  
No verified decision — no execution.

Optional enterprise extension:

A boundary that can be bypassed is not a boundary.

### Pitch

Use as a dedicated section:

**Act II — The Decision Boundary**

Position MCC-Core as the missing boundary between autonomous proposal and authorized execution.

Then add the enforcement layer:

**Act III — Mandatory Evaluation Path**

Position MCC-Core not as advisory governance, but as enforced execution governance.

The agent does not voluntarily ask for permission.  
The system gives the agent no ungated path to execution.

### Code

Use as invariants and naming discipline:

```python
"""
MCC-Core invariant:

A proposal is not permission.
Intent is not authority.
A proposed action remains non-authoritative until a verified decision is produced.

Only a valid MCC decision token may cross the execution gate.

No verified decision — no execution.
"""
```

Mandatory evaluation path invariant:

```python
"""
Mandatory Evaluation Path invariant:

Agents must not hold direct execution authority.

All execution-capable tools must be accessible only through an ExecutionGate.
The gate must require a valid VerifiedDecisionToken before execution.

If a tool can be called without MCC evaluation, the integration is invalid.

A boundary that can be bypassed is not a boundary.
No verified path — no trusted execution.
"""
```

Suggested naming:

```python
PreExecutionState
DecisionBoundary
MandatoryEvaluationPath
VerifiedDecisionToken
ExecutionGate
ExecutionConsequence
AuditChain
```

---

## 12. Doctrine Lines

Potential is not consequence.  
Intent is not authority.  
A proposal is not permission.  
Model output is not authorization.  
Only a verified decision can turn autonomous possibility into accountable execution.

A boundary that can be bypassed is not a boundary.  
Agents may propose; they must not directly execute.  
No direct tool access — only gated execution.  
No verified path — no trusted execution.

No verified decision — no execution.

---

## 13. Final Doctrine Statement

MCC-Core governs the decision boundary where autonomous intent becomes authorized execution.

Before that boundary, actions are only potential.

After that boundary, execution is either authorized, denied, escalated, constrained, and audited — or it does not occur.

But the boundary is valid only if execution-capable systems are structurally required to pass through it.

MCC-Core must not rely on voluntary agent compliance.

If an agent can bypass MCC-Core and execute directly, the system is not MCC-governed.

A proposal is not permission.  
Intent is not authority.  
Execution requires a verified decision.  
Execution paths require mandatory evaluation.

No verified decision — no execution.  
No verified path — no trusted execution.

---

## 14. Doctrine Status

This is a foundational doctrine asset of AXLOGIQ / MCC-Core.

It defines MCC-Core not as a guardrail, not as an agent framework, not as a model-behavior layer, and not as an advisory permission service.

It defines MCC-Core as the verified decision boundary for autonomous execution, enforced through mandatory evaluation paths.

The model proposes.  
MCC-Core decides.  
The gate enforces.  
The audit chain records.
