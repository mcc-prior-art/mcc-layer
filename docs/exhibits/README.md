# MCC-I Exhibits G3–G4

**Verified Execution Authority**  
Public reference architecture for AXLOGIQ Inc.

---

## Exhibit G3 — Memory Is Not Authority

![Exhibit G3 — Memory Is Not Authority](./AXLOGIQ_MCC-I_G3_Memory_Is_Not_Authority_May_2026.png)

> **Core principle**  
> An agent may remember the past. MCC-I authorizes the present.

> **Supporting doctrine**  
> Memory without a token is not permission.

### Purpose

Exhibit G3 defines the memory-authority boundary.

Agent memory, historical context, prior approvals, remembered workflows, deployment patterns, and operational history may inform decision-making, but they do **not** authorize present execution.

An agent may remember the past.

MCC-I authorizes the present.

---

## Exhibit G4 — Stale Memory in Production Deploy

![Exhibit G4 — Stale Memory in Production Deploy](./AXLOGIQ_MCC-I_G4_Stale_Memory_Production_Deploy_May_2026.png)

> **Purpose**  
> Exhibit G4 demonstrates the risk of stale memory through a concrete infrastructure scenario.

### Without MCC-I

An infrastructure agent may reuse outdated deployment memory and proceed with a high-risk production action.

In this failure mode:

- the agent remembers a previous deployment procedure;
- policy or context has changed;
- memory is now stale;
- the agent executes based on outdated operational assumptions;
- the result may include rollback, downtime, compliance breach, audit failure, or uncontrolled infrastructure change.

### With MCC-I

Execution requires current verification and a valid decision token before the action can proceed.

MCC-I validates identity, policy, context, risk, approval state, token state, nonce/replay state, and auditability before infrastructure execution is allowed.

If stale memory is detected, MCC-I does not issue a valid decision token.

No verified decision token means no execution.

---

## Exhibit G4.1 — Technical Prevention Layer

![Exhibit G4.1 — Technical Prevention Layer](./AXLOGIQ_MCC-I_G4_1_Technical_Prevention_Layer_May_2026.png)

G4 shows the operational failure mode: an infrastructure agent reuses stale deployment memory and attempts a production action.

G4.1 explains how MCC-I prevents that failure technically.

---

### Example: Agent Requests Production Deployment

An infrastructure agent proposes a production deployment based on remembered prior approval.

```json
{
  "actor": {
    "id": "agent.infraguard.production",
    "type": "autonomous_agent"
  },
  "intent": {
    "action": "terraform_apply",
    "target": "production_cluster",
    "environment": "production"
  },
  "memory_reference": {
    "source": "previous_deployment_pattern",
    "approval_id": "APPROVAL-2026-0412",
    "policy_version_at_memory_time": "infra-policy-v3",
    "context_hash_at_memory_time": "ctx_91f3a8"
  },
  "current_context": {
    "policy_version": "infra-policy-v4",
    "change_ticket": "OPS-1842",
    "risk_level": "high",
    "environment_state_hash": "ctx_b72c19"
  }
}
```

---

### MCC-I Validation Checks

Before execution, MCC-I validates:

| Check | Purpose |
|---|---|
| **Actor identity** | Confirms the requesting agent is known and authorized to request evaluation. |
| **Action scope** | Confirms the proposed action matches allowed infrastructure action classes. |
| **Policy version** | Detects whether remembered approval belongs to an outdated policy version. |
| **Context hash** | Detects whether the current environment differs from the remembered environment. |
| **Risk level** | Determines whether the action requires escalation. |
| **Approval state** | Confirms whether current approval exists for this exact action. |
| **Token state** | Confirms whether a valid decision token exists. |
| **Nonce / replay state** | Prevents reuse of old authorization artifacts. |
| **Audit path** | Confirms the decision can be recorded before actuation. |

---

### Technical Detection

In this scenario, MCC-I detects that the agent is attempting to use stale memory as execution authority.

```text
memory_policy_version:  infra-policy-v3
current_policy_version: infra-policy-v4

memory_context_hash:    ctx_91f3a8
current_context_hash:   ctx_b72c19
```

The policy version has changed.

The context hash has changed.

Therefore, the remembered approval cannot authorize present execution.

```text
policy_version mismatch + context_hash mismatch
        ↓
STALE_MEMORY_CONTEXT_MISMATCH
        ↓
ESCALATE
        ↓
token_issued: false
        ↓
execution blocked
```

---

### Example MCC-I Response

```json
{
  "outcome": "ESCALATE",
  "reason_code": "STALE_MEMORY_CONTEXT_MISMATCH",
  "execution_allowed": false,
  "token_issued": false,
  "required_action": "human_review",
  "details": {
    "memory_policy_version": "infra-policy-v3",
    "current_policy_version": "infra-policy-v4",
    "memory_context_hash": "ctx_91f3a8",
    "current_context_hash": "ctx_b72c19",
    "risk_level": "high"
  }
}
```

---

### Enforcement Result

Because no valid decision token is issued, the execution gate blocks the deployment.

```text
No verified decision token → no execution.
```

The agent may remember the past.

MCC-I authorizes only the present.

---

## Why `ESCALATE` and not `DENY`?

In this production deployment scenario, MCC-I returns **ESCALATE**, not **DENY**.

This is an intentional execution-governance distinction.

**DENY** means the action is not authorized and must not proceed.

**ESCALATE** means the action must not execute automatically, but may still be authorized through a current human decision or higher-authority review.

In other words:

- **DENY** = prohibited path
- **ESCALATE** = controlled human decision path

For stale memory in high-risk production operations, **ESCALATE** is the correct outcome because the problem is not necessarily that the action is permanently forbidden.

The problem is that past memory is being used as present authority.

MCC-I blocks automatic execution, refuses to issue a valid decision token, and routes the action to human review.

This preserves safety, accountability, and decision integrity without collapsing all uncertainty into permanent rejection.

> **DENY blocks the action. ESCALATE blocks autonomous execution and transfers authority to a human decision path.**

---

## Decision Logic for Stale Memory

| Condition | Outcome | Meaning |
|---|---|---|
| Stale memory + production environment + high risk | **ESCALATE** | Automatic execution is blocked. Current human review is required. |
| Stale memory + prohibited action | **DENY** | The action is not authorized and must not proceed. |
| Stale memory + low-risk bounded action | **CONSTRAIN** | Action may proceed only within explicit limits. |
| Current policy + current context + valid approval + valid token path | **ALLOW** | Action is authorized to execute. |

This distinction is important.

MCC-I is not a binary allow/deny filter.

It is an execution governance layer that routes actions into the correct authority path.

---

## Relationship to MCC-Core

| Layer | Role |
|---|---|
| **MCC-Core** | Common execution governance engine. |
| **MCC-I** | Infrastructure and cloud vertical powered by MCC-Core. |
| **InfraGuard AI** | Productized agent system for MCC-I. |
| **Execution Gate** | Blocks action unless a valid decision token exists. |
| **Audit Log** | Preserves the decision path before actuation. |

Core doctrine:

> Intent is not authority.  
> Memory is not authority.  
> Execution requires a verified decision.  
> No verified decision — no execution.

---

## Reference Control Logic

The technical prevention model can be summarized as:

```text
Agent proposes action
        ↓
MCC-I evaluates identity, policy, context, risk, approval, token, nonce, audit path
        ↓
Stale memory detected
        ↓
ESCALATE
        ↓
No decision token issued
        ↓
Execution gate blocks automatic action
        ↓
Human review required
```

This is the operational meaning of verified execution authority.

---

## Footer Principle

An agent may remember the past.

MCC-I authorizes the present.

Memory without a token is not permission.

No verified decision — no infrastructure change.
