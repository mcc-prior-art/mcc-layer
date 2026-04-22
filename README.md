# MCC v1.5 Policy Engine — Reference Implementation

![Status](https://img.shields.io/badge/status-alpha-orange)
![Prior Art](https://img.shields.io/badge/prior%20art-2026--04--22-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**Fail-closed control layer** for policy-gated execution with **cryptographic hash-chain audit**.

---

## Prior Art Notice

This repository establishes public prior art as of **2026-04-22** for a fail-closed policy engine with tamper-evident SHA256 hash-chain audit logging.

- **Release:** v1.5  
- **Commit (Git SHA-1):** `9b4bfad1b6af628f4feb39e9913d98fe586aa766`  

All artifacts are publicly accessible and reproducible at the time of publication.

---

## TL;DR

- **Deny-by-default** execution  
- **Fail-closed** on uncertainty, violation, or internal error  
- Policy-gated boundary between **intent** and **execution**  
- Tamper-evident audit via **SHA256 hash-chain**

---

## Control Model

MCC enforces a strict separation between:

- **Intent** — what the system proposes  
- **Execution** — what is actually allowed  

All actions pass through a policy gate before execution.

### Default behaviour

| Condition        | Decision |
|-----------------|----------|
| Unknown intent  | `DENY`   |
| Policy violation| `DENY`   |
| Policy error    | `DENY`   |
| System error    | `DENY`   |

**Execution requires an explicit `ALLOW` decision.**

---

## Why Fail-Closed?

In security-sensitive environments, failing open (allowing action when unsure) leads to systemic risk.  

MCC fails **closed**:
- ambiguity → `DENY`
- error → `DENY`
- unknown → `DENY`

This guarantees deterministic control and auditability.

---

## Decision Contract

```python
decision = mcc.evaluate(intent)

decision.verdict   # "ALLOW" | "DENY"
decision.reason    # explanation string
decision.trace_id  # audit trace reference
```

---

## 🚀 60-Second Quickstart

```bash
pip install mcc-policy-engine
```

```python
from mcc import PolicyEngine

mcc = PolicyEngine()  # deny-by-default, SHA256 audit log

def execute(intent):
    return f"EXECUTED: {intent}"

def run_tool(intent):
    decision = mcc.evaluate(intent)

    if decision.verdict == "DENY":
        return f"BLOCKED: {decision.reason} (trace_id={decision.trace_id})"

    return execute(intent)

# Example: dangerous action
result = run_tool({"action": "delete_user", "user_id": 1})
print(result)
# BLOCKED: Destructive action violates baseline policy. (trace_id=abc123)
```

---

## Execution Flow

```
Intent → MCC.evaluate() → Decision
                 ↓
        ALLOW → execute()
        DENY  → block
```

---

## Audit: SHA256 Hash-Chain

Every evaluation produces an immutable audit record:

```text
record_N = {
  "prev_hash": hash_of_record_N-1,
  "timestamp": ...,
  "intent": ...,
  "verdict": "ALLOW" | "DENY",
  "reason": "...",
  "trace_id": "..."
}

current_hash = SHA256(prev_hash + timestamp + intent + verdict + reason)
```

### Properties

- **Tamper-evident**
- **Order-preserving**
- **Cryptographically verifiable**

---

## Security Properties

- **Fail-closed**: any uncertainty or failure → `DENY`
- **Deny-by-default**: no implicit execution
- **Policy-gated execution**: intent ≠ execution
- **Traceability**: every decision is auditable

---

## Use Cases

- AI agents (tool execution)
- Financial systems (payments)
- Robotics (action gating)
- API orchestration
- Autonomous systems

---

## Scope

This implementation establishes public prior art for:

- meta-cognitive control layers
- policy-gated execution
- fail-closed AI safety mechanisms
- tamper-evident decision auditability

---

## License

MIT. No patent rights are granted.
