> **Prior Art Notice**  
> This repository establishes public prior art as of 2026-04-22 for a fail-closed policy engine with tamper-evident SHA256 hash-chain audit logging.  
> Release: v1.5  
> Commit (Git SHA-1): 9b4bfad1b6af628f4feb39e9913d98fe586aa766  
> All artifacts are publicly accessible and reproducible at the time of publication.

# MCC v1.5 Policy Engine — Reference Implementation

Fail-closed control layer for policy-gated execution with cryptographic hash-chain audit.

---

## TL;DR

- **Deny-by-default** execution  
- **Fail-closed** on uncertainty, violation, or internal error  
- **Policy-gated** boundary between intent and execution  
- **Tamper-evident** audit via SHA256 hash-chain  

---

## Control Model

MCC enforces a strict separation between:
- **Intent** — what the system proposes  
- **Execution** — what is actually allowed  

All actions pass through a policy gate before execution.

**Default behavior**
- Unknown intent → **DENY**  
- Policy violation → **DENY**  
- Policy error → **DENY**  
- System error → **DENY**  

Execution requires an explicit **ALLOW** decision.

---

## Decision Contract

```python
decision = mcc.evaluate(intent)

decision.verdict   # "ALLOW" | "DENY"  
decision.reason    # string explanation  
decision.trace_id  # audit trace reference  
