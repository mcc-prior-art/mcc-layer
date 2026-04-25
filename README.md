# MCC — Meta-Cognitive Control

Before npm, JavaScript projects had dependencies — but no standard way to declare them.

Before MCC, AI agents had execution power — but no standard way to declare authority.

package.json made dependencies explicit.
mcc.yaml makes execution authority explicit.

Agents should not execute just because they generated intent.

Execution requires a decision.

---

**Quickstart**

1. Create mcc.yaml:

version: 1.0
actions:
  payments:
    ALLOW: amount < 100
    ESCALATE: amount < 10000
    DENY: amount >= 10000
  tools:
    ALLOW: scope == "read"
    ESCALATE: scope == "write"
    DENY: scope == "admin"
audit: true
rollback: true

2. Wrap your agent:

from mcc import guard

@guard(policy="mcc.yaml")
def transfer_money(amount, user):
    stripe.PaymentIntent.create(...) # This now runs through MCC

**The Problem**

Every agent framework executes tool calls right after the LLM decides. There is no boundary.
$40B + 5GW of compute means errors scale to millions in minutes.

**The Fix**

MCC inserts a decision layer between intent and execution: ALLOW / DENY / ESCALATE.
Every action is audited. Every critical action requires approval. Every mistake can be rolled back.

**License**: MIT  
**Status**: v0.1.0 alpha  
**Author**: [@axlogiq_ai](https://x.com/axlogiq_ai)
