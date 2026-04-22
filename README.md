# MCC (Meta-Cognitive Control)

A control layer between AI-generated intent and real-world execution.  
Non-Production Use only.

---

## Core Thesis

AI systems can generate actions.  
They cannot reliably determine whether those actions should be executed.

MCC introduces a formal boundary between:

- intent generation (LLMs, agents)
- execution authority (systems, APIs, workflows)

Execution requires a decision.

---

## Why This Matters

As soon as systems:

- call APIs
- move money
- trigger workflows
- control external systems

they stop being passive models and become actors.

Without a control boundary, execution becomes implicit.  
That is a systemic risk.

MCC defines that missing layer.

---

## Architectural Pattern

AI Model → Intent → MCC → Decision → Execution (or Denial)

- model proposes
- MCC evaluates
- only approved actions execute

The model does not execute directly.  
Execution authority is separated from generation.

---

## Decision Model

MCC produces one of three outcomes:

- ALLOW
- DENY
- ESCALATE

Default: deny-by-default (fail-closed)

If something is unclear, invalid, or unsafe, it does not execute.

---

## Example + Minimal Integration

Input:

    {
      "intent": "send_payment",
      "amount": 50000,
      "recipient": "external_vendor"
    }

Decision:

    DENY
    reason: amount exceeds policy threshold

Minimal integration:

    def mcc_evaluate(request):
        if request["intent"] == "send_payment" and request["amount"] > 10000:
            return "DENY"
        return "ALLOW"

    decision = mcc_evaluate({
        "intent": "send_payment",
        "amount": 50000,
        "recipient": "external_vendor"
    })

    if decision == "ALLOW":
        execute_payment()
    else:
        block_execution()

Result:

- No API call
- No execution
- External state remains unchanged

MCC acts as a hard execution gate between AI and the real world.

---

## Reference Implementation

This repository provides a minimal PoC demonstrating:

- deny-by-default execution model
- structured intent validation
- policy-based decision logic
- strict separation of intent and execution

Use cases:

- research
- evaluation
- architectural prototyping

---

## Where MCC Fits

MCC applies to any system where AI can act:

- AI agents with tool execution
- financial and transactional systems
- API-driven automation
- robotics and real-world control systems
- enterprise AI governance layers

---

## Prior Art

This repository establishes public prior art for the MCC control-layer pattern:

- control boundary between AI and execution
- deny-by-default execution gating
- separation of intent and authority

Private Canon materials are not disclosed.

---

## Licensing

Use of this repository is governed by the MCC Evaluation License 1.0.

- Non-Production Use only
- Production use requires a separate commercial agreement

See LICENSE for details.

---

## Commercial Use

Production deployment and enterprise integration are available under separate terms.

Includes:

- access to MCC Canon specifications
- production-grade policy design
- governance, audit, and safety guarantees
- integration and certification support

Contact:  
mcc.prior.art.2026@proton.me

---

## Statement

MCC is not another model.  
MCC is not another interface.

It is the missing layer between intelligence and action.

Systems that act must be controlled.

MCC defines that control.
