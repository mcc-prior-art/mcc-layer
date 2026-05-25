# MCC-I Exhibits G3–G4

**Verified Execution Authority**  
Public reference architecture for AXLOGIQ Inc.

---

## Exhibit G3 — Memory Is Not Authority

![Exhibit G3 — Memory Is Not Authority](AXLOGIQ_MCC-I_G3_Memory_its_not_Authority_May_2026.PNG)

> **Core principle**  
> An agent may remember the past. MCC-I authorizes the present.

> **Supporting doctrine**  
> Memory without a token is not permission.

**Purpose**  
Exhibit G3 defines the memory-authority boundary. Agent memory, historical context, prior approvals, and remembered workflows may inform decision-making, but they do **not** authorize present execution.

---

## Exhibit G4 — Stale Memory in Production Deploy

![Exhibit G4 — Stale Memory in Production Deploy](AXLOGIQ_MCC-G4_Stale_Memory_Production_Deploy_May_2026.png.PNG)

> **Purpose**  
> Exhibit G4 demonstrates the risk of stale memory through a concrete infrastructure scenario.

**Without MCC-I**  
An agent may reuse outdated deployment memory and proceed with a high-risk production action.

**With MCC-I**  
Execution requires current verification and a valid decision token before the action can proceed.

---

## Relationship to MCC-Core

| Layer       | Role                                      |
|-------------|-------------------------------------------|
| **MCC-I**       | Infrastructure & Cloud Execution Governance vertical |
| **MCC-Core**    | The underlying technical decision engine             |

In this exhibit series:
- **G3** = Principle
- **G4** = Operational validation

**Together they show:** Remembered context is not execution authority. Infrastructure execution requires a **current verified decision**.

---

## Claim Hygiene

These exhibits are **public reference architecture and technical review materials**.

They should **not** be described as:
- Certified production safety materials
- Government-approved materials
- Third-party-endorsed materials
- Production-certified infrastructure controls

They should be described as:

> Public reference architecture and exhibit materials for MCC-I verified execution authority.

---

**← Back to MCC-Core**  
[Main documentation](../..)
