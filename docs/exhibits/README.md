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
Exhibit G3 defines the memory-authority boundary. While agent memory and historical context may inform evaluation, they do **not** authorize execution.

---

## Exhibit G4 — Stale Memory in Production Deploy

![Exhibit G4 — Stale Memory in Production Deploy](AXLOGIQ_MCC-G4_Stale_Memory_Production_Deploy_May_2026.png.PNG)

> **Purpose**  
Exhibit G4 demonstrates the risk through a concrete infrastructure scenario.

**Without MCC-I**  
An agent may reuse stale deployment memory and proceed with a high-risk production action.

**With MCC-I**  
Execution requires current verification and a valid decision token.

---

## Relationship to MCC-Core

| Component   | Role                                                                 |
|-------------|----------------------------------------------------------------------|
| **MCC-I**       | Infrastructure & Cloud Execution Governance vertical                 |
| **MCC-Core**    | Technical decision engine that enforces verified execution authority |

**In this series:**
- G3 = Principle
- G4 = Operational validation

Infrastructure execution requires a **current verified decision**.

---

## Claim Hygiene

These are **public reference architecture and technical review materials**.

They should **not** be described as certified production safety materials, government-approved materials, or production-certified controls.

**Correct description:**  
Public reference architecture and exhibit materials for MCC-I verified execution authority.

---

**← Back to MCC-Core**
