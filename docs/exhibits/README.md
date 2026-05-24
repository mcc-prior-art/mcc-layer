# MCC-I Exhibits G3–G4

This folder contains the MCC-I verified execution authority exhibit series for AXLOGIQ Inc.

## Exhibit G3 — Memory Is Not Authority

![Exhibit G3 — Memory Is Not Authority](./AXLOGIQ_MCC-I_G3_Memory_Is_Not_Authority_May_2026.jpg)

**Core principle:**

> An agent may remember the past. MCC-I authorizes the present.

**Supporting doctrine:**

> Memory without a token is not permission.

Exhibit G3 defines the memory-authority boundary: agent memory, historical context, prior approvals, and remembered workflows may inform decision-making, but they do not authorize present execution.

---

## Exhibit G4 — Concrete Example: Stale Memory in Production Deploy

![Exhibit G4 — Concrete Example: Stale Memory in Production Deploy](./AXLOGIQ_MCC-I_G4_Stale_Memory_Production_Deploy_May_2026.jpg)

Exhibit G4 validates the principle through a concrete infrastructure scenario.

Without MCC-I, an agent may reuse stale deployment memory and proceed toward a high-risk production action.

With MCC-I, execution requires current verification and a valid decision token before the action can proceed.

---

## Series Footer Standard

```text
01 / 02
VERIFIED EXECUTION AUTHORITY
Powered by MCC-Core
Founder & Architect: Alexandr Ponomariov
AXLOGIQ Inc. • May 2026
axlogiq.com • axlogiq.ai • axlogiq.org • github.com/mcc-prior-art/mcc-layer
```

```text
02 / 02
VERIFIED EXECUTION AUTHORITY
Powered by MCC-Core
Founder & Architect: Alexandr Ponomariov
AXLOGIQ Inc. • May 2026
axlogiq.com • axlogiq.ai • axlogiq.org • github.com/mcc-prior-art/mcc-layer
```

---

## Recommended README Placement

Add this section after **Memory Is Not Authority** or after the **MCC-I — Infrastructure & Cloud** section:

```markdown
## Exhibits: Memory Is Not Authority

MCC-I includes a two-part exhibit series demonstrating the verified execution authority principle.

- **Exhibit G3 — Memory Is Not Authority:** agent memory may inform evaluation, but it does not authorize execution.
- **Exhibit G4 — Stale Memory in Production Deploy:** concrete infrastructure case showing how MCC-I blocks stale-context execution unless a current verified decision token exists.

See: [`docs/exhibits/`](./docs/exhibits/)
```

---

## Claim Hygiene

These exhibits should be described as public reference architecture / technical review materials.

They should not be described as certified production safety materials, government-approved materials, or third-party-endorsed materials.
