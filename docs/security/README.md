# `docs/security/` — Index

This directory holds versioned, point-in-time security governance documents that were authored, reviewed, and approved outside the normal engineering PR flow, then published to the repository as-is. They are historical artifacts: each carries its own authorship date and version, and is **not** edited in place when circumstances change. Status changes are recorded in separate, clearly dated addendum documents instead — see below.

## Contents

| Document | Version | Date | Status |
| --- | --- | --- | --- |
| [`MCC_CORE_STRATEGIC_ROADMAP_v1.2.md`](./MCC_CORE_STRATEGIC_ROADMAP_v1.2.md) | v1.2 | 28 October 2026 | Approved working engineering direction, published verbatim |
| [`MCC_CORE_THREAT_MODEL_v1.0.md`](./MCC_CORE_THREAT_MODEL_v1.0.md) | v1.0 | 28 October 2026 | Proposed for independent review, published verbatim |
| [`PR122_POST_MERGE_ADDENDUM.md`](./PR122_POST_MERGE_ADDENDUM.md) | — | 29 October 2026 | Post-merge status update to the two documents above; see that file's own scope note |
| [`PR124_P1_COMPLETION_ADDENDUM.md`](./PR124_P1_COMPLETION_ADDENDUM.md) | — | 29 October 2026 | Post-merge status update: P1 (Verifiable Delegation & Intent Binding, PR #124) merged; P2-A/P2-B next; see that file's own scope note |

## Relationship to other `docs/` security content

This repository has several pre-existing, differently-scoped documents that predate and are **not superseded by** the ones in this directory:

- [`../THREAT_MODEL.md`](../THREAT_MODEL.md) — the adversary model specifically for the PR #71 independent-assurance baseline (`assurance/`). Narrower in scope than the STRIDE-based model here, and about a different subsystem.
- [`../SECURITY_MODEL.md`](../SECURITY_MODEL.md) — a short, general statement of fail-closed principles and control categories.
- [`../ROADMAP.md`](../ROADMAP.md) — an unversioned, general feature roadmap, distinct from the dated, versioned Strategic Engineering Roadmap in this directory.

If a future reader needs "the roadmap" or "the threat model" for this repository, check both this directory and the top-level files above — they answer different, complementary questions rather than one replacing the other. Reconciling or merging them is a documentation gap, not yet addressed here (see the handoff PR description that introduced this directory for the full list of known gaps).

## Conventions used in this directory

- **Never edit a published, dated, versioned document in place to reflect a later event.** Publish a new, separately dated addendum instead, and link it from the original's index entry above.
- **An addendum updates status; it does not re-litigate or re-review.** If a genuinely new security review is warranted, it produces its own dated findings document (following this repository's existing security-engagement conventions), not a silent edit to an already-approved document.
- **Preserve every stable threat/control ID** (e.g. the Threat Model's `T-01`...`T-12`) across all future revisions. Never renumber or reuse an ID after publication.
