# RUNTIME_STATE_AUDIT.md — Phase 0 Ground Truth

**Branch:** `feat/wire-runtime-v1.11.0` (from `main` @ `097691e`)
**Date:** 2026-06-25
**Author:** automated audit (for AX review)
**Rule:** accuracy over optimism. Where a claim in the brief differs from the tree, the **tree wins** and the discrepancy is recorded.

---

## 1. Module inventory — governance stack is ALREADY ON `main`

The brief anticipated that consensus / challenge / gate / nonce might live only on unmerged branches (PR #15, PR #16). **They do not.** PR #15 (N-of-M consensus) and PR #16 (gateway challenge) were already **merged into `main`**. Every governance module is present on `main` today:

| Module | Path | Present on `main`? | Introduced by (provenance SHA) |
|---|---|---|---|
| Multi-Context Consensus (N-of-M) | `src/mcc_core/consensus.py` | ✅ yes | `1c8c76e` feat(consensus): Multi-Context Consensus 3/3 |
| Consensus challenge (gateway nonce) | `src/mcc_core/challenge.py` | ✅ yes | `aa4451e` Add consensus challenge |
| Enforcement coordinator | `src/mcc_core/coordinator.py` | ✅ yes | `b87df52` feat(governance): txn binding/idempotency/velocity |
| Execution gate (fail-closed) | `src/mcc_core/gate.py` | ✅ yes | `75d535e` runtime: signed decision tokens + fail-closed gate |
| Nonce registry (replay protect) | `src/mcc_core/nonce.py` | ✅ yes | `75d535e` runtime: signed decision tokens + fail-closed gate |

**Consequence for Phase 1:** there is **nothing to cherry-pick**. The reviewed code from PR #15/#16 is already on `main`. Phase 1 *wires* these in-tree modules into `main.py:/evaluate` via imports — it does **not** port, copy, or re-merge any branch. No `git cherry-pick -x` is required because no source branch is involved; provenance of the modules themselves is the table above.

`git branch -a` at audit time: only `main` and this working branch exist remotely; all feature branches (#7, #15, #16, #17, #18) are merged and deleted.

---

## 2. What `/evaluate` actually calls today (verified, not assumed)

`main.py` (FastAPI app, `version="1.2.0-ed25519"`) imports from `mcc_core` **only**:

```python
from mcc_core import (AuditLog, DecisionEngine, PolicyBundle, SigningKey, hash_payload)
```

`/evaluate` → `MCC.evaluate()` →
1. idempotency cache check (in-process),
2. **policy decision**: `OPAAdapter.evaluate()` (real OPA) **or** `LocalFallbackPolicy` when `MCC_USE_OPA=false`,
3. audit-before-authority (`AuditLog.append`, hash-chain, fsync),
4. `DecisionEngine.issue_token()` (Ed25519) for ALLOW/CONSTRAIN only,
5. Prometheus metrics + return.

**It does NOT reach** `consensus`, `challenge`, `coordinator`, `gate`, or `nonce`. Confirmed: `main.py` imports none of them. This is the gap Phase 1 closes.

---

## 3. Discrepancies between the brief and the tree (tree wins)

| Brief claim | Actual tree | Resolution |
|---|---|---|
| `main.py` FastAPI `version="1.1.0-opa"` | `version="1.2.0-ed25519"` (`main.py:475`). The string `1.1.0-opa` **does not exist anywhere** in the repo. | Reconcile the *actual* runtime string (`1.2.0-ed25519`) → `1.11.0`. |
| "`1.2.0-ed25519` = hardened harness version → keep" | `1.2.0-ed25519` **is** `main.py`'s runtime FastAPI app version, not a separate harness. There is no separate self-test "harness version" string in the tree. | Treat `1.2.0-ed25519` as **product/runtime** → reconcile to `1.11.0`. No harness string to keep. |
| "Keep existing behavior … HMAC `X-MCC-Signature`" | **No HMAC and no `X-MCC-Signature` exist** in `main.py` or anywhere in the runtime. `main.py` uses Ed25519 decision tokens; a code comment states "no transport-level symmetric signature." | **Do NOT introduce HMAC.** `CLAUDE.md` forbids HMAC (lines 77/90/149), the pre-commit checklist greps for it, and `tests/test_mcc_core.py::test_no_hmac_in_authority_bearing_runtime` fails the build if `hmac` appears in the runtime path. The actual "existing behavior to preserve" is: **idempotency cache, Prometheus metrics, ALLOW/DENY/ESCALATE/CONSTRAIN enum, Ed25519 tokens, fail-closed**. Flagged for AX. |
| `v1.10.1` is "attached to Exhibit G6 and self-test evidence" in-repo | In-repo, `v1.10.1` appears at **exactly one** location: `CLAUDE.md:76` (`**Version:** v1.10.1-stable-professional`). The `docs/exhibits/` G3/G4 files are PNG images with no editable version string; no "G6" text file exists in-tree. The G6 / self-test evidence is presumably external (signed docs AX holds). | Freeze `v1.10.1` everywhere. The single in-repo occurrence (`CLAUDE.md:76`) is a doctrine stack label — **flagged for AX, not edited** (see §4). |

---

## 4. Version-string classification (every match tagged into exactly one category)

Canonical runtime release version for this work = **`1.11.0`** (already established in `GOVERNANCE.md`, anchored to the PR #4 merge). Only the **product/runtime** category is reconciled.

| file:line | string | category | action |
|---|---|---|---|
| `main.py:475` | `1.2.0-ed25519` | **product/runtime** | reconcile → `1.11.0` (drop engine suffix; engine is reported in `/health`) |
| `gateway/app.py:340` | `1.0.0-mvp` | **product/runtime** (gate-as-a-service) | reconcile → `1.11.0` |
| `interceptors/egress_proxy.py:384` | `1.0.0-mvp` | **product/runtime** (the one interceptor) | reconcile → `1.11.0` |
| `GOVERNANCE.md:5,7,16,18,25` | `v1.11.0` | product/runtime (release record) | **keep** — already correct |
| `mcc.yaml:1` | `version: "1.0"` | **protocol/schema** (declarative policy-ref version) | keep |
| `policies.yaml:1` | `version: 1` | **protocol/schema** (policy schema) | keep |
| `CLAUDE.md:76` | `v1.10.1-stable-professional` | **historical/doctrine** stack label | **FLAG for AX — do not edit** (v1.10.1 frozen; CLAUDE.md is a sensitive guardrail. If AX wants the doctrine label bumped to 1.11.0, AX edits it.) |
| `README.md:6` | `v1.5.3` (+ date 2026-06-12) | **documentation** (NIW-protected file) | **FLAG for AX — do not edit** (`README.md` is 🔒 Protected per CLAUDE.md; no structural changes without AX approval) |
| GitHub repo "About"/sidebar | `MCC v1.5` | product/runtime label, but **not a file** (GitHub repo description) | **FLAG for AX** — set via GitHub settings/API, cannot be changed in this PR |
| `README.md:1255-1261` | "Status: Prototype / Technical Review" | **documentation/doctrine** maturity | keep (AX decides) |
| `README.md` "Doctrine Lines v1.0" (×n) | `v1.0` | **doctrine** version (independent) | keep |
| `README.md:194` | `MCC v0.5` (archived X post) | **historical** | freeze |

**Canonical source of truth (Phase 2):** introduce a single `VERSION` file containing `1.11.0`; the three product/runtime app strings derive from / match it; the CI drift-guard checks only those three locations and explicitly excludes the frozen/keep/flag strings.

---

## 5. Phase 1 wiring plan (summary; detail in the PR)

`/evaluate` will route through the **two-phase protocol** using the in-tree modules (no new deps):

- **Phase A — `POST /evaluate/challenge`:** `ChallengeService` issues a one-time **nonce-bound** challenge binding `actor + action + resource + payload + policy_hash`.
- **Phase B — `POST /evaluate`:** policy decision (OPA/local) **and** N-of-M quorum via `ConsensusVerifier` over **cryptographically verified evaluator votes from distinct trusted evaluator identities** → `DecisionEngine` token bound to the nonce → `EnforcementCoordinator` (which runs `ExecutionGate` verify + nonce consume, quorum re-check, challenge single-use consume, audit-before-actuation). Fail-closed at every boundary.

**Honesty constraint (carried into code + docs):** the runtime verifies signatures, evaluator **identity uniqueness**, **trust membership**, **quorum (N-of-M)**, action **bindings**, token **expiry**, and **veto**. It does **NOT** guarantee organizational/operational/model-level **independence** of evaluators — that is a deployment/governance property, not a software guarantee.
