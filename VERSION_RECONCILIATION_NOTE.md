# VERSION_RECONCILIATION_NOTE.md — MCC-Core v1.11.0

**Canonical runtime release version = `1.11.0`** (already established in
`GOVERNANCE.md`, anchored to the PR #4 merge). Single source of truth: the
repo-root **`VERSION`** file, read in code by `mcc_core.version.RUNTIME_VERSION`.

**Only the product/runtime category is reconciled.** Harness, protocol/schema,
documentation/doctrine, and frozen historical/exhibit versions have independent
lifecycles and are left intact, per the Phase 0 classification
(`RUNTIME_STATE_AUDIT.md` §4).

---

## Per-string disposition

| file:line | string (old) | category | action (new / kept / frozen) |
|---|---|---|---|
| `VERSION` (new) | — → `1.11.0` | product/runtime (canonical source) | **created** = `1.11.0` |
| `main.py` FastAPI `version=` | `1.2.0-ed25519` | product/runtime | **→ `RUNTIME_VERSION` (1.11.0)**. Engine suffix dropped from the version field; the signing engine is still reported at `/health` (`signing.algorithm = Ed25519`). |
| `gateway/app.py` `version=` | `1.0.0-mvp` | product/runtime | **→ `RUNTIME_VERSION` (1.11.0)** |
| `interceptors/egress_proxy.py` `version=` | `1.0.0-mvp` | product/runtime | **→ `RUNTIME_VERSION` (1.11.0)** |
| `GOVERNANCE.md` | `v1.11.0` (×5) | product/runtime (release record) | **kept** — already correct |
| `mcc.yaml:1` | `version: "1.0"` | protocol/schema (policy-ref) | **kept** — independent lifecycle |
| `policies.yaml:1` | `version: 1` | protocol/schema (policy) | **kept** — independent lifecycle |
| `README.md:6` | `v1.5.3` | documentation (🔒 NIW-protected) | **FLAGGED for AX — not edited** (see below) |
| GitHub repo "About"/sidebar | `MCC v1.5` | product/runtime label, **not a file** | **FLAGGED for AX** — set via GitHub repo settings/API, cannot be changed in this PR |
| `README.md` "Status / Prototype" | maturity label | documentation/doctrine | **kept** (AX decides) |
| `README.md` "Doctrine Lines v1.0" | `v1.0` | doctrine version | **kept** — independent |
| `README.md:194` | `MCC v0.5` (archived post) | historical | **frozen** |
| `CLAUDE.md:76` | `v1.10.1-stable-professional` | historical/doctrine stack label | **FROZEN / FLAGGED for AX — not edited** (see below) |

## Items AX must handle manually (under counsel)

1. **`CLAUDE.md:76` — `v1.10.1-stable-professional`.** This is the only in-repo
   occurrence of `v1.10.1`. It reads as the doctrine "current stack version,"
   but `v1.10.1` is **frozen historical evidence** (Exhibit G6 / self-test
   evidence, held externally). Per the brief's instruction to *flag, not edit,*
   when a `v1.10.1` reference is ambiguous, this was left untouched. If AX wants
   the doctrine stack label to read `v1.11.0`, **AX edits `CLAUDE.md` directly**
   — it is a sensitive guardrail file and the change is a doctrine decision.

2. **`README.md:6` — `v1.5.3`** and the GitHub sidebar **"MCC v1.5".**
   `README.md` is 🔒 **NIW-protected** (CLAUDE.md: no structural changes without
   explicit approval). The GitHub "About" text is a repository setting, not a
   tracked file. Both are product-facing version labels that *would* reconcile
   to `1.11.0`, but reconciling them is **AX's call** and is done outside this
   PR (README edit under counsel; sidebar via GitHub settings).

## Frozen — never edited by this work

- `v1.10.1` anywhere it serves as historical evidence (G6, self-test logs,
  signed exhibits). The single in-repo reference (`CLAUDE.md:76`) is confirmed
  **unchanged** in this PR's diff, and a CI guard asserts it remains present.

## Drift guard

`scripts/check_version_drift.py` (CI: the `invariants` job) enforces that every
runtime entrypoint derives its version from the canonical `VERSION` file — no
hardcoded literal may reappear. It is demonstrated in CI to (a) pass when
canonical, (b) **fail** on a deliberately reintroduced runtime literal, and (c)
**not** inspect or fire on the frozen/historical, schema, doctrine, or README
strings. A second CI step asserts the frozen `v1.10.1` reference is intact.
