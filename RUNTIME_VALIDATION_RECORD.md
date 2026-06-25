# RUNTIME_VALIDATION_RECORD.md — MCC-Core v1.11.0

**Subject:** wiring the full governance stack into the public `/evaluate` entrypoint.
**Branch:** `feat/wire-runtime-v1.11.0`
**Date:** 2026-06-25

> The model proposes. MCC-Core decides. The gate enforces. The audit chain records.
> Intent is not authority. Execution requires a verified decision. No verified decision — no execution.

---

## 1. What changed

`main.py` (the public REST runtime) previously routed `/evaluate` through the
base policy-decision layer only (OPA / local fallback → Ed25519 token). It now
wires the **complete governance pipeline** that already exists in
`src/mcc_core/` (consensus, challenge, gate, nonce, coordinator):

**Two-phase protocol**
- **Phase A — `POST /evaluate/challenge`:** the gateway issues a one-time,
  nonce-bound challenge binding `actor + action + resource + payload + policy`.
- **Phase B — `POST /evaluate`:** policy decision (OPA/local) **and** N-of-M
  quorum over cryptographically verified evaluator votes → `ExecutionGate`
  (signature + binding + one-time nonce consume) → single-use challenge consume
  → hash-chain audit, orchestrated by the `EnforcementCoordinator`.

The pipeline is **active** when an evaluator trust set is configured
(`MCC_CONSENSUS_TRUST_CONFIG`) and a policy bundle is loaded; otherwise the
runtime serves the base policy-decision layer and reports `governance.active=false`
in `/health`. `MCC_REQUIRE_GOVERNANCE=true` refuses fail-open startup.

## 2. Precise technical claim (NIW-critical honesty constraint)

The runtime **cryptographically verifies evaluator votes from distinct trusted
evaluator identities**. Concretely it verifies: Ed25519 **signatures**,
evaluator **identity uniqueness** (one ballot per evaluator), **trust
membership** (kid ∈ configured evaluator set), **quorum** (N-of-M), action
**bindings** (action/payload/actor/resource/policy_hash/nonce), token **expiry**,
and **veto** (any trusted DENY is decisive).

It **does NOT** guarantee **organizational, operational, or model-level
independence** of those evaluators. Independence is a deployment/governance
property outside the software's control. "Verified votes" ≠ "guaranteed
independent evaluators." This wording is carried verbatim into the code
(`GovernancePipeline` docstring, `/evaluate` response `quorum.claim`, `/health`)
and must survive into sworn NIW documentation.

## 3. Fail-closed boundaries (every one resolves to DENY)

| Condition | Result |
|---|---|
| no challenge / no votes supplied | DENY |
| insufficient quorum (< N) | DENY |
| evaluator veto (trusted DENY) | DENY |
| duplicate evaluator identity | DENY (counted once → below threshold) |
| non-member / untrusted evaluator | DENY (vote ignored → below threshold) |
| forged / tampered signature | DENY |
| challenge unknown / expired / already consumed | DENY |
| action/actor/resource/payload/policy/nonce mismatch | DENY |
| replayed nonce | DENY (one-time nonce + single-use challenge) |
| expired token (verified past its window) | DENY (ExecutionGate) |
| OPA unreachable (pre-existing) | DENY |
| audit write unconfirmable | DENY |

## 4. Acceptance criteria — status

- [x] Import graph: `/evaluate` reaches quorum + challenge + gate + nonce + coordinator (no dead imports).
- [x] New fail-closed tests added and green (`tests/test_runtime_wired.py`, 15 tests).
- [x] All prior tests still green (full suite **385 passed**).
- [x] No code ported from branches — PR #15/#16 modules were already on `main` (see `RUNTIME_STATE_AUDIT.md` §1); nothing cherry-picked.
- [x] Section 5 below contains **actual captured stdout** + SHA-256 (no synthetic logs).
- [x] HMAC **not** introduced (forbidden by CLAUDE.md + `test_no_hmac_in_authority_bearing_runtime`); the brief's "HMAC X-MCC-Signature" claim was inaccurate (see audit §3).

## 5. Captured validation output (real, local run)

The block below is the **verbatim stdout** of a local run on
`feat/wire-runtime-v1.11.0` (committed as `RUNTIME_VALIDATION_phase1.log`).

- **Log file:** `RUNTIME_VALIDATION_phase1.log`
- **SHA-256:** `5f6af8f5d534f54a8356d15c6dc46b83d5f8ce50cadc6af2627149e4af4ae7e7`
- Reproduce: `sha256sum RUNTIME_VALIDATION_phase1.log`

```text
### MCC-Core v1.11.0 — Phase 1 wired-runtime validation
### date: 2026-06-25T15:36:40Z | python: Python 3.11.15

===== A. End-to-end governance pipeline through main.py:/evaluate (TestClient) =====
governance active: True | version: 1.11.0

--- 1. valid 3-of-3 ---
decision: ALLOW | token: True | quorum: True

--- 2. insufficient quorum (2 votes) ---
decision: DENY | reason: consensus required: NO_CONSENSUS: 2/3 agreed

--- 3. veto (1 DENY) ---
decision: DENY | reason: consensus required: VETO: eval-2 voted DENY

--- 4. no votes / no challenge ---
decision: DENY | reason: no challenge / quorum evidence supplied; fail-closed

--- 5. replayed challenge/nonce (reuse same challenge) ---
first: ALLOW | replay: DENY | reason: challenge not open (state CONSUMED); fail-closed

--- 6. duplicate evaluator (eval-0 x3) ---
decision: DENY | reason: consensus required: NO_CONSENSUS: 1/3 agreed

--- 7. non-member evaluator (untrusted key) ---
decision: DENY | reason: consensus required: NO_CONSENSUS: 2/3 agreed

--- 8. challenge/payload mismatch (votes bound to different payload) ---
decision: DENY | reason: consensus required: NO_CONSENSUS: 0/3 agreed

ALL GOVERNANCE PIPELINE CHECKS PASSED

===== B. Committed fail-closed test suite (tests/test_runtime_wired.py) =====
tests/test_runtime_wired.py::test_valid_quorum_allows_with_token PASSED  [  6%]
tests/test_runtime_wired.py::test_challenge_endpoint_binds_the_operation PASSED [ 13%]
tests/test_runtime_wired.py::test_insufficient_quorum_denies PASSED      [ 20%]
tests/test_runtime_wired.py::test_veto_denies PASSED                     [ 26%]
tests/test_runtime_wired.py::test_no_challenge_or_votes_denies PASSED    [ 33%]
tests/test_runtime_wired.py::test_replayed_nonce_denies PASSED           [ 40%]
tests/test_runtime_wired.py::test_duplicate_evaluator_identity_denies PASSED [ 46%]
tests/test_runtime_wired.py::test_non_member_evaluator_denies PASSED     [ 53%]
tests/test_runtime_wired.py::test_forged_signature_denies PASSED         [ 60%]
tests/test_runtime_wired.py::test_challenge_payload_mismatch_denies PASSED [ 66%]
tests/test_runtime_wired.py::test_unknown_challenge_denies PASSED        [ 73%]
tests/test_runtime_wired.py::test_expired_challenge_denies PASSED        [ 80%]
tests/test_runtime_wired.py::test_expired_token_denies PASSED            [ 86%]
tests/test_runtime_wired.py::test_base_mode_unchanged_without_trust_set PASSED [ 93%]
tests/test_runtime_wired.py::test_require_governance_without_trust_refuses_startup PASSED [100%]
======================== 15 passed, 1 warning in 0.49s =========================

===== C. Runtime version drift-guard =====
DRIFT GUARD OK: runtime version is canonical = 1.11.0
  runtime entrypoints derive from VERSION: main.py, gateway/app.py, interceptors/egress_proxy.py
  (frozen/historical v1.10.1, schema, doctrine, and README strings are intentionally NOT inspected)
```

The full suite (`pytest tests/`) reports **385 passed** on the same branch.
