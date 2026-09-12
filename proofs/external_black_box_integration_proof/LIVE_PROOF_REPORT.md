# Live Proof Report — External Black-Box Integration Proof

**DO NOT MERGE.**

This report supersedes PR #114's original `LIVE_PROOF_REPORT.md` after
PR #115's hardening (fail-closed consumer/orchestrator verdict logic,
corrected canonical-hash wording, removed leftover "Astra" title). This
is a fresh live re-run under the hardened harness — a new `proof_id` and
a new real GitHub issue, per PR #115's explicit requirement not to reuse
PR #114's issue #7.

## A. Baseline

Starting `main` SHA: `54f5b084928281a7d34fda3ae5ab66d0e5a3aa14` (PR #114's
merge commit). Branch: `fix/external-black-box-proof-harness-hardening`.

## B. Files changed

| File | Purpose |
|---|---|
| `proofs/external_black_box_integration_proof/mcc_side/run_server.py` | Removed leftover "Live Astra Black-Box..." title; now model-neutral (Finding 4) |
| `proofs/external_black_box_integration_proof/run_black_box_proof.py` | Added `_compute_overall_verdict`: fail-closed `overall_verdict`/`overall_failure_reasons`, requiring consumer PROVEN + EXECUTED + verified single-match read-back (Finding 2) |
| `proofs/external_black_box_integration_proof/external_consumer_snapshot/consumer.py` | Re-synced snapshot of the hardened external consumer (see below) |
| `proofs/external_black_box_integration_proof/README.md` | PR #115 hardening note; corrected byte-identity wording (Finding 3) |
| `proofs/external_black_box_integration_proof/LIVE_PROOF_REPORT.md` | This file — regenerated for the new run |
| `proofs/external_black_box_integration_proof/sanitized_live_run.json` | Regenerated evidence, no secrets |
| `proofs/external_black_box_integration_proof/sha256_manifest.txt` | Regenerated hashes |
| `tests/test_external_black_box_proof_harness_verdict.py` | New: 22 tests exercising the actual verdict/exit-code decision functions (not string search) for conditions A-L + positive controls |
| `tests/test_external_black_box_proof_architecture_guards.py` | Updated 2 tests whose string-search assertions were stale after Finding 1's refactor; behavior they guard is unchanged and now additionally covered by the new verdict tests |

The real external consumer — outside this repository, at
`/tmp/mcc-live-external-consumer/consumer.py` — was rewritten to add the
fail-closed `REQUIRED_CHECKS`/`_finalize` verdict logic (Finding 1) and
corrected `canonical_hash` wording (Finding 3). No file under
`src/mcc_core/`, `gateway/proposal_execution_*`, `mcc_proposal/`, or any
existing actuator/authority module was touched.

## C. Externality proof

Unchanged from PR #114: separate filesystem location, own git repo, own
isolated virtualenv (`/tmp/mcc-live-external-consumer/.venv`, only
`httpx`). This run's isolation check:
```
"mcc_core": "import failed as expected: ModuleNotFoundError: No module named 'mcc_core'",
"gateway.proposal_execution_service": "import failed as expected: ModuleNotFoundError: No module named 'gateway'",
"mcc_proposal": "import failed as expected: ModuleNotFoundError: No module named 'mcc_proposal'",
"mcc_layer_path_in_sys_path": false,
"cwd": "/tmp/mcc-live-external-consumer"
```

## D. Live-model provenance

**Requested model:** `gpt-4o-mini` — **Returned:** `gpt-4o-mini-2024-07-18`
**Response ID:** `chatcmpl-ENN9T5ryAffhOtIU2NpVBXbp34aYJ`
**OpenAI request ID:** `req_ee1d1338f6c444d39864b163f2aa25b9`
**Usage:** `prompt_tokens: 231, completion_tokens: 101, total_tokens: 332`
**is_live:** `true`. Same sandboxed-network-proxy caveat as PR #114
applies and is retained here: all outbound HTTPS in this session passes
through this environment's own agent proxy. No claim about "GPT-6 Astra"
is made anywhere in this evidence.

## E. Proposal and corrected hash-binding wording (Finding 3)

```json
{
  "action": "create_github_issue",
  "resource": "mcc-prior-art/mcc-phase2-sandbox",
  "payload": {
    "title": "Integration Proof: External System Trigger",
    "body": "This issue was created by a real, live external integration proof. Please reference the identifier for locating this issue: mcc-blackbox-6c720ad09e004786972e150f8c1b2c2e."
  }
}
```

`proof_id` (`mcc-blackbox-6c720ad09e004786972e150f8c1b2c2e`) was minted
before the model call; the model included it verbatim on its own
(`proof_id_present_in_model_output: true`).

**Corrected wording, per Finding 3:** `captured_proposal_sha256` and
`submitted_proposal_sha256` are both
`42187e55b27ac358e524ef21d21fa2b20367b44b15a7d19e1ba00d71f9a60363` —
`proposal_hash_binding_verified: true`. This is a canonical SHA-256
binding over the proposal's `action`/`resource`/`payload` fields,
computed at capture time and re-verified immediately before submission.
**It establishes that those fields' canonical content was unchanged
between capture and submission — it does not, and this report does not
claim it does, establish literal HTTP wire-level byte identity of the
outbound request.** (PR #114's report used "the bytes MCC received are
exactly the bytes the model produced," which overstated what the
mechanism proves; this report and the underlying code comments/docstrings
have been corrected.)

## F. Public API traversal

`POST /v1/proposals` → `200`, `{"status": "PROPOSED", "proposal_binding": "sha256:1599e23a..."}`
`POST /v1/operations/{id}/execute` → `200`, `{"status": "EXECUTED", "decision": "ALLOW", "audit_ref": "efc65f5e..."}`

## G. Authority path

Unchanged: the existing, unmodified `ProposalExecutionService` →
tenant resolution → authority evaluation → signed decision →
`EnforcementCoordinator` → durable admission → audit-before-actuation
path made the decision. The consumer supplied only
`action`/`resource`/`payload`/`logical_operation_id`/`actor` over HTTP.

## H. Real side effect

GitHub issue **#8** in `mcc-prior-art/mcc-phase2-sandbox`:
<https://github.com/mcc-prior-art/mcc-phase2-sandbox/issues/8>
(a NEW issue, not PR #114's issue #7).

## I. Independent read-back

Two separate paths:
1. Orchestrator's own repo-scoped `urllib` read-back: `verified: true, attempt: 4, total_count: 1, issue #8`.
2. This investigation's separate GitHub MCP tool call (`mcp__github__issue_read`) — same result:
   ```
   number: 8, title: "Integration Proof: External System Trigger",
   body contains: "mcc-blackbox-6c720ad09e004786972e150f8c1b2c2e"
   created_at: 2026-09-12T18:54:09Z
   ```

## J. Replay/idempotency

Second execute → `200`, `{"status": "BLOCKED", "reason": "operation already executed", "audit_ref": null}`. No second GitHub issue for this `proof_id` (read-back `total_count: 1`).

## K. Negative controls

| Control | Result | Side effect |
|---|---|---|
| Replay | `BLOCKED` | None |
| Invalid API key | submit `401`, execute `401` | None |
| Unauthorized action (valid key, no authority) | submit `200`/`PROPOSED`, execute `200`/`DENIED` | None |
| Malformed proposal (missing `action`) | `422` | None |
| No signing/authority/Gate/coordinator access | guard tests pass | — |
| No direct GitHub write path / actuator reference | guard tests pass | — |

## L. Fail-closed harness verdict logic (PR #115, Findings 1 & 2)

**Consumer** (`consumer.py::_finalize`, called from every return path in
`main()`): evaluates all 14 `REQUIRED_CHECKS`, seeded all-False and only
ever flipped to True at the exact point a condition is positively
confirmed. This run:
```json
"proof_checks": {
  "live_model_call_succeeded": true, "proof_id_in_model_output": true,
  "proposal_hash_binding_verified": true, "submit_http_200": true,
  "submit_status_proposed": true, "execute_http_200": true,
  "execute_status_executed": true, "replay_http_200": true,
  "replay_status_blocked": true, "invalid_auth_submit_401": true,
  "invalid_auth_execute_401": true, "unauthorized_submit_accepted": true,
  "unauthorized_execute_denied": true, "malformed_submit_422": true
},
"failed_checks": [], "result": "PROVEN"
```

**Orchestrator** (`run_black_box_proof.py::_compute_overall_verdict`):
requires consumer returncode 0, consumer `result == "PROVEN"`,
`execute_status == "EXECUTED"`, `independent_readback.verified == true`,
and `independent_readback.total_count == 1`. This run:
```json
"overall_verdict": "PROVEN", "overall_failure_reasons": []
```

**Proof that failure is actually fail-closed, not just claimed:**
`tests/test_external_black_box_proof_harness_verdict.py` calls these two
functions directly (not string search) with each of the 14 consumer
conditions and 4 orchestrator conditions individually falsified —
22/22 tests pass, each asserting non-zero exit / `"NOT PROVEN"` /
the specific failed check named. See section N of the PR report for
counts.

## M. Architecture delta

**NONE.** `git diff 54f5b08..HEAD --stat -- src/ gateway/proposal_execution_service.py gateway/proposal_execution_stack.py mcc_proposal/` is empty. Only `proofs/` and one new/one updated test file changed.

## N. Final verdict

**EXTERNAL BLACK-BOX PROOF HARNESS — FAIL-CLOSED AND REPRODUCIBLE**

The underlying integration proof itself (per PR #114's own five
questions, re-confirmed on this new run):
1. External process integrates without importing MCC internals? **YES**
2. Genuine live OpenAI response materially produced the proposal? **YES** (`gpt-4o-mini`)
3. Proposal crossed only the documented public HTTP boundary? **YES**
4. MCC-controlled execution created a real external GitHub side effect? **YES** (issue #8)
5. Side effect independently verified with no duplicate on replay? **YES**

"GPT-6 Astra"-specific provenance remains **NOT PROVEN** in this
environment, unchanged from PR #114's own record; `mcc-phase2-sandbox`
issue #5's existing correction was not altered.

## Note on an unrelated extra live run

During validation of this hardening, one additional full live run was
triggered by mistake (re-running the orchestrator to double-check its
exit code, when the already-captured evidence already answered the
question) — it produced a second, real, harmless GitHub issue,
`mcc-prior-art/mcc-phase2-sandbox` **#9** (`proof_id
mcc-blackbox-c6b23d79555242a0a0101aa051d357d6`), also `overall_verdict:
PROVEN`, written to a scratch path (`/tmp/verify_exit.json`, not part of
this repository) rather than this evidence package. Recorded here rather
than silently omitted, consistent with this proof's own transparency
requirements; it does not affect the evidence above, which is drawn
entirely from the intended run (issue #8).
