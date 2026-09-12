# Live Proof Report — External Black-Box Integration Proof (PR #114)

**DO NOT MERGE.**

## A. Baseline

Starting `main` SHA: `731ab5942994963cfb47d2fad107ba3709e94496` (PR #113's
merge commit). Branch: `feat/live-astra-external-black-box-proof`.

## B. Files changed

| File | Purpose |
|---|---|
| `proofs/external_black_box_integration_proof/mcc_side/run_server.py` | Real governed HTTP server subprocess. Reuses `build_external_pilot_app` (PR #113), a real GitHub actuator (PR #108/#110/#112, unchanged), and real Redis-backed registries. New file, no existing code modified. |
| `proofs/external_black_box_integration_proof/run_black_box_proof.py` | Orchestrator: spawns the server subprocess, spawns the external consumer as a separate subprocess with an isolated venv/cwd/env, performs an independent GitHub read-back over a third code path. New file. |
| `proofs/external_black_box_integration_proof/external_consumer_snapshot/consumer.py` | Committed byte-for-byte copy of the external consumer (real location: outside this repository, `/tmp/mcc-live-external-consumer/consumer.py`), so the static architecture guard tests can scan it without reaching outside the repo checkout. New file. |
| `proofs/external_black_box_integration_proof/README.md` | Proof layout, scope correction record, isolation-caveat writeup. New file. |
| `proofs/external_black_box_integration_proof/sanitized_live_run.json` | Machine-readable evidence from the actual live run. No secrets (all keys/tokens redacted by the scripts before ever being written). New file. |
| `tests/test_external_black_box_proof_architecture_guards.py` | 16 offline tests: static AST guards (forbidden imports/names/calls) with non-vacuity probes per category, plus a dynamic import-and-run check of the consumer's own isolation self-check function. New file. |

No existing file under `src/mcc_core/`, `gateway/`, `mcc_proposal/`,
`examples/external_pilot/`, `examples/phase2_live_sandbox/`, or
`examples/gpt6_astra_reference/` was modified.

## C. Externality proof

The external consumer (`/tmp/mcc-live-external-consumer/`, not part of
this repository) is isolated by:

* **Separate filesystem location and git repository.** `git init`'d
  independently, own `README.md`/`requirements.txt` (only `httpx`), no
  relationship to the mcc-layer checkout.
* **Separate, freshly-created Python virtualenv**
  (`/tmp/mcc-live-external-consumer/.venv`), containing only `httpx`.
  This was necessary because this container's *ambient* Python
  interpreter carries an unrelated, pre-existing editable install of
  this repo's own `mcc_client` SDK from earlier SDK development work
  (`/usr/local/lib/python3.11/dist-packages/__editable__.mcc_client-0.1.0.pth`
  → `sdk/python/src`), which would have placed an mcc-layer path on
  `sys.path` for any process on the machine. Confirmed the isolated
  venv's `sys.path` contains no mcc-layer reference:
  ```
  ['', '/usr/lib/python311.zip', '/usr/lib/python3.11',
   '/usr/lib/python3.11/lib-dynload',
   '/tmp/mcc-live-external-consumer/.venv/lib/python3.11/site-packages']
  ```
* **Runtime self-check, actually executed** (not assumed): the
  consumer's `check_mcc_internals_unavailable()` attempts
  `__import__("mcc_core")`, `__import__("gateway.proposal_execution_service")`,
  and `__import__("mcc_proposal")`, and records each result. From the
  live run's own evidence (`isolation_check` in `sanitized_live_run.json`):
  ```
  "mcc_core": "import failed as expected: ModuleNotFoundError: No module named 'mcc_core'",
  "gateway.proposal_execution_service": "import failed as expected: ModuleNotFoundError: No module named 'gateway'",
  "mcc_proposal": "import failed as expected: ModuleNotFoundError: No module named 'mcc_proposal'",
  "mcc_layer_path_in_sys_path": false,
  "cwd": "/tmp/mcc-live-external-consumer"
  ```
* **Static guard, independent of the runtime check**:
  `tests/test_external_black_box_proof_architecture_guards.py` AST-scans
  the committed snapshot for any import of `mcc_core`, `gateway.*`,
  `mcc_proposal`, `egress_proxy.executor`, direct GitHub write clients
  (`github`/`pygithub`), any MCC signing/Gate/coordinator/authority name,
  or any direct-GitHub-API call token — 16/16 tests pass, including one
  non-vacuity probe per forbidden category proving the guard actually
  catches a planted violation (verified by temporarily reverting each
  guard and confirming the corresponding probe fails — see test run
  output in section L).

## D. Live-model provenance

**Requested model:** `gpt-4o-mini`
**Returned model:** `gpt-4o-mini-2024-07-18` (a normal, expected
dated-snapshot resolution of the alias — not a different model family)
**Response ID:** `chatcmpl-ENLx8WjB18AqWP2Fw6w7eDf4mEHWq`
**OpenAI request ID:** `req_e0f5cb10790e4697a2a77268935b9ee5`
**Created (unix):** `1789234638`
**Usage:** `prompt_tokens: 227, completion_tokens: 96, total_tokens: 323`
**is_live:** `true` — `call_live_model()` performs exactly one
`httpx.post` to `https://api.openai.com/v1/chat/completions`; no fixture,
cache, or fallback branch exists in that function (confirmed by
`test_consumer_has_single_live_model_call_site` and
`test_consumer_raises_rather_than_substitutes_on_model_call_failure`).

**Sandboxed-network-proxy caveat (explicitly retained per instruction):**
all outbound HTTPS in this session — including this OpenAI call — passes
through this environment's own agent network proxy. This is disclosed
because it is material: it means "live" here is relative to what this
sandboxed environment can reach, not an out-of-band, disinterested
network path. This caveat is exactly why the separate "GPT-6 Astra"
investigation in this same PR could not be resolved to PROVEN (see
`README.md`) — the same channel that reports `gpt-4o-mini` responses here
was the only channel that ever affirmed a `gpt-6-astra` model, and that
specific claim was not independently corroborated. `gpt-4o-mini`, by
contrast, is not a novel or contested claim — it is the same model this
repository's own prior, already-merged live proofs (PR #112, and issue
#5's own correction) already used and recorded, and this run reproduces
that same, previously-accepted evidentiary basis.

## E. Proposal (model-generated, secrets removed)

```json
{
  "action": "create_github_issue",
  "resource": "mcc-prior-art/mcc-phase2-sandbox",
  "payload": {
    "title": "Integration Proof Issue",
    "body": "This issue was created by a real, live external integration proof. Please reference the following string for locating this issue later: mcc-blackbox-757067efbdb4492498ea16d4d701fe87."
  }
}
```

`proof_id` (`mcc-blackbox-757067efbdb4492498ea16d4d701fe87`) was minted by
the consumer *before* the model call and given to the model only as an
instruction to include verbatim — the model chose the title and the rest
of the body content itself. The consumer aborts (never proceeds, never
injects the identifier itself) if the model's own output does not
literally contain it — this run's `proof_id_present_in_model_output:
true` confirms the model complied on its own.

**Hash binding:** `captured_proposal_sha256` (computed immediately after
parsing the model's JSON output) and `submitted_proposal_sha256`
(recomputed immediately before the HTTP POST) are both
`144922a69369df1632121de9385c9976a2c34cd8306e09f57fcee72e48624fb4` —
`proposal_hash_binding_verified: true`. The bytes MCC received are
exactly the bytes the model produced.

## F. Public API traversal

* `POST /v1/proposals` → `200`, `{"accepted": true, "status": "PROPOSED", "proposal_binding": "sha256:e0fe644f..."}`
* `POST /v1/operations/{id}/execute` → `200`, `{"status": "EXECUTED", "decision": "ALLOW", "audit_ref": "1ac88dd9..."}`

Both via `X-Api-Key` header authentication only — no signed token, no
authority claim, and no MCC-internal object ever passed by or to the
consumer. These are the exact two endpoints documented in
`docs/EXTERNAL_PILOT_INTEGRATION.md`.

## G. Authority path

The consumer's own request never contains, references, or constructs a
signing key, decision token, or authority claim (confirmed by the
architecture guard's `FORBIDDEN_SIGNING_NAMES` check and its non-vacuity
probe). The `EXECUTED` decision and its `audit_ref` came from the
server subprocess's real, unmodified stack: `build_external_pilot_app` →
`gateway.proposal_execution_service.ProposalExecutionService` → the
existing tenant resolution → authority evaluation → signed decision →
`EnforcementCoordinator` → durable admission → audit-before-actuation
path (PR #111/#112/#113, unchanged by this PR). The consumer supplied
only `action`/`resource`/`payload`/`logical_operation_id`/`actor` over
HTTP — nothing that could itself constitute or bypass an authority
decision.

## H. Real side effect

GitHub issue **#7** in `mcc-prior-art/mcc-phase2-sandbox`:
<https://github.com/mcc-prior-art/mcc-phase2-sandbox/issues/7>

Title: "Integration Proof Issue". Body contains the exact proof
identifier and matches the hash-bound submitted payload.

## I. Independent read-back

Two separate, independent confirmations, neither of which is the
actuator's own return value:

1. **Orchestrator's own read-back** (`run_black_box_proof.py`, plain
   `urllib.request`, no MCC code, no consumer code, no actuator code) —
   `GET /repos/mcc-prior-art/mcc-phase2-sandbox/issues` (repo-scoped;
   this environment's GitHub token is a Claude-Code-issued,
   repository-scoped credential and returns `403` on the global
   `/search/issues` endpoint — documented in the code), filtered
   client-side for the exact proof identifier. Result (retry 3/5, GitHub
   read-after-write lag): `verified: true, total_count: 1, issue #7`.
2. **This investigation's separate GitHub MCP tool call**
   (`mcp__github__issue_read`, a third, independently-implemented code
   path — different HTTP client, different auth mechanism — from both
   the actuator and the orchestrator's own script):
   ```
   number: 7, title: "Integration Proof Issue",
   body contains: "mcc-blackbox-757067efbdb4492498ea16d4d701fe87"
   state: open, created_at: 2026-09-12T17:37:20Z
   ```

Exactly one matching issue found by both independent paths.

## J. Replay / idempotency

Second `POST /v1/operations/{id}/execute` on the same
`logical_operation_id` → `200`, `{"status": "BLOCKED", "reason":
"operation already executed", "audit_ref": null}`. No second GitHub
issue was created (confirmed by the independent read-back's
`total_count: 1`).

## K. Negative controls

| Control | Result | Side effect |
|---|---|---|
| A. Replay | `BLOCKED` | None (see J) |
| B. Invalid API key | submit `401`, execute `401` | None — rejected before any MCC processing |
| C. Unauthorized action (valid key, no authority for `unauthorized_black_box_action`) | submit `200`/`PROPOSED`, execute `200`/`DENIED` | None |
| D. Malformed proposal (missing `action`) | submit `422`, `{"detail":[{"type":"missing","loc":["body","action"],"msg":"Field required"}]}` | None |
| E. Structural: no signing/authority-token/Gate/coordinator access | 6/6 dedicated guard tests pass, each with a non-vacuity probe | — |
| F. Structural: no direct GitHub write path, no actuator reference | 4/4 dedicated guard tests pass (forbidden import + forbidden `api.github.com` call token + non-vacuity probes) | — |

## L. Tests

Targeted (this PR's own new test file):
```
tests/test_external_black_box_proof_architecture_guards.py: 16 passed
```

PR #113's own external pilot tests and PR #111/#112 architecture guards
(unmodified by this PR — re-run to confirm no regression):
```
tests/test_external_pilot_*.py, tests/test_proposal_execution_api*.py,
tests/test_universal_execution_proof_architecture_guards.py: see full-suite run below
```

Full suite and assurance suite results are recorded in the PR
description at push time (section L is completed there with the actual
`pytest`/assurance counts from that run, compared against the PR
#113-round baseline). No `src/mcc_core/` files changed, so mutation/TLA+
were not re-run, consistent with this session's established convention
(mutation/TLA+ target `src/mcc_core/` invariants specifically; this PR
touches none of those files).

## M. Architecture delta

**NONE.** No file under `src/mcc_core/`, `gateway/proposal_execution_*`,
`mcc_proposal/`, or any existing actuator/authority module was modified.
This PR adds only: one new orchestration script, one new server-wiring
script (reusing existing, unmodified components), one committed consumer
snapshot, one new test file, and evidence/docs. `git diff --stat` against
`origin/main` for this PR touches no path under `src/`.

## N. Final verdict

**EXTERNAL BLACK-BOX INTEGRATION PROOF — PROVEN**

1. Can an external process integrate without importing MCC internals? **YES**
2. Did a genuine live OpenAI API response materially produce the proposal? **YES** (model: `gpt-4o-mini`)
3. Did the proposal cross only the documented MCC public HTTP boundary? **YES**
4. Did MCC-controlled execution create a real external GitHub side effect? **YES**
5. Was that side effect independently verified with no duplicate on replay? **YES**

**GPT-6 ASTRA-SPECIFIC PROVENANCE — NOT PROVEN IN THIS ENVIRONMENT.**
See `README.md`, "Important scope correction," for the full record of
that separate, unsuccessful verification attempt. No claim about a model
named "GPT-6 Astra" is made anywhere in this evidence package, and
`mcc-prior-art/mcc-phase2-sandbox` issue #5's existing correction on that
same point was not altered.
