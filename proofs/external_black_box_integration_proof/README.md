# External Black-Box Integration Proof (PR #114, hardened by PR #115)

> **PR #115 hardening note:** the original PR #114 harness could return
> `result: "COMPLETED"` / exit 0 even if one of the proof's required
> conditions had silently failed. PR #115 made both the consumer and the
> orchestrator fail-closed: the consumer now evaluates all 14 required
> conditions explicitly (`proof_checks`/`failed_checks`/`result:
> "PROVEN"|"NOT PROVEN"`, exit 0 only on `"PROVEN"`), and the orchestrator
> additionally requires the consumer's own verdict, `execute_status ==
> "EXECUTED"`, and a verified, exactly-one-match independent GitHub
> read-back before reporting `overall_verdict: "PROVEN"` (exit 0) —
> otherwise `"NOT PROVEN"` (non-zero), with explicit
> `overall_failure_reasons`. See `tests/test_external_black_box_proof_harness_verdict.py`
> for the tests proving this fails closed on each falsified condition.
> PR #115 also corrected overclaimed "byte-identical"/"exact bytes"
> wording (see "What this proves / does not prove" below) and removed
> leftover "Astra" wording from `mcc_side/run_server.py`'s docstring.
> This did not change PR #114's own recorded historical evidence, which
> remains valid as-is.

Proves that a genuinely external consumer — isolated from MCC-Core
internals, running outside this repository, with no MCC imports, signing
keys, or actuator references — can integrate with PR #113's External
Pilot Integration Pack strictly through its documented public HTTP
boundary (`POST /v1/proposals` then `POST /v1/operations/{id}/execute`)
and cause a real governed external side effect (a real GitHub issue in
`mcc-prior-art/mcc-phase2-sandbox`), using a genuine live call to a real
OpenAI model.

**DO NOT MERGE.** No changes to `src/mcc_core/`, Gate semantics, decision
token semantics, policy evaluation, audit-before-actuation, durable
execution admission, or tenant isolation. This PR only adds a
reproducible proof harness under `proofs/`, one new test file, and no
changes to any existing MCC-Core, gateway, or `examples/external_pilot`
code.

## Important scope correction — read this first

An earlier round of this same investigation set out to prove this using
a model referred to as **"GPT-6 Astra."** That claim could not be
independently verified against any reachable source in this environment:

* This repository's own prior corrected record
  (`docs/EXTERNAL_PILOT_INTEGRATION.md`, and
  `mcc-prior-art/mcc-phase2-sandbox` issue #5) already documents that an
  earlier "GPT-6 Astra" claim in this project was a provenance mistake —
  the real model used was `gpt-4o-mini` behind an internal
  `OpenAIAstraProvider` abstraction, and "GPT-6 Astra" is only this
  repository's own internal reference-abstraction label.
* Attempts to independently verify a *new* "GPT-6 Astra" claim against
  external sources all failed: `openai.com`, `developers.openai.com`,
  `docs.aws.amazon.com`, and `openrouter.ai` are all blocked by this
  environment's own network egress proxy (`EGRESS_BLOCKED`); two cited
  Reuters URLs were unreachable, and one of them — on inspection — was
  about a different, unrelated model ("Mythos-5"), not Astra.
* The only channel that ever affirmed a model literally named
  `gpt-6-astra` was `https://api.openai.com/...` reached through this
  session's own sandboxed network proxy — the same kind of channel that
  produced the earlier, already-corrected false claim in issue #5. That
  is not independent verification, and it is not treated as one here.

**Conclusion for the record:** the "GPT-6 Astra" claim is **NOT PROVEN**
in this environment. This PR does not build a proof around it, does not
create any external artifact asserting it, and does not alter issue #5's
existing correction.

**What this PR actually proves instead:** the exact same external
black-box integration boundary — external, isolated consumer; live,
non-mocked OpenAI model call; public-HTTP-only submission; real MCC
authority evaluation; real GitHub side effect; independent read-back —
run honestly against a model that *is* directly, repeatedly, and
consistently verifiable from this environment: **`gpt-4o-mini`**, the
same model issue #5's own correction already identifies as the real
model behind this project's prior live proofs. See
`LIVE_PROOF_REPORT.md` for the full run record.

## Layout

```
proofs/external_black_box_integration_proof/
├── README.md                        (this file)
├── LIVE_PROOF_REPORT.md             (A-N report, per-run evidence)
├── mcc_side/
│   └── run_server.py                (real governed HTTP server; MCC-side, privileged)
├── run_black_box_proof.py           (orchestrator: spawns server + consumer subprocesses)
├── external_consumer_snapshot/
│   └── consumer.py                  (committed copy of the external consumer, for guard tests)
└── sanitized_live_run.json          (evidence from the actual live run; no secrets)
```

The external consumer's real, running copy lives entirely OUTSIDE this
repository — at `/tmp/mcc-live-external-consumer/` during the live run —
as its own standalone git repository with its own `README.md` describing
its isolation claims. `external_consumer_snapshot/consumer.py` is a
byte-for-byte copy of that file, committed here only so the static
architecture guard tests
(`tests/test_external_black_box_proof_architecture_guards.py`) can scan
it without reaching outside the repository checkout.

## How the proof runs

```
run_black_box_proof.py (orchestrator, inside mcc-layer, privileged)
   │
   ├── spawns mcc_side/run_server.py as a subprocess
   │     -- real governed HTTP server, reusing PR #111-113's
   │        build_external_pilot_app unchanged, a real GitHub actuator,
   │        real Redis-backed durable registries
   │     -- prints ONE line of JSON connection info (base_url, a fresh
   │        single-use API key, action, resource) to stdout, then blocks
   │
   ├── spawns /tmp/mcc-live-external-consumer/consumer.py as a SEPARATE
   │   subprocess, using a CLEAN, ISOLATED virtualenv interpreter
   │   (/tmp/mcc-live-external-consumer/.venv) with no mcc-layer path on
   │   sys.path and no mcc-layer editable install -- see "Isolation
   │   caveat" below for why this matters
   │     -- cwd = the consumer's own directory, never mcc-layer
   │     -- connection info passed as plain CLI arguments, exactly as a
   │        real integrator receives credentials out-of-band
   │
   │   consumer.py then, entirely on its own:
   │     1. attempts (and records failure of) importing mcc_core /
   │        gateway.proposal_execution_service / mcc_proposal
   │     2. makes a REAL live call to OpenAI's Chat Completions API
   │     3. hash-binds the captured proposal to what it submits
   │     4. POSTs to MCC's public /v1/proposals and
   │        /v1/operations/{id}/execute endpoints only
   │     5. runs the 4 negative controls (replay, invalid auth,
   │        unauthorized action, malformed input)
   │     6. prints one line of JSON evidence
   │
   └── after the consumer exits, performs an INDEPENDENT GitHub
       read-back via a THIRD, separate code path (plain urllib, a
       repo-scoped GitHub REST call, no MCC code, no consumer code, no
       actuator code) -- further independently re-confirmed in this PR's
       own investigation via the session's separate GitHub MCP tool
       (see LIVE_PROOF_REPORT.md)
```

## Isolation caveat (found and fixed during this proof)

The first live run flagged `mcc_layer_path_in_sys_path: true` in the
consumer's own isolation self-check — not because the consumer imported
anything wrong, but because this container's global Python
`site-packages` carries an **unrelated, pre-existing editable install of
this repository's own `mcc_client` SDK** (`sdk/python/src`), installed
during earlier, unrelated SDK development work in this same container.
That install placed an mcc-layer path on `sys.path` for *any* Python
process on the machine, regardless of `PYTHONPATH` or cwd — which would
have silently contaminated the externality proof.

Fixed by running the consumer under a **dedicated, freshly-created
virtualenv** (`/tmp/mcc-live-external-consumer/.venv`, containing only
`httpx`) rather than the ambient interpreter. Confirmed clean:
`sys.path` in that venv contains no mcc-layer reference of any kind. The
second (and reported) live run shows `mcc_layer_path_in_sys_path: false`.
This is recorded here rather than silently fixed, because it is exactly
the kind of gap Phase 1's own externality requirement exists to catch.

## What this proves / does not prove

**PROVEN** (see `LIVE_PROOF_REPORT.md` for the full run):

* A genuinely external, dependency-isolated process (separate cwd,
  separate git repo, separate clean virtualenv, no mcc-layer import
  possible) can integrate with PR #113's pack using only its documented
  public HTTP contract.
* A real, live, non-mocked call to `gpt-4o-mini` materially produced the
  submitted proposal content. A canonical SHA-256 hash over the
  proposal's `action`/`resource`/`payload` fields, computed at capture
  time and re-verified immediately before submission, confirms those
  fields were unchanged between the two points (canonical/semantic
  equality — this is not a claim of literal HTTP wire-level byte
  identity, which is not independently captured or asserted here).
* MCC's existing, unmodified authority path (tenant resolution → stored
  proposal → authority evaluation → signed decision →
  `EnforcementCoordinator` → durable admission → audit-before-actuation)
  made the real decision — the consumer never touched any of those
  components directly.
* A real GitHub issue was created in `mcc-prior-art/mcc-phase2-sandbox`
  as the governed side effect, independently confirmed via two separate
  read-back paths (a plain urllib script in the orchestrator, and this
  investigation's own GitHub MCP tool call) to contain the exact,
  model-generated, hash-bound proof identifier.
* Replay produced no second side effect (`BLOCKED`); invalid
  authentication was rejected (`401`) before any MCC processing;
  policy-unauthorized action was `DENIED` after authentication but before
  execution; malformed input was rejected (`422`) at the schema layer.
  All four with zero GitHub side effects.

**NOT PROVEN** (see "Important scope correction" above): that a model
called "GPT-6 Astra" exists and was used. This PR does not claim it.

**NOT CLAIMED BY THIS PR**: independent third-party adoption (this proof
was still run by the same party that built the pack), production
deployment, any regulatory/formal certification.
