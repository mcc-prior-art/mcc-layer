# External Pilot Integration Pack

PR #113. Makes the already-proven PR #111 (Pilot Execution API) + PR #112
(agent/framework/actuator-neutral real execution proof) governed
execution boundary consumable by an external engineering team with
minimal integration friction. Introduces **no** new authority, signing,
Gate, coordinator, idempotency, reconciliation, or actuator-dispatch
architecture — every decision is made by the existing, unmodified
`gateway.proposal_execution_service.ProposalExecutionService`, reached
only through the existing, unmodified public HTTP routes.

> Intelligence can propose. Authority must verify. Execution must enforce.
>
> PROPOSAL != PERMISSION. IDENTITY != AUTHORITY. INTELLIGENCE != AUTHORITY.
>
> No verified authority → no execution.

```
YOUR AGENT / MODEL / WORKFLOW
   |
   | generic proposal over HTTP        POST /v1/proposals
   v
MCC PILOT API
   |
   v
VERIFIABLE EXECUTION AUTHORITY         trusted server-side tenant resolution
   |                                   -> tenant-owned stored proposal
   |                                   -> trusted authority evaluation
   |                                   -> signed authority
   v
CONTROLLED EXECUTION BOUNDARY          POST /v1/operations/{id}/execute
   |                                   -> EnforcementCoordinator
   |                                   -> tenant-scoped durable admission
   |                                   -> audit-before-actuation
   v
YOUR ACTUATOR                          ResourceBoundUpstream.execute(...)
```

## 1. What this pack is not

Not another architecture redesign. Not another Astra-specific proof. Not
a new execution path. It is packaging, integration ergonomics,
documentation, reference adapters, tests, and reproducibility over the
EXISTING boundary — model-neutral, framework-neutral, actuator-neutral.

## 2. How to connect your agent

**Replace exactly one file:** `examples/external_pilot/client/example_producer.py`.

Any producer — an LLM agent on any framework, a rules engine, a
human-operated tool, a deterministic pipeline — can use MCC as long as it
can eventually emit this generic shape and submit it via
`examples/external_pilot/client/mcc_pilot_client.py`'s
`MCCPilotClient.submit_proposal`:

```json
{
  "logical_operation_id": "your-own-idempotent-operation-id",
  "actor": "a-plain-label",
  "action": "what-capability-is-being-asked-for",
  "resource": "what-it-targets-or-null",
  "payload": { "...": "arbitrary, action-specific content" }
}
```

| Field | Trusted or untrusted? | What MCC does with it |
|---|---|---|
| `X-Api-Key` header | Trusted — resolved server-side to a tenant_id | The ONE thing that decides who you are. Never taken from the body. |
| `actor` | Untrusted, informational only | Stored and returned on status reads; **never read by authority evaluation** (`ProposalExecutionService.authorize_and_execute` calls `self._authority.evaluate(identity=tenant_id, ...)` — `record.actor` does not appear in that method at all). |
| `action`, `resource`, `payload` | Untrusted proposal content | Authority evaluates `(tenant_id, action, payload)`; if allowed, the proposal's own **stored** content — never anything re-supplied later — becomes what gets signed and executed. |

**What the integrator must never bypass:** the reference client
(`MCCPilotClient`) has zero import of `mcc_core`, zero import of
`gateway.proposal_execution_service`, no signing-key material, and no
actuator reference anywhere — verified statically by
`tests/test_external_pilot_architecture_guards.py`. It depends only on
`httpx` (a plain HTTP client, not an agent framework or model-provider
SDK) — no OpenAI SDK, no Anthropic SDK, no LangGraph, no CrewAI, no
AutoGen, no VoltAgent, no MCP, no GitHub-specific vocabulary, required or
otherwise.

**Expected failure behavior:** a missing/invalid API key → `401`, zero
side effects. A well-formed but unauthorized proposal → `DENIED`, zero
side effects. Malformed input → `422`/`REJECTED`, zero side effects.
Your producer should treat every non-`EXECUTED` status as "did not
happen" — including `BLOCKED`, `EXECUTION_FAILED`, `RESOURCE_MISMATCH`,
and `ESCALATED`.

### GPT-6 Astra / OpenAI status (provenance note)

This pack is **not** Astra-specific. The repository's existing
`examples/gpt6_astra_reference` material is referenced only as ONE
previous/reference upstream example, unchanged. Per PR #112's own
corrected record: the real, live model PR #112 actually ran against was
**`gpt-4o-mini`** — a genuine OpenAI model. "GPT-6 Astra" is this
repository's own internal reference-abstraction label
(`examples/gpt6_astra_reference`), not the identity of any real model;
this document does not, and must not, restate the earlier
misattribution PR #112 corrected.

## 3. How to connect your actuator

**THE AGENT NEVER GETS THE ACTUATOR DIRECTLY.** The actuator remains
server-side, behind MCC-controlled execution, reached only through the
existing `gateway.proposal_execution_service.ResourceBoundUpstream`
contract — the ONLY actuator boundary `ProposalExecutionService`
accepts. See `examples/external_pilot/actuator/demo_actuator.py` for the
smallest safe implementation template.

**Required interface:**

```python
class ResourceBoundUpstream:
    resource: Optional[str]          # fixed, trusted, set once at construction
    async def execute(self, *, resource, action, payload) -> Any: ...
```

* `resource` — your actuator's OWN fixed, trusted destination. Set once,
  by the deployment operator, at construction time. **Never** derived
  from proposal content, request payload, or any other untrusted input.
* `dispatch(*, resource, action, payload)` — the ONE place you write your
  real system call (an internal API, a queue publish, a database write,
  a robot command). `ResourceBoundUpstream.execute` independently
  re-verifies `resource` against your fixed configuration immediately
  before calling `dispatch` — you never need to re-implement that check.

**What MCC verifies before your actuator is ever called:** authenticated
caller → trusted tenant resolution → tenant-owned stored proposal →
trusted authority evaluation → signed authority →
`EnforcementCoordinator` → tenant-scoped durable admission →
audit-before-actuation. Your actuator's `dispatch` is the LAST step, not
a shortcut around any of the above.

**Success / failure / UNKNOWN contract** (`gateway.proposal_execution_service.ProposalExecStatus`):

| Your `dispatch`... | MCC reports | Durable state |
|---|---|---|
| Returns normally | `EXECUTED` | Resolved |
| Never called (denied/blocked before dispatch) | `DENIED` / `BLOCKED` / `RESOURCE_MISMATCH` / `REJECTED` | No admission reserved, or safely released |
| Raises | `EXECUTION_FAILED` ("outcome indeterminate") | `UNKNOWN` — **ownership retained**, never silently released, never auto-retried |

**Reconciliation expectations:** if your `dispatch` raises, MCC does
**not** guess whether the side effect actually happened. The operation's
durable state is left `UNKNOWN`, and a replayed `/execute` call is
`BLOCKED`, never silently re-dispatched (see scenario G below). Resolving
`UNKNOWN` from independently-verified evidence is the EXISTING,
unmodified `gateway.proposal_execution_service.reconcile_proposal_operation`
function — an **operator-side** capability, deliberately **not** exposed
over HTTP (PR #111 removed that route to eliminate a configuration-level
split-brain risk; PR #112 did not reintroduce it; this pack does not
either — see `examples/external_pilot/scenarios.py::scenario_g_unknown_reconciliation`
for a full, reproducible demonstration calling that function directly).
An external agent never calls it; a deployment operator's own
reconciliation tooling does, over an independent evidence source it
trusts.

**Idempotency expectations:** `logical_operation_id` is the durable
identity a retry/replay is checked against — your actuator's `dispatch`
should be safe to call once per genuinely-new operation; MCC's own
`EnforcementCoordinator`/idempotency registry ensures your `dispatch` is
never invoked twice for the same `(tenant_id, logical_operation_id)`
once it has resolved.

## 4. Fresh-clone quick start

```bash
pip install -r requirements.txt -r requirements-dev.txt
PYTHONPATH=src:.:sdk/python/src python3 examples/external_pilot/run_external_pilot_self_check.py
```

Zero configuration, zero external services, zero network calls, zero
secrets. See `examples/external_pilot/README.md` for the full quick
start and `examples/external_pilot/.env.example` for what a REAL
deployment (your own credentials, your own authority grants, optionally
real Redis-backed durable state) configures — all fail-closed: missing
mandatory configuration refuses startup (`ExternalPilotConfigError`),
never silently falls back to demo authority.

## 5. Required pilot scenarios

All eight, reproducible over the real HTTP boundary, in
`examples/external_pilot/scenarios.py` (shared by
`tests/test_external_pilot_scenarios.py` and the self-check script):

| # | Scenario | What it proves |
|---|---|---|
| A | Happy path | generic producer → proposal accepted → authority → signed → executed exactly once → evidence returned |
| B | Policy denial | an unauthorized proposal produces zero actuator side effects |
| C | Replay | repeated execution of the same tenant + logical operation causes no second side effect |
| D | Tenant isolation | one tenant cannot read or execute another tenant's proposal (tenant-safe `NOT_FOUND`) |
| E | Resource binding | an actuator bound to resource A refuses a proposal authorized for resource B |
| F | Payload/action binding | a caller attempting to smuggle a different action/resource/payload/authority field onto the execute request has it silently ignored — the dispatched content matches only what was originally proposed |
| G | UNKNOWN/reconciliation | an ambiguous outcome is never auto-retried to a false `EXECUTED`; the existing `reconcile_proposal_operation` resolves it from independently-verified evidence, without exposing a new HTTP route |
| H | Unauthenticated | a missing/invalid API key fails closed (`401`) with zero actuator side effects |

## 6. Evidence output

Both `tests/test_external_pilot_scenarios.py` and
`run_external_pilot_self_check.py` produce, per scenario: tenant
identifier, `logical_operation_id`, action, resource, authority decision,
execution status, `audit_ref`, reconciliation outcome (scenario G), and
actuator dispatch count. The self-check additionally prints a
machine-readable JSON summary. Neither ever prints a private key, bearer
token, API secret, or raw sensitive environment value.

## 7. What this proves / does not prove

**PROVEN** (by this repository's own internal tests, and by PR #112's
real, live evidence, unchanged and not restated here):

* internal repository tests — the full existing suite, plus this pack's
  own scenario and architecture-guard tests;
* PR #112's upstream/framework/actuator replaceability proof;
* PR #112's real, live OpenAI-model (`gpt-4o-mini`) → MCC → real GitHub
  actuator proof (see `docs/UNIVERSAL_EXECUTION_PROOF.md`).

**READY FOR:**

* external third-party integration attempts against this pack's
  documented client/actuator contracts.

**NOT YET PROVEN BY THIS PACK ALONE:**

* independent third-party adoption — no external party has run this pack yet;
* production deployment at a customer;
* payment-network certification;
* robotics certification;
* enterprise production SLA;
* any formal/regulatory external certification.

This pack is not called an "external pilot success" until an actual
independent external party has run it.

## 8. Architecture guards

`tests/test_external_pilot_architecture_guards.py` statically proves the
bring-your-own-agent client (`client/mcc_pilot_client.py`,
`client/example_producer.py`) never imports `mcc_core` authority/Gate/
coordinator/signing material, never imports
`ProposalExecutionService`/`EnforcementCoordinator`/`ResourceBoundUpstream`,
never holds a signing key, and never invokes an actuator directly — with
non-vacuity probes proving the guard actually catches each of those
plantable bypasses. `gateway/proposal_execution_service.py` /
`proposal_execution_api.py` / `proposal_execution_stack.py`'s own
provider/framework/domain neutrality is **already** guarded by
`tests/test_proposal_execution_api_architecture_guards.py` (PR #111) and
`tests/test_universal_execution_proof_architecture_guards.py` (PR #112)
— unmodified by this PR, not duplicated here.

## 9. No reconciliation expansion

There is no `POST /v1/operations/{id}/reconcile` route in this
repository (removed in PR #111, not reintroduced by PR #112 or this PR).
`reconcile_proposal_operation` remains an importable, operator-side
Python function only — scenario G calls it directly, never over HTTP.
