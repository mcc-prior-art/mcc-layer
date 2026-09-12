# Universal Execution Authority — Agent- and Actuator-Neutral Real Proof

PR #112. Proves that the governed execution path introduced by PR #106
(the Phase 2 bridge) and exposed over HTTP by PR #111 (the Pilot
Execution API) is independent of (1) the upstream intelligence/agent/
framework that produced a proposal and (2) the downstream execution
domain/actuator that carries it out.

> Intelligence can propose. Authority must verify. Execution must enforce.
>
> INTELLIGENCE != AUTHORITY. IDENTITY != AUTHORITY. PROPOSAL != PERMISSION.
>
> No verified authority → no execution.

```
ANY INTELLIGENCE
  -> GENERIC PROPOSAL
  -> MCC VERIFIABLE EXECUTION AUTHORITY
  -> GENERIC CONTROLLED-EXECUTION BOUNDARY
  -> ANY ACTUATOR
```

## 1. What this PR is not

MCC-Core does not compete at the intelligence layer, and it does not
become a domain-specific product. This PR selects GitHub issue creation
as the concrete external side effect only because this repository already
has a safe, real, reviewed actuator for it (PR #108/#110). It is **not**
a GitHub productization PR, an OpenAI/Anthropic/Google/Meta
integration, or an agent-framework integration. No provider SDK, no
agent-framework SDK, and no domain-specific vocabulary (GitHub, AWS, SAP,
payments, robotics, industrial) enters `gateway/proposal_execution_service.py`,
`gateway/proposal_execution_api.py`, or `gateway/proposal_execution_stack.py`
— enforced by a static guard, see §6.

## 2. Exact upstream proposal boundary

The proposal boundary (`POST /v1/proposals`, unchanged from PR #106/#111)
accepts `logical_operation_id`, `actor`, `action`, `resource`, `payload`.
`actor` is stored and returned in status reads, but is **never** read by
the authority evaluation — `ProposalExecutionService.authorize_and_execute`
calls `self._authority.evaluate(identity=tenant_id, action=action,
context=payload, ...)`; `record.actor` does not appear in that call at
all (proven structurally in
`tests/test_universal_execution_proof.py::test_upstream_replaceability_structural_proof_actor_never_drives_authority`
by asserting the literal string `record.actor` is absent from
`ProposalExecutionService.authorize_and_execute`'s own source).
`identity` is exclusively the authenticated, server-resolved `tenant_id`
— never a caller-supplied field, never a model/provider identity, never a
confidence score, never a reasoning trace.

Any client capable of POSTing that JSON shape over authenticated HTTP is
a valid upstream — an OpenAI-based agent, an Anthropic-based agent, a
Google-based agent, an AWS/Azure-hosted agent, an open-source or
enterprise-built agent, a deterministic application, a human-operated
client, or a future intelligence system, all use the identical contract.

## 3. Exact MCC authority boundary

Unchanged from PR #106/#111:

```
authenticated caller
  -> trusted server-side tenant resolution   (X-Api-Key -> tenant_id)
  -> tenant-owned stored proposal              (ProposalRegistry.get)
  -> trusted authority evaluation              (AuthorityModel.evaluate)
  -> signed authority                          (DecisionEngine.issue_token)
  -> EnforcementCoordinator
  -> tenant-scoped durable admission            (IdempotencyRegistry)
  -> audit-before-actuation                     (AuditLog)
  -> ResourceBoundUpstream
  -> controlled actuator
```

Authority reasons only over generic execution claims: identity, action,
resource, payload binding, scope, policy, validity, replay, durable
execution identity, audit, execution outcome. It never interprets what
`resource`/`action`/`payload` mean in any particular business domain —
`resource` might be a GitHub repository, an AWS account, a bank account,
or a robot; MCC-Core verifies only that the exact bound `(action,
resource, payload_hash)` triple is authorized, never how the action is
actually carried out.

## 4. Exact controlled-execution / actuator boundary

`gateway.proposal_execution_service.ResourceBoundUpstream` is the entire
contract: a `.resource` attribute (the actuator's own fixed destination)
plus `async def execute(*, resource, action, payload)`. This PR proves
the boundary is real, not aspirational, by running the IDENTICAL generic
path through two structurally different actuators with zero MCC-Core
changes:

- `examples.phase2_live_sandbox.actuator.GitHubSandboxUpstream` (reused
  unchanged) — the real, reviewed GitHub actuator.
- `examples.universal_execution_proof.generic_ledger_actuator.GenericLedgerUpstream`
  (new, PR #112, test-only) — an in-memory, non-GitHub stand-in
  implementing the exact same shape.

`type(stack.exec_stack.service) is ProposalExecutionService` holds for
both — the SAME class drives both stacks
(`tests/test_universal_execution_proof.py::test_actuator_replaceability_non_vacuity_generic_ledger`).

## 5. Reuse (no second actuator architecture)

Reused, unchanged:

- `examples/phase2_live_sandbox/actuator.py` (`GitHubSandboxUpstream`)
- `examples/phase2_live_sandbox/config.py` (`SandboxConfig`, the live-safety gate)
- `examples/phase2_live_sandbox/evidence.py` (`make_sandbox_evidence_verifier`)
- `examples/phase2_live_sandbox/marker.py` (composite tenant::op-id marker)
- `examples/gpt6_astra_reference/github_actuator.py` (`GitHubIssueActuator`)
- `examples/gpt6_astra_reference/mock_github_service.py` (offline test double)
- `examples/_demo_server.py` (`DemoServer`/`free_port`, for the live proof's real HTTP server)
- `gateway/proposal_api.py` / `gateway/proposal_execution_api.py` / `gateway/proposal_execution_stack.py` (PR #111, unmodified)

New in this PR: `examples/universal_execution_proof/` (composition +
non-vacuity actuator only), two test files, one doc, one manual workflow.
**Zero changes** to `src/mcc_core/`, `gateway/proposal_execution_service.py`,
or any PR #111 file.

## 6. Framework/provider/domain-neutrality guard

`tests/test_universal_execution_proof_architecture_guards.py` statically
forbids, via AST import scanning, `gateway/proposal_execution_service.py`
/ `proposal_execution_api.py` / `proposal_execution_stack.py` from
importing any agent-framework SDK (LangGraph, CrewAI, AutoGen, VoltAgent,
MCP, A2A) or model/provider SDK (OpenAI, Anthropic, Google's
`generativeai`, `boto3`, Azure), and forbids literal GitHub API vocabulary
(`api.github.com`, `/repos/`, `IssueIn`, `GITHUB_ISSUE_ACTION`,
`GitHubIssueActuator`, `html_url`, `issue_number`, etc.) from appearing in
those files at all. Non-vacuity probes plant both classes of coupling in
a throwaway file and prove the guard catches them.

## 7. Live proof (real external execution)

Ran `examples/universal_execution_proof/run_live_proof.py` against the
real GitHub REST API and a real, dedicated, disposable sandbox repository
(`mcc-prior-art/mcc-phase2-sandbox` — not `mcc-prior-art/mcc-layer`,
refused by the reused `SandboxConfig` guard regardless), through PR #111's
actual HTTP surface, over a real `uvicorn` server on a real TCP port, hit
with a real `httpx` client — never an in-process ASGI transport.

Result: **EXECUTED**, real external issue created
([`mcc-prior-art/mcc-phase2-sandbox#3`](https://github.com/mcc-prior-art/mcc-phase2-sandbox/issues/3)),
independently observed via a second, unrelated code path
(`mcp__github__list_issues`), replay returned `BLOCKED` (not a second
`EXECUTED`), and exactly one matching external issue exists for that
operation. See the PR body for the full evidence record.

One operational note, not a governance finding: the real GitHub REST
API's issue-listing endpoint can lag its own just-completed write by a
short, variable interval (observed empirically; the local mock service
has no such lag). This affects only how quickly the live proof script's
own post-hoc, non-authoritative observation converges — `run_live_proof.py`
retries that read up to 5 times with a 1s backoff. It has no bearing on
any MCC-Core authority/durability decision, all of which complete
synchronously, before this read-only observation step ever runs.

## 8. Universal replaceability test

**Upstream:** could OpenAI / Meta / Anthropic / Google / enterprise /
open-source intelligence (GPT-6 Astra, §10, being the concrete producer
this PR runs end to end) be swapped without changing MCC-Core authority
semantics? **YES** — §2's boundary depends only on the HTTP shape and the
authenticated tenant identity, never on `actor` or any provider signal.

**Framework:** could the orchestration/framework layer be replaced
without changing MCC-Core authority semantics? **YES** — §6's guard
proves the authority boundary imports no framework SDK; any client
capable of the HTTP contract works.

**Downstream:** could GitHub be replaced by AWS / Azure / GCP / SAP /
payment / robotics / industrial actuator implementing the same
controlled-execution contract without changing MCC-Core authority
semantics? **YES** — §4's actuator-replaceability non-vacuity test runs
the identical path through a structurally different, non-GitHub actuator
with zero MCC-Core changes.

## 9. No reconciliation expansion

There is no `POST /v1/operations/{id}/reconcile` route in this repository
(removed in PR #111) and this PR does not reintroduce one. The GitHub
reads used to verify the live proof (§7) are plain, read-only evidence
inspection — a direct call to `make_sandbox_evidence_verifier`'s returned
function and a plain `GET /repos/{owner}/{repo}/issues` — never an HTTP
API, never a mutation of durable state.

## 10. GPT-6 Astra as the concrete upstream (correction addendum)

The concrete upstream producer for this proof's end-to-end evidence is
**GPT-6 Astra** — this repository's own existing intelligence-layer
reference abstraction (`examples/gpt6_astra_reference/astra_provider.py`,
`AstraProvider.propose(task) -> AstraResponse`, `DeterministicAstraProvider`,
`AstraProposal`), reused completely unchanged. No new provider
integration is part of this PR.

`examples/universal_execution_proof/astra_upstream.py` is the ENTIRE
adapter: it calls the existing `DeterministicAstraProvider` (the
reference/offline provider this repository's own demos and tests already
default to — no live model call, no credential) and translates the
resulting `AstraProposal` into the plain `{actor, action, resource,
payload}` shape `POST /v1/proposals` already accepts. `actor` is the only
addition, a plain label never read by authority (§2).

Astra cannot mint or bypass execution authority: `AstraProvider`/
`AstraProposal` carry no signing key, no attestation material, and no
reference to `mcc_core`/the Gate/the coordinator at all — proven
structurally by the EXISTING, unmodified
`tests/test_gpt6_astra_reference_architecture_guards.py` (not duplicated
here) — and behaviorally by `astra_upstream.py`'s own source containing
none of `ResourceBoundUpstream(`, `.execute(resource=`,
`EnforcementCoordinator`, `ExecutionGate`, `AuthorityModel`,
`DecisionEngine`, `SigningKey`, or `issue_token`
(`tests/test_universal_execution_proof_astra_upstream.py::test_astra_upstream_module_never_touches_actuator_or_authority`).
A self-refusal or malformed Astra output raises before anything is ever
submitted to MCC-Core at all.

**Live result:** `examples/universal_execution_proof/run_live_proof_astra.py`
— identical wiring/safety gate to `run_live_proof.py`, sourcing the
proposal from Astra instead of a hardcoded dict — ran for real against
`mcc-prior-art/mcc-phase2-sandbox` and produced a real external issue
([`#4`](https://github.com/mcc-prior-art/mcc-phase2-sandbox/issues/4)),
independently confirmed via `mcp__github__list_issues` (a separate code
path). Replay returned `BLOCKED`; exactly one matching external issue
exists for that operation. See the PR body for the full evidence record.

## 11. Limitations

- The live proof used two real external issues in total across this
  round's development (`#2`, created during initial verification-script
  debugging before a transient evidence-lookup consistency-lag bug in
  the SCRIPT — not the governed path — was fixed; and `#3`, the final,
  fully-verified run). Both are harmless, disposable sandbox artifacts;
  neither was deleted, since this proof performs no destructive actions
  and closing/deleting was not requested.
- Not wired into `gateway/app.py`'s default startup, consistent with PR
  #111's own posture — this remains a reference composition
  (`examples/universal_execution_proof/`), not a production deployment
  decision.
- The generic ledger actuator (§4) is explicitly test-only, not a second
  production actuator architecture.
