# Constitution → Engineering Invariants

This document maps each principle in `docs/MCC-CORE-CONSTITUTION.md` to
a concrete engineering invariant, the point in the existing MCC-Core
architecture that enforces it, and the automated tests that prove it.
Every test named below is real, exists in this repository, and passes
(`pytest tests/constitution/` — see `docs/CONSTITUTION-COMPLIANCE.md`
for the run evidence). No new authorization framework was introduced;
every invariant is enforced by the **existing** `DecisionEngine` /
`ExecutionGate` / `AuthorityModel` / `EnforcementCoordinator` /
`AuditLog` / nonce registries.

## Authority Principal Separation (deployment-level corollary of INV-01/INV-06/INV-10)

This is a separation-of-powers requirement, not a credential-hygiene
convenience. Three distinct control planes govern an autonomous system,
and MCC-Core occupies exactly one of them:

> **Safety** controls model behavior (what the model is inclined to
> propose). **Containment** controls where the agent can operate (network
> reachability, process/container boundaries). **Authority** controls
> whether a consequential action may execute at all — this is MCC-Core's
> plane, and only its plane.
>
> MCC-Core must remain the independent authority boundary even if the
> agent is fully compromised. A compromised agent may defeat its own
> safety training and may attempt to defeat its containment — the
> authority boundary is what must hold regardless, because it never
> depended on the agent's behavior or location to begin with: it depends
> on the agent never holding the credential that would let it decide for
> itself.

This is not a new, eleventh invariant alongside INV-01 through INV-10 below
— it is the same principle those ten already state, applied one layer
outward, to **who is allowed to hold which credential at deployment time**,
not only to what the governed code path allows at runtime:

> An autonomous system may propose an operation, but the security principal
> that controls the proposer MUST NOT possess sufficient capability to
> issue, approve, sign, or otherwise create executable authority for that
> same operation.
>
> INTELLIGENCE ≠ AUTHORITY. PROPOSER ≠ AUTHORIZER.
> COMPROMISE OF THE AGENT MUST NOT IMPLY COMPROMISE OF EXECUTION AUTHORITY.

INV-01 (no self-authorization) and INV-06 (executor cannot authorize) prove
this at the *code* level: the agent/executor's own source never imports or
constructs `SigningKey`/`AuthorityModel`/`DecisionEngine`. Authority
Principal Separation is the same claim checked at the *deployment* level:
even when an agent container's own code never reads a privileged
credential, that credential must not be reachable from the agent's
environment, mounts, or process at all — because "my code doesn't use it"
is not a security boundary against a compromised process, a dependency
that dumps its environment, or a future code change in that same
container.

**Enforcement point:** `tests/test_agent_operator_credential_separation.py`
(a specific confirmed finding, with a real runtime reproduction against the
actual `egress_proxy` application), `tests/test_authority_principal_separation_scanner.py`
(a repository-wide scanner classifying every service across every
`docker-compose*.yml` file as `ROLE_AGENT` or not, by name heuristic, and
asserting no `ROLE_AGENT` service's EFFECTIVE merged environment —
env_file content plus explicit `environment:`, interpolated — contains an
authority-plane secret, unless an explicit, reviewed, reasoned exception is
recorded in `KNOWN_COMBINED_ROLE_EXCEPTIONS`), and the adversarial runtime
proofs in `tests/test_authority_principal_separation_adversarial*.py`
(compromised-agent-cannot-self-approve, separated-authority-succeeds-
exactly-once, stolen-credential-rejected, wrong-binding-rejected,
authority-unavailable-fails-closed — against the real governed stacks, and
for the reference-agent pilot, against the actual shipped container
scripts loaded by path).

**Status: no documented exceptions remain in the Docker Compose topology.**
All three single-process reference demos that previously held the operator
key (`governed_agent_compose_demo.py` / `mcc-agent`, `notify_pilot_agent.py`
/ `pilot-agent`, `reference_agent_runner.py` / `reference-agent`) have been
refactored into genuinely separate agent/operator process pairs
(`mcc-operator`, `pilot-operator`, `reference-agent-operator` respectively,
the latter two sharing `deploy/pilot/gateway_approval_operator.py`), each
coordinating only through a shared, non-secret state file (a pending
approval's `request_id` and the original proposal — never a credential).
`KNOWN_COMBINED_ROLE_EXCEPTIONS` in the scanner is intentionally left as an
empty dict, not deleted, so a future regression has an obvious place to be
reviewed and documented rather than silently reintroducing the pattern.

**Two single-process reference library/example files were also found and
fixed, outside the Compose scanner's scope** (it only scans
`docker-compose*.yml`, not Python call sites):

- `examples/governed_agent/mcc_client.py`'s `GovernedMCCClient` has no
  `approve`/`deny_approval` method at all; only a new, separate
  `OperatorConsole` class does. This module is reused as a real, in-process
  embedded runtime dependency in two other places, not only as a demo —
  `egress_proxy/runtime.py` (the actual egress proxy gateway) and
  `src/mcc_agent/client.py`'s `EmbeddedGovernanceClient` — both updated to
  construct a separate `OperatorConsole` internally rather than calling
  `approve`/`deny_approval` on the client object directly.
- `examples/agent_runtime_mcc.py`'s agent and MCC authority are now
  genuinely separate OS processes (`multiprocessing`), not merely separate
  objects in one process; the agent-side `AgentRuntimeClient` never
  imports or constructs `SigningKey` / `DecisionEngine` / `ExecutionGate`.

Enforcement: `tests/test_authority_principal_separation_adversarial_example_scripts.py`
(Cases A-E for both).

**A sixth instance, discovered during this same audit, is also now closed:**
`src/mcc_agent/agent.py`'s `GovernedAgent.arun()` previously called
`self.client.approve(approval_id)` directly on the SAME
`EmbeddedGovernanceClient` object it uses to `submit()` the proposal — the
same combined-role pattern as the demos above, one level further out, in
pilot (`src/`) code rather than `examples/`. Fixed the same way: the
`GovernanceClient` Protocol (`submit`/`execute_after_approval`/
`verify_audit_chain`) no longer declares `approve`/`deny_approval`; a
separate `OperatorClient` Protocol does, and `GovernedAgent.__init__` takes
an optional, separately-constructed `operator: Optional[OperatorClient]`.
Without one, ESCALATE reports `PENDING_APPROVAL` and stops — `GovernedAgent`
never falls back to approving through its own client.
`EmbeddedGovernanceClient.approve`/`deny_approval` were likewise removed in
favor of a public `.operator` property exposing the same `OperatorConsole`
it already built internally. All 5 call sites in `src/mcc_agent/demo.py`
and the shared `_agent()` test factories in `tests/test_mcc_agent.py` /
`tests/test_pilot_release.py` updated to wire `operator=client.operator`.
Enforcement: `tests/test_authority_principal_separation_adversarial_mcc_agent.py`
(Cases A-E).

**Status: zero known combined proposer/authority principals remain**
across the compose topology, the example/library code, and pilot (`src/`)
code, as of this audit.

## INV-01 — No self-authorization

**Constitutional principle:** Authority remains with the owner;
Intelligence proposes, authority verifies, execution enforces.

**Invariant:** An agent must never be able to create or fabricate its
own authorization decision.

```
Agent -> Proposal -> MCC-Core -> Decision -> Execution
```

Never:

```
Agent -> Execution
```

**Enforcement point:** `mcc_core.gate.ExecutionGate.verify` (rejects any
token not signed by a trusted key — `UNTRUSTED_KEY`/`INVALID_SIGNATURE`)
and `mcc_core.coordinator.EnforcementCoordinator.enforce` (gate check is
step (a), unconditionally first). Structurally: agent-side packages
(`src/mcc_agent/`, `examples/reference_governed_agent/`, excluding
documented independent-authority tooling) hold no `SigningKey`.

**Automated tests:** `tests/constitution/test_inv01_no_self_authorization.py`
(6 tests): forged-key token rejected, unsigned dict rejected, tampered
valid token rejected, self-declared-approval payload does not execute,
agent packages hold no signing key (with non-vacuity probe).

## INV-02 — No consequential execution without authorization

**Constitutional principle:** Authority remains with the owner; No plane
may usurp the role of another.

**Invariant:** Every consequential action must have a valid MCC-Core
decision before execution. If MCC-Core's own infrastructure is
unavailable: FAIL CLOSED.

**Enforcement point:** `ExecutionGate.verify`'s outer exception wrapper
(any internal exception → `GATE_ERROR: fail-closed`);
`EnforcementCoordinator.enforce`'s durable-admission and velocity steps,
which rely on `RedisIdempotencyRegistry`/`RedisVelocityRegistry`'s own
fail-closed backend-error handling (never silently proceeding on a
backend outage); `DecisionEngine.issue_token`'s refusal to issue a token
for a non-executable verdict (`TokenNotIssuable`).

**Automated tests:** `tests/constitution/test_inv02_fail_closed_without_authorization.py`
(6 tests): missing token never executes, DENY verdict cannot even
produce a token, nonce backend down fails closed, idempotency backend
down blocks before execution (real `RedisIdempotencyRegistry` over a
failing client), velocity backend down blocks before execution (real
`RedisVelocityRegistry`), a malformed token of any shape denies rather
than raising.

## INV-03 — Exact-action authorization

**Constitutional principle:** Execution remains within boundaries;
Intelligence proposes, authority verifies, execution enforces.

**Invariant:** Authorization must be bound to the exact action being
executed. Changing action, target, payload, policy hash, or context
after authorization invalidates execution.

**Enforcement point:** `ExecutionGate.verify`'s scope-binding checks —
`ACTION_HASH_MISMATCH`, `PAYLOAD_HASH_MISMATCH`, `POLICY_HASH_MISMATCH`,
and the generic `binding` loop (`BINDING_MISMATCH`) — plus the fact that
every claim lives inside one Ed25519-signed structure, so splicing any
single field from a second valid token invalidates the signature.

**Automated tests:** `tests/constitution/test_inv03_exact_action_authorization.py`
(8 tests): action/payload/target/policy-hash/tenant/actor substitution
all rejected; cross-token field-splicing rejected (signature check);
positive control (unmodified token accepted).

## INV-04 — Memory cannot authorize

**Constitutional principle:** Authority remains with the owner.

**Invariant:** Memory may provide context. Memory must never grant
authority. A record like "the user normally allows this" must never
become an authorization decision.

**Enforcement point:** `mcc_core.authority.AuthorityModel.evaluate`
decides purely from `(identity, action, verified mandate, declarative
`max_`/`min_`/`allowed_` constraints on the untrusted context)` — an
arbitrary free-form context claim cannot itself satisfy a constraint it
does not name, and identity with no mandate at all is unaffected by
context content of any kind.

**IMPLEMENTATION GAP:** this repository has no first-class agent-memory
subsystem (every "Memory" hit in the codebase is an
`InMemory<X>Registry` durable-state backend, unrelated to this
principle). The invariant is proven at the only level currently
testable — see the test file's own module docstring — not proven
end-to-end against a real memory component, because none exists.

**Automated tests:** `tests/constitution/test_inv04_memory_cannot_authorize.py`
(4 tests): memory-shaped claim without a mandate stays ESCALATE;
memory-shaped claim cannot satisfy a named numeric constraint (stays
DENY); `AuthorityModel.evaluate`'s signature has no memory/history
parameter; positive control (a real mandate does grant ALLOW).

## INV-05 — Intelligence cannot increase authority

**Constitutional principle:** Growth of intelligence does not imply
growth of authority.

**Invariant:** Changing or upgrading the underlying model must not
automatically increase permissions. The same action, through different
model identities/runtimes, remains policy-controlled.

**Enforcement point:** `AuthorityModel.evaluate`'s signature has no
model/runtime parameter at all; `actor_id`/model-label metadata on a
decision token is documented and proven informational-only (PR #113:
"never read by authority evaluation"); `Mandate`/`ActionPolicy` have no
model/capability-tier field a policy could even reference.

**Automated tests:** `tests/constitution/test_inv05_intelligence_cannot_increase_authority.py`
(5 tests): no model/runtime parameter in `evaluate`'s signature;
identical verdict across differently-labeled "models" for the same
identity/action/context; a claimed more-capable model does not bypass a
violated constraint; two tokens differing only in `actor_id` enforce
identically at the gate; `Mandate`/`ActionPolicy` dataclass fields
contain no model/capability keys.

## INV-06 — Executor cannot authorize

**Constitutional principle:** No plane may usurp the role of another;
Intelligence proposes, authority verifies, execution enforces.

**Invariant:** The executor only executes an already-verified decision.
It must never contain fallback authorization logic.

**Enforcement point:** Real actuator entrypoints
(`examples/gpt6_astra_reference/github_actuator.py::GitHubIssueActuator.__call__`,
`egress_proxy/executor.py::HTTPEgressExecutor`) take only
`(action, payload)` / the pre-verified request — no
`agent_requested`/`decision`/`verdict` parameter exists for a fallback
`if agent_requested_action: execute` to even be written against; they
import no Authority-plane primitive (`AuthorityModel`, `DecisionEngine`,
`issue_token`).

**Automated tests:** `tests/constitution/test_inv06_executor_cannot_authorize.py`
(5 tests): actuator call signature has no agent-request/authority
parameter; actuator modules import no authority primitives (with
non-vacuity probe); an executor with zero internal guard logic of its
own still never runs without a valid token, and does run with one
(positive control).

## INV-07 — Audit-before-execution

**Constitutional principle:** Authority is verifiable, not merely
trusted; the doctrine line's own ordering (decide → enforce → record is
the STATED order, but the actual enforced order durably records the
pre-actuation decision before dispatch).

**Invariant:** For consequential actions: Decision → Audit → Execution,
never Execution → Audit.

**Enforcement point:** `EnforcementCoordinator.enforce`'s explicit a-h
ordering — step (e) durably records the pre-enforcement decision before
step (f) (dispatch commitment) and step (g) (execution); `AuditLog`'s
hash-chained, fsync'd append.

**Automated tests:** `tests/constitution/test_inv07_audit_before_execution.py`
(5 tests): the executor callback itself reads the audit log and
confirms a pre-actuation entry already exists (runtime proof, not a
comment); an outcome entry exists afterward; a BLOCKED decision is still
audited; the audit chain is tamper-evident (`AuditLog.verify_chain`
catches a single-character edit); non-vacuity of the assertion style.

## INV-08 — Replay protection

**Constitutional principle:** Execution remains within boundaries;
Authority is verifiable, not merely trusted.

**Invariant:** A valid authorization decision must not be reusable
outside its intended execution context.

**Enforcement point:** `ExecutionGate.verify`'s nonce consumption
(`NonceRegistry.consume`, checked last so a static-check failure never
burns the nonce); nonce is bound into the signed token, so it cannot be
recycled across tokens without breaking the signature — and even an
explicitly-repeated nonce value across two independently-signed tokens
is rejected on second consumption.

**Automated tests:** `tests/constitution/test_inv08_replay_protection.py`
(5 tests): same token rejected on second `verify`; same token cannot
execute twice through the coordinator (side effect happens exactly
once); an explicitly shared nonce across two different tokens is
rejected on the second; an expired token is rejected independent of
nonce freshness; positive control (two genuinely distinct nonces both
succeed).

## INV-09 — MCC-Core boundary

**Constitutional principle:** Execution remains within boundaries; No
plane may usurp the role of another.

**Invariant:** The agent must not have a direct execution path to
consequential tools.

**Enforcement point:** Static import guards over `src/mcc_agent/` and
the reference agent's execution files, re-deriving (not duplicating the
maintenance of) the existing pattern from
`tests/test_mcc_agent_no_direct_egress.py`; the agent's own client names
`GovernedMCCClient`/`GovernanceClient` as its only execution path.

**Automated tests:** `tests/constitution/test_inv09_mcc_core_boundary.py`
(5 tests): `mcc_agent` package has no direct-network/direct-actuator
import; reference agent execution files likewise; two non-vacuity
probes (planted network import, planted actuator construction); the
agent client module names the governed client type.

## INV-10 — No plane usurpation

**Constitutional principle:** No plane may usurp the role of another.

**Invariant, five sub-claims:**

| Sub-claim | Status |
|---|---|
| a. Intelligence cannot authorize | **PROVEN** (INV-01, re-asserted) |
| b. Memory cannot authorize | **PARTIALLY PROVEN** (INV-04) — see IMPLEMENTATION GAP above |
| c. Executor cannot authorize | **PROVEN** (INV-06, re-asserted) |
| d. UI cannot directly authorize | **IMPLEMENTATION GAP** — no UI/frontend code exists in this repository at all; there is no real boundary to test |
| e. Only the Authority plane issues the execution decision | **PROVEN** |

**Enforcement point (e):** `DecisionEngine.issue_token` is the only
intended caller of `SigningKey.sign_token` for a *decision*; every
`.sign_token(` call site outside the Authority-plane modules
(`core.py`, `mandate.py`, `approvals.py`, `consensus.py`, `challenge.py`,
`signing.py`) is a plane-usurpation violation.

**Automated tests:** `tests/constitution/test_inv10_no_plane_usurpation.py`
(7 tests), including two that make the gaps themselves checked,
version-controlled facts (they fail loudly the moment a memory package
or a UI directory is added, forcing this document to be revisited
rather than silently going stale) and one consolidated end-to-end test
of the four-role formula.

## Summary

| Invariant | Test file | Tests | Status |
|---|---|---|---|
| INV-01 | `test_inv01_no_self_authorization.py` | 6 | PROVEN |
| INV-02 | `test_inv02_fail_closed_without_authorization.py` | 6 | PROVEN |
| INV-03 | `test_inv03_exact_action_authorization.py` | 8 | PROVEN |
| INV-04 | `test_inv04_memory_cannot_authorize.py` | 4 | PARTIALLY PROVEN (documented gap) |
| INV-05 | `test_inv05_intelligence_cannot_increase_authority.py` | 5 | PROVEN |
| INV-06 | `test_inv06_executor_cannot_authorize.py` | 5 | PROVEN |
| INV-07 | `test_inv07_audit_before_execution.py` | 5 | PROVEN |
| INV-08 | `test_inv08_replay_protection.py` | 5 | PROVEN |
| INV-09 | `test_inv09_mcc_core_boundary.py` | 5 | PROVEN |
| INV-10 | `test_inv10_no_plane_usurpation.py` | 7 | PARTIALLY PROVEN (2 of 5 sub-claims are documented gaps) |
| **Total** | | **56** | |
