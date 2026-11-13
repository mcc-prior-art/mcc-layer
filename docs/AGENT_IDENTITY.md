# Per-agent identity and mandate subject binding (V05, part 2)

> Remediation following an internal adversarial assessment
> (`security/redteam-assessment-r1` @ `cb5bd33`, finding V05). This is not an
> independent audit, and it is not a claim of complete security.

## The problem this closes

PR #134 bound every signed mandate to a tenant. Within a tenant, though, the
governance HTTP API authenticated only the **tenant**:
- one shared agent `X-API-Key` per mount;
- `actor` was a request field.

Reproduced on `main` @ `1f0bd3a` through real HTTP authentication:

| Step | Caller | Result |
|---|---|---|
| Agent A executes its own tenant-bound mandate | shared tenant key | EXECUTED (control) |
| Agent B presents A's copied mandate with `actor=A` | **the same** shared tenant key | **EXECUTED**: impersonation |
| Agent B presents it with `actor=B` | shared key | BLOCKED `SUBJECT_MISMATCH` |
| Agent B creates an approval naming `actor=A`; an operator approves; B executes it as A | shared key | **EXECUTED** |

The only prerequisites were the tenant's shared key, which every agent of the
tenant holds, and a copy of A's mandate JSON.

## The contract

**Credential resolution is server-controlled.** `gateway/agent_identity.py`
maps a presented `X-API-Key` to exactly one `(tenant_id, principal_id)`
through a registry file. Identity is **never** derived from:
- `actor`, or any other body field (the strict request schema rejects unknown
  fields with 422);
- the mandate's contents;
- any other header.

**Identity routes** are `POST /mandates/execute`, `POST /approvals` and
`POST /approvals/{id}/execute`. On these routes:
- The key must be a **registered, active** credential of the mount's tenant.
  The result is the trusted `AuthenticatedAgent`.
- The mount's **shared tenant key grants no identity**:
  `403 AGENT_IDENTITY_REQUIRED`.
- Rejected credentials:
  - unknown, missing or empty key → `401 INVALID_API_KEY`;
  - revoked → `403 AGENT_CREDENTIAL_REVOKED`;
  - another tenant's credential → `403 AGENT_CREDENTIAL_WRONG_TENANT`.
- The authenticated principal must equal `actor`, otherwise
  `BLOCKED AGENT_PRINCIPAL_MISMATCH`. After signature verification it must
  also equal the signed mandate `subject` (`SUBJECT_MISMATCH` /
  `AGENT_SUBJECT_MISMATCH`).
- On `POST /approvals`, an agent may request approval **only for itself**
  (`403`, and no record is created). The approval mandate is minted for the
  request's actor, so this stops an agent from obtaining authority in another
  agent's name upstream.

**Every refusal happens before** any decision token, approval consumption,
idempotency reservation, audit `pre_actuation` record or actuator call. A
rejected attempt therefore never blocks a later legitimate retry with the same
idempotency key.

**Unchanged:**
- PR #134 strict tenant binding;
- R1–R4;
- exact-operation binding, signatures and replay protection;
- audit-before-actuation;
- durable UNKNOWN/reconciliation;
- single-use approvals.

## What this does NOT prevent

- **Theft of an agent's own credential.** Whoever presents agent A's key *is*
  A to the gateway. This contract authenticates credentials; it is not proof
  of possession, and it is not hardware-bound. The response to a leaked key
  is rotation and revocation (below). Deployments must deliver each key only
  to its own agent (see *Credential distribution*).
- **Non-identity routes are not covered.** See the route coverage matrix.

## Configuration

| Setting | Default | Meaning |
|---|---|---|
| `MCC_AGENT_IDENTITY_MODE` | `strict` | `strict`: identity routes require a registered per-agent credential. `legacy-shared-key`: the shared tenant key is accepted there with a caller-asserted `actor`. That is the pre-remediation behaviour and provides **no protection against within-tenant impersonation**; registered credentials are still enforced. Any other value refuses startup. |
| `MCC_AGENT_CREDENTIALS_CONFIG` | unset | Path of the registry JSON. Unset means no registered agents, so every identity request fails closed with 403. A malformed or ambiguous file refuses startup. |

Registry format (only SHA-256 hashes are stored; never raw keys):

```json
{"agents": [
  {"credential_id": "cred-payments-bot-1", "tenant_id": "pilot",
   "principal_id": "agent/payments-bot",
   "key_sha256": "<sha256 hex of the raw key>", "status": "active"}
]}
```

**Fail-closed loading.** All of the following refuse to load; there is never a
partial registry:
- unknown or missing fields;
- an empty or padded id;
- a hash that is not 64 lowercase hex characters;
- a `status` other than `active`/`revoked`;
- a duplicate `key_sha256`, i.e. one key for two principals;
- a duplicate `credential_id`.

## Provisioning, rotation and revocation

```bash
# provision: prints the raw key ONCE; the registry keeps only its hash
python scripts/generate_agent_credential.py --config secrets/agents.json \
    --tenant-id pilot --principal-id agent/payments-bot
# rotate: provision a second credential for the same principal, deploy it, then
python scripts/generate_agent_credential.py --config secrets/agents.json --revoke <old credential_id>
```

- **Multiple active keys.** A principal may hold several active credentials,
  so rotation needs no downtime.
- **When changes take effect.** The registry is read at startup; restart or
  roll the gateway instances after any change. A revoked credential is refused
  (403) from the next start.
- **Same key on every agent route.** A registered credential also works on the
  read-only routes of its own tenant (`/mandates/verify`, approval status,
  `gateway/app.py` `/verify`), on `/evaluate` **for its own principal only**,
  on the consensus routes (F1: identity routes) and on the VoltAgent
  evaluator quorum (which must be given the same registry). An agent needs
  one key.
- **Ambiguity refuses to start.** A mount's shared key that is also a
  registered credential is refused (`AgentCredentialConfigError`): one secret
  must not mean both "any agent of this tenant" and "this agent".

## Migration

1. For every agent that executes mandates or requests or executes approvals,
   provision a credential with its `principal_id` equal to the `actor` it uses
   and to the `subject` its mandates are issued to.
2. Give each agent its own key, sent as `X-API-Key` exactly as before. No
   client code changes: the SDK, the VoltAgent TS client and the pilot client
   already send that header.
3. Point the gateway at the registry (`MCC_AGENT_CREDENTIALS_CONFIG`).
4. **Operators approve; agents execute.** Operator tooling holds only the
   operator credential and only approves. The escalating agent executes its
   own approved operation with its own credential. An operator never holds or
   presents an agent credential (see *Credential distribution*).
5. `MCC_AGENT_IDENTITY_MODE=legacy-shared-key` exists only to keep an
   unmigrated deployment running. It restores the impersonation exposure and
   should be temporary.

## Credential distribution (PR #135 review fix)

**Finding (reproduced on `d8fa730`).** The first version of this PR passed the
whole provisioning map `MCC_AGENT_API_KEYS` (every principal's raw key) to every
agent container. Two composes were affected:
`docker-compose.pilot-voltagent.yml:180` and
`docker-compose.pilot-clinic-voltagent.yml:166`. The demo composes also
committed raw demo keys and gave one container several principals.

- **Static evidence.** In the resolved compose config with synthetic canaries,
  every agent container received all three principals' keys.
- **Dynamic evidence.** A real-HTTP run against `gateway.app` was configured
  from that resolved gateway environment. It ran as a local process, not a live
  container. In it, B read A's key from B's own environment and executed A's
  copied approval: `EXECUTED`, with 1 receipt.

Selecting the right key in application code enforced nothing: a compromised
container reads its whole environment.

**Design.** The provisioning secrets stay inside the trusted provisioning
boundary:

| Element | Holds |
|---|---|
| `agent-credentials-init`: one-shot `python -m gateway.agent_provisioning`, root, `network_mode: none` | The only process that ever sees more than one raw agent key. It writes each agent's credential (mode 0400, owned by that agent's runtime uid) into **that agent's own named volume**. It also writes the registry, SHA-256 hashes only, for the gateway and quorum. |
| Each agent container (one per principal) | Its own volume, mounted **read-only** at `/run/mcc-agent` (`MCC_AGENT_CREDENTIAL_FILE`). Nothing else: no provisioning map, no other agent's key, no tenant shared key (`MCC_GATEWAY_API_KEY`), no operator key. |
| Gateway and quorum | The hash-only registry. |
| Operator tooling | The operator key only. It approves and hands the single-use mandate back. The **agent executes** its own approved operation. |
| `.env.pilot` | No agent key at all. |
| `.dockerignore` | Keeps `.env*`, `secrets/`, `*.key`, `*.pem` and credential files out of every build context and image. |

**Fail-closed on the agent side** (`gateway.agent_provisioning.load_agent_credential`
and `integrations/voltagent/src/agent-credential.ts`):
- a missing, unreadable or malformed credential file is refused;
- unknown, missing, empty or padded fields are refused;
- a provisioning map in the agent's environment is refused outright, even next
  to a valid file;
- a configured actor that differs from the provisioned principal is refused.

**Persistence and rotation.**
- Credentials are reused across restarts.
- `make pilot-rotate-agent PRINCIPAL=agent/...`, or `--rotate`, replaces one
  principal's key and rewrites the registry.
- The gateway reloads the registry at start.

**Verified in real containers** (`tests/container/test_agent_credential_isolation.py`,
mandatory CI job `agent-credential-isolation`):
- **Isolation.** B's environment, readable filesystem, mounts and image contain
  none of A's credential, the shared or operator key, or the build-context
  canaries.
- **Impersonation.** B, using its own key and A's copied mandate, is refused on
  both execute routes and on `POST /approvals`. Spoofed headers and body
  fields gain nothing. Rejected requests leave no audit record and no receipt,
  and do not consume the approval.
- **Positive controls.** A then executes using the idempotency key B tried, the
  approval is single-use, B executes its own operation, and the audit chain
  verifies.
- **Negative control.** Reintroducing the leak (mounting A's volume into B)
  makes exactly the isolation tests fail.

### Shipped pilots and demos

| Deployment | Agent containers (one per principal) |
|---|---|
| `docker-compose.pilot-voltagent.yml` (deployable) | `voltagent-agent` (agent/notify-bot), `voltagent-agent-unknown` (agent/unknown). The operator step (`make pilot-approve`) approves in the gateway container; the agent then executes with its own key. |
| `docker-compose.pilot-clinic-voltagent.yml` (deployable) | `clinic-agent` (agent/axflow-clinic) |
| `docker-compose.notify-pilot.yml`, `docker-compose.reference-agent.yml` | `*-agent` (agent/notify-bot), `*-agent-escalate` (agent/unknown). The operator sidecar is approve-only, as before. |
| `docker-compose.voltagent.yml` (CI E2E) | `voltagent-agent`, `voltagent-agent-unknown`, plus the approve-only `voltagent-operator` sidecar. The agent runner no longer performs the operator role and holds no operator key. |

`scripts/compose_agents_e2e.sh` runs these per-principal stacks: it starts the
infrastructure, waits for health, then runs each agent container to
completion, and any failure fails the job.

**Trusted multi-agent test harnesses are a different thing.** The in-process
harnesses under `tests/` (for example `tests/_notify_harness.py` and
`tests/interoperability/harness.py`) and the VoltAgent `testserver` play
several principals inside one trusted test process, using deterministic
per-principal keys. They test the gateway's contract. They are not agent
deployments and never ship as one.

## Threat model and its limits

**In scope: a fully compromised agent container.** Assume an attacker controls
agent B's container: its code, environment and files, its own credential, and
arbitrary requests. Assume B can collude with other compromised agents and copy
mandates or approvals. Then:
- B holds no other principal's credential, so it cannot authenticate as A;
- presenting A's copied mandate or approval with its own key is refused;
- B cannot create an approval in A's name;
- authentication alone grants no authority: B's own operations still pass
  independent authorization (mandate, quorum, approval policy).

Colluding agents can each act only as themselves. They can pool what they are
individually authorized to do; this contract does not reduce that.

**Out of scope: compromise of the trusted side.** None of the above holds if
any of these is compromised:
- the provisioning boundary or the Docker host;
- the gateway process or its host;
- the decision-token signing key, an approval-signing or mandate-issuer key, or
  a consensus evaluator quorum;
- the operator credential, which can approve within the independent authority
  policy.

**Also not prevented:**
- **Theft of an agent's own credential.** The key is a bearer secret with no
  proof of possession; the response is rotation.
- **Tampering with the shared ESCALATE state volume.** Agents can tamper with
  it, which can deny service (delete or alter a hand-off). It grants no
  authority: the mandate is signed for its subject and exact operation. Per-agent
  state volumes are a follow-up.
- **Revocation latency.** Revocation takes effect when the gateway restarts.

See `docs/proposals/FLEET_IDENTITY_HARDENING_PLAN.md` (PROPOSAL; F1 implemented,
see the next section; F2-F7 not implemented) for the follow-up design.

## F1: consensus and `/evaluate` bound to the authenticated agent

**Reproduced on PR #135 head `2761f4f`**, real HTTP (in-process uvicorn
gateway, real loopback notification service, honest evaluators). Agent B,
presenting its OWN registered credential:

| Probe | Result before F1 |
|---|---|
| `POST /evaluate` with `identity = A` | ALLOW + decision token signed for A |
| `/consensus/challenge` + `/consensus/verify` + `/consensus/execute` as A | challenge for A, verify ALLOW, **EXECUTED, receipt +1** |
| REAL VoltAgent evaluator quorum `/vote` for actor A, then execute | 3 ALLOW votes for A, **EXECUTED, receipt +1** |
| A's own challenge + A's honest votes, executed by B | **EXECUTED** (A's challenge burned) |
| the shared tenant key on `/consensus/challenge` | 200 |

After F1 every probe is refused (403 / BLOCKED), receipts +0, and A's own
control executes. Script: the reproduction lives in the PR description;
regression tests: `tests/test_f1_consensus_identity_http.py`.

**Contract** (strict, the default; breaking for consensus clients):

- **Consensus routes are identity routes.** `/consensus/challenge`,
  `/consensus/verify` and `/consensus/execute` require a registered, active
  per-agent credential of the mount's tenant whose principal equals `actor`
  (`AGENT_PRINCIPAL_MISMATCH` otherwise). The shared tenant key is refused
  (403 `AGENT_IDENTITY_REQUIRED`); revoked / other-tenant credentials 403,
  unknown 401. Library callers pass `agent=` (an omitted agent is refused).
- **Challenges are bound to the authenticated agent.** A gateway-issued
  challenge records the server-resolved `tenant_id` and the authenticated
  `principal_id` (both returned to the client). `/consensus/execute` refuses a
  challenge issued to another principal or tenant
  (`CHALLENGE_PRINCIPAL_MISMATCH` / `CHALLENGE_TENANT_MISMATCH`) before it is
  consumed. The coordinator re-checks the tenant when it consumes the
  challenge; a tenant-scoped challenge is never consumable by an unscoped
  consumer.
- **Votes are bound to the tenant.** Every counted vote must carry a signed
  `tenant_id` equal to the server-resolved tenant (checked by the service
  before the token and again by the coordinator). The vote's signed `actor`
  claim is its principal binding: the gateway accepts a request only when
  `actor` is the authenticated principal, so a counted vote's `actor` is
  always that principal. *No separate `principal_id` vote claim was added: it
  would duplicate `actor` byte for byte.*
- **`/evaluate` binds identity.** A registered agent credential may evaluate
  only as itself (`identity` and `actor_id` must be its principal), in every
  mode. In strict mode the shared tenant key may not evaluate as a
  **registered** agent (any status); identities that are not registered
  agents (a service's own policy identity, the MVP interceptor's callers) are
  unchanged — the shared key is a tenant **service** credential that is never
  provisioned into agent containers (enforced by the PR #135 isolation
  test). `/evaluate` mints a signed token but no gateway execute route
  accepts one; its consumers are interceptors.
- **The evaluator quorum votes only for the agent that asked.** `/vote`
  requires a registered per-agent credential (its own shared key only in
  explicit `legacy-shared-key` mode); `actor` must be that principal; the
  quorum forwards that same credential to `/evaluate`, so the gateway
  authenticates the principal the votes are for; every vote carries the
  tenant. Evaluators that sign votes themselves (reference
  `ConsensusAuthorizer`, pilot driver) take the tenant and principal from the
  gateway-issued challenge and refuse a challenge not bound to the decision's
  actor.
- **Order.** Every identity refusal happens before any decision token,
  challenge consumption, idempotency reservation, velocity reservation, audit
  record or actuator call (tested: audit entry count, challenge state, a
  legitimate retry with the same idempotency key).
- **Preserved.** Distinct-evaluator counting, duplicate / forged / expired /
  mismatched vote rejection, veto, threshold, challenge single-use, gate
  nonce replay protection.

**Honest-quorum assumption.** F1 binds votes to a tenant and to the request's
authenticated principal. It does not make a dishonest or compromised
evaluator quorum safe: N colluding evaluator keys can still sign anything for
any principal. A quorum that signs without authenticating the requester (as
the harness evaluators in tests do) is outside this contract.

**Legacy mode.** `MCC_AGENT_IDENTITY_MODE=legacy-shared-key` (server-side,
explicit) restores caller-asserted `actor` on the consensus routes and lets
the shared key evaluate as any identity. It gives NO protection against
within-tenant impersonation. Registered credentials stay bound in every mode,
and the tenant binding of votes and challenges applies in every mode.

## Trust boundaries

- **HTTP.** The only source of identity is the registry lookup of `X-API-Key`.
  The resulting `AuthenticatedAgent` is passed **explicitly** to
  `GovernanceService.execute_with_mandate` / `execute_with_approval` /
  `create_approval` (`agent=`).
- **Direct library callers** (`GovernanceService` used in-process) are
  outside the HTTP boundary.
  - **Strict mode** (default, or `MCC_AGENT_IDENTITY_MODE`): an **omitted**
    `agent` is refused (`AGENT_IDENTITY_REQUIRED`); it never falls back to
    trusting `actor`. Anything that is not an `AuthenticatedAgent` is refused
    (`AGENT_IDENTITY_INVALID`).
  - **A caller that constructs an `AuthenticatedAgent`** is asserting that it
    authenticated that agent itself. The library cannot verify that. Embed the
    service only behind your own authentication.

## Route coverage matrix

| Entry point | Consumes a signed mandate? | Per-agent identity enforced | Notes |
|---|---|---|---|
| `POST /mandates/execute` | yes (standing or approval-minted) | **yes**: route + service | principal = actor = signed subject |
| `POST /approvals/{id}/execute` | yes (approval-minted) | **yes**: route + service (delegates to the mandate path) | single-use unchanged |
| `POST /approvals` (create) | no, but mints authority for `actor` | **yes**: actor must be the principal | refused before any record |
| `POST /approvals/{id}/approve`, `/deny`, `/invalidate` | no | operator key (unchanged) | approval mandate is minted for the record's actor, now always the creating principal |
| `POST /mandates/verify`, `GET /approvals/{id}` | no (read-only, no token) | no: shared or registered tenant key | informational |
| `POST /consensus/challenge`, `/consensus/verify`, `/consensus/execute` | no: authority is the N-of-M evaluator quorum, signed over `actor` + `tenant_id` | **yes (F1)**: route + service; challenge bound to tenant + principal; votes bound to tenant | before F1: verified impersonation (B with its own key EXECUTED as A). Refused before token / challenge consumption / reservation / audit |
| `GovernanceService.execute_with_delegation` (no HTTP route) | no: an owner-signed delegation | **no** (library only) | delegation subject compared with a caller-supplied actor; library trust boundary applies |
| `gateway/app.py` `POST /evaluate` | no: unsigned config mandates (`AuthorityModel`); returns a signed decision token for `identity` | **yes for agent credentials (F1)**: an agent key evaluates only as itself; the shared key may not evaluate as a registered agent (strict) | the shared tenant (service) key still evaluates non-agent identities — a holder of that key can act as any *unregistered* identity; it is never provisioned to agents |
| `gateway/app.py` `GET /verify` | no (read-only) | no: shared or registered tenant key | informational |
| VoltAgent evaluator quorum `POST /vote` | no: signs votes over the gateway's authoritative payload | **yes (F1)**: registered credential, actor = principal, credential forwarded to `/evaluate`, votes carry the tenant | quorum shared key only in explicit legacy mode |
| `main.py` `/evaluate`, `/evaluate/challenge` (separate runtime) | no | **no — OPEN** (no per-agent registry; one tenant key) | consensus via its own embedded coordinator, which is tenant-unscoped; `identity` is a body field. Follow-up F1b |
| egress proxy `POST /v1/http/execute` (separate service) | no: config `AuthorityModel` + optional consensus | **no — OPEN** (one service key, `actor` is a body field) | its coordinator is tenant-unscoped (votes need no `tenant_id`; a gateway-issued tenant-scoped challenge is NOT consumable there). Follow-up F1b |
| MVP interceptor (`interceptors/egress_proxy.py`) | no | **no — OPEN** | identity from `X-MCC-Identity`, evaluated with the shared service key; F1 now refuses that key for a *registered* agent identity, so it works only for unregistered identities. Production intent: mTLS/workload identity. Follow-up F1b |
| Pilot Execution API `POST /v1/proposals` + `/v1/operations/{id}/execute` (mounted only in `examples/external_pilot`) | no: config `AuthorityModel` | **no — OPEN** | tenant-level `MCC_PROPOSAL_TENANTS` keys; the proposal's `actor` is caller-asserted. Follow-up F1b |

**No alternate route consumes a signed mandate**, so none bypasses this
contract for the V05 copied-mandate attack. **F1 closes the verified
consensus-path impersonation on the gateway** (and binds `/evaluate` and the
quorum). The rows marked **OPEN** are separately deployed runtimes or
example-only surfaces that authenticate only a tenant/service key and take
the actor from the caller. They are listed so they are not mistaken for
covered; follow-up F1b in the fleet plan.

## Test and demo migrations

The original red-team corpus is unchanged. Existing tests and demos were
migrated to **explicit per-agent credentials**; no assertion was removed or
weakened.

- **HTTP fixtures:** the key each test client already sent becomes that
  agent's registered credential, and the mount's shared tenant key becomes a
  separate unused value (`tests/_agent_credentials.py`).
- **Substitution tests reach their intended check.** Where a test substitutes
  another actor (`agent/ATTACKER`, `agent/intern`, `agent/an-impostor`,
  `agent/other-unknown`), that actor now holds **its own** credential. The
  test therefore still reaches the signed-subject / approval binding it
  targets, instead of stopping early at the new principal check. A scratch
  probe confirmed that no pre-existing test passes merely because the
  identity layer rejected it.
- **Direct library callers** pass the trusted `agent=` they authenticated
  themselves. This covers tests, `benchmarks/workload.py`,
  `examples/gpt6_astra_reference/pipeline.py`, the Redis smoke scripts and
  the assurance negative-control harness, all under the library trust
  boundary above.
- **In-process demos** that boot `gateway.app` (`examples/governance_http_demo.py`,
  the Control Room runtime in `tools/control-room/backend/runtime.py`) write a
  hash-only registry for their demo agent and send that agent's own key on
  the identity routes.
- **Out-of-process harnesses** (`tests/interoperability/harness.py`,
  `assurance/sut/harness.py`, `tests/_notify_harness.py`, the reference
  localstack, the VoltAgent `testserver.py`) register a deterministic
  per-principal key: `<shared key>::agent::<principal>`.
- **Cases with no stronger migration:**
  - `tests/test_pilot_client.py::test_request_approval_creates_pending` mounts
    the approval routes on a fresh app with an explicit credential, because
    the module-level `gateway.app` has no registry in the test environment.
  - `tests/test_v05_mandate_tenant_binding_http.py::test_request_fields_cannot_supply_the_tenant`
    intentionally asserts that another tenant's key is refused at
    authentication (401).
- **Changed by the credential-distribution fix** (the behaviour under test was
  the flaw itself):
  - **`tests/test_voltagent_operator_cli_idempotency.py`.** It asserted that the
    operator EXECUTES the approved operation, which meant using the agent's
    credential. The operator now only approves, so the execution assertions
    moved to the agent (`integrations/voltagent/tests/agent-credential.test.ts`).
    Its Round 26/27 checks are kept: reuse of `correlationId` as the idempotency
    key, and fail-closed handling of a missing, blank or non-string
    `correlationId` before any gateway call. The operator-side fail-closed
    assertions are unchanged.
  - **`tests/test_agent_operator_credential_separation.py`.** Its positive
    control required each agent to still hold the shared tenant key. It now
    also accepts the agent's own credential file, and only if that file is
    delivered on a read-only volume mounted at its directory.
  - **`TestNotifyPilotAgentScriptStillWorksEndToEnd`.** The scenario matrix now
    runs as two processes, one per principal, each with only its own credential
    file. Both must pass.

### F1 migration record (consensus, `/evaluate`, quorum)

No assertion was removed or weakened. Every consensus client now presents the
**actor's own** credential, and every vote producer signs the tenant.

- **Shared-key clients moved to the actor's key** (otherwise their negatives
  would have stopped at the new identity refusal): the interoperability
  harness (`_client(base, principal)`, all 5 adapters × 7 scenarios), the
  assurance consensus helpers (`sut.agent_key(actor)`), `test_integration_contract`,
  `test_governed_executor_pilot`, `test_reference_governed_agent`,
  `test_pilot_deployment`, `test_voltagent_quorum` (`stack.agent(actor)`),
  `test_axflow_clinic_pilot`, the compliance stack and its **replay probe**
  (`mcc_compliance/runner.py`: the replay is now attempted by the same agent;
  with the shared key it would have been "blocked" by identity, vacuously),
  the reference-agent CLI's self-contained mode, the Control Room, the
  VoltAgent TS integration tests.
- **Vote producers sign `tenant_id`:** test fixtures (`votes_for`, `_votes`,
  `hz.votes`, `gw.votes`, `sut.gateway_*votes`), `ConsensusAuthorizer` and the
  pilot driver (from the challenge, refusing a challenge not bound to the
  decision's actor), the compliance stack, the Control Room, the quorum.
- **Evaluate-as-another-agent fixed in tests:** two tests evaluated a second
  principal's decision through the first principal's client
  (`test_reference_governed_agent` mandate-substitution case,
  `test_authority_principal_separation_adversarial_notify` case D). They now
  evaluate with that principal's own client; the assertion (the substituted
  mandate is refused at execution) is unchanged.
- **Library callers** of `verify_consensus` / `execute_with_consensus` pass
  the trusted `agent=` (`test_governance_service_attestation`,
  `test_trusted_time_round4`), so they still reach the attestation and
  trusted-time checks they target.
- **Quorums in tests** receive the gateway's hash-only registry
  (`NotifyPilotHarness.agent_registry_path`, `testserver.py`).
- **Gateway harnesses** reuse the gateway's own `/evaluate` binding
  (`evaluate_caller_dep` + `enforce_evaluate_identity`): `_notify_harness`,
  the interop gateway process, the reference localstack, `testserver.py`.
- **New negatives** added next to existing ones (each with a positive
  control on the same challenge): votes for another tenant / no tenant in
  `test_challenge_http`, `test_consensus_enforcement_http`; the full matrix in
  `tests/test_f1_consensus_identity_http.py`.
- **`deploy/pilot`** (Docker pilot runbook): `generate_pilot_config.py` now
  provisions `agent/payments-bot`'s own credential; the gateway gets
  `MCC_AGENT_CREDENTIALS_CONFIG`; RUNBOOK §5 and the driver use that key. This
  also repairs §5b, which since V05 part 2 used the shared key on `POST
  /approvals` for another actor.

