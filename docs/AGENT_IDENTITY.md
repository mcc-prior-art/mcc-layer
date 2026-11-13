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
  non-identity agent routes of its own tenant (verify, status, consensus,
  `gateway/app.py` `/evaluate` and `/verify`), and on the VoltAgent evaluator
  quorum when it is given the same registry. An agent needs one key.
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

See `docs/proposals/FLEET_IDENTITY_HARDENING_PLAN.md` (PROPOSAL, not implemented) for the follow-up design, including the verified consensus-path impersonation that this contract does not cover.

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
| `POST /consensus/challenge`, `/consensus/verify`, `/consensus/execute` | **no**: authority is the N-of-M evaluator quorum, signed over `actor` | **no — OPEN, verified impersonation** | `actor` is caller-asserted. Verified: agent B with its OWN key obtained honest votes for actor A and `/consensus/execute` EXECUTED as A. Follow-up F1 in `docs/proposals/FLEET_IDENTITY_HARDENING_PLAN.md` (breaking for consensus clients) |
| `GovernanceService.execute_with_delegation` (no HTTP route) | no: an owner-signed delegation | **no** (library only) | delegation subject compared with a caller-supplied actor; library trust boundary applies |
| `gateway/app.py` `POST /evaluate`, `GET /verify` | no: unsigned config mandates (`AuthorityModel`), decision-only / read-only | **no** (out of scope) | `MCC_GATEWAY_API_KEY` or a registered agent credential (tenant-level auth only); `identity` is a body field. Same caller-asserted-identity class; tracked separately |
| VoltAgent evaluator quorum `POST /vote` | no: signs votes over the gateway's authoritative payload | **no** | quorum key or a registered agent credential (tenant-level auth only) |
| `main.py` `/evaluate` (governance mode) | no | **no** (out of scope) | consensus-based |
| egress proxy `POST /v1/http/execute` | no: config `AuthorityModel` | **no** (out of scope) | `actor` is a body field |
| MVP interceptor (`interceptors/egress_proxy.py`) | no | **no** (out of scope) | identity from `X-MCC-Identity` (documented as mTLS/workload identity in production) |

**No alternate route consumes a signed mandate**, so none bypasses this
contract for the V05 copied-mandate attack. **But the consensus path lets one
agent act as another for whatever the evaluator quorum approves for that
actor** (verified, above). That is the same impersonation class, through a
different authority source, and this PR does not close it. The routes marked *out of scope*
have their own caller-asserted-identity exposure for **other** authority
sources. They are listed so they are not mistaken for covered.

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

