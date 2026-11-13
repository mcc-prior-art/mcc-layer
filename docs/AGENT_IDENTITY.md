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
  is rotation and revocation (below).
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
4. **Operator tooling that executes an approval on an agent's behalf** must
   now present **that agent's** credential. An operator key alone has never
   been able to execute; the shared agent key no longer can either.
5. `MCC_AGENT_IDENTITY_MODE=legacy-shared-key` exists only to keep an
   unmigrated deployment running. It restores the impersonation exposure and
   should be temporary.

### Shipped pilots and demos

| Deployment | How it is wired |
|---|---|
| `docker-compose.notify-pilot.yml`, `docker-compose.reference-agent.yml`, `docker-compose.voltagent.yml` | gateway (and quorum) read the committed demo registry `deploy/pilot/agent_credentials.demo.json` (hashes of non-secret demo keys); the agent container gets `MCC_AGENT_API_KEYS` (JSON `{principal: key}`) and each principal it drives presents its own key |
| `docker-compose.pilot-voltagent.yml`, `docker-compose.pilot-clinic-voltagent.yml` (deployable, `.env.pilot`) | the operator sets `MCC_AGENT_API_KEYS` in the git-ignored `.env.pilot`; at every gateway start `integrations/voltagent/mcc_side/agent_credentials.py` writes the hash-only registry to the config volume (missing/malformed keys refuse to start). `operator_cli.py` executes an approved escalation with the **escalated agent's** own key |

The TS client (`agentApiKey` in `integrations/voltagent/src/agent.ts`) and the
Python demo runners pick the acting principal's key from `MCC_AGENT_API_KEYS`
and fail closed when it has no entry; they never fall back to acting as an
agent with the shared key.

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
| `POST /consensus/challenge`, `/consensus/verify`, `/consensus/execute` | **no**: authority is the N-of-M evaluator quorum, signed over `actor` | **no** (out of scope) | `actor` is caller-asserted and bound by the evaluators' signatures; consensus tenant isolation is tracked separately |
| `GovernanceService.execute_with_delegation` (no HTTP route) | no: an owner-signed delegation | **no** (library only) | delegation subject compared with a caller-supplied actor; library trust boundary applies |
| `gateway/app.py` `POST /evaluate`, `GET /verify` | no: unsigned config mandates (`AuthorityModel`), decision-only / read-only | **no** (out of scope) | `MCC_GATEWAY_API_KEY` or a registered agent credential (tenant-level auth only); `identity` is a body field. Same caller-asserted-identity class; tracked separately |
| VoltAgent evaluator quorum `POST /vote` | no: signs votes over the gateway's authoritative payload | **no** | quorum key or a registered agent credential (tenant-level auth only) |
| `main.py` `/evaluate` (governance mode) | no | **no** (out of scope) | consensus-based |
| egress proxy `POST /v1/http/execute` | no: config `AuthorityModel` | **no** (out of scope) | `actor` is a body field |
| MVP interceptor (`interceptors/egress_proxy.py`) | no | **no** (out of scope) | identity from `X-MCC-Identity` (documented as mTLS/workload identity in production) |

**No alternate route consumes a signed mandate**, so none bypasses this
contract for the V05 copied-mandate attack. The routes marked *out of scope*
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

