# Fleet-wide agent identity hardening — design and validation plan (PROPOSAL)

> **Status: PROPOSAL for AX's review. Nothing in this document is implemented
> beyond what PR #135 contains.** The fleet-hardening objective stays **OPEN**
> until the approved follow-up PRs below land and their adversarial acceptance
> tests pass on their final commits. Passing CI is not an independent audit,
> and nothing here claims unconditional or "unhackable" security.
>
> Evidence labels used below:
> **[verified]** reproduced in this work (command or test named);
> **[static]** reasoning from the code, not executed;
> **[proposed]** design, not implemented;
> **[assumption]** untested premise.

> **Status update (F1 PR, branch `claude/amazing-goldberg-85g3jt`, stacked on
> PR #135):** F1 is implemented **for the gateway** — `/consensus/challenge|
> verify|execute` are identity routes, challenges record the tenant and the
> authenticated principal, votes carry a signed `tenant_id`, `/evaluate`
> binds agent credentials to their own principal, and the VoltAgent quorum
> votes only for the agent that authenticated to it. See
> `docs/AGENT_IDENTITY.md`, "F1". The other F1 rows of section 3.D — the
> egress proxy, the MVP interceptor, `main.py` and the example-only Pilot
> Execution API — are separately deployed runtimes with no per-agent
> registry and remain **OPEN**, now tracked as **F1b**. F2–F7 are not
> implemented. The fleet objective stays **OPEN**.

## 1. Objective and threat model

**Objective.** A fully compromised agent B must not acquire agent A's identity
or authority. Colluding agents must not manufacture another principal's
identity, expand delegated permissions, or bypass independent authorization.
**Authentication never grants execution authority by itself.**

**In scope: compromised agents.** The attacker controls one or more agent
containers. It can:
- read their environment and files, and change their code;
- share their credentials with other agents;
- copy mandates and approvals;
- send arbitrary requests, and race gateways.

**Out of scope: compromised trusted components.** Each must be assumed honest;
compromising any one voids the guarantees below.

| Trusted component | What its compromise breaks |
|---|---|
| Provisioning boundary | Mints arbitrary identities |
| Gateway hosts or processes | Every decision |
| Decision-token signing key | Arbitrary tokens |
| Mandate-issuer, approval or delegation-owner keys | Arbitrary authority |
| A quorum of consensus evaluators | Arbitrary consensus |
| Operator credential | Approves anything the independent authority policy permits |
| Shared state (Redis) | Replay, single-use and budget guarantees |
| The container runtime or host kernel | Isolation between agents |

**What no identity scheme can prevent.** A compromised process that can invoke
its own signer can act as itself: anything its own identity is authorized to
do. A non-exportable key (TPM, HSM, KMS) stops key exfiltration. It does not
stop use of the key from the compromised host, and it authorizes nothing on
its own.

## 2. Where PR #135 leaves the system

| Property | State |
|---|---|
| Per-agent credential → (tenant, principal), server-side | **[verified]** `gateway/agent_identity.py`; `tests/test_v05_agent_identity_http.py` |
| Principal = `actor` = signed mandate subject on `/mandates/execute`, `/approvals/{id}/execute`; approval creation only for self | **[verified]** same tests, and real containers in `tests/container/test_agent_credential_isolation.py` |
| Each agent container holds only its own credential (deployable and demo composes) | **[verified]** real containers, plus a negative control |
| Credential form | Bearer API key, SHA-256 in the registry. No proof of possession and no request binding |
| Revocation | Registry read at gateway start: a restart is required. **No bounded propagation** |
| Shared enforcement | Nonce, approval single-use, idempotency/dispatch ownership, velocity and challenge are Redis-backed and fail closed (pre-existing; P2-B HA lab) |
| **Consensus path impersonation** | **[verified] OPEN, HIGH.** Agent B, with its own key, ran evaluate → challenge → honest votes → `/consensus/execute` as agent A and got EXECUTED (1 receipt). Script: the PR's validation notes. Consensus consumes no mandate, so the PR #135 contract does not cover it. Honest evaluators sign for whatever actor the request names. |
| Egress proxy, interceptor, `/evaluate` | **[static] OPEN.** `actor` comes from the body (egress) or the `X-MCC-Identity` header (interceptor); identity is a body field (`/evaluate`). Same caller-asserted class. |
| Delegation | **[static]** Owner-signed and single-level: there is no re-delegation, so attenuation holds by construction. Library-only, with no HTTP route. Its subject is compared with a caller-supplied `actor` under the library trust boundary. |

## 3. Design

### A. Strong agent authentication [proposed]

**Options compared**

| Mechanism | Stops | Does not stop |
|---|---|---|
| Bearer key (today) | Agent B lacking A's key | Use of a key exfiltrated from env, logs, a proxy or a state volume; replay of a captured request; substitution by an intermediary |
| mTLS with a per-agent client certificate | Key exfiltration when the key is non-exportable; network-level impersonation | Request content binding past the TLS terminator: proxies, re-encryption and gateway logs see the plaintext request |
| **Ed25519 request signatures with a per-agent key** (recommended, optionally plus mTLS) | Exfiltration (non-exportable signer); replay (unique `jti` and short `exp`); substitution of operation, payload, audience or authority reference, end to end through proxies | A compromised agent using its own signer to act as itself |

**Why Ed25519 request signatures.** It reuses the repository's signing
primitive (`mcc_core.signing`; no HMAC anywhere). It binds the *exact
executable operation*, not just the channel, and it survives TLS-terminating
proxies.

**Key custody**
- The private key lives in a signer the agent can invoke but not read: a
  sidecar over a Unix socket, a TPM/KMS handle, or a workload-identity agent.
- The registry stores each principal's **public** key with `not_before` and
  `not_after`. Several keys may be valid at once, for rotation.

**Signed request (header `MCC-Agent-Signature`).** A detached Ed25519 signature
over the canonical JSON (`mcc_core.signing` canonicalization) of:

```
{ "v": 1,
  "principal_id", "tenant_id", "credential_id",          # who
  "aud": "<gateway deployment id>",                     # intended audience
  "method": "POST", "target": "/approvals/{id}/execute" # exact route (normalized path, no query)
  "operation": { "action", "resource", "payload_sha256", # exact executable operation
                 "transaction_id", "idempotency_key" },
  "authority_ref": { "kind": "mandate|approval|consensus|delegation",
                     "id": "<mandate_id|approval_id|challenge_id|delegation_id>",
                     "digest": "<sha256 of the authority document>" },
  "iat", "exp",                                         # exp - iat <= 60 s
  "jti": "<128-bit random>" }                           # unique replay identifier
```

**Gateway verification order.** All of these happen before any token,
reservation, approval consumption or audit record. Each failure fails closed
with a stable code.
1. Look up the key by `credential_id`. It must be registered, active and
   within its validity window.
2. Check the signature.
3. `principal_id`/`tenant_id` must equal the registry entry and the mount's
   tenant.
4. `aud` must equal this deployment.
5. `method` and the normalized `target` must equal the actual request.
6. `operation` must equal the canonicalized body (the payload is hashed
   server-side) and `actor` must equal `principal_id`.
7. `authority_ref.digest` must equal the presented mandate, approval or
   delegation.
8. `iat` and `exp` must be within skew of trusted time (`TrustedTimeSource`).
9. `jti` is claimed atomically in the shared nonce registry, with TTL ≥ `exp`
   plus skew.

**Edge cases**
- **Ambiguity is rejected.** Duplicate JSON keys, non-canonical numbers, a body
  that doesn't parse to exactly the signed operation, and query strings on
  identity routes are all refused.
- **Proxies and retries.** Proxies may change transport headers but never the
  body or path. A retry is a **new** signature (new `jti`) over the **same**
  `idempotency_key`. The existing idempotency and dispatch-ownership layer
  stops duplicate execution, and a replayed `jti` is rejected.
- **Rotation.** Add the new public key, deploy the new signer, then revoke the
  old key (B, below).

**Breaking contract.**
- Every identity-route client must sign: SDK, VoltAgent TS client, pilot
  client and egress callers.
- Migration: `MCC_AGENT_AUTH_MODE=bearer|signed|signed-required`. The default
  stays `bearer` until AX approves the switch. Enforcement deployments then
  require `signed-required` (E).

### B. Fleet-wide revocation with a bounded propagation time [proposed]

- **Source of truth.** A signed registry bundle: Ed25519 over the canonical
  registry plus a monotonic `version` and an `issued_at`, signed by the
  provisioning key. Gateways reject an unsigned bundle and any version older
  than the newest they have seen (rollback protection).
- **Revocations** are written to a shared Redis set, `revoked:{credential_id}`
  with a timestamp, by the provisioning tool. The tool also bumps
  `registry:version`.
- **Authorization point.** The credential status is checked on every
  identity-route request, before any token is issued. It is re-checked at the
  coordinator, immediately before dispatch ownership is taken. The token
  carries `credential_id`, so a credential revoked between decision and
  dispatch is refused at dispatch.
- **Freshness.** Each gateway may cache the status for at most `T_cache`
  (proposed 2 s). The bound is: **revocation visible on every gateway within
  `T_cache` plus Redis replication lag** (zero on a single primary), and in
  practice ≤ 2 s.
  - If Redis is unreachable, or the cached status is older than `T_cache`, new
    identity-route executions are **denied**. There is no fail-open fallback.
- **No retroactive cancellation.** An operation already past dispatch ownership
  is not cancelled. It completes or goes UNKNOWN and is reconciled, and the
  audit chain attributes it to the credential that was valid at dispatch time.
- **Test.** Revoke a credential mid-traffic across N gateways and measure the
  last accepted request after the revocation timestamp. Pass requires that
  time to be ≤ `T_cache` + measured lag on every gateway, with zero
  post-bound acceptances.

### C. Atomic shared enforcement [mostly existing; gaps proposed]

**Already in place (pre-existing):**
- **Exactly one success per consumed item:** atomic Redis claims for replay
  nonces, the challenge single-use, approval consume, and the idempotency
  RESERVED → EXECUTED/FAILED lifecycle with dispatch ownership.
- **Uncertain outcomes:** UNKNOWN plus reconciliation after an uncertain
  dispatch. A reservation is released only on a proven pre-dispatch `BLOCKED`.
  An exception after dispatch ownership never releases it.
- **Budgets:** atomic velocity and aggregate budgets.

**Gaps to close:**
1. The `jti` registry for signed requests (A).
2. Cross-gateway identity tests with real gateway processes. This extends the
   `tests/ha/` lab, which runs only one gateway today.
3. The Redis durability contract under failover (AOF fsync policy, `WAIT`).
   Split-brain safety is **unproven** [assumption] and must be stated as such.
   An unverified failover must refuse to operate until reconciliation.
4. **Legitimate retries versus duplicates.**
   - Same `idempotency_key` with the same operation: idempotent result, never a
     second dispatch.
   - Same key with a different operation: refused (existing binding).
   - A new key is a new operation and is subject to budgets.

### D. Every authority path [inventory]

| Path | Authentication | Independent authorization | Tenant / operation binding | Final enforcement | Identity contract | Action |
|---|---|---|---|---|---|---|
| `POST /mandates/execute` | Per-agent key → principal | Signed mandate (issuer trust) | Signed tenant claim; exact operation; subject = principal = actor | Gate + coordinator | **Enforced** | A (sign) |
| `POST /approvals`, `/approvals/{id}/execute` | Per-agent key; operator key for `/approve` | Operator plus independent authority policy; single-use approval mandate | Tenant claim; exact approved payload; subject = principal | Gate + coordinator (single-use consume) | **Enforced** | A |
| `/consensus/challenge`, `/consensus/execute` | Shared tenant key **or** any registered key | N-of-M evaluator votes over (action, actor, payload, resource, policy_hash, nonce) | **No tenant in the vote; `actor` caller-asserted** | Gate + coordinator (challenge single-use) | **Not enforced: impersonation [verified]** | **PR F1** |
| `GovernanceService.execute_with_delegation` (library) | Library trust boundary | Owner-signed delegation (dedicated trust root) | Tenant, recipient, amount, currency, purpose; per-delegation budget | Gate + coordinator | Subject vs caller-supplied actor | F6 |
| `gateway/app.py` `/evaluate` | Shared or registered key | Config `AuthorityModel` (unsigned) | `identity` is a body field | Decision only; the token is consumed by other paths | Caller-asserted | F1 |
| Egress proxy `/v1/http/execute` | Single egress key | Config `AuthorityModel` + consensus | `actor` body field | Egress executor | Caller-asserted | F1 |
| MVP interceptor | `X-MCC-Identity` header | Gateway `/evaluate` | Header identity | Interceptor | Caller-asserted (production expects mTLS/workload identity) | F1 / F4 |
| `main.py` governance mode | Consensus | Quorum | As consensus | Coordinator | As consensus | F1 |

**Consensus requirements (F1)**
- `actor` must equal the authenticated principal on `/consensus/challenge` and
  `/consensus/execute`.
- The challenge must be bound to that principal and tenant.
- Votes must carry `tenant_id` and the authenticated `principal_id` in their
  signed binding, so evaluators sign for an authenticated principal and not a
  claimed one.
- Distinct voters are counted by evaluator id (one ballot each).
  - **Honest-quorum assumption [assumption]:** the threshold is meaningful only
    if fewer than `threshold` evaluator keys are controlled by one party and the
    evaluators make independent decisions.
  - Collusion of `threshold` evaluators is out of scope.
  - Duplicate or replayed votes are already rejected [verified, existing tests].
- Breaking: consensus clients and quorums must authenticate per agent.

**Delegation requirements (F6)**
- Delegation stays single-level until a chain is approved. Any re-delegation
  must prove attenuation: child scope ⊆ parent; child validity ⊆ parent; child
  limits ≤ the parent's remaining limits.
- Recipient binding: delegation subject = authenticated principal.
- Shared aggregate limits must count against one budget key per **owner and
  scope**, not per delegation. Otherwise an owner, or colluding recipients
  holding several delegations, multiplies the effective limit. Today the
  budget is per `delegation_id` [static].

### E. Deployment enforcement [proposed]

**Enforcement profile.** `MCC_ENFORCEMENT_PROFILE=production` refuses to start
if any of these holds:
- `MCC_AGENT_IDENTITY_MODE` or `MCC_MANDATE_TENANT_MODE` is a legacy value;
- shared-key agent authentication is enabled on identity routes;
- the registry is unsigned or empty;
- the gateway process is configured to import agent code.

Development compatibility stays in an explicit `development` profile that the
production startup refuses.

**Static CI guards**, extending `tests/test_authority_principal_separation_scanner.py`:
- no agent-classified compose service holds `MCC_AGENT_API_KEYS`, the shared
  tenant key, an operator key, signing keys, or a volume other than its own
  credential volume;
- no agent image `COPY` touches secrets.

**Topology.**
- Agents have no network route to protected actuators: already enforced in the
  composes [verified, existing tests].
- No agent code runs inside the gateway process.
- Agents never hold authority-signing, operator, or other agents'
  credentials [verified for the shipped composes].

## 4. Ordered follow-up PRs (each focused; breaking contracts flagged)

| # | PR | Breaking? | Acceptance tests (on that PR's final commit) |
|---|---|---|---|
| F1 | **Bind consensus, `/evaluate`, egress and interceptor identity to the authenticated principal** (actor = principal; tenant and principal in the challenge and votes) | **Yes**: consensus clients, quorum, egress callers | The verified consensus impersonation is refused with zero actuation. Each path gets B-as-A, copied-material and spoofed-header cases plus positive controls. The red-team corpus is unchanged. |
| F1b | **Per-agent identity for the separately deployed runtimes**: egress proxy `/v1/http/execute`, MVP interceptor, `main.py`, Pilot Execution API (`/v1/proposals` actor) — adopt the per-agent registry (or workload identity), bind `actor` to it, tenant-scope their coordinators | **Yes**: egress / interceptor / proposal callers | Same B-as-A, copied-material and spoofed-header matrix per runtime, with positive controls |
| F2 | **Signed registry bundle + online revocation** (B) | Registry format v2 | Revocation-propagation bound under traffic across ≥ 3 gateways; Redis-outage denial; rollback rejected |
| F3 | **Ed25519 request signatures** (A), dual mode then required | **Yes**: all identity clients | Substitution of path, payload, audience or authority; replay across gateways; expiry; rotation overlap; proxy re-encoding rejected |
| F4 | **Enforcement profile and startup guards** (E) | Yes, for unmigrated deployments | Startup refusal matrix; static scanner extensions |
| F5 | **Per-agent ESCALATE state hand-off** via a gateway API, replacing the shared state volume | Pilot tooling | Removes the shared-volume denial-of-service surface |
| F6 | **Delegation recipient binding and owner-scope aggregate budgets**; attenuation rules for any future chain | Delegation budget semantics | Collusion over several delegations cannot exceed the owner-scope limit |
| F7 | **3,000-principal adversarial validation and performance harness** (section 5) | No | The acceptance criteria below |

F1 (gateway scope) is implemented in the PR stacked on #135; F1b is the
recommended next PR for the separately deployed runtimes. AX may require F1
to merge together with PR #135, because PR #135 alone leaves the verified
same-tenant impersonation path through gateway consensus.

## 5. Phase 3: reproducible 3,000-principal adversarial validation [proposed]

### 5.1 Terms (never conflated in reporting)

| Term | Meaning | Planned size |
|---|---|---|
| **Provisioned identities** | Registry entries, each with its own key | 3,000 principals over 10 tenants (300 each) |
| **Concurrently active clients** | Simultaneous request generators | Stepped: 50, 200, 500, 1,000 |
| **Isolated containers** | Real agent containers, each holding only its own credential | Representative sample: 50 containers (2 per tenant for 10 tenants, plus colluding groups) |
| **Simulated clients** | Processes or coroutines that hold an assigned credential | The rest |
| **Gateways** | Separate gateway processes or containers sharing Redis | 3, behind a round-robin load balancer, plus direct addressing for cross-gateway replay |

3,000 registry entries are **not** a 3,000-agent deployment, and the report
must say which layer each number comes from.

### 5.2 Coverage

**Identity layer: every ordered distinct pair.** 3,000 × 2,999 = 8,997,000
pairs. Each runs through the real registry resolve plus
`agent_identity_error` and the subject check (pure functions; in-process and
parallelized). For every pair (B, A): B's credential with `actor=A` and with
A's signed subject must be refused, and A's own must be accepted. Report: pairs
evaluated, refused, accepted, and any discrepancy (the pass bar is zero).

**HTTP/E2E: stratified samples through real gateways**
- ≥ 1,000 ordered pairs same-tenant and ≥ 1,000 cross-tenant via simulated
  clients;
- ≥ 100 pairs between real isolated containers.

**Attack matrix.** Each row runs under legitimate background traffic, and each
records unauthorized actuations, refusals and false refusals:
- same- and cross-tenant impersonation on every authority path in table D;
- copied mandates and approvals; copied consensus material (after F1);
- collusion: k ∈ {2, 5, 20} colluding principals pooling credentials,
  mandates and approvals to reach an operation none is authorized for alone;
- concurrent consumption of shared budgets (velocity and aggregate) from many
  principals and gateways;
- key rotation and revocation during traffic (F2/F3), measuring the
  propagation bound;
- replay of a captured request, `jti` or approval against a **different**
  gateway;
- approval execution races: same approval to N gateways at once;
- gateway restart and stale instances (an old registry version, or an old
  revocation cache);
- shared-state outage and network partition (Redis kill, iptables DROP;
  reusing `tests/ha/`);
- malformed requests and operation substitution (R1–R4 corpora at scale).

### 5.3 Measurements

- Latency p50, p95 and p99 per route.
- Throughput (requests per second, and executions per second).
- CPU and RSS per gateway, Redis ops/s, and rejection rate by code.
- Every security control enabled. Reported with workload, concurrency, hardware
  (CPU model and cores, RAM), OS/kernel, container runtime, Redis topology,
  commit SHA, and the list of enabled controls.

**Capacity targets: proposed, to be approved by AX before any benchmarking.**
- Identity check overhead: p99 < 1 ms in-process.
- Identity-route execution through a gateway (Redis on the same host): p95 <
  50 ms and p99 < 150 ms at 200 concurrent clients, excluding the external
  actuator.
- Sustained ≥ 300 governed executions/s across 3 gateways.
- Revocation propagation ≤ 2 s.

Targets are never met by disabling a control. A miss is reported as a miss.

### 5.4 Acceptance criteria (every one is required)

1. **Zero** unauthorized actuations across the executed attack matrix, counted
   by external receipts and actuator invocations, not by status strings.
2. Authorized operations succeed under supported conditions; the false-refusal
   rate is reported.
3. Uncertain security state (Redis down, stale revocation, unverifiable time,
   unknown key) fails closed for new execution.
4. **No** duplicate execution in any replay or race scenario.
5. Revocation meets its approved propagation bound on every gateway.
6. Delegation and collusion never expand authority beyond the union of the
   colluders' own authority.
7. Performance results carry the full environment record in 5.3.

**Reproducibility.**
- Seeded generators and a pinned commit.
- One command per layer (`make fleet-validate-identity`, `-http`, `-containers`).
- Raw JSONL results are kept as CI artifacts.
- The report states which rows ran, which were skipped and why, and which
  environments were not tested (for example: multi-host, managed Redis
  failover, real KMS/TPM).

## 6. Residual risks after all follow-ups (stated, not solved)

- A compromised agent acts as itself within its own authority.
- Compromise of any trusted component in section 1.
- Collusion of a full evaluator quorum, or of the operator together with a
  permissive authority policy.
- Availability attacks: an agent flooding its own allowance, or Redis outages,
  which deny service by design.
- Correctness of a Redis failover in split-brain conditions is unproven until
  tested.
