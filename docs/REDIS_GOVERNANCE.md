# Shared Redis Governance State

> Redis here is **enforcement state, not a cache.** In a multi-instance MCC
> deployment, replay protection, idempotency, velocity, approval, and revocation
> decisions must be one coherent, atomic state across every runtime instance.
> Loss of required Redis availability results in **denial/error, not
> authorization.** There is **no silent in-memory fallback** in enforcement
> mode.

This document describes how MCC-Core keeps that state safe under concurrency,
retries, Redis failures, and adversarial inputs.

## 1. Which registries use Redis

| Registry | Module | Atomic primitive | Security role |
|---|---|---|---|
| Nonce / anti-replay | `nonce.py` | `SET key 1 NX EX` | one-time decision-token nonce |
| Idempotency | `idempotency.py` | `SET key RESERVED\|binding NX EX` | exactly-once business operation |
| Velocity / aggregate | `velocity.py` | **Lua script** (`_RESERVE_LUA`) | count / cumulative-amount / new-destination ceilings, anti-splitting |
| Consensus challenge | `challenge.py` | `SET k NX EX` + `SET k:consumed NX` | gateway-issued one-time nonce, single-use |
| Approval (ESCALATE) | `approvals.py` | `SET k NX EX` + `SET k:consumed NX` | single-use approval mandate |
| Mandate revocation | `mandate.py` | `SADD` / `SISMEMBER` | revocation visible across instances |

Each has an `InMemory*` twin for tests / single-process development. Backend
selection is **explicit** (`MCC_*_BACKEND`), never inferred.

## 2. Atomicity guarantees

The security-sensitive moment of every registry is a single server-side atomic
operation, so two instances cannot diverge by reading the same old value and
both proceeding:

- **Nonce / idempotency / challenge / approval single-use** — `SET … NX`: the
  *first* caller creates the key; every other concurrent caller gets `nil`. No
  `GET`-then-`SET`.
- **Revocation** — `SADD` / `SISMEMBER` are single atomic commands; a revoked id
  is visible to every instance immediately.
- **Velocity** — the whole *check → increment → (refund on breach)* decision runs
  as **one Lua script** (`velocity._RESERVE_LUA`). Concurrent reservers cannot
  observe the same old counter and both bypass a ceiling, no partial multi-field
  state is observable, and a breach refund happens inside the same atomic step
  (no refund-window race). Count and amount ceilings hold across separately
  signed transactions (anti-splitting) and across instances.

## 3. Canonical key model

All keys derive from `redis_keys.py`:

```
mcc:{schema}:{env}:{registry}:{suffix}
```

- `mcc` — fixed product namespace.
- `{schema}` — key-schema version (`v1`); lets the format evolve without reading
  an incompatible layout.
- `{env}` — deployment / environment / trust-domain separator from
  `MCC_REDIS_NAMESPACE` (preferred) or `MCC_ENV`; normalized to a safe charset,
  bounded, never empty (`default`).
- `{registry}` — registry type, so types never share a key space.
- `{suffix}` — the record id(s). Long, sensitive, or attacker-controlled
  components are **SHA-256 hashed** (`hash_component`, 128-bit) rather than
  embedded raw. Velocity dimension values (actor / resource / beneficiary) and
  the destination set member are hashed, so **no raw secret or payload appears
  in a key name** and `:`-separator injection cannot forge a collision.

The revocation set uses `singleton_key("revoked", env)` → `mcc:v1:{env}:revoked`.

## 4. TTL behavior

- Nonce TTL is derived from the decision token's validity window and clamped to
  `[min, max]`; a non-positive / malformed TTL is rejected.
- Idempotency `RESERVED` records carry a short TTL (stale-reservation recovery);
  `EXECUTED` carries a long TTL (completed operations are remembered across
  restarts).
- Challenge / approval records expire by their issued window (Redis key TTL).
- Velocity keys are **window-bucketed** (`w{floor(now/window)}`) and the TTL is
  set **once on first touch** (not extended on every reserve).

## 5. Fail-closed behavior

Every enforcement-critical Redis failure denies:

- connection refusal, timeout, auth failure, command/script error, malformed or
  unexpectedly-typed response, missing required state, (de)serialization error →
  the registry returns the fail-closed value (`False` / `ERROR` / `DENY` /
  `UNAVAILABLE`), never an implicit allow.
- A misconfigured required backend (`MCC_*_BACKEND=redis` or
  `MCC_GOVERNANCE_BACKEND=redis` without `MCC_REDIS_URL`) **refuses startup** —
  there is no downgrade to in-memory.

## 6. Configuration

| Variable | Default | Meaning |
|---|---|---|
| `MCC_REDIS_URL` | *(unset)* | `redis://` or `rediss://` (TLS) URL. Required for any Redis backend. |
| `MCC_REDIS_OP_TIMEOUT_SECONDS` | `0.5` | per-operation socket timeout |
| `MCC_REDIS_CONNECT_TIMEOUT_SECONDS` | `1.0` | connect timeout |
| `MCC_REDIS_NAMESPACE` / `MCC_ENV` | `default` | key environment / trust-domain segment |
| `MCC_GOVERNANCE_BACKEND` | `memory` | wired `/evaluate` pipeline: `memory` (process-local) or `redis` (shared). |
| `MCC_NONCE_BACKEND` / `MCC_IDEMPOTENCY_BACKEND` / `MCC_VELOCITY_BACKEND` / `MCC_CHALLENGE_BACKEND` / `MCC_APPROVAL_BACKEND` / `MCC_REVOCATION_BACKEND` | `memory` | per-registry backend for the gateway/coordinator layer. |

The Redis client is built in one place (`redis_client.py`); credentials are
never logged. TLS is selected by the `rediss://` URL scheme.

## 7. Runtime wiring

The wired `main.py:/evaluate` pipeline (`GovernancePipeline`) takes its four
registries from `_build_governance_registries(MCC_GOVERNANCE_BACKEND, env)`:

- `memory` → in-memory, `governance.replay_scope = "process-local"` (single
  instance only).
- `redis` → Redis-backed, `governance.replay_scope = "shared-redis"`
  (multi-instance). `MCC_REDIS_URL` is required; absence fails closed at startup.

`/health` reports the active `governance.replay_scope` and a note, so the
configuration can never claim shared protection while running in-memory.

## 8. Local development

```bash
redis-server --port 6399 --save "" &
MCC_REDIS_URL=redis://127.0.0.1:6399/0 python scripts/redis_runtime_smoke.py
```

Unit tests model multi-instance Redis with an in-process `FakeRedis`
(`tests/_fakeredis.py`) — including an `eval` that runs the velocity reserve
script — so cross-instance behavior is tested deterministically without a
server. The real-Redis smoke proves the Lua actually executes in Redis.

## 9. Multi-instance deployment expectations

- Point every instance at the same Redis (same `MCC_REDIS_URL`, same
  `MCC_REDIS_NAMESPACE`/`MCC_ENV`) and the same signing key.
- Use `MCC_GOVERNANCE_BACKEND=redis` (and the per-registry `*_BACKEND=redis`
  for the gateway layer). Replay/idempotency/velocity/approval/revocation state
  is then one shared, atomic state.
- Do **not** run multi-instance with `memory` backends — replay, idempotency,
  velocity, approval, and revocation would each be per-process and divergent.

## 10. Redis outage behavior

If required Redis is unavailable, enforcement-critical operations **deny or
error**; they never authorize. A challenge cannot be minted, a nonce cannot be
consumed (so no token actuates), an idempotency key cannot be reserved, a
velocity window cannot be reserved, and a revocation cannot be confirmed —
each fails closed.

## 11. Migration / compatibility

- Public registry constructors and `from_url` are unchanged; the
  `*_registry_from_env` builders now derive the namespace from the canonical
  key model and build the client centrally.
- **Key format changed** to the canonical `mcc:v1:{env}:{registry}:…` layout.
  Governance state is ephemeral (TTL-bounded replay/idempotency/velocity/
  challenge/approval), so there is **no data migration**: old keys simply expire.
  The revocation set is the one durable structure — re-add revocations under the
  new `mcc:v1:{env}:revoked` key during the cutover window if a non-empty legacy
  revocation list exists.
- The velocity Redis path now requires server-side scripting (`EVAL`), available
  in all supported Redis versions.

## 12. Threat model and residual limitations

**Defended:** non-atomic read/modify/write races, concurrent ceiling bypass,
transaction-splitting, inconsistent/colliding keys, missing/incorrect TTLs,
malformed Redis data (fail-closed), namespace collisions, replay, duplicate
idempotency, negative/NaN/infinite velocity amounts, silent in-memory fallback,
and credential logging.

**Not claimed / residual:**

- This does **not** make the system "unbreakable" or "production certified." It
  hardens the shared-state layer; deployment, network, and Redis operational
  security remain the operator's responsibility.
- Redis itself must be deployed securely (auth, TLS, network isolation, HA). A
  compromised Redis is a compromised governance state.
- Approval *operator* state transitions (`approve`/`deny`/`invalidate`) use a
  read-then-write; the **security-critical single-use consume is atomic**
  (`SET NX`), but a concurrent operator approve+deny race resolves to last-write
  (a usability, not a safety, concern — consume still cannot double-spend).
- Idempotency surfaces a conflicting binding as a fail-closed duplicate; it does
  not return the original deterministic *result body* (that is the gateway/
  response layer's concern).
- Cross-instance correctness assumes a single logical Redis (or a correctly
  configured HA/cluster). Split-brain Redis is out of scope.
