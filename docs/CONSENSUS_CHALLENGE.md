# Consensus Challenge — the gateway issues the nonce

Multi-Context Consensus binds evaluator votes (and the decision token) to a
one-time `nonce` so the evidence cannot be replayed. If the **client** chooses
that nonce, the client controls the anti-replay material — it can pre-compute,
coordinate, or reuse nonces. A **consensus challenge** moves that authority to
the gateway: the gateway mints a cryptographically strong, single-use nonce
inside a challenge bound to the exact operation, persists it atomically with a
TTL, and consumes it exactly once before actuation.

> The model proposes. **The gateway issues the challenge.** The evaluators
> concur. MCC-Core decides. The gate enforces. The audit chain records.

## Handshake

```
client → POST /consensus/challenge { action, actor, resource, context }
       ← { challenge_id, nonce, action, actor, resource,
           payload_hash, policy_hash, issued_at, expires_at }
       → evaluators each sign a ConsensusVote bound to that nonce
       → POST /consensus/execute { challenge_id, votes, … }
       ← EXECUTED   (or BLOCKED, fail-closed, upstream never reached)
```

1. **Issue.** The gateway canonicalizes the payload through the action profile,
   computes `payload_hash`, generates `nonce = secrets.token_urlsafe(32)` (256
   bits), and stores a single-use `ChallengeRecord` bound to
   `action / actor / resource / payload_hash / policy_hash` with a TTL. The
   client receives the nonce (it needs it to gather votes) and the binding.
2. **Vote.** Each independent evaluator signs a vote over the challenge's nonce
   (plus action/payload/actor/resource/policy_hash) with its own Ed25519 key.
3. **Execute.** The client returns `challenge_id` + the votes. The gateway
   re-resolves the challenge (unknown / not open → fail closed), uses its nonce
   to verify the N-of-M consensus, issues the decision token carrying that
   nonce and `auth_claims.challenge_id`, and runs the one coordinator path.
4. **Consume.** Inside the coordinator — after the gate verifies the token and
   the mandatory consensus check passes, **before** any idempotency / velocity
   reservation, execution, or the pre-actuation audit write — the challenge is
   consumed **exactly once**, re-bound to the token's
   `action / actor / resource / payload_hash / policy_hash / nonce`. A
   `challenge_consumed` entry is written to the hash chain before
   `pre_actuation`, preserving audit-before-actuation.

## The challenge record

| Field | Meaning |
|---|---|
| `challenge_id` | opaque id (`chal-…`); names the challenge on execute |
| `nonce` | gateway-generated, 256-bit, URL-safe, **one-time** |
| `action`, `action_hash` | the bound action |
| `actor` | the bound caller |
| `resource` | the bound target |
| `payload_hash` | `sha256` of the canonical payload |
| `policy_hash` | the gateway's policy version |
| `issued_at` / `expires_at` | validity window (TTL-enforced by the store) |
| `state` | `ISSUED → CONSUMED` (single-use) or `→ EXPIRED` |

State machine:

```
ISSUED ──consume──► CONSUMED        (single-use, terminal)
   └────(ttl)─────► EXPIRED
```

## What is rejected (all fail closed)

| Case | Where it is caught |
|---|---|
| unknown `challenge_id` | service re-resolve + coordinator consume |
| expired challenge | store TTL / logical expiry |
| reused challenge | single-use consume (and the one-time nonce at the gate) |
| nonce / action / actor / resource / payload / policy mismatch | consume re-binding + consensus vote binding |
| malformed or forged votes | `ConsensusVerifier` (untrusted kid / bad signature) |
| below threshold / veto | `ConsensusVerifier` |
| client-supplied nonce, no challenge | `require_challenge` → BLOCKED |

A mismatched consume attempt does **not** spend the challenge — only a fully
bound, valid consume flips it to `CONSUMED`.

## HTTP API

| Method | Endpoint | Boundary |
|---|---|---|
| `POST` | `/consensus/challenge` | agent — mint a single-use challenge (gateway owns the nonce) |
| `POST` | `/consensus/execute` | agent — supply `challenge_id` + votes; executes only on a valid, bound, consumed challenge |

```json
POST /consensus/challenge
{ "action": "deploy_release", "actor": "agent/ops",
  "resource": "cluster-1", "context": { "target": "cluster-1", "environment": "prod" } }
→ { "challenge_id": "chal-…", "nonce": "…", "action": "deploy_release",
    "actor": "agent/ops", "resource": "cluster-1", "payload_hash": "sha256:…",
    "policy_hash": "sha256:…", "issued_at": 1780000000, "expires_at": 1780000120 }

POST /consensus/execute
{ "challenge_id": "chal-…", "votes": [ {/* signed vote */}, … ],
  "actor": "agent/ops", "action": "deploy_release", "resource": "cluster-1",
  "context": { … }, "idempotency_key": "op-1" }
→ { "status": "EXECUTED" | "BLOCKED", "reason": "…", "decision": "ALLOW", … }
```

## Deployment

| Env | Default | Notes |
|---|---|---|
| `MCC_CHALLENGE_BACKEND` | `memory` | `memory` or `redis`. `redis` requires `MCC_REDIS_URL`; refuses to fall back (no silent downgrade) |
| `MCC_REQUIRE_CHALLENGE` | `false` | when truthy, the coordinator refuses to actuate without a gateway-issued challenge — clients can no longer supply their own nonce |

For multi-instance deployments use `MCC_CHALLENGE_BACKEND=redis` so the
single-use consume holds across every gateway instance (atomic `SET NX`).
`MCC_REQUIRE_CHALLENGE=true` pairs naturally with `MCC_REQUIRE_CONSENSUS=true`:
the gateway issues the nonce, the evaluators bind to it, and no action actuates
without a fresh, consumed challenge.

## Backward compatibility

Additive and opt-in. With `MCC_REQUIRE_CHALLENGE` unset, the existing
`/consensus/execute` (client-supplied nonce) path is unchanged; a `challenge_id`
is simply an optional field. The challenge store, like every other registry,
fails closed on backend errors and never silently downgrades from Redis to
in-memory.
