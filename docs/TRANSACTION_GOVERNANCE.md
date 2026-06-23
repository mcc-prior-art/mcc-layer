# Transaction Governance — Five Distinct Protections

MCC-Core layers five *different* guarantees around an executed operation. They
are often conflated; they are not the same, and each fails closed independently.

| Layer | Question it answers | Scope | Backed by |
|---|---|---|---|
| **1. Nonce replay protection** | Has *this exact token* already been used? | One decision token | `RedisNonceRegistry` / `InMemoryNonceRegistry` |
| **2. Business-operation idempotency** | Has *this business operation* already executed (even via a different token)? | One `idempotency_key` | `RedisIdempotencyRegistry` / `InMemory…` |
| **3. Transaction binding** | Is this the *exact authorized operation* (actor, resource, transaction, payload, payment fields)? | One token ↔ one operation | Ed25519 signature + `payload_hash` + gate binding |
| **4. Velocity limits** | Too many actions / too much volume / too many new destinations in a window? | An aggregate over a window | `RedisVelocityRegistry` / `InMemory…` |
| **5. Aggregate limits (anti-splitting)** | Can several individually-valid transactions together breach a ceiling? | A cumulative ceiling across transactions | atomic reservation in the velocity registry |

A nonce stops a *token* being replayed. It does **not** stop a *second, freshly
signed token* re-running the same payment — that is what idempotency (2) is for.
Neither stops *four different* valid payments from together exceeding a ceiling —
that is what aggregate reservation (5) is for. Keeping these separate is the
point of this document.

---

## Domain-neutral by design

The decision token model is generic. Every token carries:

```
transaction_id, idempotency_key, actor_id, resource_id, action,
payload_hash (canonical), policy_hash, auth_claims (optional, opaque)
```

None of these are payment-specific. Payment fields — **source, beneficiary_id,
amount, currency** — are introduced only by an *action-specific profile*
(`PaymentProfile`), and they travel in two signature-covered places:

* inside the **canonical payload** (so `payload_hash` covers them), and
* inside the opaque **`auth_claims`** map on the token (so the signature covers
  them as first-class authorization facts).

Non-payment actions use the generic `ActionProfile`, carry no payment
vocabulary, and are completely unaffected. New domains add a profile, not a
change to the universal token.

---

## Transaction binding (3) — what a substitution looks like

* Changing **amount, currency, beneficiary, or source** changes the canonical
  payload → `payload_hash` mismatch → `PAYLOAD_HASH_MISMATCH` deny.
* Changing **actor, resource, or transaction_id** between what was authorized
  and what is executed → `BINDING_MISMATCH` deny at the gate (the gate compares
  the operation's identity to the token's signed claims).
* The token itself cannot be edited — every claim is under the Ed25519
  signature.

A token that does not carry a given field is simply *not bound* on it (an
authentic `None`, also under the signature, so it cannot be stripped to
downgrade); generic actions therefore keep working.

---

## The execution order (and why it is fixed)

`EnforcementCoordinator.enforce` runs one fixed sequence; nothing may execute
out of order:

```
a. validate the decision token + exact operation binding   (ExecutionGate)
b. consume the one-time nonce                               (ExecutionGate)
c. atomically reserve the idempotency key                   (IdempotencyRegistry)
d. atomically reserve velocity / aggregate capacity         (VelocityRegistry)
e. durably record the pre-enforcement decision              (audit-before-actuation)
f. execute                                                  (the executor / forward)
g. record the execution outcome                             (audit)
h. finalize the idempotency state -> EXECUTED               (IdempotencyRegistry)
```

Any **indeterminate infrastructure failure before (f)** — a registry that
cannot reserve, an audit write that cannot be confirmed — fails closed: the
operation does not run and every capacity already reserved is released. An
executor failure at (f) marks the idempotency key `FAILED` (freed for a
deliberate retry) and reports fail-closed; it never silently finalizes.

### Idempotency lifecycle

```
(absent) --reserve--> RESERVED --execute--> EXECUTED   (terminal: never again)
                          |
                          +--fail / release--> (absent)  (retryable)
```

`RESERVED` carries a TTL, so a crashed executor's reservation is recovered when
the TTL lapses (stale-RESERVED recovery). `EXECUTED` is durable and survives
restarts, so a completed operation cannot re-run after a process bounce.

---

## Anti-splitting (5)

Velocity capacity is *reserved atomically before execution*. Each reservation is
serialized by the backend (atomic `SET NX` / `INCR` / `INCRBYFLOAT`), and any
reservation that would cross a ceiling is refused and refunded. Concurrent
requests therefore cannot independently pass the same remaining limit, and four
individually-valid `4000` payments cannot bypass a `10000` cumulative ceiling —
the fourth (or third) reservation is the one refused. Because the cumulative
counter is keyed by aggregation dimensions (actor, source, …) and not by token,
the ceiling holds across *separately-signed* transactions.

---

## Configuration

| Concern | Backend env | Notes |
|---|---|---|
| Nonce | `MCC_NONCE_BACKEND` = `memory`\|`redis` | + `MCC_REDIS_URL` for redis |
| Idempotency | `MCC_IDEMPOTENCY_BACKEND` = `memory`\|`redis` | + `MCC_REDIS_URL` |
| Velocity | `MCC_VELOCITY_BACKEND` = `memory`\|`redis` | + `MCC_REDIS_URL` |

Selecting `redis` without `MCC_REDIS_URL` raises at startup — there is **no
silent fallback** to in-memory state in an enforcement deployment. A Redis
outage at request time denies, it does not downgrade. Velocity ceilings for the
pilot are defined in `gateway/pilot_policy.py` (`PILOT_VELOCITY`).

See also `docs/MVP_GATEWAY.md` (gateway + interceptor) and
`RUNTIME_DEPLOYMENT.md` (operational env vars).
