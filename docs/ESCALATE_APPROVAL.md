# ESCALATE — Human-in-the-Loop Approval

`ESCALATE` is no longer a dead end. It is the entry point to a complete,
auditable approval flow that converts a human decision into a **bounded,
single-use, signed authority** — never into a direct execution.

## Flow

```
proposal
  → MCC evaluation
  → ESCALATE                         (no token; needs human authority)
  → approval request (PENDING)
  → human APPROVE / DENY
  → on APPROVE: a scoped, signed, time-limited, single-use approval mandate
  → re-evaluation (MandateAuthority verifies the mandate)
  → decision token (bound to mandate_id + approval_id + action_hash + payload)
  → execution gate (signature, binding, nonce)
  → audit-before-actuation
  → coordinator consumes the approval (single-use)  → execute  /  block
```

Approval mints authority; it does not execute. Execution still passes the full
gate + coordinator path, and the approval is **consumed at actuation**, so a
human approving twice, or a captured token being replayed, cannot double-execute.

## State machine

```
                approve                       consume (single-use)
   PENDING ───────────────► APPROVED ───────────────────────────► CONSUMED
     │  │                      │                                   (terminal)
     │  │ deny                 │ ttl
     │  ▼                      ▼
     │ DENIED (terminal)     EXPIRED (terminal)
     │
     │ ttl
     ▼
   EXPIRED
     ▲
     └────────── invalidate (PENDING or APPROVED) ──► INVALIDATED (terminal)
```

| State | Meaning |
|---|---|
| `PENDING` | awaiting a human decision |
| `APPROVED` | approved; a single-use approval mandate has been minted |
| `DENIED` | terminally refused; cannot be approved later |
| `EXPIRED` | TTL lapsed before approval or consumption |
| `CONSUMED` | the approval was used exactly once at actuation; terminal |
| `INVALIDATED` | administratively voided |

## Binding (what a forged/substituted approval looks like)

The approval mandate is signed by the approver key and bound to the **exact**
operation: actor (subject), action (`action_scope` = the single action, plus
`action_hash`), resource (`resource_scope`), `transaction_id`, `policy_hash`,
`payload_hash`, and `constraints`. At re-evaluation `MandateAuthority` rejects:

* a different **actor** → `SUBJECT_MISMATCH`
* a widened/different **action** → `ACTION_SCOPE_MISMATCH`
* a different **resource** → `RESOURCE_SCOPE_MISMATCH`
* a drifted **policy version** → `POLICY_BINDING_MISMATCH`

At actuation `ApprovalService.consume` additionally rejects a mismatched
`action_hash`, `transaction_id`, or `payload_hash`, and enforces single-use:
a second consume of the same approval is `already consumed (replay)`. Expired,
reused, altered, or non-`APPROVED` approvals all fail closed.

## Service boundary (API)

`ApprovalService` is the clean boundary for requesting, recording, approving,
denying, and consuming approvals:

| Method | Effect |
|---|---|
| `request(actor, action, resource, transaction_id, policy_hash, payload_hash, constraints, ttl)` | create a `PENDING` request → `request_id` |
| `get(request_id)` | current record + state (lazily expires) |
| `approve(request_id)` | `PENDING → APPROVED`; returns the signed approval mandate |
| `deny(request_id)` | `PENDING → DENIED` (terminal) |
| `invalidate(request_id)` | `PENDING/APPROVED → INVALIDATED` |
| `consume(request_id, action_hash, transaction_id, payload_hash)` | atomic single-use; binds to the exact operation |

The `EnforcementCoordinator`, when given an `ApprovalService`, calls `consume`
automatically for any token whose `auth_claims.approval_id` is set — single-use
is therefore tied to *execution*, not merely to re-evaluation.

## Operator workflow

1. The agent's proposal evaluates to `ESCALATE`. The interceptor/agent calls
   `request(...)` and surfaces the `request_id` to an operator queue.
2. An operator reviews and calls `approve(request_id)` or `deny(request_id)`.
   Approval returns a mandate handed back to the agent.
3. The agent re-submits with the mandate; MCC re-evaluates → `ALLOW`/`CONSTRAIN`
   → token → gate → coordinator consumes the approval → execute.
4. Audit records every transition and an audit-before-actuation entry.

## Deployment

| Env | Default | Notes |
|---|---|---|
| `MCC_APPROVAL_BACKEND` | `memory` | `memory` or `redis` |
| `MCC_REDIS_URL` | *(unset)* | required when backend is `redis` |

`RedisApprovalRegistry` makes the request store and single-use consume durable
and cross-instance (consume is an atomic `SET NX`, so exactly one instance can
consume an approval). Selecting `redis` without `MCC_REDIS_URL` raises at
startup — no silent fallback. Approver public keys go into the verifier trust
set (see `docs/SIGNED_MANDATES.md`).

## Backward compatibility

Additive. Tokens issued without an approval are unaffected; the coordinator's
consume step is a no-op unless an `ApprovalService` is configured and a token
carries `auth_claims.approval_id`.
