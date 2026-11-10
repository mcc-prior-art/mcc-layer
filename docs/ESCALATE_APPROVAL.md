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

### Route-independent enforcement (R1 remediation)

The approval binding is a property of the **signed mandate**, not of the route
it is presented on. The approver key is trusted in the same `TrustSet` as
ordinary mandate issuers, so an approval-minted mandate also verifies on
`POST /mandates/execute`. Before the R1 fix, only `execute_with_approval` put
`approval_id` into the decision token, so the same mandate on the plain
mandate route ran as a reusable standing grant: no payload binding, no
single-use consume, and no invalidation check (internal red-team cases V05,
V16 ×3).

Now:

* `MandateVerifier` derives the approval binding from the signature-covered
  claims (`approval_id`, `single_use`, `action_hash`, `payload_hash`,
  `transaction_id`). If any one is present, all must be present and
  well-formed, with `single_use == true`. Otherwise →
  `MALFORMED_APPROVAL_MANDATE`. A partial binding is never downgraded to a
  standing grant. `MandateAuthority` returns the binding on its decision.
* `GovernanceService.execute_with_mandate`, which both execute routes go
  through, rejects a different action (`APPROVAL_ACTION_MISMATCH`), any final
  executable payload whose hash after a CONSTRAIN rewrite is not the approved
  `payload_hash` (`APPROVAL_PAYLOAD_MISMATCH`), and a different
  `transaction_id`. It fails closed if no approval service can consume the
  approval, and always writes the mandate's own
  `approval_id` into the token's `auth_claims`. That claim is written last,
  so nothing can override it.
* `EnforcementCoordinator` atomically consumes that approval before actuation.
  A token that names an `approval_id` on a coordinator with no
  `ApprovalService` is `BLOCKED`, not executed.
* `POST /approvals/{request_id}/execute` additionally requires the mandate's
  `approval_id` to equal the path `request_id`.

Tests: `tests/test_r1_approval_mandate_binding_http.py`.

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

## Independent authority-side policy (unattended ESCALATE)

`approve(request_id)` has exactly two legitimate authority models:

1. **Explicit human approval** — an authenticated operator reviews the
   request and decides. This is the operator workflow above, unchanged.
2. **Independent authority-side policy** — for an unattended deployment with
   no human in the loop (e.g. a demo sidecar that polls for pending
   escalations), `ApprovalService` can be constructed with an
   `authority_policy: AuthorityPolicy` (`mcc_core.authority_policy`). When
   set, `approve()` additionally requires the policy's own `ALLOW` for the
   record's exact, server-stored `tenant_id`/`actor`/`action`/`resource`/
   `payload`/`policy_hash` and its `request_id` as the logical-operation
   identity — never anything the caller of `approve()` supplies. No
   matching rule (including an unconfigured policy) is `DENY`; the record
   stays `PENDING`.

This closes a gap an unattended operator sidecar would otherwise have: an
operator key alone authenticates *who* may call approve, not *whether this
exact operation* should be approved. Holding the operator key must never be
sufficient by itself to rubber-stamp whatever a (possibly compromised)
proposer caused to be escalated — `AGENT-CONTROLLED INPUT != AUTHORITY
DECISION`.

`AuthorityPolicy.from_file(path)` loads a small JSON ruleset (`rules`: each
with `action`, `tenant`, `actors`, `resource_pattern`, and optional
`payload_bounds` with `in`/`eq`/`max`/`min` operators). It is deliberately
narrow and explicit — there is no implicit "any actor"/"any tenant" wildcard,
an empty `rules` list is rejected at load time (ambiguous, not "unrestricted"),
and a missing/malformed file raises `AuthorityPolicyError` rather than
silently proceeding without one. See `deploy/pilot/authority_policy.notify.json`
/ `authority_policy.egress.json` for the shape the three pilot demos ship,
and `MCC_AUTHORITY_POLICY_CONFIG` / `MCC_EGRESS_AUTHORITY_POLICY_CONFIG` for
how each gateway loads it — set ONLY on the gateway service, never on an
agent or operator container.

The unattended operator scripts (`deploy/pilot/gateway_approval_operator.py`,
`deploy/pilot/governed_agent_pilot_operator.py`) read only the pending
request's `request_id` from agent-written coordination state and call
`approve`; they never read or trust any other field in that file, and they
never hold an execute-capable credential (approving mints a mandate, it does
not actuate — the proposer that owns the original operation performs its own
subsequent `execute` call with its own credential).

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

Additive. Tokens issued without an approval are unaffected, and so are
ordinary (non-approval) mandates on `/mandates/execute`. Since the R1 fix, a
token that carries `auth_claims.approval_id` on a coordinator with no
`ApprovalService` is `BLOCKED` (fail-closed); previously the consume step was
silently skipped. An approval-minted mandate presented on `/mandates/execute`
is now consumed single-use, exactly as on `/approvals/{id}/execute`.
