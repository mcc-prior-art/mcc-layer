# Multi-Context Consensus (N-of-M)

A single authority source — a policy, a mandate, an approval — is **one
opinion**. Multi-Context Consensus requires several *independent* evaluators,
each its own trust context with its own Ed25519 key, to agree before authority
is granted. No single evaluator, and no single compromised key, can manufacture
a decision.

> The model proposes. **Multiple independent contexts must concur.** MCC-Core
> decides. The gate enforces. The audit chain records.

It is a **pre-token authority step**: consensus produces the verdict that
justifies issuing a decision token. It does **not** change the four verdicts,
the token, the gate, or the coordinator. The decision token (and the entire
existing execution path) only runs once consensus is reached:

```
proposal → [ N-of-M signed evaluator votes ] → consensus verdict
         → decision token → gate → audit-before-actuation → coordinator → upstream
```

## Votes

Each evaluator emits a signed `ConsensusVote` (`mcc_core.issue_vote`) bound to
the exact operation:

| Field | Meaning |
|---|---|
| `evaluator_id` | the voting context's id (one ballot per evaluator) |
| `verdict` | `ALLOW` / `DENY` / `ESCALATE` / `CONSTRAIN` |
| `action_hash`, `payload_hash`, `actor` | binds the vote to *this* operation |
| `nbf` / `exp` | validity window |
| `kid` / `sig` | Ed25519 signature; the kid must be a trusted evaluator |

A vote signed by an untrusted key, bound to a different action/payload/actor, or
outside its window is ignored. Votes are non-secret signed attestations.

## Policy & verdict

`ConsensusPolicy(threshold, veto_on_deny=True, on_fail=DENY)`:

* **threshold** distinct *trusted* `ALLOW` votes are required. `3-of-3
  unanimous` = `threshold=3` with three evaluators; `2-of-3` = `threshold=2`.
* any trusted `DENY` **vetoes** (when `veto_on_deny`).
* below threshold → `on_fail` (default `DENY`).
* `ESCALATE`/`CONSTRAIN` votes count as "not ALLOW" toward the threshold.

`ConsensusVerifier.verify(votes, action, payload, actor)` returns a
`ConsensusResult` with the verdict, the distinct ALLOW evaluators, the count of
rejected votes, and a `consensus_hash`. Fail-closed: any exception → DENY.

### What an attack looks like (all fail closed)
| Attack | Defense |
|---|---|
| forged vote | untrusted kid / bad signature → ignored |
| one evaluator stuffing the ballot | **distinct** evaluator_id; duplicate ballots ignored |
| vote substitution / replay onto another op | action_hash / payload_hash / actor binding |
| stale vote | validity window |
| a lone evaluator or key | cannot reach a threshold ≥ 2 alone |

## Token binding & audit

On consensus, the issued token's `auth_claims.consensus` records
`{threshold, agreement, evaluators, consensus_hash}` — a signature-covered,
auditable record of *which* contexts concurred (no key material). The gate,
nonce, idempotency, velocity, and audit-before-actuation steps then run exactly
as for any other token.

## HTTP API

| Method | Endpoint | Boundary |
|---|---|---|
| `POST` | `/consensus/verify` | agent — pure check; returns the verdict + evaluators |
| `POST` | `/consensus/execute` | agent — execute only on consensus, through the one coordinator path |

```json
POST /consensus/execute
{ "votes": [ {/* signed vote */}, … ], "actor": "agent/ops",
  "action": "deploy_release", "resource": "cluster-1",
  "context": { "target": "cluster-1", "environment": "prod" },
  "idempotency_key": "op-1" }
```
→ `{ "status": "EXECUTED" | "BLOCKED", "reason": "…", "decision": "ALLOW", … }`.
A blocked decision never reaches the upstream.

## Deployment

| Env | Default | Notes |
|---|---|---|
| `MCC_CONSENSUS_TRUST_CONFIG` | *(unset)* | JSON trust set of **evaluator** public keys (same format as the mandate trust config); unset = consensus disabled |
| `MCC_CONSENSUS_THRESHOLD` | `3` | required distinct ALLOW votes |

Evaluator keys are independent of the mandate/approval trust roots, so the
contexts that vote are genuinely separate. Selecting consensus without a config
leaves it disabled (the `/consensus/*` endpoints fail closed).

## Domain neutrality

Consensus is generic: it votes over an `action_hash` + canonical `payload_hash`
+ `actor`, nothing domain-specific. It composes with every profile (payments,
infrastructure, robotics) and every other layer unchanged.

## Backward compatibility

Additive and opt-in. With no `MCC_CONSENSUS_TRUST_CONFIG` the feature is
disabled and nothing changes. Tokens issued via consensus carry an extra
`auth_claims.consensus` record (signature-covered); the gate does not require
it. The four verdicts and the decision model are unchanged.
