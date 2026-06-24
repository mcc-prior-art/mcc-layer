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
| `resource`, `policy_hash`, `nonce` | *(optional)* extra binding dimensions; **required to match when the operation supplies them** |
| `nbf` / `exp` | validity window |
| `kid` / `sig` | Ed25519 signature; the kid must be a trusted evaluator |

A vote signed by an untrusted key, bound to a different action/payload/actor, or
outside its window is ignored. Votes are non-secret signed attestations.

`resource`, `policy_hash`, and `nonce` are added to the signed claims only when
supplied to `issue_vote`. When the verifier is given them (the mandatory path
always is), a counted vote **must** carry a matching value — a vote that lacks
or mismatches a required dimension is rejected. The one-time `nonce` is what
makes the consensus *evidence itself* non-replayable: votes bound to a consumed
nonce cannot authorize a second operation.

## Policy & verdict

`ConsensusPolicy(threshold, veto_on_deny=True, on_fail=DENY)`:

* **threshold** distinct *trusted* `ALLOW` votes are required. `3-of-3
  unanimous` = `threshold=3` with three evaluators; `2-of-3` = `threshold=2`.
* any trusted `DENY` **vetoes** (when `veto_on_deny`).
* below threshold → `on_fail` (default `DENY`).
* `ESCALATE`/`CONSTRAIN` votes count as "not ALLOW" toward the threshold.

`ConsensusVerifier.verify(votes, action, payload, actor, resource=None,
policy_hash=None, nonce=None)` returns a `ConsensusResult` with the verdict, the
distinct ALLOW evaluators, the count of rejected votes, and a `consensus_hash`
(which itself covers `resource`/`policy_hash`/`nonce`). Fail-closed: any
exception → DENY.

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

## Mandatory consensus — enforced at the gate, not just before the token

The pre-token step above answers *"may we mint a token?"*. **Mandatory
consensus** answers the stronger question *"may this exact token actuate?"* —
and enforces it inside the execution path, where DENY means DENY.

When the coordinator is built with `require_consensus=True`, **no governed
action reaches actuation** unless a valid N-of-M consensus, bound to the
*issued token's* exact `action`, `actor_id`, `payload`, `resource_id`,
`policy_hash`, and one-time `nonce`, is supplied. The check runs immediately
after the gate verifies the token and consumes the nonce, **before** any
idempotency or velocity reservation, execution, or audit-before-actuation
record — and it fails closed:

```
token + votes → gate (verify + consume nonce) → revocation re-check
   → ✅ require_consensus: ConsensusVerifier.verify(votes, bound to the token)
        ├─ valid N-of-M ALLOW → record `consensus_verified` → continue
        └─ missing / <N / veto / duplicate / untrusted / bad-sig / expired
           / action·actor·resource·payload·policy·nonce mismatch / replayed
           → record `actuation_rejected` → BLOCKED (upstream never called)
   → idempotency → velocity → pre_actuation (audit) → execute → finalize
```

Because the votes are bound to the **token's one-time nonce**, the evidence is
single-use: replaying it against a fresh token (new nonce) fails the nonce
match, and replaying the same token fails at the gate (nonce already consumed).
A `consensus_verified` entry is written to the hash-chain *before* the
pre-actuation record, preserving audit-before-actuation.

The guarantee is path-independent: with mandatory consensus on, a path that
carries no votes (e.g. `/mandates/execute`) also fails closed — there is no way
to actuate without consensus.

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
  "idempotency_key": "op-1", "nonce": "nonce-abc123" }
```
→ `{ "status": "EXECUTED" | "BLOCKED", "reason": "…", "decision": "ALLOW", … }`.
A blocked decision never reaches the upstream. On the mandatory path the client
supplies the one-time `nonce`; the evaluators sign their votes over it, the
gateway issues the token carrying it, and the coordinator re-verifies the votes
against it.

## Deployment

| Env | Default | Notes |
|---|---|---|
| `MCC_CONSENSUS_TRUST_CONFIG` | *(unset)* | JSON trust set of **evaluator** public keys (same format as the mandate trust config); unset = consensus disabled |
| `MCC_CONSENSUS_THRESHOLD` | `3` | required distinct ALLOW votes |
| `MCC_REQUIRE_CONSENSUS` | `false` | when truthy, the coordinator refuses to actuate **any** governed action without valid consensus bound to the token. Setting it without `MCC_CONSENSUS_TRUST_CONFIG` **refuses startup** (no fail-open) |

Evaluator keys are independent of the mandate/approval trust roots, so the
contexts that vote are genuinely separate. Selecting consensus without a config
leaves it disabled (the `/consensus/*` endpoints fail closed). Enabling
`MCC_REQUIRE_CONSENSUS` makes consensus mandatory for the whole execution path;
the builder will not start fail-open if no evaluator trust set is configured.

## Domain neutrality

Consensus is generic: it votes over an `action_hash` + canonical `payload_hash`
+ `actor`, nothing domain-specific. It composes with every profile (payments,
infrastructure, robotics) and every other layer unchanged.

## Backward compatibility

Additive and opt-in. With no `MCC_CONSENSUS_TRUST_CONFIG` the feature is
disabled and nothing changes; with `MCC_REQUIRE_CONSENSUS` unset the coordinator
behaves exactly as before. The new vote dimensions (`resource`/`policy_hash`/
`nonce`) are only enforced when supplied, so existing votes and the reproducible
3-of-3 evidence package remain valid. Tokens issued via consensus carry an extra
`auth_claims.consensus` record (signature-covered); the gate does not require
it. The four verdicts and the decision model are unchanged.
