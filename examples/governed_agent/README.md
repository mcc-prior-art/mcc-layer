# Governed Agent — end-to-end demo

> The model proposes. MCC decides. The gate enforces. The audit chain records.
>
> **The executor acts only after a verified MCC decision.**

A small, deterministic, runnable example proving that **MCC-Core sits between an
AI agent and an executor**. The agent never calls the executor directly: it only
*proposes*; MCC-Core decides (`ALLOW` / `DENY` / `ESCALATE` / `CONSTRAIN`); the
execution gate enforces; and the mock executor runs **only** through that
governed path, only after a verified decision and a written audit record.

It uses the **real** MCC-Core runtime already in this repository — `AuthorityModel`
(verdicts + constraint rewriting), `DecisionEngine` (Ed25519 token),
`ExecutionGate` (signature + audience + expiry + payload-hash + one-time nonce),
`EnforcementCoordinator` (idempotency + velocity + audit-before-actuation +
single-use approval consume), `ApprovalService` (the ESCALATE loop), and the
nonce / idempotency / velocity / approval registries (in-memory or Redis-backed).
No governance logic is re-implemented in the example.

There are two governed paths:

```
Basic:               Agent → MCC → Gate → Executor
Consensus-required:  Agent → Challenge → N-of-M Consensus → MCC → Gate → Executor
```

The consensus-required path uses the real `ChallengeService`, `ConsensusVerifier`,
and the coordinator's `require_consensus` / `require_challenge` gates — there is
**no demo-only verifier or second consensus engine**. Consensus is an
*additional required predicate*: it does **not** replace mandate authority,
approvals, nonce, idempotency, velocity, the gate, or audit.

## What this proves

- An agent cannot execute on its own authority — **no verified decision, no execution**.
- The agent never issues its own challenge and never signs evaluator votes — it **cannot self-authorize consensus**. The gateway issues the challenge; an independent `EvaluatorPool` (separate keys) signs votes.
- There is **no agent→executor path**: the executor is only reachable via the gate/coordinator, and it refuses any call without a verified decision token.
- All four verdicts behave correctly, including `CONSTRAIN` rewriting the body so the executor receives only the **authorized** payload (never the original unsafe one).
- Replay (one-time nonce), idempotency (exactly-once + conflicting binding), velocity, and single-use approvals all **fail closed**.
- Redis-backed governance state is **one shared state across two runtime instances**; with required Redis unavailable, execution **fails closed** — no silent in-memory fallback.
- Malformed / unknown decisions never execute, and successful executions carry **audit linkage**.

## Architecture

```
Agent  (proposes only; no credentials, no executor reference)
  │  ProposedAction { actor, action, resource, payload, transaction_id,
  │                   idempotency_key, nonce, correlation_id, policy/authority ctx }
  ▼
GovernedMCCClient  (the ONLY path; wiring + fail-closed dispatch, no decisions)
  ├─ AuthorityModel.evaluate ─────────► ALLOW | DENY | ESCALATE | CONSTRAIN
  │                                         (CONSTRAIN rewrites forward_context)
  ├─ DecisionEngine.issue_token  (Ed25519, over the AUTHORIZED body, binds nonce)
  └─ EnforcementCoordinator.enforce
        ├─ ExecutionGate.verify   (signature, audience, expiry, payload-hash, nonce consume)
        ├─ (ESCALATE) ApprovalService single-use approval consume
        ├─ idempotency reserve     (exactly-once / conflicting-binding fail-closed)
        ├─ velocity reserve        (aggregate ceilings)
        ├─ audit-before-actuation  (hash-chain, fsync)
        └─ executor()  ─────────► Mock Executor   (records authorized payload)
```

### Sequence (Mermaid)

```mermaid
sequenceDiagram
    actor Agent
    participant Client as GovernedMCCClient
    participant MCC as MCC-Core (AuthorityModel)
    participant Gate as ExecutionGate + Coordinator
    participant Audit as Audit chain
    participant Exec as Mock Executor

    Agent->>Client: propose(action, payload, nonce, idem, txn)
    Client->>MCC: evaluate(actor, action, context)
    MCC-->>Client: verdict (+ authorized/constrained body)
    alt DENY or unresolved ESCALATE or malformed
        Client-->>Agent: BLOCKED (no execution)
    else ALLOW / CONSTRAIN (or approved ESCALATE)
        Client->>Gate: enforce(signed token, executor)
        Gate->>Gate: verify signature, audience, expiry, payload-hash
        Gate->>Gate: consume one-time nonce; idempotency; velocity; approval
        Gate->>Audit: pre-actuation record (hash-chain, fsync)
        Gate->>Exec: execute(action, AUTHORIZED payload, token)
        Exec-->>Gate: executed
        Gate->>Audit: actuation result
        Client-->>Agent: COMPLETED (+ audit correlation)
    end
```

### Consensus-required path (Mermaid)

```mermaid
sequenceDiagram
    actor Agent
    participant Client as GovernedMCCClient (gateway)
    participant Pool as EvaluatorPool (independent)
    participant MCC as ConsensusVerifier + AuthorityModel
    participant Gate as Gate + Coordinator
    participant Exec as Mock Executor

    Agent->>Client: propose(action, payload)
    Client->>Client: issue_challenge (gateway-issued, nonce-bound)
    Client-->>Pool: challenge (action/actor/resource/payload_hash/policy_hash)
    Pool-->>Client: N independent signed votes (bound to the challenge nonce)
    Client->>MCC: enforce(token, votes)
    MCC->>MCC: verify N-of-M (signatures, identity uniqueness, trust, bindings, expiry, veto)
    alt below threshold / forged / duplicate / mismatch / expired / veto
        MCC-->>Agent: BLOCKED (no execution)
    else valid threshold
        MCC->>Gate: authority + nonce + challenge consume + idempotency + velocity + audit
        Gate->>Exec: execute(action, authorized payload, token)
        MCC-->>Agent: COMPLETED
    end
```

What MCC verifies for each vote (the real `ConsensusVerifier` semantics):
signatures, **evaluator identity uniqueness**, **trust membership**, **N-of-M
threshold**, binding to **action / payload / actor / resource / policy_hash /
nonce(challenge)**, the **validity window**, and **veto** (any trusted DENY is
decisive). The one-time challenge nonce makes the evidence non-replayable.

## Why the agent cannot execute directly

The agent holds no signing key, no credentials, and **no reference to the
executor**. The executor's only entrypoint requires an `authorization` — the
Ed25519 decision token MCC issued for that exact operation — and refuses any
call without one (`UnauthorizedExecution`). The token is produced only after
`AuthorityModel` returns an executable verdict and the gate verifies it. So the
sole route to the executor is: propose → decide → enforce → execute.

## How to run

```bash
# the demo (prints a human-readable trace; memory mode, no services needed)
python examples/governed_agent/scenarios.py

# the tests
python -m pytest tests/examples/test_governed_agent.py -q

# multi-instance against a REAL Redis (the @skipif real-Redis test then runs)
redis-server --port 6399 --save "" &
MCC_REDIS_URL=redis://127.0.0.1:6399/0 python -m pytest tests/examples/test_governed_agent.py -q
```

## Environment variables

| Variable | Default | Effect |
|---|---|---|
| `MCC_REDIS_URL` | *(unset)* | Enables the real-Redis multi-instance test. When set, the example's Redis-backed registries share state across instances. `rediss://` enables TLS. |
| `MCC_ENV` / `MCC_REDIS_NAMESPACE` | `default` | Canonical key namespace / trust-domain segment (see `docs/REDIS_GOVERNANCE.md`). |

The demo prints **no** secrets, signing keys, tokens, or sensitive config.

## Memory mode vs Redis mode

- **Memory mode** (default): in-memory registries — single process, deterministic, perfect for the demo and unit tests. Replay/idempotency/velocity hold **within one process only**.
- **Redis mode**: pass Redis-backed registries (`RedisNonceRegistry`, `RedisIdempotencyRegistry`, …). State is shared across instances, so a nonce consumed by instance A is rejected by instance B. Required-Redis-unavailable → fail closed (no fallback). See `docs/REDIS_GOVERNANCE.md`.

## Fail-closed behavior

Every one of these yields a non-executing result (the executor is never called):
missing required field, unknown/malformed verdict, runtime error, `DENY`,
unresolved `ESCALATE`, replayed nonce, duplicate or conflicting idempotency
binding, velocity breach, forged/expired/mismatched/replayed approval,
audit-write failure, and Redis-required-but-unavailable.

## Scenarios and expected results

| # | Scenario | Expected |
|---|---|---|
| 1 | **ALLOW** (valid mandate, in bounds) | executes exactly once |
| 2 | **DENY** (destructive / no policy) | never executes |
| 3 | **ESCALATE** (no mandate) | blocked; valid approval → executes once; forged/replayed approval → rejected |
| 4 | **CONSTRAIN** (amount over cap) | executes with the **clamped** payload; original never executed |
| 5 | **Replay** (same nonce) | second attempt blocked |
| 6 | **Idempotency** (same key) | duplicate blocked; conflicting binding fails closed |
| 7 | **Velocity** (over `max_count`) | breach blocked with the runtime verdict (`DENY`) |
| 8 | **Multi-instance** (shared Redis) | nonce consumed on A → rejected on B |
| 9 | **Redis required & down** | execution fails closed; no in-memory fallback |
| 10 | **Malformed/unknown verdict** | never executes |
| 11 | **Consensus-required** | valid N-of-M → continues to authority/gate/executor; below-threshold / forged / untrusted / duplicate / wrong-challenge / wrong-action / wrong-payload / wrong-actor / expired / veto / replayed-challenge → DENY; valid consensus on a DENY/ESCALATE action still blocks (consensus ≠ bypass) |

### Configuration (consensus mode) — explicit and fail-closed

| Setting | Effect |
|---|---|
| `consensus_required=True` | the coordinator runs with `require_consensus` + `require_challenge`: no actuation without a valid N-of-M bound to a gateway-issued, single-use challenge. |
| `trusted_evaluators` (kid → Ed25519 public key) | the evaluator trust set. **Required** when `consensus_required=True` — absent/empty → startup refused (no silent non-consensus fallback). |
| `consensus_threshold` (N) | distinct trusted ALLOW votes required; `N > len(trusted_evaluators)` → startup refused. |

The agent does not receive or control any of these; the gateway/runtime owns the
challenge service and the trust set.

## What is executed in the live runtime path now

The example drives the **real** runtime end to end, in both modes:

- **Basic path:** AuthorityModel verdict → Ed25519 token → ExecutionGate
  (signature/audience/expiry/payload-hash/one-time nonce) → idempotency →
  velocity → audit-before-actuation → executor; ESCALATE via the single-use
  ApprovalService.
- **Consensus path (now wired):** gateway `ChallengeService.issue` →
  independent evaluator votes → real `ConsensusVerifier` N-of-M (inside the
  coordinator's `require_consensus`) → single-use challenge consume
  (`require_challenge`) → the same authority/gate/nonce/idempotency/velocity/
  audit path → executor.

## Current limitations

- **Consensus + `CONSTRAIN`:** consensus is verified over the *proposed* body.
  If MCC `CONSTRAIN`s (rewrites) the payload, the executed body differs from
  what the evaluators approved, so the binding no longer matches and it **fails
  closed** — a *safe* outcome (evaluators never consented to the clamped body),
  not a silent rewrite. A "re-consent after constraint" flow is a possible
  follow-up. The consensus demo therefore exercises the `ALLOW` path.
- **Consensus + ESCALATE approval execution:** with `consensus_required=True`,
  `execute_with_approval` must also carry challenge + votes (otherwise the
  coordinator fails closed for missing consensus). The demo shows that valid
  consensus does **not** turn an ESCALATE into an ALLOW; it does not wire the
  combined approval+consensus execution (left explicit for the next PR).
- `ESCALATE` here means "no standing mandate → human approval required." The
  approval is consumed single-use and bound to action/transaction/payload by the
  coordinator; the example relies on that binding rather than re-verifying the
  approval mandate's signature a second time (the gateway's `execute_with_approval`
  does the extra signature step).
- The demo's authority config is a small in-process `AuthorityModel`; production
  authority would be a verifiable/signed mandate store (the lookup contract is
  identical).

## Trust / configuration assumptions (consensus mode)

- The runtime verifies **cryptographically signed votes from distinct trusted
  evaluator identities** — signatures, identity uniqueness, trust membership,
  threshold, bindings, expiry, veto. It does **not** guarantee organizational,
  operational, or model-level **independence** of the evaluators; that is a
  deployment/governance property, not a software guarantee.
- The evaluator **trust set** (public keys) and the **challenge service** are
  owned by the gateway/runtime, never the agent. Their integrity is a deployment
  responsibility; a compromised evaluator key set weakens consensus to the
  number of honest distinct keys.
- The decision-token signing key, evaluator keys, and (in Redis mode) Redis must
  be deployed securely.

## Residual risks

- Memory mode is single-instance only; multi-instance enforcement **requires**
  Redis mode (and a securely deployed Redis — auth/TLS/network/HA).
- This demo proves runtime governance behavior; it does **not** claim production
  certification or that the surrounding deployment is secure. **Not** production-certified.
- A compromised signing key, evaluator trust set, or Redis would compromise the
  guarantees — key and state management are deployment responsibilities.

## Mapping to domains (without making the core domain-specific)

MCC-Core is **domain-neutral**: it governs `(actor, action, resource, payload)`
with numeric/`allowed_` constraints. The same flow maps to:

- **Fintech** — `action="send_payment"`, `payload={"amount", "beneficiary"}`, a mandate `max_amount` cap → `CONSTRAIN` clamps the amount; velocity caps anti-split.
- **Robotics** — `action="move_arm"`, `payload={"force", "zone"}`, constraints `max_force` / `allowed_zone` → `CONSTRAIN` or `DENY`.
- **Infrastructure** — `action="scale_cluster"` / `delete_database`, constraints `max_nodes`, `requires=none` → hard `DENY` for irreversible actions.

In every case the *core* sees only generic fields and the four verdicts; the
domain lives in the profile/constraint config, never in the engine.
