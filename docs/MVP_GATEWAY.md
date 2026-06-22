# MCC-Core MVP — Gateway, Authority Model, and the One Interceptor

> The model proposes.
> MCC-Core decides.
> The gate enforces.
> The audit chain records.

The decision engine, Ed25519 token signing, hash-chained audit, and the
fail-closed gate already existed. The MVP adds the two things that live
*around* the gate and turn it into a product:

1. **An authority model** — how a verdict comes to exist.
2. **One interceptor** — how an action physically passes through the gate.

---

## 1. The hard truth about enforcement (read this first)

A decorator (`@mcc.govern`) and a webhook step (Make/n8n) are **opt-in on
every action**. The agent can simply *not call you* on the dangerous step —
and then MCC is a recommendation, not enforcement. You will have sold
"control" that is bypassed by one line of config.

> **DENY means DENY only when you own the execution path.**

That is why the MVP ships **exactly one** interceptor: the **egress proxy**.
The agent's outbound calls physically pass through it. A DENY is a connection
the upstream never sees. There is no opt-out, because the agent does not own
the path — MCC does.

The other interceptors (MCP proxy, SDK decorator, webhook node) are real and
useful, but they are *distribution*, not *enforcement*. Build them when a
client needs them; never let them be mistaken for the proxy's guarantee.

---

## 2. Authority model — where a verdict comes from

`ALLOW / DENY / ESCALATE / CONSTRAIN` are meaningless without a statement of
*which action requires which authority*. A verdict in MCC-Core does **not**
come from a bare condition like `amount <= 5000`. It comes from a mandate:

> An identity presents an action.
> MCC-Core checks whether that identity holds a **verified mandate** for the
> authority the action requires.
> The verdict follows. The decision is signed. It goes in the journal.

Two declarative pieces (`src/mcc_core/authority.py`), no DSL:

- **Mandate registry** — `identity → [granted authorities (+ constraints, expiry)]`.
- **Action policies** — ordered `action-pattern → required authority → verdicts`:
  - holds a valid mandate, context within its constraints → `on_mandate` (default **ALLOW**)
  - holds a valid mandate, context breaches a constraint → `on_violation` (default **CONSTRAIN**)
  - no valid mandate for the required authority → `without_mandate` (default **ESCALATE**)
  - `requires: null` (no mandate can ever authorize, e.g. irreversible delete) → `without_mandate` (set to **DENY**)
  - no policy matches → **DENY** (deny-by-default)

On a pilot this is hardcoded for one client: `gateway/pilot_policy.py`. When
the second client arrives, that file forks — the engine, gateway, and
interceptor do not.

The exact authority config is hashed (`policy_hash`) and embedded in every
decision token, so a token is cryptographically bound to the policy that
produced it; the execution gate rejects tokens issued under any other policy.

---

## 3. The gate as a service

`gateway/app.py`

```
POST /evaluate   {identity, action, context}
              -> {decision, reason, signature, audit_id,
                  decision_token, constraints, enforce, ...}
GET  /verify     -> recompute the audit hash chain, report integrity
GET  /export     -> hand the signed append-only log to an auditor
GET  /health
```

- ALLOW / CONSTRAIN return an **Ed25519-signed decision token**; DENY /
  ESCALATE never do (no token, no execution).
- Every evaluation is written to the append-only hash-chain audit log
  **before** any authority is released. Audit-write failure → DENY.
- Token-issuance failure → DENY (downgrade is itself audited).

### Two modes

| Mode      | `enforce` | Behavior                                                        |
|-----------|-----------|-----------------------------------------------------------------|
| `inline`  | `true`    | The interceptor enforces. DENY/ESCALATE block.                  |
| `observe` | `false`   | Decisions are computed and recorded, **not** enforced.          |

`observe` lets a client run MCC in shadow over real traffic, build the audit
record, and see exactly what *would* have been blocked — before it is trusted
to block. Set per deployment (`MCC_GATEWAY_MODE`) or per request (`mode`).

---

## 4. The interceptor — egress proxy

`interceptors/egress_proxy.py`

```
agent --HTTP--> [ MCC egress proxy ] --HTTP--> upstream
                      |
                      +-- map request -> (identity, action, context)
                      +-- POST /evaluate
                      +-- ALLOW / CONSTRAIN -> forward (carry token)
                      +-- DENY  / ESCALATE  -> 403, upstream never reached
```

Drop-in: point the agent's `HTTP_PROXY` / base URL at MCC. Client code is not
touched; interception happens on the network. Identity arrives via
`X-MCC-Identity` (in production: mTLS client cert / signed workload identity).
The governing logic (`ActionMapper`, `EgressGovernor`) is socket-free and
unit-tested; the forwarding layer is thin.

### Run the end-to-end demo

```bash
python examples/egress_proxy_demo.py
```

Starts a real upstream, gateway (inline), and proxy on loopback and drives
four requests through. ALLOW and CONSTRAIN reach the upstream; DENY and
ESCALATE never do — proven by what the upstream actually saw.

---

## Known limitations (honest list)

- **CONSTRAIN is surfaced, not yet applied.** The proxy forwards a CONSTRAIN
  with the mandate's bounds in `X-MCC-*` headers but does **not** rewrite the
  request body (e.g. clamp the amount to the cap). Until body rewriting lands,
  a CONSTRAIN behaves like a conditional ALLOW that advertises its bound. This
  is the first thing to harden for any payments pilot.
- **HTTPS interception** requires the proxy to terminate TLS (the agent trusts
  the proxy CA) or be given absolute-form requests. The MVP targets HTTP and
  TLS-terminating deployments.
- **Token re-verification at the proxy** is optional in the MVP: the proxy and
  gateway share a trust domain and the proxy enforces the returned decision
  directly. Wiring the proxy through `ExecutionGate` (signature + nonce) closes
  the loop fully and is the natural next step.
- **Pilot mandates are hardcoded.** Intentional for one client; needs a
  verifiable mandate store (each mandate itself signed) before multi-tenant.
