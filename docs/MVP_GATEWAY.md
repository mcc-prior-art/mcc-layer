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
                      +-- verify signed token through ExecutionGate
                      |     (Ed25519 signature + audience + expiry +
                      |      action/payload-hash + single-use nonce)
                      +-- ALLOW      -> forward original body
                      +-- CONSTRAIN  -> forward REWRITTEN body (clamped to cap)
                      +-- DENY/ESCALATE or any error -> 403/502, upstream never reached
```

Drop-in: point the agent's `HTTP_PROXY` / base URL at MCC. Client code is not
touched; interception happens on the network. Identity arrives via
`X-MCC-Identity` (in production: mTLS client cert / signed workload identity).
The governing logic (`ActionMapper`, `EgressGovernor`) is socket-free and
unit-tested; the forwarding layer is thin.

**The token is enforced, not trusted.** On the inline path the proxy does not
act on the gateway's word — it verifies the Ed25519-signed decision token
through `ExecutionGate` before forwarding: signature against the gateway's
trusted key, audience, expiry, the action/payload-hash binding, and a
single-use nonce (replay protection). The proxy keys its gate from the
gateway's `/health` at startup. If the token does not verify, or no gate is
configured, the request is blocked — fail-closed.

**CONSTRAIN actually rewrites the request.** When a mandate caps `amount` at
5000 and the agent asks for 99000, the gateway clamps the body to
`{"amount": 5000}`, signs the token over the *clamped* body, and returns it as
`forward_context`. The proxy forwards exactly that — so the gate's payload-hash
check and the upstream both see 5000. CONSTRAIN is enforcement, not a header.

### Run the end-to-end demo / smoke test

```bash
python examples/egress_proxy_demo.py
```

Starts a real upstream, gateway (inline), and proxy on loopback and drives
four requests through. It **asserts** the outcomes and exits non-zero on any
miss, so it doubles as the CI smoke test (`smoke` job in
`.github/workflows/mcc-runtime-ci.yml`):

- ALLOW → reaches upstream
- CONSTRAIN → reaches upstream with the body **rewritten** to the cap (5000)
- DENY / ESCALATE → blocked at the proxy; upstream never sees them

---

## Known limitations (honest list)

- **Constraint rewriting covers numeric clamps only.** `max_`/`min_` on a
  present numeric field are clamped (this is what CONSTRAIN applies). An
  `allowed_` violation or a missing/non-numeric field has no safe value to
  invent, so it fails closed to **DENY** rather than forwarding something
  non-conforming. Richer, action-specific rewriting (e.g. currency, recipient
  allowlists) is future work.
- **Replay protection backend is selectable.** The proxy's `ExecutionGate`
  picks its nonce registry from the environment (`nonce_registry_from_env`):
  `MCC_NONCE_BACKEND=memory` (default) uses the single-process
  `InMemoryNonceRegistry`; `MCC_NONCE_BACKEND=redis` + `MCC_REDIS_URL` uses
  `RedisNonceRegistry`, whose atomic `SET NX EX` on a shared Redis rejects
  replays **across every proxy/gate instance**. Multi-instance enforcement
  deployments must select Redis — the registry never silently falls back from
  Redis to in-memory, and an unreachable Redis fails closed (denied), it does
  not downgrade. See `RUNTIME_DEPLOYMENT.md` → *Nonce replay protection*.
- **HTTPS interception** requires the proxy to terminate TLS (the agent trusts
  the proxy CA) or be given absolute-form requests. The MVP targets HTTP and
  TLS-terminating deployments.
- **Observe mode is deliberately non-enforcing.** In observe the proxy is
  transparent: it forwards the original request unchanged and never blocks,
  even on a gateway error. The fail-closed guarantee is an *inline*-mode
  property; observe exists to build the audit record in shadow first.
- **Pilot mandates are hardcoded.** Intentional for one client; needs a
  verifiable mandate store (each mandate itself signed) before multi-tenant.
