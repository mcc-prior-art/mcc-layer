# MCC-Core Pilot v0.1 — Governed Agent

Release baseline for the first end-to-end governed AI agent built on MCC-Core.

## 1. Product purpose

Demonstrate, in running code, that an autonomous agent's external actions can be
governed end to end by MCC-Core: the agent proposes, MCC-Core decides, the
execution gate enforces, the governed HTTPS executor performs the request, and
the append-only audit chain records. Intent is not authority — a proposal is
never permission.

## 2. Architecture

```
User Goal
  → Governed Agent (src/mcc_agent: planner + supported client)
  → Structured Action Proposal
  → MCC-Core Governance Runtime (AuthorityModel → DecisionEngine → ExecutionGate
                                 → EnforcementCoordinator → ApprovalService)
  → ALLOW / DENY / ESCALATE / CONSTRAIN
  → Execution Gate (fail-closed)
  → Governed HTTPS Executor (egress_proxy.HTTPEgressExecutor: SSRF + TLS + audit)
  → External Pilot API (pilot_api: separate network service)
  → Audit Evidence (append-only hash chain)
```

The agent package (`src/mcc_agent/`) is a thin orchestrator: a deterministic
`planner`, typed `models`, a supported `client` (the `GovernanceClient`
protocol + an in-process `EmbeddedGovernanceClient`), and a `demo`. It holds no
executor, no signing key, performs no outbound networking, and imports no HTTP
client (enforced by a static test).

## 3. Supported governance outcomes

| Verdict | Meaning in the pilot |
|---------|----------------------|
| `ALLOW` | Trusted agent + in-bounds action → executed once. |
| `DENY` | An action no mandate can authorize (or a disallowed destination) → blocked, no execution. |
| `ESCALATE` | No standing mandate → human approval required; executes only after a valid, single-use approval. |
| `CONSTRAIN` | Over-cap value → clamped to the mandate bound, re-hashed; only the constrained payload executes. |

Default is fail-closed: without a verified ALLOW (or an approved/constrained
authorization), the gate does not open.

## 4. Execution path & security invariants

* **No verified decision → no execution.** The governed `HTTPEgressExecutor`
  refuses any call lacking a verified MCC authorization (`UnauthorizedExecution`).
* **Audit before actuation.** A durable audit write precedes execution; an audit
  failure fails closed (no execution).
* **No executor bypass.** The agent never calls an external API directly; the
  governed executor is the only outbound caller.
* **Replay / idempotency / nonce.** A reused nonce or idempotency key executes at
  most once.
* **CONSTRAIN integrity.** The clamped body is re-hashed and bound to the token;
  the original over-cap payload is never sent.
* **SSRF / TLS.** Loopback, link-local, private, IPv6 ULA, multicast,
  unspecified, metadata, IPv4-mapped, embedded-credential, malformed, and
  non-HTTPS-in-production destinations are blocked before connection (reusing the
  egress proxy's `validate_destination` + IP-pinned executor).
* **Fail-closed dependencies.** Redis-backed state unavailable → no execution, no
  in-memory fallback.

These are reused from `src/mcc_core/` and `egress_proxy/` — not reimplemented.

## 5. Deployment components

| Service | Image / command | Role |
|---------|-----------------|------|
| `redis` | `redis:7-alpine` | Nonce/idempotency/velocity/approval state. |
| `pilot-api` | `pilot_api.app:app` | The external enterprise API the agent acts upon. |
| `mcc-gateway` | `egress_proxy.app:app` | MCC-Core governed gateway: authority + gate + governed HTTPS executor + audit. |
| `mcc-agent` | `governed_agent_compose_demo.py` | The governed agent runner. |

`docker compose -f docker-compose.pilot.yml up --build` starts the stack. The
network model isolates the agent from the external API (only the gateway reaches
it).

## 6. Supported pilot scenarios

1. ALLOW — create CRM lead executes and reaches the external API.
2. DENY — prohibited action blocked; external state unchanged.
3. ESCALATE — pending approval → executes only after a valid approval; invalid /
   forged / expired / untrusted / mis-bound approvals do not authorize execution.
4. CONSTRAIN — over-cap budget clamped + re-hashed; original never sent.
5. BYPASS — direct executor / direct API call refused.
6. REPLAY — reused idempotency key executes exactly once.
7. REDIS FAILURE — fail closed, no execution, no fallback.
8. SSRF / UNSAFE DESTINATION — blocked before connection.
9. AUDIT FAILURE — audit-before-actuation holds; no execution.

## 7. Test results

The in-process pilot proves every scenario against a real loopback external API
through the real runtime:

```
PYTHONPATH=src python -m mcc_agent.demo        # 10/10 checks PASS
python -m pytest tests/test_mcc_agent.py tests/test_mcc_agent_no_direct_egress.py -q
                                               # 40 passed
MCC_REDIS_URL=redis://127.0.0.1:6399/0 python -m pytest tests/ -q   # full suite green
```

## 8. Evidence location

`evidence/governed_agent_pilot/` — scenario summary, structured proposals,
governance decisions, approval/constraint/execution results, external API
operation records, replay/Redis/SSRF/audit-failure results, audit-chain
verification, and a SHA-256 manifest (reproducible via
`python -m mcc_agent.demo --evidence`). All keys/fixtures are test-only; no
production secrets or personal data.

## 9. Known limitations

* The in-process pilot uses a per-action pilot `AuthorityModel` (configuration);
  the Docker gateway uses the egress proxy's host/method/amount authority. Both
  are the same MCC-Core engine, configured differently.
* The deterministic planner covers a fixed set of pilot goals (no LLM yet).
* Signing keys are ephemeral in the pilot; mandates are config-level.
* The Docker network boundary is a pilot illustration, not a production control.

## 10. Production hardening still required

* Persistent, rotated Ed25519 signing keys; signed, revocable mandates at scale.
* Network policy / service identity / workload isolation (e.g. Kubernetes
  NetworkPolicy, a service mesh, a firewalled egress subnet) in addition to the
  Docker network boundary.
* HTTPS-only egress to the external API (the pilot uses plain HTTP on a private
  network for convenience).
* An LLM planner behind the deterministic one, with the same proposal contract.
* Production observability/alerting (already available via `docs/OBSERVABILITY.md`).

## 11. Reproduction steps

```bash
# In-process pilot (no Docker, no credentials):
PYTHONPATH=src python -m mcc_agent.demo --evidence

# Full containerized pilot:
docker compose -f docker-compose.pilot.yml up --build
docker compose -f docker-compose.pilot.yml run --rm mcc-agent \
    python /app/governed_agent_compose_demo.py
curl http://localhost:9100/operations     # inspect external API state
```
