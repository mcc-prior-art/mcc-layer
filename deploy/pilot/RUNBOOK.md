# MCC-Core Pilot Runbook

A deterministic, copy-pasteable guide to running the unified governance runtime
as a real execution-control layer: the gateway + Redis (+ a governed echo
upstream), with fail-closed startup and the four governance paths.

> One runtime. No parallel engine, no demo-only verifier, no second coordinator,
> no executor bypass. See `docs/unified-governance-runtime.md`.

Everything below is run from the repository root unless noted.

-----

## 0. Prerequisites

- Docker + Docker Compose v2 (`docker compose version`).
- Python 3.11 + `pip install -r requirements-dev.txt` (for the local config
  generator, the SDK, and the reference integration).
- Free local ports: `8001` (gateway), `6379` (Redis), `9100` (echo upstream).

-----

## 1. Generate keys and trust configs (no secrets committed)

```bash
python deploy/pilot/generate_pilot_config.py
```

This writes, into `deploy/pilot/secrets/` (git-ignored, mode-0600 keys):

| File | Contents |
|---|---|
| `gateway_signing.pem` | decision-token signing key (private) |
| `approver_signing.pem` | approval-mandate issuer key (private) |
| `mandate_issuer_signing.pem` | mandate issuer key — sign pilot mandates with this (private) |
| `evaluator_{1..3}.pem` | independent consensus evaluator keys (private) |
| `trust.pilot.json` | mandate trust set — **public** keys only |
| `consensus_trust.json` | consensus evaluator trust set — **public** keys only |

Nothing here is committed (`deploy/pilot/.gitignore`). Rotate by re-running with
`--force` (and rolling the trust configs).

## 2. Configure API keys

```bash
cp deploy/pilot/.env.example deploy/pilot/.env
# edit deploy/pilot/.env: set MCC_GATEWAY_API_KEY and MCC_GATEWAY_OPERATOR_API_KEY
```

`.env` holds only the two API keys. Leaving `MCC_GATEWAY_OPERATOR_API_KEY` empty
disables **all** operator actions (approve/deny/revoke/trust) — fail-closed.

-----

## 3. Start

```bash
docker compose -f deploy/pilot/docker-compose.yml up --build -d
```

The gateway starts only when its required dependencies are satisfied
(fail-closed startup):

- `MCC_ENV=pilot` ⇒ a valid mandate trust set is **required** (`MCC_TRUST_CONFIG`);
- `MCC_REQUIRE_CONSENSUS=1` ⇒ a consensus verifier is **required**
  (`MCC_CONSENSUS_TRUST_CONFIG`) — no fail-open;
- the Redis-backed registries **require** `MCC_REDIS_URL`;
- the container is `healthy` only once `/ready` returns 200 (Redis reachable,
  trust + verifier + signing loaded).

Watch it become ready:

```bash
docker compose -f deploy/pilot/docker-compose.yml ps
```

### Verifying fail-closed startup (optional)

Break a requirement and observe the refusal:

```bash
# Remove the consensus trust file and restart the gateway -> it refuses to start.
mv deploy/pilot/secrets/consensus_trust.json /tmp/ct.json
docker compose -f deploy/pilot/docker-compose.yml up -d mcc-gateway
docker compose -f deploy/pilot/docker-compose.yml logs mcc-gateway | tail -5   # RuntimeError: refusing fail-open startup
mv /tmp/ct.json deploy/pilot/secrets/consensus_trust.json                       # restore
docker compose -f deploy/pilot/docker-compose.yml up -d mcc-gateway
```

-----

## 4. Health and readiness

```bash
curl -s localhost:8001/health | python -m json.tool
curl -s localhost:8001/ready  | python -m json.tool   # {"ready": true, "checks": {... "redis": true ...}}
```

`/health` is liveness (process up). `/ready` is readiness: it returns **503**
until Redis is reachable and trust/verifier/signing are loaded.

-----

## 5. Run each governance path

Set shell vars for brevity:

```bash
export KEY=$(grep MCC_GATEWAY_API_KEY deploy/pilot/.env | cut -d= -f2)
export OP=$(grep MCC_GATEWAY_OPERATOR_API_KEY deploy/pilot/.env | cut -d= -f2)
```

### 5a. The four verdicts — authority (`POST /evaluate`)

```bash
# ALLOW  — payments-bot within its mandate cap
curl -s localhost:8001/evaluate -H "x-api-key: $KEY" \
  -d '{"identity":"agent/payments-bot","action":"send_payment","context":{"amount":1000}}' | python -m json.tool

# CONSTRAIN — over the cap; forward_context is clamped to 5000 (the executed body)
curl -s localhost:8001/evaluate -H "x-api-key: $KEY" \
  -d '{"identity":"agent/payments-bot","action":"send_payment","context":{"amount":99000}}' | python -m json.tool

# ESCALATE — no standing mandate
curl -s localhost:8001/evaluate -H "x-api-key: $KEY" \
  -d '{"identity":"agent/nobody","action":"send_payment","context":{"amount":10}}' | python -m json.tool

# DENY — irreversible action no mandate can authorize
curl -s localhost:8001/evaluate -H "x-api-key: $KEY" \
  -d '{"identity":"agent/ops-bot","action":"delete_database","context":{}}' | python -m json.tool
```

### 5b. ESCALATE → human approval (`/approvals`)

```bash
# Agent opens a request bound to the exact operation.
REQ=$(curl -s localhost:8001/approvals -H "x-api-key: $KEY" \
  -d '{"actor":"agent/nobody","action":"send_payment","resource":"acct-1","payload_hash":"sha256:demo"}' \
  | python -c 'import sys,json;print(json.load(sys.stdin)["request_id"])')

# Operator grants it -> mints a single-use, signed approval mandate.
curl -s localhost:8001/approvals/$REQ/approve -H "x-operator-key: $OP" -X POST | python -m json.tool
```

The approval **mints authority; it never executes**. Execution still runs the one
governed path (`/approvals/{id}/execute`), which consumes the approval single-use.

### 5c. Consensus → governed execution (driver)

The consensus path needs N independent signed votes. The driver signs them with
the local evaluator keys and drives the whole path over HTTP (it plays the agent,
the evaluators, and the operator for the demo):

```bash
MCC_GATEWAY_URL=http://localhost:8001 \
MCC_GATEWAY_API_KEY=$KEY MCC_GATEWAY_OPERATOR_API_KEY=$OP \
python deploy/pilot/pilot_driver.py
```

Expected: the four verdicts, a governed consensus **EXECUTED** (forwarded to the
echo upstream), and a valid audit chain.

### 5d. CONSTRAIN with re-consensus + no-bypass (reference integration)

The full combined flow — a CONSTRAIN producing a **new payload hash** that forces
**new consensus** before the clamped body is executed, with the original amount
never sent, and a direct executor call refused — is the in-process reference
integration on the real runtime:

```bash
python examples/pilot_reference_integration.py
```

Expected: only ALLOW / approved-ESCALATE / re-consensused-CONSTRAIN reach
upstream; the original `{amount: 10000}` never does; the direct (unsigned) call
is refused.

-----

## 6. Inspect the audit chain

```bash
# Recompute the hash chain and report integrity + the signing public key.
curl -s localhost:8001/verify -H "x-api-key: $KEY" | python -m json.tool

# Export the append-only signed log for an external auditor.
curl -s "localhost:8001/export?fmt=json" -H "x-api-key: $KEY" -o mcc-audit.json

# Or read it straight from the audit volume.
docker compose -f deploy/pilot/docker-compose.yml exec mcc-gateway tail -n 5 /data/audit.jsonl
```

Every evaluation, pre-actuation decision, and actuation result is a chained,
`fsync`-ed entry written **before** any authority is released.

-----

## 7. Stop and clean

```bash
# Stop containers, keep the audit volume.
docker compose -f deploy/pilot/docker-compose.yml down

# Stop and remove the audit volume too.
docker compose -f deploy/pilot/docker-compose.yml down -v

# Remove local secrets (irreversible — regenerate with step 1).
rm -rf deploy/pilot/secrets deploy/pilot/.env
```

-----

## Configuration reference

| Variable | Meaning | Fail-closed effect |
|---|---|---|
| `MCC_ENV=pilot` | pilot trust enforcement | requires a valid `MCC_TRUST_CONFIG` |
| `MCC_GATEWAY_API_KEY` | agent `X-API-Key` | wrong/absent → 401 |
| `MCC_GATEWAY_OPERATOR_API_KEY` | operator `X-Operator-Key` | empty → all operator actions 403 |
| `MCC_GATEWAY_SIGNING_KEY_PATH` | decision-token key (PEM) | empty → ephemeral key (dev only) |
| `MCC_TRUST_CONFIG` | mandate trust set (public keys) | pilot: missing/empty/malformed → refuse start |
| `MCC_REQUIRE_CONSENSUS=1` | mandatory N-of-M consensus | set without a verifier → refuse start |
| `MCC_CONSENSUS_TRUST_CONFIG` | evaluator trust set (public keys) | required when consensus is required |
| `MCC_CONSENSUS_THRESHOLD` | N of M required | unsatisfiable threshold → refuse start |
| `MCC_REQUIRE_CHALLENGE=1` | mandatory gateway-issued nonce | client-supplied nonce no longer accepted |
| `MCC_REDIS_URL` | Redis for shared state | required by the `*_BACKEND=redis` registries |
| `MCC_*_BACKEND=redis` | nonce/idempotency/velocity/approval/challenge/revocation | unreachable Redis → `/ready` 503, no fallback |
| `MCC_UPSTREAM_BASE` | external service governed execution forwards to | absent → governed execution `EXECUTION_FAILED` |

No private keys, tokens, or credentials are ever written to logs or committed.
