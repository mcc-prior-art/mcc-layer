# OPA / Rego Integration

## Purpose

MCC-Core now includes a real OPA/Rego policy adapter.

The runtime calls OPA before issuing an execution decision.

OPA decides policy.

MCC-Core binds that policy decision into the execution governance envelope: identity, context, constraints, signed response, fail-closed behavior, metrics, audit direction, and gate enforcement.

---

## Policy Endpoint

MCC-Core calls:

```text
POST /v1/data/mcc/decision
```

The request body sent to OPA:

```json
{
  "input": {
    "tenant": "demo",
    "trace_id": "abc123",
    "session_id": "s1",
    "intent": "send_payment",
    "args": {
      "amount": 750
    },
    "ts_unix": 1760000000
  }
}
```

OPA returns:

```json
{
  "result": {
    "decision": "ALLOW",
    "reason": "payment within autonomous approval threshold",
    "constraints": {
      "max_amount": 5000
    },
    "policy_ref": "mcc.rego/send_payment/allow"
  }
}
```

MCC-Core supports:

```text
ALLOW
DENY
ESCALATE
CONSTRAIN
```

---

## Fail-Closed Behavior

If OPA is unavailable, times out, returns invalid JSON, omits `result`, or returns an invalid decision, MCC-Core returns:

```json
{
  "decision": "DENY",
  "reason": "OPA ...; fail closed",
  "policy_ref": "fail-closed"
}
```

There is no permissive fallback when `MCC_USE_OPA=true`.

---

## Run

```bash
docker compose up --build
```

Then:

```bash
curl -s http://localhost:8000/health
```

Expected:

```json
{
  "status": "ok",
  "policy_engine": "opa",
  "opa_status": "ok",
  "fail_closed": true
}
```

---

## Evaluate

```bash
curl -s -X POST http://localhost:8000/evaluate \
  -H "Content-Type: application/json" \
  -H "X-API-Key: demo-key" \
  -d '{
    "session_id": "s1",
    "intent": "send_payment",
    "args": { "amount": 750 },
    "idempotency_key": "demo-1"
  }'
```

Expected decision:

```json
{
  "decision": "ALLOW",
  "reason": "payment within autonomous approval threshold"
}
```

---

## Fail-Closed Test

Stop OPA while MCC remains running.

Then call `/evaluate`.

Expected decision:

```text
DENY
```

Reason should indicate OPA timeout or HTTP error with fail-closed behavior.
