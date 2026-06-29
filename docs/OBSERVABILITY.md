# Operational Readiness & Observability

> Instrumentation only. Observability records what the governance runtime decided —
> it never decides, authorizes, retries, or alters a decision. Nothing in this layer
> weakens fail-closed behavior.

This document covers the observability and operational-readiness surface of the
governed egress path (`egress_proxy/`). It does **not** introduce a parallel runtime,
executor, governance path, or audit system: the same `GovernedMCCClient` /
`EnforcementCoordinator` / `HTTPEgressExecutor` make every decision and the single
append-only hash-chain audit log remains the authoritative record. Operational logs,
metrics, and traces are an *index over* that record, never a substitute for it.

The relevant module is [`egress_proxy/observability.py`](../egress_proxy/observability.py).

---

## 1. Architecture

```
client request
   │  (correlation id resolved/generated, validated)
   ▼
EgressService.handle ──► span("egress.request") ──► _dispatch ──► GovernedMCCClient
   │                                                                │
   │  (after the verdict: never before, never altering it)          │  coordinator:
   ▼                                                                │  gate → consensus
record metrics  ◄───────────────────────────────────────────────── │  → challenge
emit redacted event                                                 │  → revocation
   │                                                                │  → approval
   ▼                                                                │  → idempotency
HTTPExecuteResponse (outcome, error_code, correlation_id)           │  → velocity
                                                                    │  → AUDIT (durable)
GET /metrics   GET /livez   GET /ready                              │  → executor
(Prometheus)   (liveness)   (readiness)                            (governed egress)
```

Key property: every metric/event/span is emitted **after** the governance verdict is
known, on the path back to the caller. The observability code never sits between a
proposal and the gate, and never has a way to produce an ALLOW.

---

## 2. Correlation model

* Every request has a correlation id. It is resolved by
  `resolve_correlation_id(raw)`:
  * **absent/empty** → a fresh id `corr-<uuid4hex>` is generated;
  * **supplied** → validated against `^[A-Za-z0-9._:\-]{1,128}$`; a malformed id is
    **rejected** with `CorrelationError` (never sanitized-and-trusted).
* A rejected id returns HTTP 400, `outcome: INVALID_REQUEST`, `error_code:
  INVALID_CORRELATION_ID`, and increments `mcc_correlation_rejected_total`.
* The id propagates through proposal intake → governance → challenge/consensus →
  approvals/mandates → gate → credential resolution → HTTPS/mTLS egress → the audit
  entry (`correlation_id` field on the `egress_execution` record), and is returned to
  the caller both as the `X-MCC-Correlation-Id` response header and the
  `correlation_id` response field.
* **The correlation id is never an authorization input.** It is an observability
  handle only; no decision consults it.

---

## 3. Error taxonomy

Stable, bounded `ErrorCode` values (`egress_proxy/observability.py`). Responses carry
the code in `error_code` and a fixed safe message — **no raw exception text or stack
traces ever leave the process** (`safe_message(code)`).

| Code | Meaning | Typical outcome |
|------|---------|-----------------|
| `OK` | Executed through the governed path | ALLOW |
| `INVALID_REQUEST` | Could not canonicalize the action | INVALID_REQUEST |
| `INVALID_CORRELATION_ID` | Malformed external correlation id | INVALID_REQUEST |
| `GOVERNANCE_DENY` | Authority denied the action | DENY |
| `ESCALATION_REQUIRED` | Human approval required first | ESCALATE |
| `CONSENSUS_REQUIRED` | N-of-M votes must be supplied | CONSENSUS_REQUIRED |
| `CONSENSUS_FAILED` | Consensus verification failed (threshold/veto/invalid) | DENY |
| `CONSTRAINT_RECONSENSUS` | Authority clamped; fresh authorization required | CONSTRAIN |
| `APPROVAL_INVALID` | Approval missing, expired, or invalid | DENY |
| `MANDATE_INVALID` | Mandate validation failed (forged/expired/revoked/scope) | DENY |
| `NONCE_REPLAY` | Replay / reused nonce denied | DENY |
| `IDEMPOTENCY_CONFLICT` | Idempotency conflict | DENY |
| `VELOCITY_EXCEEDED` | Velocity / aggregate limit exceeded | DENY |
| `SSRF_DENIED` | Destination/scheme rejected (SSRF/DNS) | DENY |
| `REDIRECT_DENIED` | Unsafe redirect rejected | DENY |
| `TLS_FAILED` | TLS verification failed | DENY |
| `MTLS_FAILED` | Client identity / CA material invalid | DENY |
| `CREDENTIAL_DENIED` | Credential scope/authorization denied | DENY |
| `CREDENTIAL_UNAVAILABLE` | Credential provider unavailable | DEPENDENCY_UNAVAILABLE |
| `DEPENDENCY_UNAVAILABLE` | Redis/registry fail-closed | DEPENDENCY_UNAVAILABLE |
| `AUDIT_WRITE_FAILED` | Durable audit write failed (no execution) | DEPENDENCY_UNAVAILABLE |
| `UPSTREAM_TIMEOUT` | Governed upstream call timed out | UPSTREAM_TIMEOUT |
| `UPSTREAM_ERROR` | Governed upstream transport error | UPSTREAM_ERROR |
| `RESPONSE_TOO_LARGE` | Upstream response exceeded the cap | RESPONSE_TOO_LARGE |
| `TELEMETRY_EXPORT_FAILED` | OTel span export failed (isolated, no effect) | n/a |
| `READINESS_FAILED` | A readiness probe failed | n/a |
| `INTERNAL_ERROR` | Unclassified internal error (safe-messaged) | DEPENDENCY_UNAVAILABLE |

Governance-layer denials whose category is only available as a safe internal reason
string are mapped to a code by `classify_reason(reason)` (keyword → code); executor
failure categories are mapped by `EXECUTOR_CATEGORY_TO_CODE`. Neither mapping is ever
consulted for an authorization decision — only for the response code and metrics.

---

## 4. Metrics reference

Exposed at `GET /metrics` in Prometheus text format. **All series are
bounded-cardinality**: labels are drawn only from fixed small sets — never URLs,
actor ids, transaction ids, credential refs, or arbitrary error strings. Each app has
its own isolated `CollectorRegistry`.

| Metric | Type | Labels (bounded) |
|--------|------|------------------|
| `mcc_governance_decisions_total` | counter | `verdict` ∈ {ALLOW,DENY,ESCALATE,CONSTRAIN} |
| `mcc_governance_decision_latency_seconds` | histogram | — |
| `mcc_egress_requests_total` | counter | `outcome` (Outcome enum) |
| `mcc_consensus_total` | counter | `result` ∈ {success,failure} |
| `mcc_approval_latency_seconds` | histogram | — |
| `mcc_approvals_expired_total` | counter | — |
| `mcc_mandate_validation_failures_total` | counter | — |
| `mcc_nonce_replay_denials_total` | counter | — |
| `mcc_idempotency_conflicts_total` | counter | — |
| `mcc_velocity_violations_total` | counter | — |
| `mcc_redis_failures_total` | counter | — |
| `mcc_redis_up` | gauge | — |
| `mcc_credential_resolution_total` | counter | `result` ∈ {success,failure} |
| `mcc_https_execution_total` | counter | `result` ∈ {success,failure} |
| `mcc_tls_failures_total` | counter | `type` ∈ {tls,mtls} |
| `mcc_redirect_denials_total` | counter | — |
| `mcc_ssrf_denials_total` | counter | — |
| `mcc_audit_write_failures_total` | counter | — |
| `mcc_failclosed_dependency_total` | counter | — |
| `mcc_correlation_rejected_total` | counter | — |
| `mcc_telemetry_export_failures_total` | counter | — |
| `mcc_readiness_ready` | gauge | — |

Bounded label series are pre-initialized to 0 so dashboards/alerts have stable series.

---

## 5. Health & readiness semantics

Liveness and readiness are **distinct** endpoints with distinct meanings.

* **`GET /livez` — liveness.** Proves only that the process is running:
  `{"alive": true, "version": ...}`. No dependency checks, no secrets, no internal
  topology. Use as the orchestrator liveness probe; a restart is the only remedy for a
  liveness failure.
* **`GET /ready` — readiness.** Validates required production dependencies/config and
  returns a `checks` map of **booleans/strings only** (`runtime_initialized`,
  `audit_durable`, `redis` (when required), `consensus_verifier` (when consensus is
  required), `ephemeral_signing_key`, `credential_provider`). Returns **HTTP 503** when
  any required check fails — Redis unreachable, audit not durable, consensus verifier
  not loaded, or the runtime not initialized. It never exposes secrets, raw startup
  errors, or internal topology. Sets `mcc_readiness_ready` and `mcc_redis_up`.
* `GET /health` is retained for backward compatibility (liveness-style) and exposes
  only the public policy hash, never secrets.

An instance failing `/ready` should be taken out of rotation by the load balancer; it
will fail closed for any request that depends on the missing dependency regardless.

---

## 6. Safe logging rules

Structured events are emitted via `emit_event(logger, stage, **fields)` as
machine-readable JSON (`{"event":"mcc.egress","stage":..., ...}`) with the correlation
id, stage, verdict, error code, and duration. `redact()` enforces the rules:

* **Never logged**: `authorization`, `proxy-authorization`, `cookie`, `set-cookie`,
  `x-api-key`, `x-operator-key`, `api-key`, `headers`, `body`, `upstream_body`,
  `votes`, `credential`, `secret`, `token`, `password`, `private_key`, `cert_pem`,
  `key_pem`, `ca_pem`, `value` (and these keys nested inside dicts).
* Values are reduced to safe primitives; non-primitives become a type name.
* Logging failures are swallowed — logging must never break the request path.
* **Operational logs do not replace the durable audit chain.** They are an index; the
  hash-chain audit log is the evidence.

---

## 7. OpenTelemetry configuration

OTel is **optional**. The runtime works with no collector installed; OpenTelemetry is
not a required dependency.

* `span(name, attributes, *, metrics)` is a no-op when `opentelemetry` (or a collector)
  is absent.
* Span names are sanitized; only a fixed allow-list of attributes is set
  (`mcc.stage`, `mcc.outcome`, `mcc.verdict`, `mcc.error_code`, `mcc.correlation_id`,
  `http.method`, `mcc.host`, `mcc.status`) — never secrets, URLs with credentials, or
  unbounded values.
* **Export isolation invariant:** span creation/attribute/finish failures are caught,
  counted (`mcc_telemetry_export_failures_total`), and swallowed. A telemetry export
  failure can never authorize execution, bypass governance, trigger a retry, or change
  a decision. The wrapped body always runs.

To enable tracing, install `opentelemetry-api`/`opentelemetry-sdk` and configure an
exporter via the standard `OTEL_*` environment variables; the proxy will pick up the
global tracer automatically. (Installing OTel is a dependency change — get approval per
`CLAUDE.md`.)

---

## 8. Alerting & incident response

* Example Prometheus scrape config: [`deploy/observability/prometheus.yml`](../deploy/observability/prometheus.yml)
* Example alert rules: [`deploy/observability/alerts.yml`](../deploy/observability/alerts.yml)
* Incident runbook (detection → containment → recovery → evidence → rollback):
  [`deploy/observability/INCIDENT_RUNBOOK.md`](../deploy/observability/INCIDENT_RUNBOOK.md)

**Install the rules** by pointing Prometheus `rule_files` at `alerts.yml` (already
referenced in the example `prometheus.yml`), and wire Alertmanager as needed.

The alerts cover audit-write failure, Redis outage, replay spikes, consensus failures,
credential-resolution failures, TLS/mTLS failures, executor failures, elevated DENY
rate, readiness failure, fail-closed-dependency denials, and telemetry-export failures.

> **Operators must never bypass MCC-Core to restore service.** Fail-closed denials are
> the system working as designed. The remedy is always to restore the failed
> dependency, never to route around the gate. See RULE ZERO in the runbook.

---

## 9. Evidence collection

When investigating an incident or producing a compliance record:

1. Pivot on the **correlation id** (`X-MCC-Correlation-Id` / `correlation_id`).
2. Use operational events as an index to locate the relevant window.
3. Treat the **append-only hash-chain audit log** as the authoritative evidence; verify
   chain continuity across the window (gateway `/verify` / `/export`; egress execution
   entries chain into the same log).
4. Confirm no action executed without a verified ALLOW token, and that no secret,
   credential, private key, or bearer token appears in any log, metric, span, response,
   or audit entry.

---

## 10. Security invariants preserved

Observability changes nothing about enforcement. All of the following remain true:

* No verified decision → no execution; the gate is fail-closed.
* Audit-before-execution: the durable audit write precedes actuation; an audit failure
  denies (`AUDIT_WRITE_FAILED`) and nothing executes.
* No executor bypass: the governed `HTTPEgressExecutor` is the only outbound call.
* Credential resolution only after authorization (inside the executor).
* HTTPS-only in production; SSRF and DNS-rebinding (IP-pinning) protection enforced.
* Nonce/idempotency/mandate/consensus/approval/velocity/constraint enforcement intact.
* Fail-closed dependency behavior (Redis/registry/audit) — no in-memory fallback to
  "recover" throughput, and telemetry failure never affects a decision.
