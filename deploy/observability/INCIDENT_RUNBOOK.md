# MCC-Core Egress Proxy — Incident Runbook

Operational response procedures for the governed egress path. Each section maps to
an alert in `alerts.yml` and follows the same shape: **Detection → Containment →
Recovery → Evidence preservation → Rollback**.

> ## RULE ZERO — Operators must never bypass MCC-Core to restore service.
>
> The governance gate is fail-closed **by design**. When a dependency fails, the
> correct state is *denied execution*, not *unverified execution*. There is no
> "emergency allow", no in-memory fallback for Redis registries, and no disabling of
> the audit chain, TLS verification, consensus, or the executor's safety checks to
> "get traffic flowing". Restoring service means **restoring the failed dependency**,
> never routing around the gate. Any change that would let an action execute without
> a verified ALLOW token is an incident in itself.

The four-line invariant holds during every incident:

```
The model proposes.
MCC-Core decides.
The gate enforces.
The audit chain records.
```

---

## Correlation-first triage

Every request carries a correlation id (`X-MCC-Correlation-Id` response header, the
`correlation_id` request/response field, and the `correlation_id` on operational
events and the audit entry). Start every investigation by pivoting on it:

1. Grab the correlation id from the client report or the alerting context.
2. Find the structured operational events (`{"event":"mcc.egress", ...}`) for that id
   — they carry `stage`, `verdict`, `error_code`, and `duration_ms` (never secrets).
3. Cross-reference the **durable audit chain** for the authoritative record. Operational
   logs are an index; the audit chain is the evidence. Never treat logs as a substitute.

Stable error codes (see `docs/OBSERVABILITY.md` for the full table) tell you which
section below applies, e.g. `DEPENDENCY_UNAVAILABLE` → Redis outage; `AUDIT_WRITE_FAILED`
→ audit failure; `CONSENSUS_FAILED` → consensus; `TLS_FAILED`/`MTLS_FAILED` → TLS.

---

## AUDIT_WRITE_FAILURE  — `MCCAuditWriteFailure` (critical)

**Detection.** `mcc_audit_write_failures_total` increasing; responses carry
`error_code: AUDIT_WRITE_FAILED`; nothing executes (audit-before-execution).

**Containment.** This is already contained: with no durable audit write, the gate does
not actuate. Take the instance out of rotation (it will fail `/ready` if audit
durability is the cause) so clients fail fast against a healthy instance.

**Recovery.** Investigate the audit volume: disk full, permissions, `fsync` failing,
read-only mount. Fix the storage condition. The hash chain is append-only — do **not**
truncate, rewrite, or "repair" it to clear the error.

**Evidence preservation.** Snapshot the audit log file and surrounding operational
events before any storage remediation. Preserve filesystem state (df, mount options,
dmesg) for the post-incident review.

**Rollback.** If a recent deploy changed the audit path/permissions/mount, roll back to
the previous known-good image. Never roll "forward" by disabling auditing.

---

## REDIS_OUTAGE  — `MCCRedisDown` / `MCCFailClosedDependency` (critical)

**Detection.** `mcc_redis_up == 0`; `mcc_failclosed_dependency_total` /
`mcc_redis_failures_total` rising; responses `DEPENDENCY_UNAVAILABLE`; `/ready` → 503.

**Containment.** The proxy is already failing closed. Confirm load balancers are honoring
`/ready` (503) and shedding the unhealthy instance. Do **not** set the registries to
in-memory to "ride out" the outage — that breaks cross-instance replay/idempotency/
velocity/approval/challenge guarantees.

**Recovery.** Restore Redis (failover, restart, network path). Readiness recovers
automatically once Redis is reachable; the proxy resumes issuing ALLOW tokens.

**Evidence preservation.** Capture Redis logs, the `mcc_redis_up` timeline, and the count
of `DEPENDENCY_UNAVAILABLE` denials during the window (no actions executed unverified).

**Rollback.** If a config/deploy changed the `MCC_REDIS_URL` or registry selection, roll
back to the previous Redis wiring.

---

## READINESS_FAILURE  — `MCCReadinessFailing` (critical)

**Detection.** `mcc_readiness_ready == 0`; `/ready` returns 503 with a `checks` map.

**Containment.** The orchestrator should already be withholding traffic. Verify the
instance is out of rotation.

**Recovery.** Read the `checks` map (booleans/strings only): `runtime_initialized`,
`audit_durable`, `redis`, `consensus_verifier`, `ephemeral_signing_key`,
`credential_provider`. Whichever required check is false points to the failed dependency
— follow that section. Note: an **ephemeral signing key** (`ephemeral_signing_key: true`)
is acceptable only outside production; configure a persistent signing key for prod.

**Evidence preservation.** Save the `/ready` body and the deploy/config diff.

**Rollback.** Roll back the deploy that introduced the missing/invalid production config.

---

## REPLAY_SPIKE  — `MCCNonceReplaySpike` (warning)

**Detection.** `mcc_nonce_replay_denials_total` spiking; `error_code: NONCE_REPLAY`.

**Containment.** Replays are already denied. Identify the source via correlation ids /
operational events — a client retry storm vs. a deliberate replay attack.

**Recovery.** If a buggy client is retrying with stale nonces, fix the client to mint
fresh nonces/challenges. If malicious, apply upstream rate-limiting / block the source.
The gate's behavior does not change either way.

**Evidence preservation.** Export the affected correlation ids and the audit entries for
the replayed actions.

**Rollback.** Roll back a recently deployed client integration if it is the source.

---

## CONSENSUS_FAILURE  — `MCCConsensusFailures` (warning)

**Detection.** `mcc_consensus_total{result="failure"}` rising; `error_code:
CONSENSUS_FAILED` (or `CONSENSUS_REQUIRED` when votes are simply absent).

**Containment.** Below-threshold / vetoed / invalid-vote actions are denied. Confirm the
evaluator pool and the consensus trust config.

**Recovery.** Restore evaluator availability; verify trusted evaluator keys, threshold,
and that votes bind to the current `policy_hash`/nonce. A trust-config or policy-hash
mismatch denies legitimately — fix the config, do not lower the threshold to pass traffic.

**Evidence preservation.** Capture the vote-verification failure category from events and
the audit record.

**Rollback.** Roll back a recent trust-config / policy change that broke vote binding.

---

## CREDENTIAL_RESOLUTION_FAILURE  — `MCCCredentialResolutionFailures` (warning)

**Detection.** `mcc_credential_resolution_total{result="failure"}` rising; `error_code:
CREDENTIAL_DENIED` or `CREDENTIAL_UNAVAILABLE`.

**Containment.** Secrets are resolved **only after authorization**, inside the executor.
A resolution failure means no upstream call was made with that credential.

**Recovery.** Check scope binding (allowed hosts/methods/actions/envs), the provider
configuration, and that the requested `credential_ref` exists. Never widen scope or log
the secret to debug — use the safe redacted metadata (`credential_resolved`, `credential_ref`).

**Evidence preservation.** Save the redacted credential metadata and events. Confirm no
secret appears in logs/metrics/audit (it must not).

**Rollback.** Roll back a recent credential-config change.

---

## TLS_FAILURE  — `MCCTLSFailures` (warning)

**Detection.** `mcc_tls_failures_total{type="tls"|"mtls"}` rising; `error_code:
TLS_FAILED` / `MTLS_FAILED`.

**Containment.** Failed TLS verification means no plaintext/unverified call was made.
**Never** disable verification, pin to `CERT_NONE`, or set `verify=False` to recover.

**Recovery.** For `tls`: check upstream certificate validity/expiry, hostname, and the
configured CA bundle. For `mtls`: check the client-identity material (cert+key) and CA.
Replace expired/invalid material; HTTPS-only and SSRF protection remain enforced.

**Evidence preservation.** Record the failure category (expired/self-signed/untrusted/
wrong-host) from events; preserve cert metadata (not private keys).

**Rollback.** Roll back a recent CA-bundle / client-identity / upstream-endpoint change.

---

## EXECUTOR_FAILURE  — `MCCExecutorFailures` (warning)

**Detection.** `mcc_https_execution_total{result="failure"}` rising; `error_code:
UPSTREAM_TIMEOUT` / `UPSTREAM_ERROR` / `REDIRECT_DENIED` / `RESPONSE_TOO_LARGE`.

**Containment.** Authorization succeeded but the governed call failed. No bypass exists —
a failed executor simply returns a safe error; it never falls back to a direct call.

**Recovery.** Triage upstream availability/latency, redirect policy, and response-size
limits. Adjust timeouts/limits via config if the upstream legitimately needs them; do not
disable SSRF/redirect validation.

**Evidence preservation.** Capture the error code distribution and correlation ids.

**Rollback.** Roll back a recent timeout/redirect/size config change if it regressed.

---

## ELEVATED_DENY_RATE  — `MCCElevatedDenyRate` (warning)

**Detection.** DENY share of `mcc_egress_requests_total` exceeds threshold.

**Containment.** DENY is the gate working. Determine whether it is a misconfigured client,
a policy change, or an attack — via correlation ids and the `error_code` breakdown.

**Recovery.** Fix the client/policy as appropriate. Do not loosen policy to reduce the
DENY rate unless the policy change is itself reviewed and intended.

**Evidence preservation.** Snapshot the decision counters and a sample of denied
correlation ids.

**Rollback.** Roll back a recent policy/trust change that caused legitimate traffic to deny.

---

## TELEMETRY_EXPORT_FAILURE  — `MCCTelemetryExportFailures` (info)

**Detection.** `mcc_telemetry_export_failures_total` increasing.

**Containment.** None needed. Telemetry export is fully isolated: a failing OTel collector
**cannot** authorize, bypass, retry, or change any decision. The request path is unaffected.

**Recovery.** Fix the OTel collector / endpoint at leisure. The proxy runs correctly with
no collector at all.

**Evidence preservation.** Optional — collector logs.

**Rollback.** Roll back a recent OTel-endpoint config change if it introduced the failure.

---

## Post-incident

- Verify the audit hash chain is intact and continuous across the incident window
  (`/verify` / `/export` on the gateway; the egress audit entries chain to the same log).
- Confirm **no action executed without a verified ALLOW token** during the window.
- Confirm no secret/credential/private-key/bearer token appeared in any log, metric,
  span, response, or audit entry.
- File the timeline keyed by correlation ids. Record which dependency failed and how it
  was restored — explicitly note that the gate was **not** bypassed.
