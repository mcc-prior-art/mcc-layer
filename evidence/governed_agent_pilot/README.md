# Governed Agent Pilot — Reproducible Evidence

This directory holds reproducible evidence that the MCC-Core governed agent's
external actions are governed end to end: the model proposes, MCC-Core decides,
the execution gate enforces, the governed HTTPS executor performs the request,
and the audit chain records.

All keys/fixtures used by the pilot are **test-only**, generated at runtime
(ephemeral Ed25519 signing keys, in-memory/loopback state). **No production
keys, credentials, tokens, secrets, or personal data are present.**

## Files

| File | Contents |
|------|----------|
| `scenarios.json` | Per-scenario summary: proposal, MCC verdict, execution status, original vs final payload, applied constraints, external-state-changed, audit-ok, PASS/FAIL. Volatile ids (correlation/audit/transaction/idempotency) are normalized out so the file is byte-reproducible. |
| `pilot_operations.json` | Every operation the external pilot API actually performed, with a SHA-256 of each payload. Proves what reached the external system (and that DENY/CONSTRAIN/replay/SSRF/audit-failure actions did not). |
| `audit_verification.json` | Result of verifying the append-only hash-chain audit log. |
| `MANIFEST.sha256` | SHA-256 of every `*.json` evidence file. |

## Scenarios covered

1. ALLOW — create CRM lead executes and reaches the external API.
2. DENY — prohibited action blocked; external state unchanged.
3. ESCALATE — pending approval, then execution only after a valid approval;
   an invalid/unknown approval does not authorize execution.
4. CONSTRAIN — over-cap budget clamped, re-hashed, only the constrained payload
   executed; the original (10000) is never sent.
5. BYPASS — a direct executor call without MCC authorization is refused.
6. REPLAY — a reused idempotency key executes exactly once.
7. REDIS FAILURE — Redis-backed state unavailable → fail closed, no execution,
   no in-memory fallback.
8. SSRF / UNSAFE DESTINATION — loopback, link-local, private, IPv6, metadata,
   embedded-credentials, and malformed destinations are blocked before connection.
9. AUDIT FAILURE — audit persistence failure before actuation → no execution
   (audit-before-actuation invariant).

Plus a final append-only audit-chain verification.

## Reproduce

From the repository root (a local Redis is **not** required — the Redis-failure
scenario points at an unused port to demonstrate fail-closed behavior):

```bash
PYTHONPATH=src python -m mcc_agent.demo --evidence
```

This re-runs every scenario against a real loopback pilot API through the real
MCC-Core runtime and rewrites the evidence files. The `MANIFEST.sha256` is
stable across runs (volatile ids are normalized out).

Verify the manifest:

```bash
cd evidence/governed_agent_pilot && sha256sum -c <(grep -v '  MANIFEST' MANIFEST.sha256)
```
