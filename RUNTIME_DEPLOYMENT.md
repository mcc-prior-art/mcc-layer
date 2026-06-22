# MCC-Core Runtime Deployment

Operational notes for running the MCC-Core runtime (`main.py` + `src/mcc_core/`)
outside of development. The runtime is fail-closed by design: every condition
listed below resolves to denial, never to silent permission.

---

## Ed25519 signing key (required for production)

Without `MCC_SIGNING_KEY_PATH` the runtime generates an **ephemeral dev key**
on startup and logs a warning. Tokens signed by an ephemeral key become
unverifiable after every restart. This is acceptable for demos only.

Generate a persistent key:

```bash
python scripts/generate_signing_key.py /secure/path/mcc_signing_key.pem
```

The script writes a PKCS8 PEM with mode `0600` and prints the base64 public
key for distribution to execution gates. It refuses to overwrite an existing
file.

Mount it in docker-compose:

```yaml
  mcc:
    environment:
      MCC_SIGNING_KEY_PATH: /run/secrets/mcc_signing_key.pem
      MCC_SIGNING_KEY_ID: mcc-core-prod-key-1
    volumes:
      - /secure/path/mcc_signing_key.pem:/run/secrets/mcc_signing_key.pem:ro
```

Key rotation: deploy the new key under a new `MCC_SIGNING_KEY_ID`, add the new
public key to gate trust sets, then remove the old kid from trust sets. A kid
absent from a gate's trust set is effectively revoked (UNTRUSTED_KEY → deny).

---

## Environment variables

| Variable | Default | Notes |
|---|---|---|
| `MCC_SIGNING_KEY_PATH` | *(empty)* | PEM path; empty = ephemeral dev key + warning |
| `MCC_SIGNING_KEY_ID` | `mcc-core-dev-key-1` | kid embedded in every token |
| `MCC_TOKEN_ISSUER` | `mcc/core` | `iss` claim |
| `MCC_TOKEN_AUDIENCE` | `execution-gate-1` | `aud` claim; gates must be configured with the same value |
| `MCC_TOKEN_TTL_SECONDS` | `60` | token lifetime; also bounds the idempotency cache |
| `MCC_AUDIT_LOG_PATH` | `audit.jsonl` | **set this outside the repo in production** so runtime entries do not mix with the prior-art genesis chain |
| `MCC_POLICY_BUNDLE_PATH` | `policies/mcc.rego` | hashed into every token |
| `MCC_POLICY_ID` | `mcc.rego/v1` | `policy_id` claim |
| `MCC_USE_OPA` | `true` | `false` switches to the non-production local fallback |
| `MCC_OPA_URL` | `http://opa:8181` | |
| `MCC_NONCE_BACKEND` | `memory` | gate replay-protection backend: `memory` (dev/single-instance) or `redis` (multi-instance) |
| `MCC_REDIS_URL` | *(unset)* | required when `MCC_NONCE_BACKEND=redis`; the Redis shared by every gate instance |
| `MCC_API_KEY` | `demo-key` | replace in production |

---

## Nonce replay protection (gate backend)

Every execution gate consumes the decision token's single-use nonce before
authorizing. The backend is selected by `MCC_NONCE_BACKEND`:

| Backend | Class | Use |
|---|---|---|
| `memory` (default) | `InMemoryNonceRegistry` | development, single-instance pilots — rejects replays **within one process only**; not shared, not durable |
| `redis` | `RedisNonceRegistry` | production / multi-instance — atomic `SET NX EX` on a shared Redis rejects replays **across every gate instance** |

```yaml
  egress-gate:
    environment:
      MCC_NONCE_BACKEND: redis
      MCC_REDIS_URL: redis://redis:6379/0
```

**No silent fallback.** Selecting `redis` without a usable `MCC_REDIS_URL`
raises `NonceConfigError` at startup — the process refuses to run with
unshared, non-durable replay state. At request time, an unreachable or slow
Redis (operation timeout), or any indeterminate reply, resolves to a denied
nonce, never to a downgrade to in-memory mode.

**TTL.** The nonce record's TTL is derived from the token's validity window
(remaining lifetime + a clock-skew margin) and clamped to safe bounds, so the
nonce always outlives the token it protects. The configured
`nonce_ttl_seconds` on the gate is the upper bound and must be `>=` the token
TTL.

---

## Fail-closed behavior under failure

| Failure | Behavior |
|---|---|
| OPA unreachable / invalid response | decision = DENY |
| Policy bundle missing or unreadable | decisions still computed, but **no tokens issued** → no execution |
| Audit log write fails | decision downgraded to DENY |
| Token issuance fails | decision downgraded to DENY (downgrade is audited) |
| Redis unavailable / timeout / indeterminate reply at the gate | nonce state unknown → token rejected (never a fallback to in-memory) |
| `MCC_NONCE_BACKEND=redis` with no `MCC_REDIS_URL` | startup error (`NonceConfigError`), not a silent in-memory downgrade |
| Token expired / nbf in future / wrong audience / unknown kid / any hash mismatch | rejected at the gate |

None of these conditions are configurable to fail open.
