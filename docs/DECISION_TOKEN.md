# MCC-Core Decision Token

## Purpose

A decision token is a signed authority artifact.

It binds execution to a specific subject, action, payload, policy, audience, time window, nonce, constraints, and audit reference.

A valid decision token is required before execution.

**No valid token — no execution.**

---

## Token Fields

A decision token may contain:

- issuer
- key ID
- subject
- audience
- action
- payload hash
- action hash
- constraints
- policy ID
- policy hash
- nonce
- issued-at timestamp
- not-before timestamp
- expiration timestamp
- audit reference
- signature

---

## Example

```json
{
  "iss": "mcc/node-a",
  "kid": "mcc-node-a-key-1",
  "sub": "agent/payment-worker",
  "aud": "execution-gate-1",
  "jti": "mcc-node-a-001",
  "iat": 1760000000,
  "nbf": 1760000000,
  "exp": 1760000060,
  "action": "create_payment",
  "payload_hash": "sha256:...",
  "action_hash": "sha256:...",
  "constraints": {
    "max_amount_usd": 1000,
    "requires_approval_above_usd": 500
  },
  "policy_id": "prod/v1",
  "policy_hash": "sha256:...",
  "audit_start_seq": 0,
  "req_attest": "medium",
  "nonce": "..."
}
```

The token must be signed by a trusted MCC authority key.

---

## Verification

The execution gate checks:

- signature validity
- key trust
- audience binding
- token expiry
- not-before time
- revocation status
- nonce replay
- policy trust set
- local policy hash consistency
- payload hash
- action hash
- constraints
- attestation state
- audit chain state
- safe-state restrictions

If verification fails, execution is denied.
