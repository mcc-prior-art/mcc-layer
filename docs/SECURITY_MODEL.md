# MCC-Core Security Model

## Principle

MCC-Core assumes that autonomous intent is not authority.

The system fails closed by default.

Uncertainty does not authorize execution.

---

## Security Controls

The reference security model includes:

- deny-by-default behavior
- fail-closed execution
- signature verification
- canonical payload binding
- action hash binding
- policy hash binding
- nonce replay protection
- token TTL
- key revocation
- token revocation
- policy trust set validation
- append-only audit
- hash-chain integrity checks
- safe-state restrictions
- recovery token workflow

The design goal is to make execution authority explicit, verifiable, and reviewable.

---

## Fail-Closed Conditions

Execution is denied when:

- signature is invalid
- key is unknown
- key is revoked
- token is expired
- token is not yet valid
- audience does not match
- token was revoked
- nonce was already used
- policy trust set is missing
- policy trust set is expired
- policy hash is not accepted
- local policy hash does not match token policy hash
- payload hash does not match
- action hash does not match
- constraints are violated
- attestation fails
- audit chain is compromised
- system is in restricted safe state
- OPA integration is configured but not implemented

The default behavior is denial.

---

## Emergency and Recovery Principle

MCC-Core treats emergency recovery as a controlled process.

Recovery should not become a hidden bypass.

A recovery path should be:

- explicitly authorized
- signed
- time-limited
- nonce-protected
- operator-bound where applicable
- auditable
- reviewable after the fact

**Override is not bypass.**

**Recovery is not invisibility.**
