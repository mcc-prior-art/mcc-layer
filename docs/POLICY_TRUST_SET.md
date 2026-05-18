# MCC-Core Policy Trust Set

## Purpose

A policy trust set defines which policy hashes are currently accepted.

It creates an explicit relationship between policy state and execution authority.

**Policy mismatch — deny.**

---

## Policy Sources

MCC-Core does not require policy to originate inside MCC.

Policy may come from:

- OPA / Rego
- Cedar
- YAML policy definitions
- IAM / RBAC / ABAC systems
- compliance requirements
- business approval matrices
- risk engines
- safety rules
- domain-specific governance systems

MCC-Core consumes signed, versioned, auditable policy inputs and converts them into execution decisions.

Policy source may be external.

Execution authority must be verified by MCC.

---

## Rejection Conditions

MCC-Core may reject execution when:

- the policy trust set is missing
- the trust set is expired
- the policy hash is not accepted
- the policy hash is revoked
- the local policy hash does not match the token policy hash

---

## Production Policy Supply Chain

A production-grade policy supply chain should include:

- policy authoring
- review and approval
- signing
- versioning
- distribution
- revocation
- hash binding
- audit trail
- rollback strategy
