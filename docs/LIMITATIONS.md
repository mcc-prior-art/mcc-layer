# MCC-Core Limitations

## Status

This repository is a reference implementation and architecture draft.

It is not a certified production system.

---

## Known Limitations

- not formally verified
- not independently audited
- not certified for functional safety
- not certified for regulated production environments
- not a replacement for legal or compliance review
- OPA integration may be represented as a fail-closed placeholder
- attestation logic may be simplified for demonstration
- distributed consensus may be simplified for reference purposes
- production key management requires KMS / HSM / Vault-class infrastructure
- production audit storage should use durable tamper-evident storage
- production policy distribution requires a signed policy supply chain
- production distributed nonce registry requires atomic replay protection across enforcement nodes

These limitations are intentional and explicit.

The purpose of this repository is to define and demonstrate the execution governance boundary.

Accurate positioning preserves credibility.
