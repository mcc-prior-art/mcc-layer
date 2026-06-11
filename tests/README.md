# Tests

Run with:

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

`test_mcc_core.py` (42 tests) covers:

- Ed25519 signing and verification (roundtrip, tampered token, foreign key,
  garbage signature, deterministic canonical serialization)
- verdict paths: token issued for ALLOW and CONSTRAIN only; DENY and
  ESCALATE raise `TokenNotIssuable`
- execution gate: valid token accepted; missing token, tampered token,
  unknown key id, expired token, not-before violation, audience mismatch,
  payload/action/policy hash mismatch, signed non-executable verdict — all denied
- replay protection: reused nonce denied; failed static checks do not burn
  the nonce; Redis unavailable = fail-closed denial
- nonce registry: single consumption, error fail-closed, empty nonce rejected
- audit hash chain: append/verify, tamper detection, continuity across restart
- policy bundle: hash verification, tampered bundle rejected on load
- OPA adapter: unreachable OPA resolves to DENY (fail-closed)
- runtime integration (`main.py`): ALLOW returns a verifiable signed token,
  DENY/ESCALATE/unknown intent return no token, issued token passes the gate,
  token binds to the audit chain
- idempotency cache: hit within token TTL, expiry forces re-evaluation
- invariant guard: no HMAC anywhere in the authority-bearing runtime path

`opa_test_vectors.json` holds smoke vectors for the OPA/Rego policy
(`scripts/smoke_test.sh` exercises them against a running stack).

`conftest.py` redirects the audit log to a temp directory so test runs never
touch the repository's prior-art `audit.jsonl` chain.
