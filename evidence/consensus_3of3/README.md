# Reproducible Evidence — Multi-Context Consensus 3-of-3

A self-contained, reproducible evidence package proving that the
`mcc_core.ConsensusVerifier` (shipped in PR #13) enforces a **3-of-3** consensus
policy and **fails closed** under every adversarial input.

## Contents

| File | Role |
|---|---|
| `harness.py` | deterministic generator: builds signed votes, runs the real verifier, writes artifacts + `MANIFEST.sha256` |
| `verify_independent.py` | independent re-verification — imports **no** `mcc_core`; re-implements Ed25519 + the 3-of-3 rule + manifest check |
| `artifacts/evaluators.json` | trusted evaluator **public** keys, policy, and the operation under test |
| `artifacts/votes/*.json` | the signed vote inputs for each scenario |
| `artifacts/results.json` | the engine verdict per scenario |
| `artifacts/summary.json` | suite summary |
| `artifacts/VALIDATION.md` | the human-readable validation record |
| `artifacts/MANIFEST.sha256` | SHA-256 of every artifact (integrity) |

## Reproduce & verify

```bash
python evidence/consensus_3of3/harness.py             # (re)generate artifacts
python evidence/consensus_3of3/harness.py --check      # prove reproducibility (no drift) + scenarios
python evidence/consensus_3of3/verify_independent.py   # independent integrity + re-derivation
```

## Why it is reproducible

Evaluator keys are derived from fixed seeds and timestamps are fixed, so the
signed votes are constant. Ed25519 signing is deterministic (RFC 8032) and all
artifacts are canonical JSON — regeneration yields **byte-identical** files and
the same manifest. CI runs `harness.py --check` and fails on any drift.

## Scenarios

One positive (`unanimous_3of3` → ALLOW) and ten adversarial (all → DENY):
below-threshold, veto-on-deny, forged/untrusted evaluator, tampered vote,
duplicate evaluator, wrong action/payload/actor binding, expired vote, and
malformed input. See `artifacts/VALIDATION.md` for the full table.
