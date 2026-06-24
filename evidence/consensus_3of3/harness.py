#!/usr/bin/env python3
"""Reproducible evidence harness for Multi-Context Consensus 3-of-3.

Deterministic by construction: evaluator keys are derived from fixed seeds,
timestamps are fixed, votes carry no random fields, and every artifact is
written as canonical JSON. Ed25519 signatures are deterministic (RFC 8032), so
re-running this harness reproduces byte-identical artifacts and the same
SHA-256 manifest — that is the reproducibility guarantee the CI job checks.

It exercises the *real* ``mcc_core.ConsensusVerifier`` (the thing under test)
against a battery of positive and adversarial scenarios, and records the inputs
(signed votes), the verdicts, and a SHA-256 manifest. The committed artifacts
are independently re-checked by ``verify_independent.py`` (which does not import
mcc_core at all).

    python evidence/consensus_3of3/harness.py [--check]

``--check`` regenerates into a temp dir and fails if the committed artifacts
differ (used by CI to prove reproducibility) and if any scenario misbehaves.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from mcc_core import (  # noqa: E402
    ConsensusPolicy, ConsensusVerifier, SigningKey, Verdict, hash_action, hash_payload,
)

HERE = Path(__file__).resolve().parent
ARTIFACTS = HERE / "artifacts"

# Fixed operation under consideration.
ACTION = "deploy_release"
PAYLOAD = {"target": "cluster-prod-1", "environment": "prod"}
ACTOR = "agent/ops"

# Fixed validity window / evaluation time (deterministic).
IAT = 1_780_000_000
NBF = IAT - 60
EXP = IAT + 3600
NOW = IAT
THRESHOLD = 3


def fixed_key(label: str, kid: str) -> SigningKey:
    """Deterministic Ed25519 key from a labelled 32-byte seed."""
    seed = hashlib.sha256(label.encode()).digest()
    return SigningKey(Ed25519PrivateKey.from_private_bytes(seed), kid)


EVALS = {f"eval-{i}": fixed_key(f"mcc-consensus-evaluator-{i}", f"consensus-eval-{i}")
         for i in range(3)}
ROGUE = fixed_key("mcc-consensus-rogue", "consensus-rogue")
TRUSTED = {k.kid: k.public_key() for k in EVALS.values()}


def make_vote(signing_key, evaluator_id, verdict, *, sign_action=ACTION,
              sign_payload=None, sign_actor=ACTOR, exp=EXP, vote_id=None, tamper=False):
    sign_payload = PAYLOAD if sign_payload is None else sign_payload
    claims = {
        "vote_id": vote_id or f"vote-{evaluator_id}",
        "evaluator_id": evaluator_id, "verdict": verdict,
        "action_hash": hash_action(sign_action), "payload_hash": hash_payload(sign_payload),
        "actor": sign_actor, "reason": "", "iat": IAT, "nbf": NBF, "exp": exp,
    }
    vote = signing_key.sign_token(claims)
    if tamper:
        vote["verdict"] = "ALLOW" if verdict != "ALLOW" else "DENY"  # break the signature
    return vote


def scenarios():
    """(id, description, expected, adversarial, build) — build() returns the votes
    (a list, or a non-list for the malformed case)."""
    e0, e1, e2 = EVALS["eval-0"], EVALS["eval-1"], EVALS["eval-2"]
    return [
        ("unanimous_3of3", "Three independent evaluators all sign ALLOW.", "ALLOW", False,
         lambda: [make_vote(e0, "eval-0", "ALLOW"), make_vote(e1, "eval-1", "ALLOW"),
                  make_vote(e2, "eval-2", "ALLOW")]),
        ("below_threshold_2of3", "Only two ALLOW; the third ESCALATEs.", "DENY", True,
         lambda: [make_vote(e0, "eval-0", "ALLOW"), make_vote(e1, "eval-1", "ALLOW"),
                  make_vote(e2, "eval-2", "ESCALATE")]),
        ("veto_one_deny", "Two ALLOW, one trusted DENY vetoes.", "DENY", True,
         lambda: [make_vote(e0, "eval-0", "ALLOW"), make_vote(e1, "eval-1", "ALLOW"),
                  make_vote(e2, "eval-2", "DENY")]),
        ("forged_untrusted_evaluator", "A rogue (untrusted) key signs the third ALLOW.", "DENY", True,
         lambda: [make_vote(e0, "eval-0", "ALLOW"), make_vote(e1, "eval-1", "ALLOW"),
                  make_vote(ROGUE, "eval-2", "ALLOW")]),
        ("tampered_vote", "A valid ALLOW vote is mutated after signing.", "DENY", True,
         lambda: [make_vote(e0, "eval-0", "ALLOW"), make_vote(e1, "eval-1", "ALLOW"),
                  make_vote(e2, "eval-2", "DENY", tamper=True)]),
        ("duplicate_evaluator", "One evaluator casts three ALLOW ballots.", "DENY", True,
         lambda: [make_vote(e0, "eval-0", "ALLOW", vote_id="v1"),
                  make_vote(e0, "eval-0", "ALLOW", vote_id="v2"),
                  make_vote(e0, "eval-0", "ALLOW", vote_id="v3")]),
        ("wrong_action_binding", "Third vote is signed over a different action.", "DENY", True,
         lambda: [make_vote(e0, "eval-0", "ALLOW"), make_vote(e1, "eval-1", "ALLOW"),
                  make_vote(e2, "eval-2", "ALLOW", sign_action="delete_database")]),
        ("wrong_payload_binding", "Third vote is signed over a different payload.", "DENY", True,
         lambda: [make_vote(e0, "eval-0", "ALLOW"), make_vote(e1, "eval-1", "ALLOW"),
                  make_vote(e2, "eval-2", "ALLOW",
                            sign_payload={"target": "other", "environment": "prod"})]),
        ("wrong_actor_binding", "Third vote is signed for a different actor.", "DENY", True,
         lambda: [make_vote(e0, "eval-0", "ALLOW"), make_vote(e1, "eval-1", "ALLOW"),
                  make_vote(e2, "eval-2", "ALLOW", sign_actor="agent/someone-else")]),
        ("expired_vote", "Third vote is outside its validity window.", "DENY", True,
         lambda: [make_vote(e0, "eval-0", "ALLOW"), make_vote(e1, "eval-1", "ALLOW"),
                  make_vote(e2, "eval-2", "ALLOW", exp=NOW - 1)]),
        ("malformed_votes", "The votes payload is not a list.", "DENY", True,
         lambda: "not-a-list"),
    ]


def _canon(obj) -> bytes:
    return (json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def generate(out: Path) -> dict:
    (out / "votes").mkdir(parents=True, exist_ok=True)
    verifier = ConsensusVerifier(trusted_keys=TRUSTED,
                                 policy=ConsensusPolicy(threshold=THRESHOLD, veto_on_deny=True))

    files: dict[str, bytes] = {}
    results = {}
    all_pass = True

    evaluators = {
        "policy": {"threshold": THRESHOLD, "veto_on_deny": True, "on_fail": "DENY"},
        "operation": {"action": ACTION, "payload": PAYLOAD, "actor": ACTOR,
                      "action_hash": hash_action(ACTION), "payload_hash": hash_payload(PAYLOAD),
                      "now": NOW},
        "trusted_evaluators": [
            {"evaluator_id": eid, "kid": k.kid, "public_key_b64": k.public_key_b64()}
            for eid, k in EVALS.items()],
    }
    files["evaluators.json"] = _canon(evaluators)

    for sid, desc, expected, adversarial, build in scenarios():
        votes = build()
        files[f"votes/{sid}.json"] = _canon(votes)
        result = verifier.verify(votes, action=ACTION, payload=PAYLOAD, actor=ACTOR, now=NOW)
        actual = result.verdict.value
        ok = actual == expected and (not adversarial or actual == "DENY")
        all_pass = all_pass and ok
        results[sid] = {
            "description": desc, "expected": expected, "actual": actual,
            "adversarial": adversarial, "agreement": result.agreement,
            "threshold": result.threshold, "rejected_votes": result.rejected_votes,
            "allow_evaluators": result.allow_evaluators, "deny_evaluators": result.deny_evaluators,
            "reason": result.reason, "pass": ok,
        }

    files["results.json"] = _canon(results)
    files["summary.json"] = _canon({
        "suite": "multi-context-consensus-3of3", "threshold": THRESHOLD,
        "total_scenarios": len(results), "passed": sum(1 for r in results.values() if r["pass"]),
        "all_pass": all_pass,
        "operation_action_hash": hash_action(ACTION),
        "operation_payload_hash": hash_payload(PAYLOAD),
    })
    files["VALIDATION.md"] = _validation_md(results, all_pass).encode()

    # Write artifacts, then the manifest over them (sorted for stability).
    for rel, data in files.items():
        (out / rel).write_bytes(data)
    manifest_lines = [f"{_sha256(data)}  {rel}" for rel, data in sorted(files.items())]
    manifest = ("\n".join(manifest_lines) + "\n").encode()
    (out / "MANIFEST.sha256").write_bytes(manifest)

    return {"all_pass": all_pass, "manifest_sha256": _sha256(manifest),
            "files": {rel: _sha256(data) for rel, data in files.items()}}


def _validation_md(results, all_pass) -> str:
    rows = "\n".join(
        f"| `{sid}` | {'positive' if not r['adversarial'] else 'adversarial'} | "
        f"{r['expected']} | {r['actual']} | {'✅' if r['pass'] else '❌'} | {r['description']} |"
        for sid, r in results.items())
    return f"""# Validation Record — Multi-Context Consensus 3-of-3

Reproducible evidence that `mcc_core.ConsensusVerifier` enforces a **3-of-3**
policy and **fails closed** under every adversarial input. Generated by
`harness.py` (deterministic); independently re-checked by
`verify_independent.py`.

- Policy: `threshold=3`, `veto_on_deny=true`, `on_fail=DENY`
- Operation: action `{ACTION}`, payload `{json.dumps(PAYLOAD)}`, actor `{ACTOR}`
- Evaluation time: `{NOW}` (fixed); votes valid in `[{NBF}, {EXP})`
- Evaluator keys: derived from fixed seeds (deterministic); public keys in
  `artifacts/evaluators.json`

## Result: {'ALL PASS ✅' if all_pass else 'FAILURES ❌'}

| scenario | kind | expected | actual | ok | description |
|---|---|---|---|---|---|
{rows}

A "positive" scenario must reach consensus (ALLOW); every "adversarial" scenario
must **DENY** — no forged, untrusted, duplicated, mutated, mis-bound, or expired
vote can manufacture consensus, and any single trusted DENY vetoes.

## Reproduce

```bash
python evidence/consensus_3of3/harness.py            # regenerate artifacts
python evidence/consensus_3of3/verify_independent.py # independent re-verification
```

Ed25519 signing is deterministic, so regeneration yields byte-identical
artifacts; CI runs `harness.py --check` and fails on any drift. Integrity of
every artifact is pinned in `MANIFEST.sha256`.
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="regenerate into a temp dir and fail on drift or scenario failure")
    args = ap.parse_args()

    if not args.check:
        summary = generate(ARTIFACTS)
        print(f"generated {len(summary['files'])} artifacts; all_pass={summary['all_pass']}")
        print(f"manifest sha256: {summary['manifest_sha256']}")
        return 0 if summary["all_pass"] else 1

    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        fresh = generate(Path(tmp))
        if not fresh["all_pass"]:
            print("CHECK FAILED: a scenario did not behave as expected")
            return 1
        # Compare regenerated bytes against the committed artifacts.
        drift = []
        for rel, sha in fresh["files"].items():
            committed = ARTIFACTS / rel
            if not committed.exists() or _sha256(committed.read_bytes()) != sha:
                drift.append(rel)
        committed_manifest = (ARTIFACTS / "MANIFEST.sha256")
        if not committed_manifest.exists() or _sha256(committed_manifest.read_bytes()) != fresh["manifest_sha256"]:
            drift.append("MANIFEST.sha256")
        if drift:
            print("CHECK FAILED: artifacts are not reproducible / out of date:")
            for d in sorted(set(drift)):
                print("  -", d)
            print("Run: python evidence/consensus_3of3/harness.py")
            return 1
    print("CHECK PASSED: artifacts reproducible and all scenarios fail-closed as expected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
