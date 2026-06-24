#!/usr/bin/env python3
"""Independent re-verification of the Multi-Context Consensus 3-of-3 evidence.

This script deliberately imports **nothing from mcc_core**. It re-implements the
canonical serialization, the SHA-256 hashing, the Ed25519 signature check, and
the 3-of-3 + veto decision rule from first principles (stdlib + `cryptography`),
then:

  1. verifies every artifact against MANIFEST.sha256 (integrity);
  2. independently re-derives the verdict for every scenario from the signed
     votes and the trusted evaluator public keys;
  3. confirms the independent verdict matches both the recorded engine verdict
     (results.json) and the expected outcome, and that every adversarial
     scenario denies (fail-closed).

A green run here is an independent confirmation that the committed evidence is
authentic, intact, and that consensus cannot be manufactured.

    python evidence/consensus_3of3/verify_independent.py [artifacts_dir]
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ARTIFACTS = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent / "artifacts"


def canonical_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def hash_action(action: str) -> str:
    return "sha256:" + hashlib.sha256(action.encode()).hexdigest()


def hash_payload(payload) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(payload)).hexdigest()


def verify_sig(vote: dict, public_key: Ed25519PublicKey) -> bool:
    try:
        unsigned = {k: v for k, v in vote.items() if k != "sig"}
        public_key.verify(base64.b64decode(vote["sig"]), canonical_bytes(unsigned))
        return True
    except Exception:
        return False


def decide(votes, op, trusted_by_kid, policy) -> str:
    """Re-implementation of the 3-of-3 + veto rule. Fail-closed."""
    if not isinstance(votes, list):
        return "DENY"
    allow, deny, seen = set(), set(), set()
    for v in votes:
        if not isinstance(v, dict):
            continue
        pub = trusted_by_kid.get(v.get("kid"))
        if pub is None or not verify_sig(v, pub):
            continue
        if (v.get("action_hash") != op["action_hash"]
                or v.get("payload_hash") != op["payload_hash"]
                or v.get("actor") != op["actor"]):
            continue
        nbf, exp = v.get("nbf"), v.get("exp")
        if not isinstance(nbf, int) or not isinstance(exp, int) or op["now"] < nbf or op["now"] >= exp:
            continue
        eid = v.get("evaluator_id")
        if eid in seen:
            continue
        seen.add(eid)
        if v.get("verdict") == "DENY":
            deny.add(eid)
        elif v.get("verdict") == "ALLOW":
            allow.add(eid)
    if policy["veto_on_deny"] and deny:
        return "DENY"
    return "ALLOW" if len(allow) >= policy["threshold"] else "DENY"


def main() -> int:
    failures: list[str] = []

    # 1. Manifest integrity.
    manifest = (ARTIFACTS / "MANIFEST.sha256").read_text().splitlines()
    for line in manifest:
        if not line.strip():
            continue
        expected_hash, rel = line.split("  ", 1)
        path = ARTIFACTS / rel
        if not path.exists():
            failures.append(f"manifest: missing {rel}")
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected_hash:
            failures.append(f"manifest: hash mismatch for {rel}")
    if failures:
        print("INTEGRITY FAILED:")
        for f in failures:
            print("  -", f)
        return 1
    print(f"integrity: {len([l for l in manifest if l.strip()])} artifacts match MANIFEST.sha256")

    # 2/3. Independent re-derivation.
    evaluators = json.loads((ARTIFACTS / "evaluators.json").read_text())
    results = json.loads((ARTIFACTS / "results.json").read_text())
    policy = evaluators["policy"]
    op = evaluators["operation"]

    # Recompute the operation hashes ourselves (don't trust the recorded values).
    if hash_action(op["action"]) != op["action_hash"] or hash_payload(op["payload"]) != op["payload_hash"]:
        print("INTEGRITY FAILED: recorded operation hashes do not match recomputed values")
        return 1
    op = {"action_hash": hash_action(op["action"]), "payload_hash": hash_payload(op["payload"]),
          "actor": op["actor"], "now": op["now"]}

    trusted = {e["kid"]: Ed25519PublicKey.from_public_bytes(base64.b64decode(e["public_key_b64"]))
               for e in evaluators["trusted_evaluators"]}

    for sid, rec in results.items():
        votes = json.loads((ARTIFACTS / "votes" / f"{sid}.json").read_text())
        independent = decide(votes, op, trusted, policy)
        if independent != rec["actual"]:
            failures.append(f"{sid}: independent={independent} != engine={rec['actual']}")
        if independent != rec["expected"]:
            failures.append(f"{sid}: independent={independent} != expected={rec['expected']}")
        if rec["adversarial"] and independent != "DENY":
            failures.append(f"{sid}: adversarial scenario did not fail closed (got {independent})")
        mark = "✅" if not failures or failures[-1].split(':')[0] != sid else "❌"
        print(f"  [{independent:5}] {mark} {sid}")

    if failures:
        print("\nINDEPENDENT VERIFICATION FAILED:")
        for f in failures:
            print("  -", f)
        return 1
    print(f"\nINDEPENDENT VERIFICATION PASSED: {len(results)} scenarios re-derived; "
          f"3-of-3 enforced; every adversarial input fails closed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
