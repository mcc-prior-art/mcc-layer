#!/usr/bin/env python3
"""Runtime version drift-guard (Phase 2).

Enforces a single canonical **product/runtime** release version (the repo-root
``VERSION`` file) without touching the other version categories.

It checks that every runtime FastAPI app derives its reported version from the
canonical source (``version=RUNTIME_VERSION``) and that **no hardcoded runtime
version literal** has crept back into those files. Because the runtime version
is read from one file, drift across runtime entrypoints is structurally
impossible — this guard fails the build if someone reintroduces a literal.

It deliberately does NOT inspect — and must never fire on — the intentionally
independent / frozen strings:
  * `CLAUDE.md` `v1.10.1` (frozen historical/doctrine),
  * `mcc.yaml` / `policies.yaml` schema versions (protocol/schema),
  * `README.md` / doctrine narrative versions (documentation),
  * `GOVERNANCE.md` release record.

Usage:
    python scripts/check_version_drift.py            # check, exit non-zero on drift
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# The runtime (product) entrypoints whose `version=` MUST derive from VERSION.
RUNTIME_FILES = [
    "main.py",
    "gateway/app.py",
    "interceptors/egress_proxy.py",
]

# A hardcoded version literal in a `version=` assignment, e.g. version="1.2.0-x".
LITERAL = re.compile(r"""version\s*=\s*['"]v?\d+\.\d+(\.\d+)?[^'"]*['"]""")
# The required dynamic reference.
DYNAMIC = re.compile(r"version\s*=\s*RUNTIME_VERSION")

SEMVER = re.compile(r"^\d+\.\d+\.\d+([-+][0-9A-Za-z.\-]+)?$")


def main() -> int:
    failures: list[str] = []

    canonical_path = ROOT / "VERSION"
    if not canonical_path.exists():
        print("DRIFT GUARD FAILED: canonical VERSION file is missing")
        return 1
    canonical = canonical_path.read_text(encoding="utf-8").strip()
    if not SEMVER.match(canonical):
        failures.append(f"VERSION is not valid semver: {canonical!r}")

    for rel in RUNTIME_FILES:
        path = ROOT / rel
        if not path.exists():
            failures.append(f"{rel}: runtime file missing")
            continue
        text = path.read_text(encoding="utf-8")
        if LITERAL.search(text):
            failures.append(
                f"{rel}: hardcoded runtime version literal found in a version= "
                f"assignment; use version=RUNTIME_VERSION (canonical = {canonical})"
            )
        elif not DYNAMIC.search(text):
            failures.append(
                f"{rel}: no `version=RUNTIME_VERSION` found; the runtime app must "
                f"derive its version from the canonical VERSION file"
            )

    if failures:
        print("DRIFT GUARD FAILED:")
        for f in failures:
            print("  -", f)
        return 1

    print(f"DRIFT GUARD OK: runtime version is canonical = {canonical}")
    print("  runtime entrypoints derive from VERSION:", ", ".join(RUNTIME_FILES))
    print("  (frozen/historical v1.10.1, schema, doctrine, and README strings "
          "are intentionally NOT inspected)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
