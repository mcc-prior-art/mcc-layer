"""Canonical runtime release version — single source of truth.

The deployable MCC-Core runtime version lives in the repo-root ``VERSION`` file
(reconciled to ``1.11.0``). Every product/runtime entrypoint derives its
reported version from here, so the runtime version cannot drift across files.

This is the **product/runtime** version only. It is deliberately decoupled from:
  * the policy/protocol schema version (``mcc.yaml`` / ``policies.yaml``),
  * the doctrine/doctrine-lines version,
  * any frozen historical evidence/exhibit version (e.g. ``v1.10.1``, G6).
"""

from __future__ import annotations

from pathlib import Path

# src/mcc_core/version.py -> parents[2] == repo root.
_VERSION_FILE = Path(__file__).resolve().parents[2] / "VERSION"


def runtime_version() -> str:
    try:
        return _VERSION_FILE.read_text(encoding="utf-8").strip()
    except Exception:
        return "0.0.0+unknown"


RUNTIME_VERSION = runtime_version()
