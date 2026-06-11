"""Append-only hash-chain audit log with fsync on every write.

Each entry binds to the previous entry's hash. The first line of an
existing log is treated as the trust anchor (the repository ships a
genesis record dated 2026-04-22).
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from .signing import canonical_bytes

GENESIS = "GENESIS"
LEGACY_GENESIS_HASH = "genesis"


class AuditLog:
    def __init__(self, path: str) -> None:
        self.path = path
        self.prev_hash = GENESIS
        last = self._read_last_entry()
        if last is not None:
            self.prev_hash = str(last.get("hash", GENESIS))

    def _read_last_entry(self) -> "Dict[str, Any] | None":
        try:
            last_line = None
            with open(self.path, "r", encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        last_line = line
            return json.loads(last_line) if last_line else None
        except FileNotFoundError:
            return None

    @staticmethod
    def _entry_hash(prev_hash: str, body: Dict[str, Any]) -> str:
        return hashlib.sha256(
            prev_hash.encode("utf-8") + canonical_bytes(body)
        ).hexdigest()

    def append(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Write one chained entry; fsync before returning."""
        body = {
            **record,
            "ts": datetime.now(timezone.utc).isoformat(),
            "prev_hash": self.prev_hash,
        }
        entry = {**body, "hash": self._entry_hash(self.prev_hash, body)}
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self.prev_hash = entry["hash"]
        return entry

    @staticmethod
    def verify_chain(path: str) -> bool:
        """Recompute every entry hash and check linkage. The legacy genesis
        record is accepted as the trust anchor; everything else must verify."""
        try:
            entries: List[Dict[str, Any]] = []
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        entries.append(json.loads(line))
        except Exception:
            return False

        prev = None
        for entry in entries:
            declared = entry.get("hash")
            prev_hash = entry.get("prev_hash")
            if prev is not None and prev_hash != prev:
                return False
            is_legacy_anchor = (
                prev is None and declared == LEGACY_GENESIS_HASH
            )
            if not is_legacy_anchor:
                body = {k: v for k, v in entry.items() if k != "hash"}
                if AuditLog._entry_hash(str(prev_hash), body) != declared:
                    return False
            prev = declared
        return True
