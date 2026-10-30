"""Append-only hash-chain audit log with fsync on every write.

Each entry binds to the previous entry's hash. The first line of an
existing log is treated as the trust anchor (the repository ships a
genesis record dated 2026-04-22).

Every append is serialized across independent OS processes by a
POSIX advisory lock (``fcntl.flock``) on a sidecar ``<path>.lock`` file.
The lock covers the ENTIRE critical section: reading the authoritative
persistent chain head, constructing the record, computing its hash,
appending, and fsyncing. No in-memory ``prev_hash`` is ever authoritative
across processes -- ``self.prev_hash`` is retained only as a best-effort
local cache (used for diagnostics and the constructor's initial value);
every real append re-reads the true chain head from disk while holding
the lock -- via ``_tail_last_nonblank_line()``, a backward-seeking tail
read (O(size of the last entry), not O(file size); see
docs/AUDITLOG_OPTIMIZATION.md), never a cached offset or line count
substituted for actually re-reading the real last line under the lock.
A write/flush/fsync failure partway through an append rolls back any
bytes already handed to the OS before re-raising, so a caller that sees
a failed append never has to reconcile against a phantom record left
visible on disk.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List

from .signing import canonical_bytes

GENESIS = "GENESIS"
LEGACY_GENESIS_HASH = "genesis"

# Default bound on how long append() will wait to acquire the inter-process
# lock before failing closed. Deliberately short: a caller blocked this long
# on the audit log should surface as a failure (see every call site's
# existing "except Exception: fail closed" handling in gateway/app.py,
# main.py, and src/mcc_core/coordinator.py), not hang the request.
DEFAULT_LOCK_TIMEOUT_SECONDS = 10.0
_LOCK_POLL_INTERVAL_SECONDS = 0.02

# Tail-read tuning for _tail_last_nonblank_line(): start small (most audit
# entries are far smaller than this), double on each backward-seek retry
# so a pathologically large last entry is still found in O(log n) reads,
# capped so one retry never reads an unbounded amount in one shot.
_TAIL_INITIAL_CHUNK_BYTES = 4096
_TAIL_MAX_CHUNK_BYTES = 1 << 20

# Matches Python text-mode's own universal-newlines rule: \r\n, bare \r, and
# bare \n are all equivalent line separators. \r\n MUST be tried before bare
# \r in the alternation so a CRLF pair is never mistaken for two separators
# (one \r, one \n). See _tail_last_nonblank_line's docstring -- this was
# added to fix a real regression (round 2 of this change) where the
# original replacement split only on literal b"\n" and so treated a
# CR-only- or CRLF-separated file as a single unsplit line, unlike the
# original text-mode scan it replaced.
_NEWLINE_RE = re.compile(rb"\r\n|\r|\n")


def _tail_last_nonblank_line(path: str) -> "bytes | None":
    """Return the last line in ``path`` whose decoded, stripped text is
    non-empty, as raw bytes, reading only as much of the file's TAIL as
    needed -- O(size of the last entry + any trailing blank lines), never
    O(file size). This is the performance-critical replacement for a full
    forward scan (see docs/AUDITLOG_OPTIMIZATION.md for the before/after
    measurement and tests/test_audit_tail_read.py for the differential test
    proving this returns byte-identical results to the TRUE original
    text-mode forward scan for every case that matters to
    _read_last_entry()'s contract).

    Raises ``FileNotFoundError`` / other ``OSError`` exactly as opening
    and reading the whole file would (same syscalls, just fewer bytes).

    Blankness is tested the same way the original text-mode scan tested it
    -- by decoding each candidate as UTF-8 and calling ``str.strip()``,
    which (unlike ``bytes.strip()``) is Unicode-whitespace-aware (e.g. NBSP
    U+00A0, EM SPACE U+2003, U+3000, U+2028 all strip to empty). Using
    ``bytes.strip()`` here (round 1 of this change) was itself a regression:
    it only strips ASCII whitespace, so a trailing line containing nothing
    but a UTF-8-encoded Unicode whitespace character was wrongly treated as
    non-blank, selected as "the last line," and then failed JSON parsing --
    turning a benign trailing line into a spurious ``AuditCorruptionError``
    that a real append should never have hit. If a candidate fails to
    decode as UTF-8 at all, it is returned immediately (never treated as
    blank) -- this is not new corruption-detection logic, it is what lets
    ``_read_last_entry()``'s own subsequent ``.decode("utf-8")`` call raise
    the same ``UnicodeDecodeError``, uncaught, that the original sequential
    text-mode reader would have raised at the same point in the contract.

    Line splitting uses ``_NEWLINE_RE`` (``\\r\\n`` / ``\\r`` / ``\\n``,
    matching Python's own text-mode universal-newlines rule) rather than a
    literal ``\\n`` split, so a bare-CR- or CRLF-separated file is split
    into the same logical lines the original text-mode scan would have
    produced.

    Never returns a line whose start was not actually read from disk: a
    line is only considered found once it is bounded on both sides by a
    real separator match actually present in what has been read so far, or
    by true end-of-file on the right and (after growing to read the whole
    file) true start-of-file on the left. A chunk-boundary split -- even
    one that lands in the middle of a two-byte ``\\r\\n`` separator -- can
    never be mistaken for a short line; it is simply re-read with more
    context on the next, larger retry (the boundary-safety argument below
    does not depend on the separator's byte length, only on whether it is
    FULLY present in the bytes read so far).

    Deliberate, documented scope narrowing vs. the old full-file scan:
    this function does not inspect bytes earlier in the file than the
    tail it actually needs. If an EARLIER line (not the last non-blank
    one) contains invalid UTF-8, the old O(n) implementation would
    incidentally decode-fail on it while scanning past it forward -- a
    side effect of reading every byte, never a documented guarantee
    (``AuditCorruptionError``'s own docstring is specifically about the
    LAST record). That historical-corruption detection is, and remains,
    ``verify_chain()``'s job (a full, explicit, on-demand scan) -- this
    function and ``verify_chain()`` are not the same operation and were
    never meant to be. The decoding of the chosen LAST non-blank line
    itself is unaffected: this function returns it as raw bytes exactly
    as the old implementation's line iterator would have handed it to
    the caller as a (lazily-decoded) str, and the caller decodes it the
    same way, so a corrupt last line still fails the same way it always
    did.
    """
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        file_size = fh.tell()
        if file_size == 0:
            return None

        chunk_size = _TAIL_INITIAL_CHUNK_BYTES
        pos = file_size
        buf = b""
        while True:
            read_size = min(chunk_size, pos)
            pos -= read_size
            fh.seek(pos)
            buf = fh.read(read_size) + buf

            lines = _NEWLINE_RE.split(buf)
            # lines[0] is only a COMPLETE line if this read reached the
            # true start of the file (pos == 0); otherwise an earlier,
            # not-yet-read byte could still belong to it (including the
            # possibility that a \r\n separator is split across this
            # chunk's left edge), so it is skipped until a retry proves
            # otherwise. Every other element is bounded on the left by a
            # real separator FULLY present in `buf` and on the right by
            # either another real separator or true EOF (the very first
            # iteration always starts the read anchored at the true end
            # of the file, and every later iteration only extends `buf`
            # backward, so its right edge is always true EOF), so all of
            # them are safe regardless of separator length.
            safe_start = 0 if pos == 0 else 1
            for candidate in reversed(lines[safe_start:]):
                try:
                    is_blank = not candidate.decode("utf-8").strip()
                except UnicodeDecodeError:
                    # Invalid UTF-8 is never "blank" -- surface it via the
                    # same path _read_last_entry()'s own re-decode already
                    # uses, so the caller's existing, tested exception
                    # contract is unchanged by this optimization.
                    return candidate
                if not is_blank:
                    return candidate

            if pos == 0:
                # The entire file has now been read and contains nothing
                # but blank lines.
                return None

            chunk_size = min(chunk_size * 2, _TAIL_MAX_CHUNK_BYTES) if chunk_size < _TAIL_MAX_CHUNK_BYTES else chunk_size


class AuditLockError(Exception):
    """Raised when the inter-process audit lock cannot be acquired within
    the configured timeout, or fails for an unexpected OS-level reason.

    Raising this always means: no record was appended, and the persistent
    chain head was not touched. Every existing caller of
    ``AuditLog.append()`` already treats any exception from it as a
    fail-closed condition (see gateway/app.py, main.py,
    src/mcc_core/coordinator.py) -- this is a subclass of ``Exception``
    specifically so those existing generic ``except Exception`` handlers
    catch it without modification.
    """


class AuditCorruptionError(Exception):
    """Raised when the audit file's last record cannot be parsed WHILE the
    inter-process lock is held (i.e. no cooperating writer could have been
    mid-write at that moment). This indicates real corruption, not a
    benign read/write race, and must never be silently treated as "no
    entries yet" -- doing so could silently restart the chain and mask
    tampering or storage corruption.
    """


class AuditLog:
    def __init__(self, path: str, *, lock_timeout_seconds: float = DEFAULT_LOCK_TIMEOUT_SECONDS) -> None:
        self.path = path
        self.lock_path = path + ".lock"
        self.lock_timeout_seconds = lock_timeout_seconds
        # Best-effort local cache only -- see append(), which never trusts
        # this value for a real write. A transient read race at
        # construction time (another process mid-write) must not crash
        # startup; it only degrades this diagnostic cache, never the
        # authoritative chain.
        self.prev_hash = GENESIS
        last = self._read_last_entry(tolerate_parse_errors=True)
        if last is not None:
            self.prev_hash = str(last.get("hash", GENESIS))

    def _read_last_entry(self, *, tolerate_parse_errors: bool) -> "Dict[str, Any] | None":
        try:
            last_line_bytes = _tail_last_nonblank_line(self.path)
        except FileNotFoundError:
            return None
        except OSError:
            # Any other storage-level failure reading the file (permission
            # denied, path is a directory, I/O error, ...). At construction
            # time (tolerate_parse_errors=True) this is a best-effort cache
            # read only -- degrade gracefully rather than crash the whole
            # process on startup; the AUTHORITATIVE path (append(), called
            # with tolerate_parse_errors=False) re-raises so the caller's
            # existing fail-closed handling applies.
            if tolerate_parse_errors:
                return None
            raise

        if not last_line_bytes:
            return None
        # Decoded here, not inside the tail-read helper -- this is exactly
        # where the old forward-scan's lazy per-line text-mode decoding
        # would have raised for this same line, so a UnicodeDecodeError
        # here propagates the same way it always did (raw, NOT wrapped as
        # AuditCorruptionError below -- that wrapping only ever actually
        # fires for json.JSONDecodeError; see the class's own history,
        # unchanged by this optimization).
        last_line = last_line_bytes.decode("utf-8")
        try:
            return json.loads(last_line)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            if tolerate_parse_errors:
                # Constructor-time best-effort cache only; never
                # authoritative (see class docstring / append()).
                return None
            raise AuditCorruptionError(
                f"audit log's last record could not be parsed while the "
                f"inter-process lock was held (path={self.path!r}); this "
                f"indicates real corruption, not a benign race: {exc}"
            ) from exc

    @staticmethod
    def _entry_hash(prev_hash: str, body: Dict[str, Any]) -> str:
        return hashlib.sha256(
            prev_hash.encode("utf-8") + canonical_bytes(body)
        ).hexdigest()

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        """Hold an exclusive, cross-process POSIX advisory lock on
        ``self.lock_path`` for the duration of the ``with`` block. Fails
        closed: if the lock cannot be acquired within
        ``self.lock_timeout_seconds``, raises ``AuditLockError`` and the
        body is never entered -- no read of chain state, no write, no
        mutation of ``self.prev_hash``.
        """
        lock_fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        acquired = False
        try:
            deadline = time.monotonic() + self.lock_timeout_seconds
            while True:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                    break
                except OSError as exc:
                    if exc.errno not in (errno.EACCES, errno.EAGAIN):
                        raise AuditLockError(
                            f"unexpected OS error acquiring inter-process audit "
                            f"lock {self.lock_path!r}: {exc}"
                        ) from exc
                    if time.monotonic() >= deadline:
                        raise AuditLockError(
                            f"timed out after {self.lock_timeout_seconds}s "
                            f"acquiring inter-process audit lock {self.lock_path!r}; "
                            f"refusing to append without owning the lock"
                        )
                    time.sleep(_LOCK_POLL_INTERVAL_SECONDS)
            yield
        finally:
            if acquired:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)

    def append(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Write one chained entry; fsync before returning.

        The full critical section -- acquiring the inter-process lock,
        reading the AUTHORITATIVE persistent chain head (never the
        in-memory cache), constructing the record, computing its hash,
        appending, and fsyncing -- happens atomically with respect to
        every other process sharing this audit file path. ``self.prev_hash``
        is advanced only after the durable append has actually succeeded;
        any failure (lock timeout, write error, corruption) leaves it
        untouched and propagates as an exception -- no record is
        fabricated as committed, and no stale/partial state becomes the
        next write's basis.

        If the write/flush/fsync sequence fails partway (e.g. the volume
        fills up -- ENOSPC -- exactly at fsync()), any bytes already handed
        to the OS by write()/flush() are rolled back (truncated) before the
        original exception is re-raised, so a caller that sees this failure
        never has to reconcile against a phantom, non-durable record left
        visible on disk.
        """
        with self._locked():
            last = self._read_last_entry(tolerate_parse_errors=False)
            authoritative_prev_hash = (
                str(last.get("hash", GENESIS)) if last is not None else GENESIS
            )
            body = {
                **record,
                "ts": datetime.now(timezone.utc).isoformat(),
                "prev_hash": authoritative_prev_hash,
            }
            entry = {**body, "hash": self._entry_hash(authoritative_prev_hash, body)}
            with open(self.path, "a", encoding="utf-8") as fh:
                start_pos = fh.tell()
                try:
                    fh.write(json.dumps(entry, sort_keys=True) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                except Exception:
                    try:
                        fh.truncate(start_pos)
                        fh.flush()
                    except Exception:
                        pass  # best-effort rollback; the original failure still propagates
                    raise
            # Only reached after a fully durable append -- safe to advance
            # the local cache now.
            self.prev_hash = entry["hash"]
        return entry

    def verify_chain_safe(self) -> bool:
        """Full-chain verification (``verify_chain()``), performed while
        holding this log's inter-process lock -- the SAME lock ``append()``
        uses -- so a concurrent writer can never be observed mid-write.

        This is an explicit, on-demand, O(file size) operation, never part
        of ``append()``'s own hot path. Its only intended caller is
        ``src/mcc_core/audit_integrity.py``'s periodic/startup verification,
        always off any request-handling path (see that module's docstring).
        """
        with self._locked():
            return self.verify_chain(self.path)

    def genesis_fingerprint_safe(self) -> "str | None":
        """A cheap (O(1) relative to file size -- reads only the first
        line), fail-safe identity fingerprint for THIS specific audit log,
        derived from its first non-blank record. ``None`` if the file does
        not exist or is empty.

        Used exclusively by ``mcc_core.audit_integrity`` to detect a
        worker's shared integrity-state registry holding a result computed
        over a DIFFERENT underlying audit log than this process's own --
        e.g. two workers misconfigured to point at different files sharing
        one Redis registry key. Never consulted by ``append()``'s hot path
        and never a substitute for ``verify_chain()``'s own full-chain
        check. Performed under the SAME inter-process lock as
        ``append()``/``verify_chain_safe()`` so it never reads a half-
        written first line.
        """
        with self._locked():
            try:
                with open(self.path, "rb") as fh:
                    first_line = fh.readline()
            except FileNotFoundError:
                return None
            if not first_line.strip():
                return None
            return hashlib.sha256(first_line).hexdigest()

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
