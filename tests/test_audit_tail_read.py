"""Differential equivalence: the optimized O(tail) backward-seek last-line
read (``mcc_core.audit._tail_last_nonblank_line``) vs. a REFERENCE forward
full-file scan kept here ONLY to prove equivalence -- never shipped in
production code. See ``src/mcc_core/audit.py``'s own module docstring and
``_tail_last_nonblank_line``'s docstring for the one deliberate, disclosed
scope difference (historical, non-last-line corruption is no longer
incidentally detected by the hot read path -- see
test_corrupted_non_last_line_is_not_detected_by_tail_read_but_is_by_verify_chain
below, which exists specifically to pin that disclosed difference down to
an exact, tested boundary rather than leaving it as prose).

ROUND 2 CORRECTION: the reference below used to open the file in BINARY
mode and use ``bytes.strip()`` -- a *simplified binary approximation* of
the original implementation, not the original implementation itself. That
approximation is exactly why it failed to catch two real regressions in
round 1: (1) ``bytes.strip()`` only strips ASCII whitespace, while the
original text-mode scan's ``str.strip()`` is Unicode-whitespace-aware (a
trailing line containing only a Unicode space such as NBSP U+00A0 was
wrongly treated as non-blank by the optimized code, selected as "the last
line," and then spuriously failed JSON parsing); and (2) the old reference
split lines on literal ``b"\\n"`` the same way the broken optimized code
did, so it could never have caught the optimized code ALSO missing
Python's universal-newlines handling of bare ``\\r`` and ``\\r\\n``. The
reference below now opens the file in true TEXT mode with
``encoding="utf-8"``, exactly like the pre-optimization production code
did, so it exercises the real historical contract, not a simplified
stand-in for it.
"""

from __future__ import annotations

import os
import random

import pytest

from mcc_core.audit import _tail_last_nonblank_line

# ---------------------------------------------------------------------------
# Reference implementation: the TRUE original text-mode forward full-file
# scan (not a binary approximation), kept ONLY in this test file to
# differentially prove the optimized tail-read against it.
# ---------------------------------------------------------------------------


def _reference_forward_scan_last_nonblank_line(path: str) -> "bytes | None":
    """The exact pre-optimization implementation: text mode (universal
    newlines: \\r\\n / \\r / \\n all equivalent; strict UTF-8 decoding),
    ``str.strip()`` for blankness (Unicode-whitespace-aware). Raises
    ``UnicodeDecodeError`` directly from the ``for line in fh`` iteration
    for invalid UTF-8 anywhere in the file, exactly as the original
    production code did -- this is not wrapped or caught here."""
    last_line: "str | None" = None
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                last_line = line
    if last_line is None:
        return None
    # The old text-mode reader kept the line INCLUDING its trailing '\n'
    # (readline semantics); strip it here so this matches the new
    # function's contract exactly (no trailing newline in the returned
    # bytes) -- the trailing newline was never semantically meaningful
    # (json.loads tolerates it), only normalized here for a clean diff.
    return last_line.rstrip("\n").encode("utf-8")


def _both(path: str):
    old = _reference_forward_scan_last_nonblank_line(path)
    new = _tail_last_nonblank_line(path)
    if new is not None:
        new = new.rstrip(b"\n")
    return old, new


def _write(path: str, data: bytes) -> None:
    with open(path, "wb") as fh:
        fh.write(data)


# ---------------------------------------------------------------------------
# Exact-equivalence cases
# ---------------------------------------------------------------------------


def test_missing_file_both_raise_filenotfound(tmp_path):
    p = str(tmp_path / "missing.jsonl")
    with pytest.raises(FileNotFoundError):
        _reference_forward_scan_last_nonblank_line(p)
    with pytest.raises(FileNotFoundError):
        _tail_last_nonblank_line(p)


def test_empty_file(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    _write(p, b"")
    assert _both(p) == (None, None)


def test_only_blank_lines(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    _write(p, b"\n\n   \n\t\n\n")
    assert _both(p) == (None, None)


def test_single_entry_no_trailing_newline(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    _write(p, b'{"a": 1}')
    old, new = _both(p)
    assert old == new == b'{"a": 1}'


def test_single_entry_with_trailing_newline(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    _write(p, b'{"a": 1}\n')
    old, new = _both(p)
    assert old == new == b'{"a": 1}'


def test_many_entries_no_trailing_blank(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    lines = [('{"i": %d}' % i).encode() for i in range(500)]
    _write(p, b"\n".join(lines) + b"\n")
    old, new = _both(p)
    assert old == new == lines[-1]


@pytest.mark.parametrize("trailing_blanks", [1, 2, 5, 20])
def test_many_entries_with_trailing_blank_lines(tmp_path, trailing_blanks):
    p = str(tmp_path / "audit.jsonl")
    lines = [('{"i": %d}' % i).encode() for i in range(300)]
    content = b"\n".join(lines) + b"\n" + (b"\n" * trailing_blanks)
    _write(p, content)
    old, new = _both(p)
    assert old == new == lines[-1]


def test_non_ascii_utf8_content(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    lines = [
        '{"i": 0, "note": "plain"}'.encode(),
        '{"i": 1, "note": "emoji \U0001F600 éèê"}'.encode(),
        '{"i": 2, "note": "日本語"}'.encode(),
    ]
    _write(p, b"\n".join(lines) + b"\n")
    old, new = _both(p)
    assert old == new == lines[-1]


@pytest.mark.parametrize("boundary_offset", [-3, -2, -1, 0, 1, 2, 3])
def test_non_ascii_content_straddling_chunk_boundary(tmp_path, boundary_offset):
    """Construct a file whose total size sits within a few bytes of the
    tail-read's initial chunk size, with multi-byte UTF-8 characters placed
    right around that boundary, to force at least one backward-seek retry
    and exercise the "don't split a multi-byte char across chunks"
    correctness path."""
    from mcc_core.audit import _TAIL_INITIAL_CHUNK_BYTES

    pad_line = b'{"pad": "' + b"x" * 50 + b'"}\n'
    target_size = _TAIL_INITIAL_CHUNK_BYTES + boundary_offset
    padding = b""
    while len(padding) < target_size:
        padding += pad_line
    last = '{"note": "\U0001F600éèê boundary"}'.encode()
    _write(p := str(tmp_path / "audit.jsonl"), padding + last + b"\n")
    old, new = _both(p)
    assert old == new == last


# ---------------------------------------------------------------------------
# Round 2 regression tests: Unicode whitespace and CR/LF/CRLF separators
# ---------------------------------------------------------------------------

UNICODE_WHITESPACE_CHARS = [
    " ",  # NO-BREAK SPACE
    " ",  # EM SPACE
    "　",  # IDEOGRAPHIC SPACE
    " ",  # LINE SEPARATOR (whitespace per str.isspace(), but NOT a
    # universal-newlines line terminator -- stays within one logical line)
]


@pytest.mark.parametrize("ws_char", UNICODE_WHITESPACE_CHARS)
def test_trailing_unicode_whitespace_only_line_is_blank(tmp_path, ws_char):
    """Regression: a trailing line containing ONLY a Unicode whitespace
    character must be skipped as blank, exactly as the original
    str.strip()-based scan skipped it -- bytes.strip() (ASCII-only) does
    not, and wrongly selected this line as "the last line" in round 1,
    which then failed JSON parsing even though the true last entry
    (lines[-1]) was perfectly valid."""
    p = str(tmp_path / "audit.jsonl")
    lines = [b'{"i": 0}', b'{"i": 1}']
    _write(p, b"\n".join(lines) + b"\n" + ws_char.encode("utf-8") + b"\n")
    old, new = _both(p)
    assert old == new == lines[-1]


@pytest.mark.parametrize("n_trailing", [1, 2, 5])
def test_multiple_trailing_unicode_whitespace_lines(tmp_path, n_trailing):
    p = str(tmp_path / "audit.jsonl")
    lines = [b'{"i": 0}', b'{"i": 1}', b'{"i": 2}']
    trailing = (b"\xe2\x80\x83\n" * n_trailing)  # EM SPACE, UTF-8 encoded
    _write(p, b"\n".join(lines) + b"\n" + trailing)
    old, new = _both(p)
    assert old == new == lines[-1]


def test_trailing_mixed_blank_and_unicode_whitespace_lines(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    lines = [b'{"i": 0}', b'{"i": 1}']
    trailing = b"\n" + " ".encode("utf-8") + b"\n   \n" + "　".encode("utf-8") + b"\n\n"
    _write(p, b"\n".join(lines) + b"\n" + trailing)
    old, new = _both(p)
    assert old == new == lines[-1]


@pytest.mark.parametrize("sep", [b"\r", b"\r\n"])
def test_bare_cr_and_crlf_separated_entries(tmp_path, sep):
    """Regression: the original text-mode scan used universal newlines
    (\\r\\n / \\r / \\n all equivalent); the round-1 optimized reader split
    only on literal b"\\n", so a CR-only- or CRLF-separated file was
    treated as one unsplit blob instead of being split into its real
    logical lines."""
    p = str(tmp_path / "audit.jsonl")
    lines = [b'{"i": 0}', b'{"i": 1}', b'{"i": 2}']
    _write(p, sep.join(lines) + sep)
    old, new = _both(p)
    assert old == new == lines[-1]


def test_mixed_newline_conventions_between_entries(tmp_path):
    """A file whose entries are separated by a mix of \\n, \\r, and \\r\\n
    -- e.g. content that passed through different tools/platforms over
    the file's history -- must still be split into the same logical lines
    the original text-mode scan would have produced."""
    p = str(tmp_path / "audit.jsonl")
    lines = [b'{"i": 0}', b'{"i": 1}', b'{"i": 2}', b'{"i": 3}']
    content = lines[0] + b"\n" + lines[1] + b"\r" + lines[2] + b"\r\n" + lines[3] + b"\n"
    _write(p, content)
    old, new = _both(p)
    assert old == new == lines[-1]


@pytest.mark.parametrize("boundary_offset", [-2, -1, 0, 1, 2])
@pytest.mark.parametrize("sep", [b"\r", b"\r\n"])
def test_cr_separators_straddling_chunk_boundary(tmp_path, sep, boundary_offset):
    """Force the CR/CRLF separator itself to land right at the tail-read's
    initial chunk-size boundary, across several backward-seek retries,
    and confirm the fix's boundary-safety argument (which does not depend
    on separator byte-length) holds in practice, not just in the
    single-chunk case."""
    from mcc_core.audit import _TAIL_INITIAL_CHUNK_BYTES

    pad_entry = b'{"pad": "' + b"x" * 50 + b'"}'
    padding = b""
    while len(padding) < _TAIL_INITIAL_CHUNK_BYTES + boundary_offset:
        padding += pad_entry + sep
    last = b'{"note": "boundary"}'
    _write(p := str(tmp_path / "audit.jsonl"), padding + last + sep)
    old, new = _both(p)
    assert old == new == last


@pytest.mark.parametrize("boundary_offset", [-2, -1, 0, 1, 2])
def test_unicode_whitespace_straddling_chunk_boundary(tmp_path, boundary_offset):
    """Same chunk-boundary stress, but for the Unicode-whitespace-blankness
    fix specifically: a trailing NBSP-only line positioned so the tail
    reader must grow its backward-seek window at least once before
    settling on the real last entry."""
    from mcc_core.audit import _TAIL_INITIAL_CHUNK_BYTES

    pad_entry = b'{"pad": "' + b"x" * 50 + b'"}\n'
    padding = b""
    while len(padding) < _TAIL_INITIAL_CHUNK_BYTES + boundary_offset:
        padding += pad_entry
    last = b'{"note": "boundary"}'
    _write(p := str(tmp_path / "audit.jsonl"), padding + last + b"\n" + " ".encode("utf-8") + b"\n")
    old, new = _both(p)
    assert old == new == last


def test_random_fuzz_corpus_with_unicode_whitespace_and_crlf(tmp_path):
    """Extends the existing fuzz corpus (test_random_fuzz_corpus) with
    Unicode-whitespace padding lines and all three newline conventions,
    the exact two dimensions round 1's regressions came from."""
    rng = random.Random(987654321)
    seps = [b"\n", b"\r", b"\r\n"]
    for trial in range(200):
        n_entries = rng.randint(0, 30)
        parts = []
        for i in range(n_entries):
            if rng.random() < 0.25:
                # A blank-ish padding line: either plain ASCII blank or a
                # Unicode-whitespace-only line.
                if rng.random() < 0.5:
                    parts.append(b" " * rng.randint(0, 4))
                else:
                    ch = rng.choice(UNICODE_WHITESPACE_CHARS[:-1])  # skip U+2028 here; it's content-only, tested separately
                    parts.append((ch * rng.randint(1, 3)).encode("utf-8"))
            else:
                note = "".join(rng.choice("ab é日\U0001F600") for _ in range(rng.randint(0, 10)))
                parts.append(('{"i": %d, "note": %r}' % (i, note)).encode("utf-8"))
        content = b""
        for part in parts:
            content += part + rng.choice(seps)
        p = str(tmp_path / f"fuzz2_{trial}.jsonl")
        _write(p, content)
        old, new = _both(p)
        assert old == new, f"trial {trial} mismatch: old={old!r} new={new!r} content={content!r}"


def test_corrupted_last_line_invalid_json_but_valid_utf8(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    lines = [b'{"i": 0}', b'{"i": 1}', b"not-valid-json{{{"]
    _write(p, b"\n".join(lines) + b"\n")
    old, new = _both(p)
    assert old == new == b"not-valid-json{{{"


def test_corrupted_last_line_invalid_utf8_raises_identically(tmp_path):
    """The TRUE text-mode reference raises ``UnicodeDecodeError`` directly
    (from its own ``for line in fh`` text decoding) for an invalid-UTF-8
    last line -- it never gets the chance to return a candidate at all.
    The optimized tail-read instead returns the raw bytes (it never
    decodes internally), but the SAME exception, at the SAME contract
    point (``AuditLog._read_last_entry()``'s subsequent explicit
    ``.decode("utf-8")`` call), is what the caller actually observes --
    proven end-to-end in test_audit_optimization_regression.py. Here we
    confirm both paths agree that this content IS a corruption case, not
    that they raise from literally the same line of code."""
    p = str(tmp_path / "audit.jsonl")
    lines = [b'{"i": 0}', b'{"i": 1}']
    bad_last = b"\xff\xfe\x00bad"
    _write(p, b"\n".join(lines) + b"\n" + bad_last + b"\n")

    with pytest.raises(UnicodeDecodeError):
        _reference_forward_scan_last_nonblank_line(p)

    new_candidate = _tail_last_nonblank_line(p)
    assert new_candidate.rstrip(b"\n") == bad_last
    with pytest.raises(UnicodeDecodeError):
        new_candidate.decode("utf-8")


@pytest.mark.parametrize("size_kb", [1, 10, 100, 2000])
def test_large_files_various_sizes(tmp_path, size_kb):
    p = str(tmp_path / "audit.jsonl")
    n = max(1, (size_kb * 1024) // 40)
    lines = [('{"i": %d, "pad": "%s"}' % (i, "x" * 20)).encode() for i in range(n)]
    _write(p, b"\n".join(lines) + b"\n")
    old, new = _both(p)
    assert old == new == lines[-1]


def test_random_fuzz_corpus(tmp_path):
    """Randomized corpus: many small files with random blank-line padding,
    random entry counts, and random non-ASCII content, each checked for
    exact equivalence."""
    rng = random.Random(1234567)
    for trial in range(200):
        n_entries = rng.randint(0, 40)
        lines = []
        for i in range(n_entries):
            note = "".join(rng.choice("ab é日\U0001F600") for _ in range(rng.randint(0, 12)))
            lines.append(('{"i": %d, "note": %r}' % (i, note)).encode("utf-8"))
        trailing_blanks = rng.randint(0, 4)
        content = (b"\n".join(lines) + b"\n" if lines else b"") + (b"\n" * trailing_blanks)
        p = str(tmp_path / f"fuzz_{trial}.jsonl")
        _write(p, content)
        old, new = _both(p)
        assert old == new, f"trial {trial} mismatch: old={old!r} new={new!r} content={content!r}"


# ---------------------------------------------------------------------------
# Proof the optimization is genuinely O(tail), not O(file size)
# ---------------------------------------------------------------------------


def test_tail_read_does_not_read_whole_large_file(tmp_path, monkeypatch):
    """Instrument the actual bytes read from disk and prove they are
    bounded by a small multiple of the last entry's size, independent of
    how large the file is -- not just "it's fast," but that the read
    pattern itself is bounded."""
    p = str(tmp_path / "audit.jsonl")
    n = 200_000
    lines = [('{"i": %d}' % i).encode() for i in range(n)]
    _write(p, b"\n".join(lines) + b"\n")
    file_size = os.path.getsize(p)
    assert file_size > 2_000_000  # sanity: this really is a large file

    bytes_read = {"total": 0}
    real_open = open

    def counting_open(path, mode="r", *a, **kw):
        fh = real_open(path, mode, *a, **kw)
        if path == p and "b" in mode:
            real_read = fh.read

            def counting_read(size=-1):
                data = real_read(size)
                bytes_read["total"] += len(data)
                return data

            fh.read = counting_read
        return fh

    monkeypatch.setattr("builtins.open", counting_open)
    result = _tail_last_nonblank_line(p)
    assert result == lines[-1]
    # Generous bound: a handful of chunk retries at most, nowhere near the
    # full ~2MB+ file.
    assert bytes_read["total"] < 200_000, (
        f"tail read pulled {bytes_read['total']} bytes from a {file_size}-byte "
        f"file -- expected a small, size-independent amount"
    )


# ---------------------------------------------------------------------------
# The one disclosed, deliberate scope difference
# ---------------------------------------------------------------------------


def test_corrupted_non_last_line_is_not_detected_by_tail_read_but_is_by_verify_chain(tmp_path):
    """Pins down the exact, disclosed behavior difference: invalid UTF-8 in
    a line that is NOT the last non-blank line is no longer detected by the
    hot read path (a deliberate consequence of not reading the whole file
    any more -- see _tail_last_nonblank_line's docstring), but remains
    detected by an explicit verify_chain() call, which still scans
    everything. This is a disclosed scope narrowing, not a silent one."""
    from mcc_core.audit import AuditLog

    p = str(tmp_path / "audit.jsonl")
    good_first = b'{"hash": "deadbeef", "i": 0}'
    bad_middle = b"\xff\xfe corrupted historical line"
    good_last = b'{"hash": "cafebabe", "i": 2, "prev_hash": "x"}'
    _write(p, good_first + b"\n" + bad_middle + b"\n" + good_last + b"\n")

    # The hot path used by append()/__init__ does NOT choke on the
    # historical corruption -- it only ever looks at the tail.
    tail_result = _tail_last_nonblank_line(p)
    assert tail_result.rstrip(b"\n") == good_last

    # An AuditLog can be constructed and used against this file without
    # the historical corruption blocking it.
    log = AuditLog(p)
    assert log.prev_hash != "GENESIS"

    # verify_chain(), which still does a real full scan, is unaffected and
    # still fails closed on this file (corrupted historical content makes
    # it unparsable as a well-formed chain).
    assert AuditLog.verify_chain(p) is False
