"""Workstream D -- Canonical Action Format Differential Testing (PR #71).

For every input in the corpus below, an INDEPENDENTLY implemented parser
(``assurance.canonical_action``, written from ``docs/CANONICAL_ACTION_FORMAT.md``,
never by importing the SUT's own ``egress_proxy.canonical_action``) must agree
with the real, running actuator on the resulting ``action_hash`` -- or, for the
malformed corpus, both must reject the input. Canonicalization happens before
any authority/consensus decision (see ``egress_proxy/app.py``'s ``_dispatch``),
so the actuator's ``action_hash`` is observable from the very first
``CONSENSUS_REQUIRED`` response regardless of whether the actor holds any
authority -- this test never needs a successful execution, only the proposal
step, and it uses an arbitrary transaction each time.

Agreement across this corpus is evidence the format is unambiguously
specified and consistently implemented; it is not proof of the ABSENCE of
disagreement on inputs outside this corpus.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, Optional

import httpx
import pytest

from assurance.canonical_action import CanonicalActionError, action_hash, build_canonical_action

# --------------------------------------------------------------------------
# corpus: (id, method, url, headers, body) -- every entry must canonicalize
# and its hash must match the SUT's exactly.
# --------------------------------------------------------------------------
VALID_CORPUS = [
    ("simple-post-json", "POST", "http://127.0.0.1:1/x", {"Content-Type": "application/json"}, {"b": 2, "a": 1}),
    ("query-sorted-and-dup-keys", "POST", "http://127.0.0.1:1/x?z=1&a=2&a=1", {}, None),
    ("trailing-slash-and-extra-header-dropped", "GET", "http://127.0.0.1/x/",
     {"Accept": "text/plain", "X-Custom": "not-governed-ignored"}, None),
    ("raw-string-body", "POST", "http://127.0.0.1:1/x", {"content-type": "text/plain"}, "raw-string-body"),
    ("uppercase-scheme-and-method-nested-body", "post", "HTTP://127.0.0.1:1/X", {}, {"nested": {"k": "v"}, "list": [1, 2, 3]}),
    ("explicit-default-port-equals-implicit", "GET", "http://127.0.0.1:80/x", {}, None),
    ("lowercase-method-normalizes", "get", "http://127.0.0.1:1/x", {}, None),
    ("mixed-case-header-name-normalizes", "POST", "http://127.0.0.1:1/x", {"CoNtEnT-tYpE": "application/json"}, {"a": 1}),
    ("empty-body-variants-empty-dict", "POST", "http://127.0.0.1:1/x", {}, {}),
    ("empty-body-variants-empty-string", "POST", "http://127.0.0.1:1/x", {}, ""),
    ("hop-by-hop-header-dropped", "GET", "http://127.0.0.1:1/x", {"Connection": "keep-alive", "Accept": "*/*"}, None),
    ("https-default-port", "GET", "https://127.0.0.1/x", {}, None),
    ("unicode-in-body-value", "POST", "http://127.0.0.1:1/x", {}, {"name": "éèê café"}),
    ("bytes-like-raw-body", "PUT", "http://127.0.0.1:1/x", {}, "0123456789"),
    ("no-query-string", "DELETE", "http://127.0.0.1:1/resource/42", {}, None),
]

# --------------------------------------------------------------------------
# corpus: (id, method, url, headers, body) -- every entry must be REJECTED
# by both implementations (same category of malformed/unsafe input).
# --------------------------------------------------------------------------
MALFORMED_CORPUS = [
    ("unsupported-method", "TRACE", "http://127.0.0.1:1/x", {}, None),
    ("unsupported-scheme", "GET", "ftp://127.0.0.1:1/x", {}, None),
    ("embedded-credentials-in-url", "GET", "http://user:pass@127.0.0.1:1/x", {}, None),
    ("secret-bearing-header-authorization", "GET", "http://127.0.0.1:1/x", {"Authorization": "Bearer x"}, None),
    ("secret-bearing-header-cookie", "GET", "http://127.0.0.1:1/x", {"Cookie": "session=x"}, None),
    ("secret-bearing-header-x-api-key", "GET", "http://127.0.0.1:1/x", {"X-Api-Key": "sneaky"}, None),
    ("empty-method", "", "http://127.0.0.1:1/x", {}, None),
    ("empty-url", "GET", "", {}, None),
    ("url-with-no-host", "GET", "http:///x", {}, None),
    ("out-of-range-port", "GET", "http://127.0.0.1:99999/x", {}, None),
]


def _my_result(method: str, url: str, headers: Dict[str, str], body: Any) -> "Optional[str]":
    try:
        return action_hash(build_canonical_action(method=method, url=url, headers=headers, body=body))
    except CanonicalActionError:
        return None


def _sut_result(sut, method: str, url: str, headers: Dict[str, str], body: Any) -> Dict[str, Any]:
    tx = str(uuid.uuid4())
    r = httpx.post(
        f"{sut.actuator_url}/v1/http/execute", headers={"x-api-key": sut.actuator_key()},
        json={"method": method, "url": url, "headers": headers, "body": body,
              "actor": "agent/egress", "resource": "notify", "transaction_id": tx, "idempotency_key": tx},
        timeout=10.0,
    )
    payload = r.json()
    payload["_status_code"] = r.status_code
    return payload


@pytest.mark.parametrize("case_id,method,url,headers,body", VALID_CORPUS, ids=[c[0] for c in VALID_CORPUS])
def test_valid_corpus_action_hash_agrees_with_the_real_actuator(sut, case_id, method, url, headers, body):
    mine = _my_result(method, url, headers, body)
    assert mine is not None, f"{case_id}: independent implementation unexpectedly rejected a valid case"

    theirs = _sut_result(sut, method, url, headers, body)
    assert theirs["outcome"] == "CONSENSUS_REQUIRED", f"{case_id}: expected the proposal step to succeed"
    assert theirs["action_hash"] == mine, (
        f"{case_id}: independent canonicalization disagrees with the SUT "
        f"({mine} != {theirs['action_hash']})"
    )


@pytest.mark.parametrize("case_id,method,url,headers,body", MALFORMED_CORPUS, ids=[c[0] for c in MALFORMED_CORPUS])
def test_malformed_corpus_rejected_by_both_implementations(sut, case_id, method, url, headers, body):
    """Both implementations must reject every case here -- but the SUT
    rejects at one of TWO layers: request-schema validation (empty
    ``method``/``url`` never even reach canonicalization -- FastAPI/pydantic
    ``min_length=1`` rejects them with 422) or canonicalization itself
    (400, ``INVALID_REQUEST``). Both are fail-closed; this test accepts
    either, since the property under test is "never accepted", not which
    layer caught it."""
    mine = _my_result(method, url, headers, body)
    assert mine is None, f"{case_id}: independent implementation unexpectedly accepted a malformed case"

    theirs = _sut_result(sut, method, url, headers, body)
    assert theirs["_status_code"] in (400, 422), (
        f"{case_id}: SUT did not reject a malformed case (status {theirs['_status_code']})"
    )
    if theirs["_status_code"] == 400:
        assert theirs["outcome"] == "INVALID_REQUEST"


def test_materially_identical_requests_hash_identically():
    a = _my_result("post", "http://127.0.0.1:1/x", {"content-type": "application/json"}, {"a": 1})
    b = _my_result("POST", "HTTP://127.0.0.1:1/x", {"Content-Type": "application/json"}, {"a": 1})
    assert a == b


def test_materially_different_requests_hash_differently():
    a = _my_result("POST", "http://127.0.0.1:1/x", {}, {"a": 1})
    b = _my_result("POST", "http://127.0.0.1:1/x", {}, {"a": 2})
    assert a != b
