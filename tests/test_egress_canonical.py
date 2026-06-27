"""Canonical HTTP action binding: deterministic, equivalence-stable, tamper-sensitive."""

import pytest

from egress_proxy.canonical_action import (
    CanonicalActionError,
    action_hash,
    build_canonical_action,
    reconstruct_request,
)


def _h(**kw):
    return action_hash(build_canonical_action(**kw))


def test_method_and_query_and_header_order_normalized():
    a = build_canonical_action(method="post", url="http://Up:8/p?b=2&a=1",
                               headers={"Content-Type": "application/json", "Accept": "x"})
    assert a["method"] == "POST" and a["host"] == "up" and a["port"] == 8
    assert a["query"] == [["a", "1"], ["b", "2"]]
    assert a["headers"] == [["accept", "x"], ["content-type", "application/json"]]


def test_equivalent_actions_same_hash():
    h1 = _h(method="POST", url="http://up:8/p?a=1&b=2",
            headers={"content-type": "application/json"}, body={"x": 1, "y": 2})
    h2 = _h(method="post", url="http://up:8/p?b=2&a=1",
            headers={"content-type": "application/json"}, body={"y": 2, "x": 1})
    assert h1 == h2


@pytest.mark.parametrize("a,b", [
    (dict(method="POST", url="http://up/p"), dict(method="PUT", url="http://up/p")),
    (dict(method="GET", url="http://up/p"), dict(method="GET", url="http://up2/p")),
    (dict(method="GET", url="http://up/p"), dict(method="GET", url="http://up/q")),
    (dict(method="GET", url="http://up/p?a=1"), dict(method="GET", url="http://up/p?a=2")),
    (dict(method="GET", url="http://up:8/p"), dict(method="GET", url="http://up:9/p")),
    (dict(method="POST", url="http://up/p", body={"amount": 1}),
     dict(method="POST", url="http://up/p", body={"amount": 2})),
    (dict(method="POST", url="http://up/p", headers={"content-type": "a"}),
     dict(method="POST", url="http://up/p", headers={"content-type": "b"})),
])
def test_material_difference_changes_hash(a, b):
    assert _h(**a) != _h(**b)


def test_ungoverned_and_hopbyhop_headers_dropped():
    a = build_canonical_action(method="GET", url="http://up/p",
                               headers={"X-Secret": "s", "Connection": "keep-alive",
                                        "Host": "evil", "content-type": "j"})
    names = [h[0] for h in a["headers"]]
    assert names == ["content-type"]  # x-secret, connection, host all dropped


def test_reconstruct_roundtrip_json():
    a = build_canonical_action(method="POST", url="http://up:8/charge?a=1",
                               headers={"content-type": "application/json"},
                               body={"amount": 10, "currency": "USD"})
    method, url, headers, body = reconstruct_request(a)
    assert method == "POST" and url == "http://up:8/charge?a=1"
    assert headers == {"content-type": "application/json"}
    assert body == {"amount": 10, "currency": "USD"}


def test_clamped_json_action_recanonicalizes_identically():
    # The core CONSTRAIN invariant: clamping body.amount yields an action equal to
    # re-canonicalizing the clamped request (no stale body hash).
    original = build_canonical_action(method="POST", url="http://up/c", body={"amount": 10000})
    clamped = dict(original)
    clamped["body.amount"] = 5000
    rebuilt = build_canonical_action(method="POST", url="http://up/c", body={"amount": 5000})
    assert clamped == rebuilt and action_hash(clamped) == action_hash(rebuilt)
    assert action_hash(clamped) != action_hash(original)


@pytest.mark.parametrize("url", [
    "ftp://up/p", "http://user:pass@up/p", "http://up:99999/p", "://nohost", "notaurl",
])
def test_invalid_urls_rejected(url):
    with pytest.raises(CanonicalActionError):
        build_canonical_action(method="GET", url=url)


def test_unsupported_method_rejected():
    with pytest.raises(CanonicalActionError):
        build_canonical_action(method="TRACE", url="http://up/p")


def test_oversized_body_rejected():
    with pytest.raises(CanonicalActionError):
        build_canonical_action(method="POST", url="http://up/p", body={"x": "a" * (2 * 1024 * 1024)})
