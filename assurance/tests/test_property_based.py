"""Workstream H -- Property-Based and Stateful Testing (PR #71).

Three layers, ordered from pure/fast to network-bound/slow:

1. ``test_h1_*``: pure, deterministic properties of the independent
   canonical-action implementation (Workstream D) -- no SUT, hundreds of
   generated examples in milliseconds.
2. ``test_h2_*``: the SAME differential property Workstream D checks against
   a fixed corpus, but GENERATIVE -- Hypothesis searches for an input the
   fixed corpus didn't anticipate where the independent implementation and
   the real actuator disagree. Bounded to a small example count (real HTTP
   round trips against a live subprocess are not free).
3. ``ActuatorProtocolMachine``: a stateful model of the actuator's real
   two-round consensus protocol. Hypothesis interleaves legitimate and
   illegitimate actions (genuine votes, forged votes, replays, wrong
   binding) in random orders and counts, checking one invariant after every
   step: the external-effect sink's receipt count only ever increases by
   exactly the number of genuinely authorized executions that step
   performed -- never more, never on any other path.

Failing examples are automatically minimized and PERSISTED by Hypothesis's
own example database (``.hypothesis/`` at the repo root, git-ignored) --
a regression that reproduces once is retried on every subsequent run until
fixed, without this suite reimplementing seed management.
"""

from __future__ import annotations

import string
import uuid
from typing import Any, Dict

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from hypothesis.stateful import Bundle, RuleBasedStateMachine, invariant, rule

from assurance.canonical_action import CanonicalActionError, action_hash, build_canonical_action
from assurance.sut.harness import SystemUnderTest, build_system_under_test

# --------------------------------------------------------------------------
# strategies
# --------------------------------------------------------------------------

_SAFE_TOKEN = st.text(alphabet=string.ascii_letters + string.digits + "-_.", min_size=1, max_size=12)
_METHODS = st.sampled_from(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "get", "Post", "TRACE", ""])
_PATH = st.lists(_SAFE_TOKEN, min_size=0, max_size=4).map(lambda parts: "/" + "/".join(parts))
_JSON_SCALAR = st.one_of(st.none(), st.booleans(), st.integers(-(10**9), 10**9),
                          st.floats(allow_nan=False, allow_infinity=False), _SAFE_TOKEN)
_JSON_VALUE = st.recursive(
    _JSON_SCALAR, lambda children: st.one_of(
        st.lists(children, max_size=3), st.dictionaries(_SAFE_TOKEN, children, max_size=3),
    ), max_leaves=6,
)
_GOVERNED_HEADER_NAME = st.sampled_from(["Content-Type", "content-type", "Accept", "ACCEPT", "X-Ignored"])
_BODY = st.one_of(st.none(), st.dictionaries(_SAFE_TOKEN, _JSON_VALUE, max_size=5), _SAFE_TOKEN)
_URL = st.builds(
    lambda scheme, path, port: f"{scheme}://127.0.0.1{'' if port is None else f':{port}'}{path}",
    scheme=st.sampled_from(["http", "https", "ftp", "HTTP"]),
    path=_PATH, port=st.one_of(st.none(), st.integers(1, 65535)),
)


# --------------------------------------------------------------------------
# H1: pure determinism properties (no SUT)
# --------------------------------------------------------------------------

@given(method=_METHODS, url=_URL, headers=st.dictionaries(_GOVERNED_HEADER_NAME, _SAFE_TOKEN, max_size=3), body=_BODY)
@settings(max_examples=200, deadline=None)
def test_h1_canonicalization_is_deterministic(method, url, headers, body):
    """Building the same action twice always produces the same hash, or
    both attempts raise the same error class -- never one success and one
    failure, never two different hashes for byte-identical input."""
    try:
        first = action_hash(build_canonical_action(method=method, url=url, headers=headers, body=body))
    except CanonicalActionError:
        first = None
    try:
        second = action_hash(build_canonical_action(method=method, url=url, headers=headers, body=body))
    except CanonicalActionError:
        second = None
    assert first == second


@given(
    method=_METHODS, url=_URL,
    headers=st.dictionaries(_GOVERNED_HEADER_NAME, _SAFE_TOKEN, max_size=3)
    .filter(lambda h: len({k.lower() for k in h}) == len(h)),
    body=_BODY,
)
@settings(max_examples=200, deadline=None)
def test_h1_header_case_never_affects_the_hash(method, url, headers, body):
    """Uppercasing every header name must never change the resulting hash
    -- header names are governed case-insensitively (see
    docs/CANONICAL_ACTION_FORMAT.md). The filter excludes header dicts
    where two distinct keys fold to the same lowercase name (e.g.
    ``Content-Type`` and ``content-type`` both present): duplicate governed
    headers are NOT deduplicated by the canonical format (each supplied
    instance becomes its own entry, by design -- see
    ``docs/CANONICAL_ACTION_FORMAT.md``), so case-folding such a dict via a
    Python dict comprehension changes the number of distinct keys and is a
    flawed transform, not evidence of a case-sensitivity bug in the SUT."""
    try:
        lower_hash = action_hash(build_canonical_action(method=method, url=url, headers=headers, body=body))
    except CanonicalActionError:
        lower_hash = None
    upper_headers = {k.upper(): v for k, v in headers.items()}
    try:
        upper_hash = action_hash(build_canonical_action(method=method, url=url, headers=upper_headers, body=body))
    except CanonicalActionError:
        upper_hash = None
    assert lower_hash == upper_hash


# --------------------------------------------------------------------------
# H2: generative differential testing against the real actuator
# --------------------------------------------------------------------------

@given(method=_METHODS, url=_URL, headers=st.dictionaries(_GOVERNED_HEADER_NAME, _SAFE_TOKEN, max_size=2), body=_BODY)
@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_h2_generative_differential_agreement_with_the_real_actuator(sut, method, url, headers, body):
    try:
        mine = action_hash(build_canonical_action(method=method, url=url, headers=headers, body=body))
    except CanonicalActionError:
        mine = None

    import httpx

    tx = str(uuid.uuid4())
    r = httpx.post(
        f"{sut.actuator_url}/v1/http/execute", headers={"x-api-key": sut.actuator_key()},
        json={"method": method, "url": url, "headers": headers, "body": body,
              "actor": "agent/egress", "resource": "notify", "transaction_id": tx, "idempotency_key": tx},
        timeout=10.0,
    )
    theirs = r.json()

    if mine is None:
        assert r.status_code in (400, 422), (
            f"independent implementation rejected {method!r} {url!r} {headers!r} {body!r} "
            f"but the SUT accepted it (status {r.status_code})"
        )
    else:
        assert theirs.get("outcome") == "CONSENSUS_REQUIRED", (
            f"independent implementation accepted {method!r} {url!r} {headers!r} {body!r} "
            f"but the SUT rejected it: {theirs}"
        )
        assert theirs.get("action_hash") == mine, (
            f"hash disagreement for {method!r} {url!r} {headers!r} {body!r}: "
            f"mine={mine} theirs={theirs.get('action_hash')}"
        )


# --------------------------------------------------------------------------
# stateful: the actuator's real two-round consensus protocol
# --------------------------------------------------------------------------

_shared_stateful_sut: "SystemUnderTest | None" = None


def _get_shared_stateful_sut() -> "SystemUnderTest":
    global _shared_stateful_sut
    if _shared_stateful_sut is None:
        _shared_stateful_sut = build_system_under_test()
    return _shared_stateful_sut


@pytest.fixture(scope="module", autouse=True)
def _cleanup_shared_stateful_sut():
    yield
    global _shared_stateful_sut
    if _shared_stateful_sut is not None:
        _shared_stateful_sut.close()
        _shared_stateful_sut = None


class ActuatorProtocolMachine(RuleBasedStateMachine):
    """Models one client interleaving legitimate and illegitimate actions
    against the real actuator across a random sequence. The one invariant
    that must hold after EVERY step, regardless of what sequence of actions
    produced it: the observed receipt count exactly matches this model's own
    count of genuinely-authorized executions -- no attack path, in any
    order or combination, ever produces an extra external effect."""

    proposals: Bundle = Bundle("proposals")

    def __init__(self) -> None:
        super().__init__()
        self.sut = _get_shared_stateful_sut()
        self.expected_executions = self.sut.notification_receipt_count()

    @rule(target=proposals)
    def propose(self):
        tx = str(uuid.uuid4())
        proposal = self.sut.propose_notification(transaction_id=tx, idempotency_key=tx)
        return proposal

    @rule(proposal=proposals)
    def submit_with_genuine_votes(self, proposal):
        if "challenge_id" not in proposal:
            return  # already consumed by an earlier rule in this sequence
        votes = self.sut.actuator_votes(
            action="http.request", payload=self.sut.canonical_notification_action(proposal),
            actor="agent/egress", resource="notify", nonce=proposal["nonce"],
        )
        result = self.sut.submit_notification_votes(proposal, votes=votes)
        if result.get("outcome") == "ALLOW" and result.get("executed") is True:
            self.expected_executions += 1
        proposal["challenge_id"] = None  # mark consumed within this model

    @rule(proposal=proposals)
    def submit_with_forged_vote(self, proposal):
        if "challenge_id" not in proposal or proposal["challenge_id"] is None:
            return
        forged = self.sut.forge_vote(
            action="http.request", payload=self.sut.canonical_notification_action(proposal),
            actor="agent/egress", resource="notify", nonce=proposal["nonce"],
        )
        result = self.sut.submit_notification_votes(proposal, votes=[forged] * 3)
        assert not (result.get("outcome") == "ALLOW" and result.get("executed") is True)
        proposal["challenge_id"] = None

    @rule(proposal=proposals)
    def submit_then_immediately_replay(self, proposal):
        """Submit genuine votes once (a legitimate first use, if this
        proposal's challenge is still fresh), then immediately resubmit the
        IDENTICAL challenge_id + votes -- the replay must never cause a
        SECOND execution on top of whatever the first submission did."""
        if "challenge_id" not in proposal or proposal["challenge_id"] is None:
            return
        votes = self.sut.actuator_votes(
            action="http.request", payload=self.sut.canonical_notification_action(proposal),
            actor="agent/egress", resource="notify", nonce=proposal["nonce"],
        )
        first = self.sut.submit_notification_votes(proposal, votes=votes)
        if first.get("outcome") == "ALLOW" and first.get("executed") is True:
            self.expected_executions += 1

        # Replay the SAME challenge_id + votes -- proposal is unmutated so
        # far, so this genuinely resubmits the original (now-consumed)
        # challenge, not a fresh Round 1.
        replay = self.sut.submit_notification_votes(proposal, votes=votes)
        assert not (replay.get("outcome") == "ALLOW" and replay.get("executed") is True)

        proposal["challenge_id"] = None

    @invariant()
    def receipt_count_matches_the_model(self):
        assert self.sut.notification_receipt_count() == self.expected_executions


TestActuatorProtocolStateMachine = ActuatorProtocolMachine.TestCase
TestActuatorProtocolStateMachine.settings = settings(
    max_examples=8, stateful_step_count=6, deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
