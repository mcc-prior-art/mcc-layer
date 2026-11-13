"""Workstream G (extended) -- Signed External Audit Checkpoint (PR #71).

Closes a stated gap: G1-G3 (``test_audit_survivability.py``) prove the
Gateway's OWN ``/verify`` is tamper-evident, but nothing previously
anchored the chain to an INDEPENDENT, externally-signed checkpoint (a
"no mechanism anchors the audit chain itself to an external signer" gap
recorded in ``docs/ASSURANCE_COVERAGE_MATRIX.md``). See
``assurance/audit_checkpoint.py`` for the mechanism itself and exactly
what it does and does not prove.

Boots its OWN isolated SUT (module-scoped, not the shared session
fixture) because these tests deliberately tamper the audit log file
directly (mirroring G3's own precedent) -- sharing state with other
workstream files' assertions about chain validity would be a real
ordering hazard, not just style.
"""

from __future__ import annotations

import json
import uuid

import httpx
import pytest

from assurance.audit_checkpoint import (
    generate_checkpoint_key,
    issue_checkpoint,
    read_audit_entries,
    verify_checkpoint,
)
from assurance.sut.harness import build_system_under_test

ACTOR = "agent/checkpoint-bot"
ACTION = "send_notification"
RESOURCE = "notifications"


def _payload(**overrides):
    base = {"recipient": "customer-ckpt-1", "message": "assurance-g-checkpoint-probe",
            "priority": 2, "channel": "email", "correlation_id": str(uuid.uuid4())}
    base.update(overrides)
    return base


def _authorized_execute(sut) -> None:
    payload = _payload()
    ch = httpx.post(
        f"{sut.gateway_url}/consensus/challenge", headers={"x-api-key": sut.agent_key(ACTOR)},
        json={"actor": ACTOR, "action": ACTION, "resource": RESOURCE, "context": payload}, timeout=10.0,
    ).json()
    votes = sut.gateway_consensus_votes(
        action=ACTION, payload=payload, actor=ACTOR, resource=RESOURCE,
        nonce=ch["nonce"], policy_hash=ch.get("policy_hash"),
    )
    r = httpx.post(
        f"{sut.gateway_url}/consensus/execute", headers={"x-api-key": sut.agent_key(ACTOR)},
        json={"actor": ACTOR, "action": ACTION, "resource": RESOURCE, "context": payload,
              "votes": votes, "challenge_id": ch["challenge_id"],
              "idempotency_key": f"ckpt-{uuid.uuid4()}"},
        timeout=10.0,
    )
    r.raise_for_status()
    assert r.json()["status"] == "EXECUTED", r.json()


@pytest.fixture(scope="module")
def sut():
    with build_system_under_test() as s:
        yield s


@pytest.fixture(scope="module")
def checkpoint_key():
    return generate_checkpoint_key("assurance-checkpoint-2026a")


def test_g4_checkpoint_verifies_against_a_genuine_untampered_chain(sut, checkpoint_key):
    """The positive baseline: issue a checkpoint over the real, currently
    valid chain, and confirm it verifies -- both the signature (against
    the checkpoint key's OWN public half, never anything read off the
    checkpoint or the chain) and the chain-consistency check."""
    _authorized_execute(sut)
    entries = read_audit_entries(sut._gateway_harness._audit_path)  # noqa: SLF001 -- test-only, self-contained mode

    checkpoint = issue_checkpoint(checkpoint_key, entries=entries, deployment_id=sut._gateway_harness.deployment_id)  # noqa: SLF001

    result = verify_checkpoint(
        checkpoint, trusted_public_key_b64=checkpoint_key.public_key_b64(), current_entries=entries,
    )
    assert result.ok, result.to_dict()


def test_g5_checkpoint_still_verifies_after_the_chain_legitimately_grows(sut, checkpoint_key):
    """A checkpoint taken at time T must still verify later, even after
    MORE genuine entries were appended -- growth is not tampering."""
    _authorized_execute(sut)
    entries_at_checkpoint = read_audit_entries(sut._gateway_harness._audit_path)  # noqa: SLF001
    checkpoint = issue_checkpoint(
        checkpoint_key, entries=entries_at_checkpoint, deployment_id=sut._gateway_harness.deployment_id,  # noqa: SLF001
    )

    _authorized_execute(sut)  # the chain grows past the checkpointed position
    _authorized_execute(sut)
    current_entries = read_audit_entries(sut._gateway_harness._audit_path)  # noqa: SLF001
    assert len(current_entries) > len(entries_at_checkpoint)

    result = verify_checkpoint(
        checkpoint, trusted_public_key_b64=checkpoint_key.public_key_b64(), current_entries=current_entries,
    )
    assert result.ok, result.to_dict()


def test_g6_checkpoint_detects_retroactive_rewrite_of_the_checkpointed_prefix(checkpoint_key):
    """The core proof: after a checkpoint is issued, an insider with
    direct filesystem access (the SAME threat model G3 uses) rewrites an
    EARLIER entry -- the on-disk file now tells a different history than
    what was checkpointed. Verification must fail, and specifically report
    the checkpointed prefix as rewritten, not just "chain invalid".

    Boots its OWN dedicated SUT (not the shared module ``sut`` fixture):
    this test permanently corrupts its audit chain, which would break
    every OTHER test in this file that reuses the same fixture and
    expects a currently-valid chain to issue fresh checkpoints against."""
    with build_system_under_test() as sut:
        _authorized_execute(sut)
        entries_at_checkpoint = read_audit_entries(sut._gateway_harness._audit_path)  # noqa: SLF001
        checkpoint = issue_checkpoint(
            checkpoint_key, entries=entries_at_checkpoint, deployment_id=sut._gateway_harness.deployment_id,  # noqa: SLF001
        )

        # Directly rewrite the on-disk file's SECOND entry (already covered
        # by the checkpoint) -- same class of direct-filesystem-access
        # attack as corrupt_gateway_audit_chain, applied to an EARLIER
        # position instead of appended at the end. Corrupts the entry's
        # OWN declared "hash" -- guaranteed present on every real entry,
        # unlike guessing a payload field name -- so recomputation is
        # guaranteed to detect the mismatch regardless of what fields a
        # given entry happens to carry.
        path = sut._gateway_harness._audit_path  # noqa: SLF001
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        assert len(lines) >= 2, "need at least 2 real entries to rewrite an early one"
        tampered_entry = json.loads(lines[1])
        real_hash = tampered_entry["hash"]
        tampered_entry["hash"] = ("0" if real_hash[0] != "0" else "1") + real_hash[1:]
        lines[1] = json.dumps(tampered_entry, sort_keys=True) + "\n"
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(lines)

        current_entries = read_audit_entries(path)
        result = verify_checkpoint(
            checkpoint, trusted_public_key_b64=checkpoint_key.public_key_b64(), current_entries=current_entries,
        )
        assert not result.ok
        assert result.signature_valid  # the checkpoint ITSELF is untouched and still validly signed
        assert not result.chain_consistent
        assert "REWRITTEN" in result.reason or "INVALID" in result.reason


def test_g7_checkpoint_signed_by_an_untrusted_key_is_rejected(sut):
    """A syntactically valid checkpoint, correctly signed, but with a key
    the verifier was never told to trust -- must be rejected, exactly
    like an untrusted mandate/vote issuer elsewhere in this baseline."""
    forger_key = generate_checkpoint_key("untrusted-checkpoint-key")
    trusted_key = generate_checkpoint_key("the-actual-trusted-key")

    entries = read_audit_entries(sut._gateway_harness._audit_path)  # noqa: SLF001
    checkpoint = issue_checkpoint(forger_key, entries=entries, deployment_id="whatever")

    result = verify_checkpoint(
        checkpoint, trusted_public_key_b64=trusted_key.public_key_b64(), current_entries=entries,
    )
    assert not result.ok
    assert not result.signature_valid
    assert result.reason == "INVALID_CHECKPOINT_SIGNATURE"


def test_g8_checkpoint_over_a_chain_shorter_than_claimed_is_rejected(sut, checkpoint_key):
    """A checkpoint claiming N entries existed, verified against a chain
    that currently has FEWER than N entries (e.g. a genuinely different,
    freshly-reset deployment being mistakenly checked against someone
    else's checkpoint) -- must fail closed, not index out of range or
    silently pass on an empty/partial comparison."""
    entries = read_audit_entries(sut._gateway_harness._audit_path)  # noqa: SLF001
    checkpoint = issue_checkpoint(checkpoint_key, entries=entries, deployment_id="d1")

    result = verify_checkpoint(
        checkpoint, trusted_public_key_b64=checkpoint_key.public_key_b64(),
        current_entries=entries[:1],  # a much shorter chain than the checkpoint claims
    )
    assert not result.ok
    assert "SHORTER" in result.reason
