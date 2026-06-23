"""Robotics profile tests — a second non-payment domain, same universal core.

Robotics actuation expressed entirely through a profile. The universal token,
gate, authority, audit, and replay semantics are unchanged; only the profile
adds robotics fields (robot, zone, object_id, force) and rides the universal
constraint convention (allowed_*, max_*).
"""

import asyncio

import pytest

from mcc_core import (
    ActuationStatus,
    AuditLog,
    DecisionEngine,
    EnforcementCoordinator,
    ExecutionGate,
    InMemoryIdempotencyRegistry,
    InMemoryNonceRegistry,
    InMemoryVelocityRegistry,
    MandateAuthority,
    MandateVerifier,
    ProfileError,
    ProfileRegistry,
    RoboticsProfile,
    SigningKey,
    Verdict,
    VelocityLimit,
    issue_mandate,
)

run = asyncio.run
NOW = 1_780_000_000
PROFILE = RoboticsProfile()
POLICY = "sha256:robotics-policy"

CTX = {"robot": "arm-7", "zone": "ZONE-A", "object_id": "widget-3", "force": 20}


# ---- Canonical payload + claims ----

def test_canonical_requires_robot_and_zone():
    with pytest.raises(ProfileError):
        PROFILE.canonical_payload({"robot": "arm-7"})  # missing zone


def test_canonical_normalises_zone_and_force():
    cp = PROFILE.canonical_payload(CTX)
    assert cp["zone"] == "zone-a"
    assert cp["force"] == 20.0


def test_auth_claims_surface_robotics_fields():
    assert PROFILE.auth_claims(CTX) == {
        "robot": "arm-7", "zone": "zone-a", "object_id": "widget-3", "force": 20.0}


def test_velocity_descriptor_aggregates_by_robot_and_zone():
    d = PROFILE.velocity_descriptor(actor_id="op-1", resource_id="arm-7",
                                    action="move_to_zone", policy_scope="p",
                                    context=PROFILE.canonical_payload(CTX))
    assert d.dimensions["robot"] == "arm-7"
    assert d.dimensions["zone"] == "zone-a"
    assert d.amount == 20.0
    assert d.destination == "zone-a"


def test_registry_routes_robotics_actions():
    reg = ProfileRegistry.default_pilot()
    for action in ("move_to_zone", "pick_object", "release_object",
                   "enter_restricted_area", "exceed_force_limit"):
        assert isinstance(reg.for_action(action), RoboticsProfile)
    assert reg.for_action("unmapped").name == "generic"


# ---- Binding / substitution at the gate ----

def _engine_gate():
    key = SigningKey.generate("dk")
    engine = DecisionEngine(signing_key=key, issuer="mcc", audience="gate",
                            policy_id="p", policy_hash=POLICY, token_ttl_seconds=60)
    gate = ExecutionGate(trusted_keys={key.kid: key.public_key()}, audience="gate",
                         nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY)
    return engine, gate


def _token(engine, ctx, *, actor="op-1", action="move_to_zone"):
    payload = PROFILE.canonical_payload(ctx)
    return engine.issue_token(verdict="ALLOW", subject=actor, action=action, payload=payload,
                              actor_id=actor, resource_id=ctx["robot"],
                              auth_claims=PROFILE.auth_claims(ctx), now=NOW), payload


def test_robot_substitution_denied():
    engine, gate = _engine_gate()
    token, _ = _token(engine, CTX)
    tampered = PROFILE.canonical_payload({**CTX, "robot": "arm-EVIL"})
    res = run(gate.verify(token, action="move_to_zone", payload=tampered, now=NOW))
    assert not res.allowed and "PAYLOAD_HASH_MISMATCH" in res.reason


def test_zone_substitution_denied():
    engine, gate = _engine_gate()
    token, _ = _token(engine, CTX)
    tampered = PROFILE.canonical_payload({**CTX, "zone": "zone-restricted"})
    res = run(gate.verify(token, action="move_to_zone", payload=tampered, now=NOW))
    assert not res.allowed and "PAYLOAD_HASH_MISMATCH" in res.reason


# ---- Safety constraints via the universal convention ----

def _issuer():
    return SigningKey.generate("robotics-issuer")


def _mandate(key, **over):
    kw = dict(issuer="axlogiq", subject="op-1", action_scope=["move_to_zone", "pick_object"],
              resource_scope=["arm-7", "arm-*"],
              constraints={"allowed_zone": ["zone-a", "zone-b"], "max_force": 50},
              not_before=NOW - 10, not_after=NOW + 3600, policy_hash=POLICY)
    kw.update(over)
    return issue_mandate(key, **kw)


def _authority(key):
    return MandateAuthority(MandateVerifier(trusted_keys={key.kid: key.public_key()}))


def test_within_safety_envelope_allows():
    key = _issuer()
    d = run(_authority(key).authorize(_mandate(key), subject="op-1", action="move_to_zone",
                                      resource="arm-7", context=PROFILE.canonical_payload(CTX),
                                      now=NOW, policy_hash=POLICY))
    assert d.verdict == Verdict.ALLOW


def test_force_over_limit_constrains_and_clamps():
    key = _issuer()
    ctx = PROFILE.canonical_payload({**CTX, "action": "pick_object", "force": 80})
    d = run(_authority(key).authorize(_mandate(key), subject="op-1", action="pick_object",
                                      resource="arm-7", context=ctx, now=NOW, policy_hash=POLICY))
    assert d.verdict == Verdict.CONSTRAIN
    assert d.forward_context["force"] == 50


def test_restricted_zone_denied():
    key = _issuer()
    ctx = PROFILE.canonical_payload({**CTX, "zone": "zone-restricted"})
    d = run(_authority(key).authorize(_mandate(key), subject="op-1", action="move_to_zone",
                                      resource="arm-7", context=ctx, now=NOW, policy_hash=POLICY))
    assert d.verdict == Verdict.DENY  # allowed_zone violation, not clampable


def test_action_outside_scope_denied():
    key = _issuer()
    d = run(_authority(key).authorize(_mandate(key, action_scope=["move_to_zone"]),
                                      subject="op-1", action="exceed_force_limit",
                                      resource="arm-7",
                                      context={"robot": "arm-7", "zone": "zone-a"},
                                      now=NOW, policy_hash=POLICY))
    assert d.verdict == Verdict.DENY  # ACTION_SCOPE_MISMATCH


# ---- Full end-to-end execution path ----

def test_full_robotics_execution_through_coordinator(tmp_path):
    key = _issuer()
    authority = _authority(key)
    engine, gate = _engine_gate()
    coord = EnforcementCoordinator(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(),
        velocity=InMemoryVelocityRegistry(), audit=AuditLog(str(tmp_path / "a.jsonl")),
        profiles=ProfileRegistry.default_pilot(),
        velocity_limits_for=lambda a: [
            VelocityLimit(name="robot_moves", window_seconds=60, max_count=10,
                          aggregate_by=("actor", "robot"))],
    )
    ctx = PROFILE.canonical_payload(CTX)
    decision = run(authority.authorize(_mandate(key), subject="op-1", action="move_to_zone",
                                       resource="arm-7", context=ctx, now=NOW, policy_hash=POLICY))
    assert decision.verdict == Verdict.ALLOW
    token = engine.issue_token(
        verdict="ALLOW", subject="op-1", action="move_to_zone", payload=ctx,
        actor_id="op-1", resource_id="arm-7", idempotency_key="robot-op-1",
        mandate_id=decision.mandate_id, auth_claims=PROFILE.auth_claims(ctx), now=NOW)
    moved = []

    async def ex():
        moved.append(ctx["zone"])
        return "moved"

    res = run(coord.enforce(token=token, action="move_to_zone", payload=ctx, executor=ex,
                            request_binding={"actor_id": "op-1", "resource_id": "arm-7"}, now=NOW))
    assert res.status == ActuationStatus.EXECUTED
    assert moved == ["zone-a"]


def test_core_remains_domain_agnostic():
    from mcc_core import ActionProfile
    assert set(PROFILE.auth_claims({"robot": "r", "zone": "z"})) == {
        "robot", "zone", "object_id", "force"}
    assert ActionProfile().auth_claims({"anything": 1}) == {}
