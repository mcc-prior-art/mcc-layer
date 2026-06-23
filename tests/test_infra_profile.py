"""Infrastructure profile tests — domain neutrality demonstrated.

A non-payment domain expressed entirely through a profile. The universal token,
gate, authority, audit, and replay semantics are unchanged; only the profile
adds infra fields (target, environment) and rides the universal constraint
convention (allowed_*, max_*).
"""

import asyncio

import pytest

from mcc_core import (
    ActuationStatus,
    AuditLog,
    DecisionEngine,
    EnforcementCoordinator,
    ExecutionGate,
    InfraProfile,
    InMemoryIdempotencyRegistry,
    InMemoryNonceRegistry,
    InMemoryVelocityRegistry,
    MandateAuthority,
    MandateVerifier,
    ProfileError,
    ProfileRegistry,
    SigningKey,
    Verdict,
    VelocityLimit,
    issue_mandate,
)

run = asyncio.run
NOW = 1_780_000_000
PROFILE = InfraProfile()
POLICY_HASH = "sha256:infra-policy"

CTX = {"target": "cluster-prod-1", "environment": "PROD", "replicas": 5, "change_ref": "CR-42"}


# ---- Canonical payload + claims ----

def test_canonical_payload_requires_target_and_environment():
    with pytest.raises(ProfileError):
        PROFILE.canonical_payload({"target": "x"})  # missing environment


def test_canonical_payload_normalises_environment():
    cp = PROFILE.canonical_payload(CTX)
    assert cp["environment"] == "prod"
    assert cp["target"] == "cluster-prod-1"


def test_auth_claims_surface_infra_fields():
    claims = PROFILE.auth_claims(CTX)
    assert claims == {"target": "cluster-prod-1", "environment": "prod", "change_ref": "CR-42"}


def test_velocity_descriptor_aggregates_by_target_and_environment():
    d = PROFILE.velocity_descriptor(actor_id="ops-1", resource_id="cluster-prod-1",
                                    action="scale_cluster", policy_scope="p",
                                    context=PROFILE.canonical_payload(CTX))
    assert d.dimensions["target"] == "cluster-prod-1"
    assert d.dimensions["environment"] == "prod"
    assert d.amount == 5.0
    assert d.destination == "cluster-prod-1"


def test_registry_routes_infra_actions_to_infra_profile():
    reg = ProfileRegistry.default_pilot()
    assert isinstance(reg.for_action("scale_cluster"), InfraProfile)
    assert isinstance(reg.for_action("rotate_secret"), InfraProfile)
    assert reg.for_action("some_unmapped_action").name == "generic"


# ---- Binding / substitution at the gate ----

def _engine_gate():
    key = SigningKey.generate("dk")
    engine = DecisionEngine(signing_key=key, issuer="mcc", audience="gate",
                            policy_id="p", policy_hash=POLICY_HASH, token_ttl_seconds=60)
    gate = ExecutionGate(trusted_keys={key.kid: key.public_key()}, audience="gate",
                         nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY_HASH)
    return engine, gate


def _infra_token(engine, ctx, *, actor="ops-1"):
    payload = PROFILE.canonical_payload(ctx)
    return engine.issue_token(
        verdict="ALLOW", subject=actor, action="scale_cluster", payload=payload,
        actor_id=actor, resource_id=ctx["target"], auth_claims=PROFILE.auth_claims(ctx),
        now=NOW,
    ), payload


def test_target_substitution_denied():
    engine, gate = _engine_gate()
    token, _ = _infra_token(engine, CTX)
    tampered = PROFILE.canonical_payload({**CTX, "target": "cluster-EVIL"})
    res = run(gate.verify(token, action="scale_cluster", payload=tampered, now=NOW))
    assert not res.allowed
    assert "PAYLOAD_HASH_MISMATCH" in res.reason


def test_environment_substitution_denied():
    engine, gate = _engine_gate()
    token, _ = _infra_token(engine, CTX)
    tampered = PROFILE.canonical_payload({**CTX, "environment": "staging"})
    res = run(gate.verify(token, action="scale_cluster", payload=tampered, now=NOW))
    assert not res.allowed
    assert "PAYLOAD_HASH_MISMATCH" in res.reason


# ---- Constraint convention (allowed_/max_) on infra ----

def _issuer():
    return SigningKey.generate("infra-issuer")


def _infra_mandate(key, **over):
    kw = dict(
        issuer="axlogiq", subject="ops-1", action_scope=["scale_cluster"],
        resource_scope=["cluster-prod-1", "cluster-*"],
        constraints={"max_replicas": 10, "allowed_environment": ["prod", "staging"]},
        not_before=NOW - 10, not_after=NOW + 3600, issued_at=NOW, policy_hash=POLICY_HASH,
    )
    kw.update(over)
    return issue_mandate(key, **kw)


def _authority(key):
    return MandateAuthority(MandateVerifier(trusted_keys={key.kid: key.public_key()}))


def test_within_infra_constraints_allows():
    key = _issuer()
    d = run(_authority(key).authorize(
        _infra_mandate(key), subject="ops-1", action="scale_cluster",
        resource="cluster-prod-1", context=PROFILE.canonical_payload(CTX), now=NOW,
        policy_hash=POLICY_HASH))
    assert d.verdict == Verdict.ALLOW


def test_replicas_over_max_constrains_and_clamps():
    key = _issuer()
    ctx = PROFILE.canonical_payload({**CTX, "replicas": 50})
    d = run(_authority(key).authorize(
        _infra_mandate(key), subject="ops-1", action="scale_cluster",
        resource="cluster-prod-1", context=ctx, now=NOW, policy_hash=POLICY_HASH))
    assert d.verdict == Verdict.CONSTRAIN
    assert d.forward_context["replicas"] == 10


def test_disallowed_environment_denied():
    key = _issuer()
    ctx = PROFILE.canonical_payload({**CTX, "environment": "dev"})
    d = run(_authority(key).authorize(
        _infra_mandate(key), subject="ops-1", action="scale_cluster",
        resource="cluster-prod-1", context=ctx, now=NOW, policy_hash=POLICY_HASH))
    assert d.verdict == Verdict.DENY  # allowed_environment violation, not clampable


def test_action_outside_mandate_scope_denied():
    key = _issuer()
    d = run(_authority(key).authorize(
        _infra_mandate(key, action_scope=["scale_cluster"]), subject="ops-1",
        action="rotate_secret", resource="cluster-prod-1",
        context={"target": "cluster-prod-1", "environment": "prod"}, now=NOW,
        policy_hash=POLICY_HASH))
    assert d.verdict == Verdict.DENY  # ACTION_SCOPE_MISMATCH


# ---- Full end-to-end execution path ----

def test_full_infra_execution_through_coordinator(tmp_path):
    key = _issuer()
    authority = _authority(key)
    engine, gate = _engine_gate()
    coord = EnforcementCoordinator(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(),
        velocity=InMemoryVelocityRegistry(), audit=AuditLog(str(tmp_path / "a.jsonl")),
        profiles=ProfileRegistry.default_pilot(),
        velocity_limits_for=lambda a: [
            VelocityLimit(name="infra_count", window_seconds=60, max_count=5,
                          aggregate_by=("actor", "target")),
        ],
    )
    ctx = PROFILE.canonical_payload(CTX)
    decision = run(authority.authorize(_infra_mandate(key), subject="ops-1",
                                       action="scale_cluster", resource="cluster-prod-1",
                                       context=ctx, now=NOW, policy_hash=POLICY_HASH))
    assert decision.verdict == Verdict.ALLOW
    token = engine.issue_token(
        verdict="ALLOW", subject="ops-1", action="scale_cluster", payload=ctx,
        actor_id="ops-1", resource_id="cluster-prod-1", idempotency_key="infra-op-1",
        mandate_id=decision.mandate_id, auth_claims=PROFILE.auth_claims(ctx), now=NOW,
    )
    ran = []

    async def ex():
        ran.append(ctx["replicas"])
        return "scaled"

    res = run(coord.enforce(token=token, action="scale_cluster", payload=ctx,
                            executor=ex, request_binding={"actor_id": "ops-1",
                                                          "resource_id": "cluster-prod-1"}, now=NOW))
    assert res.status == ActuationStatus.EXECUTED
    assert ran == [5]


def test_core_remains_payment_agnostic():
    # The infra profile carries no payment vocabulary; the generic profile (for
    # unmapped actions) carries neither payment nor infra fields.
    assert PROFILE.auth_claims({"target": "t", "environment": "prod"}).keys() == {
        "target", "environment", "change_ref"}
    from mcc_core import ActionProfile
    assert ActionProfile().auth_claims({"anything": 1}) == {}
