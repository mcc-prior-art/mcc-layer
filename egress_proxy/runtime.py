"""Wire the embedded unified runtime for the egress proxy (no parallel engine).

The proxy embeds the *same* runtime the gateway uses, via the canonical
in-process governed client ``GovernedMCCClient`` (AuthorityModel + DecisionEngine
+ ConsensusVerifier + ChallengeService + EnforcementCoordinator + ExecutionGate +
ApprovalService + nonce/idempotency/velocity/approval/challenge registries). The
proxy supplies only:

* the **egress authority policy** (which is just an ``AuthorityModel`` config —
  ``http.request`` requires the ``http.egress`` mandate; ALLOW within bounds,
  CONSTRAIN on a clampable breach, ESCALATE without a mandate, DENY otherwise);
* the **governed executor** (the outbound HTTP call);
* the **destination policy** (SSRF).

Every ALLOW/DENY/ESCALATE/CONSTRAIN verdict and every enforcement step comes from
that runtime — the proxy decides nothing.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from mcc_core import (
    ActionPolicy,
    AuthorityModel,
    Mandate,
    MandateRegistry,
    SigningKey,
    Verdict,
    approval_registry_from_env,
    challenge_registry_from_env,
    idempotency_registry_from_env,
    nonce_registry_from_env,
    velocity_registry_from_env,
)

from examples.governed_agent.mcc_client import GovernedMCCClient

from .config import EgressSettings
from .executor import HTTPEgressExecutor
from .ssrf import DestinationPolicy, Resolver


def build_egress_authority(settings: EgressSettings) -> AuthorityModel:
    """The egress policy as an ``AuthorityModel`` (the existing decision engine).

    Constraints are evaluated by the existing convention against the canonical
    action's flat fields: ``allowed_host``/``allowed_method`` on the envelope,
    ``max_body.amount`` on a JSON body field (a CONSTRAIN clamp rewrites it → a
    new action hash)."""
    # allowed_host is always present: an empty allow-list denies every host
    # (deny-by-default — no implicit permissive destination default).
    constraints: Dict[str, Any] = {
        "allowed_method": settings.allowed_methods_list(),
        "allowed_host": settings.allowed_hosts_list(),
    }
    if settings.max_amount is not None:
        constraints["max_body.amount"] = settings.max_amount
    registry = MandateRegistry([
        Mandate(holder=settings.egress_actor_mandate, authority="http.egress",
                constraints=constraints),
    ])
    policies = [
        ActionPolicy(action="http.request", requires="http.egress",
                     on_mandate=Verdict.ALLOW, on_violation=Verdict.CONSTRAIN,
                     without_mandate=Verdict.ESCALATE),
    ]
    return AuthorityModel(registry=registry, policies=policies, default=Verdict.DENY)


def build_destination_policy(settings: EgressSettings) -> DestinationPolicy:
    hosts = settings.allowed_hosts_list()
    return DestinationPolicy(
        allow_loopback=settings.allow_loopback,
        allow_private=settings.allow_private,
        allow_link_local=settings.allow_link_local,
        allowed_hosts=frozenset(hosts) if hosts else None,
    )


def build_executor(settings: EgressSettings, *, resolver: Optional[Resolver] = None) -> HTTPEgressExecutor:
    import ssl

    tls_min = ssl.TLSVersion.TLSv1_3 if settings.tls_min_version.strip() == "1.3" \
        else ssl.TLSVersion.TLSv1_2
    return HTTPEgressExecutor(
        policy=build_destination_policy(settings),
        connect_timeout=settings.connect_timeout_seconds,
        read_timeout=settings.read_timeout_seconds,
        total_timeout=settings.total_timeout_seconds,
        max_response_bytes=settings.max_response_bytes,
        resolver=resolver,
        require_https=settings.require_https,
        allow_http=settings.allow_http,
        tls_ca_file=settings.tls_ca_file or None,
        tls_min_version=tls_min,
        max_redirects=settings.max_redirects,
    )


def _load_trusted_evaluators(path: str) -> Dict[str, Any]:
    from gateway.trust import load_trust_config

    trust = load_trust_config(json.loads(Path(path).read_text(encoding="utf-8")))
    return trust.active_trusted_keys(now=int(time.time()))


def _build_credential_provider(settings: EgressSettings):
    """Build the credential provider from a secret-free config (fail-closed: a
    selected provider with a missing/invalid config refuses startup)."""
    from .credentials import build_provider_from_config

    provider = (settings.credential_provider or "none").strip().lower()
    if provider in ("", "none"):
        return None
    if not settings.credential_config:
        raise RuntimeError(
            f"MCC_EGRESS_CREDENTIAL_PROVIDER={provider} requires MCC_EGRESS_CREDENTIAL_CONFIG; "
            "refusing fail-open startup")
    config = json.loads(Path(settings.credential_config).read_text(encoding="utf-8"))
    return build_provider_from_config(provider, config)


class EgressRuntime:
    """The embedded runtime + the egress-specific executor and policy."""

    def __init__(self, settings: EgressSettings, *, env: Optional[Mapping[str, str]] = None,
                 resolver: Optional[Resolver] = None) -> None:
        import os

        self.settings = settings
        env = os.environ if env is None else env
        self.executor = build_executor(settings, resolver=resolver)

        signing_key = (SigningKey.from_pem_file(settings.signing_key_path, settings.signing_key_id)
                       if settings.signing_key_path else None)
        self.ephemeral_signing_key = signing_key is None

        trusted_evaluators: Dict[str, Any] = {}
        if settings.require_consensus:
            if not settings.consensus_trust_config:
                raise RuntimeError(
                    "MCC_EGRESS_REQUIRE_CONSENSUS set but no consensus trust config; "
                    "refusing fail-open startup")
            trusted_evaluators = _load_trusted_evaluators(settings.consensus_trust_config)

        # Registries from the environment (Redis with no silent fallback; missing
        # required Redis refuses startup inside these builders).
        self.client = GovernedMCCClient(
            executor=self.executor,
            authority=build_egress_authority(settings),
            signing_key=signing_key,
            policy_hash=_policy_hash(settings),
            audience=settings.audience,
            audit_path=settings.audit_log_path,
            nonce_registry=nonce_registry_from_env(env),
            idempotency_registry=idempotency_registry_from_env(env),
            velocity_registry=velocity_registry_from_env(env),
            approval_registry=approval_registry_from_env(env),
            challenge_registry=challenge_registry_from_env(env),
            consensus_required=settings.require_consensus,
            consensus_threshold=settings.consensus_threshold,
            trusted_evaluators=trusted_evaluators,
        )
        # Share the runtime's audit chain so the executor can append safe egress
        # execution metadata to the SAME hash chain (post-actuation; the durable
        # pre-actuation record remains the coordinator's responsibility).
        self.executor.audit = self.client.audit
        # Credential references: build the provider (fail-closed startup if a
        # provider is selected but misconfigured) and bind the environment scope.
        self.executor.credential_provider = _build_credential_provider(settings)
        self.executor.env_name = settings.mcc_env

    @property
    def policy_hash(self) -> str:
        return self.client.policy_hash


def _policy_hash(settings: EgressSettings) -> str:
    from mcc_core import canonical_bytes, sha256_hex

    return sha256_hex(canonical_bytes({
        "policy_id": settings.policy_id,
        "actor": settings.egress_actor_mandate,
        "allowed_hosts": settings.allowed_hosts_list(),
        "allowed_methods": settings.allowed_methods_list(),
        "max_amount": settings.max_amount,
    }))
