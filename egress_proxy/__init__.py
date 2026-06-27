"""MCC-Core Enforced Outbound HTTP Egress Proxy.

The egress proxy makes MCC-Core the *enforced* execution boundary for outbound
HTTP. It is an enforcement and transport adapter over the existing unified
governance runtime — **not** a governance engine:

* it canonicalizes an outbound HTTP request into one action and binds it
  (:mod:`egress_proxy.canonical_action`);
* it submits that action through the embedded unified runtime (the same
  ``AuthorityModel`` / ``DecisionEngine`` / ``ConsensusVerifier`` /
  ``ChallengeService`` / ``EnforcementCoordinator`` / ``ExecutionGate`` /
  ``ApprovalService`` / registries the gateway uses — via ``GovernedMCCClient``);
* the actual outbound HTTP call happens only inside the governed executor
  callback (:class:`egress_proxy.executor.HTTPEgressExecutor`), after the gate
  verifies the signed token and the pre-actuation audit record is written;
* it fails closed against SSRF and destination confusion
  (:mod:`egress_proxy.ssrf`).

No verified MCC authorization — no outbound HTTP execution.
"""

from .canonical_action import (
    CanonicalActionError,
    action_hash,
    build_canonical_action,
    reconstruct_request,
)
from .ssrf import SSRFError, validate_destination

__all__ = [
    "CanonicalActionError",
    "build_canonical_action",
    "action_hash",
    "reconstruct_request",
    "SSRFError",
    "validate_destination",
]
