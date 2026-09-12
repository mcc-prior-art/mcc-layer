"""Universal Execution Authority Proof (PR #112).

Proves that the governed execution path introduced by PR #106 (the Phase
2 bridge) and exposed over HTTP by PR #111 (the Pilot Execution API) is
independent of (1) the upstream intelligence/agent/framework that
produced a proposal and (2) the downstream execution domain/actuator that
carries it out. See ``docs/UNIVERSAL_EXECUTION_PROOF.md``.

No new authority mechanism, Gate, EnforcementCoordinator, execution
registry, or actuator architecture is introduced here -- this package is
composition/wiring only, reusing:

* ``gateway.proposal_execution_stack.build_proposal_execution_stack`` (PR #111)
* ``gateway.proposal_api.mount_proposal_routes`` /
  ``gateway.proposal_execution_api.mount_proposal_execution_routes`` (the
  REAL HTTP surface -- this proof never calls
  ``ProposalExecutionService`` directly)
* ``examples.phase2_live_sandbox.actuator.GitHubSandboxUpstream`` /
  ``examples.gpt6_astra_reference.github_actuator.GitHubIssueActuator``
  (the existing, unmodified GitHub actuator -- no second implementation)
* ``examples.phase2_live_sandbox.config.SandboxConfig`` (the existing
  live-safety gate, reused unchanged)
"""

from .stack import UniversalProofStack, build_universal_proof_app, build_universal_proof_stack

__all__ = ["UniversalProofStack", "build_universal_proof_stack", "build_universal_proof_app"]
