"""External Pilot Integration Pack (PR #113).

Packaging/integration-ergonomics layer over the ALREADY-PROVEN PR #111
(Pilot Execution API) + PR #112 (agent/framework/actuator-neutral real
execution proof) governed boundary. Introduces NO new authority, signing,
Gate, coordinator, idempotency, reconciliation, or actuator-dispatch
architecture -- every decision in this package is made by the EXISTING,
unmodified ``gateway.proposal_execution_service.ProposalExecutionService``,
reached only through the EXISTING, unmodified public HTTP routes
(``gateway.proposal_api.mount_proposal_routes`` /
``gateway.proposal_execution_api.mount_proposal_execution_routes``).

See ``docs/EXTERNAL_PILOT_INTEGRATION.md`` for the integration guide and
``examples/external_pilot/README.md`` for the fresh-clone quick start.
"""
