"""Bring-your-own-agent reference material for the External Pilot
Integration Pack.

``mcc_pilot_client.py`` -- a tiny, framework-neutral HTTP client for the
EXISTING PR #111 Pilot Execution API. Zero MCC-Core imports, zero
authority/signing knowledge, zero actuator access -- it can only reach
execution the same way any other authenticated caller can: over real
HTTP, through the trusted server-side tenant boundary.

``example_producer.py`` -- the ONE template file an integrator replaces
to connect their own agent/model/workflow. It has no dependency on any
specific model provider, agent framework, or actuator domain.
"""
