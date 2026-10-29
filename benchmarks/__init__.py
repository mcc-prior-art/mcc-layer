"""P2-A Low-Latency Authority Plane: benchmark harness.

Measures the real, unmodified governed stack (``DecisionEngine`` ->
``ExecutionGate`` -> ``EnforcementCoordinator`` -> in-process mocked
actuator -> ``AuditLog``) under a mocked workload. Never calls a real
external service. See ``docs/LOW_LATENCY_AUTHORITY_PLANE.md`` for exact
reproduction commands and the honest scope of what these numbers do and
do not prove.
"""
