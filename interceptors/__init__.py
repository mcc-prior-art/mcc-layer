"""MCC-Core interceptors: where an action physically passes through the gate.

One interceptor for the MVP — the egress proxy — because it is the only kind
that owns the execution path, and therefore the only kind where DENY actually
means DENY rather than a suggestion the agent may decline to ask for.
"""
