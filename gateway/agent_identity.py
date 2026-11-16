"""Per-agent authenticated identity -- moved to :mod:`mcc_core.agent_identity`
(F1b) so separately deployed runtimes that ship only ``src/`` (``main.py``,
the egress proxy, the MVP interceptor) use the SAME registry and checks as
the gateway. This module re-exports it unchanged for existing imports."""
from mcc_core.agent_identity import (  # noqa: F401
    AGENT_IDENTITY_LEGACY,
    AGENT_IDENTITY_MODES,
    AGENT_IDENTITY_STRICT,
    AgentCredentialConfigError,
    AgentCredentialRegistry,
    AgentIdentityError,
    AuthenticatedAgent,
    Resolution,
    _Entry,
    _FIELDS,
    _HEX64,
    _STATUSES,
    agent_identity_error,
    agent_identity_mode_from_env,
    agent_registry_from_env,
    evaluate_identity_error,
    hash_agent_key,
    principal_binding_error,
)
