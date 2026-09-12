"""THE ONE FILE an external integrator replaces to connect their own
agent / model / workflow (PR #113 -- "How to connect your agent").

Any producer -- an LLM agent on any framework, a rules engine, a human-
operated tool, a deterministic pipeline -- can use MCC as long as it can
eventually emit this generic shape:

    {
        "logical_operation_id": str,   # this producer's own idempotent
                                        # operation identity (see below)
        "actor": str,                  # a plain label; MCC's trusted
                                        # authority evaluation never reads
                                        # this field (see
                                        # docs/EXTERNAL_PILOT_INTEGRATION.md
                                        # "what MCC verifies")
        "action": str,                 # what capability is being asked for
        "resource": str | None,        # what it targets, if applicable
        "payload": dict,               # arbitrary, action-specific content
    }

This module has ZERO import of any model-provider SDK (no OpenAI, no
Anthropic), ZERO import of any agent framework (no LangGraph, no CrewAI,
no AutoGen, no VoltAgent, no MCP), and ZERO GitHub-specific vocabulary --
verified statically by
``tests/test_external_pilot_architecture_guards.py``. The function below
is a template: replace ``build_proposal_from_agent_output``'s body with
whatever translation your own producer needs; everything downstream of
it (submission, authority evaluation, execution) is unchanged.

``logical_operation_id`` is the producer's responsibility, not MCC's: it
is the durable identity a retry/replay is checked against
(``PROPOSAL != PERMISSION`` still holds -- resubmitting the SAME id does
not grant new authority, it just lets the SAME governed operation be
looked up and, if already resolved, replayed safely -- see
docs/EXTERNAL_PILOT_INTEGRATION.md's replay section). A producer that
wants "one proposal per real-world intent" should mint this id itself
(e.g. deterministically from its own upstream request id), not rely on
MCC to deduplicate for it.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


def build_proposal_from_agent_output(
    agent_output: Dict[str, Any],
    *,
    logical_operation_id: str,
    actor: str,
    action: str,
    resource: Optional[str] = None,
) -> Dict[str, Any]:
    """Translate one arbitrary upstream agent/model/workflow output into
    the generic MCC proposal shape. This reference implementation simply
    forwards ``agent_output`` as the ``payload`` verbatim -- a real
    integration typically extracts/validates/reshapes specific fields out
    of its own agent's actual output format here instead.

    Nothing in this function -- or anywhere else this producer template
    touches -- ever constructs a signed authority token, calls an
    actuator, or imports anything from ``mcc_core`` /
    ``gateway.proposal_execution_service`` /
    ``gateway.proposal_execution_stack``. Producing a proposal is not
    permission to execute it; only MCC's own trusted, server-side
    authority evaluation (reached exclusively through
    ``examples.external_pilot.client.mcc_pilot_client.MCCPilotClient``)
    decides that.
    """
    return {
        "logical_operation_id": logical_operation_id,
        "actor": actor,
        "action": action,
        "resource": resource,
        "payload": dict(agent_output),
    }


__all__ = ["build_proposal_from_agent_output"]
