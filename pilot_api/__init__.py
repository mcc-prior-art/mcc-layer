"""External pilot API for the MCC-Core governed-agent pilot.

This is the *external* enterprise-style service the governed agent acts upon. It
is deliberately separate from MCC-Core: the agent never calls it directly — only
the governed HTTPS executor reaches it, and only after a verified decision. The
service keeps deterministic in-memory state and records every operation it
actually performs, so a test can prove whether an action executed.
"""

from .app import build_pilot_api, recorded_operations, reset_state

__all__ = ["build_pilot_api", "recorded_operations", "reset_state"]
