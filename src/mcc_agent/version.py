"""Release metadata for the MCC-Core governed agent pilot.

This names the pilot baseline. It does not change any runtime/governance version
(the canonical runtime VERSION is unaffected): it is the pilot's own release
label, used by the demo header, PILOT.md, and the release notes.
"""

from __future__ import annotations

PILOT_RELEASE_NAME = "MCC-Core Pilot v0.1"
PILOT_VERSION = "0.1.0-pilot"

__all__ = ["PILOT_RELEASE_NAME", "PILOT_VERSION"]
