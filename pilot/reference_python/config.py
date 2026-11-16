"""Configuration for the reference pilot integration.

Twelve-factor style: every value is settable via an ``MCC_PILOT_*``
environment variable, with conservative, safe-by-default values (mode
defaults to ``observe``, never ``enforced``). No secret is ever embedded in
this module or in the example env file — see
``pilot/reference_python/.env.pilot-readiness.example``.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import asdict, dataclass, field
from typing import Literal

Mode = Literal["observe", "enforced"]


class PilotConfigError(ValueError):
    """Invalid or missing pilot configuration."""


def load_agent_keys(path: str) -> dict[str, str]:
    """Load ``{identity: key}`` from a JSON file (fail-closed on any
    malformation). The values are secrets: never logged or exported."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as exc:
        raise PilotConfigError(f"cannot load agent keys file: {type(exc).__name__}") from None
    if not isinstance(data, dict) or not data or not all(
            isinstance(k, str) and k and isinstance(v, str) and v for k, v in data.items()):
        raise PilotConfigError("agent keys file must be a non-empty JSON object identity -> key")
    return dict(data)


@dataclass(frozen=True)
class PilotConfig:
    """Pilot runtime configuration. Immutable once constructed.

    ``api_key`` is intentionally excluded from :meth:`fingerprint` and from
    :meth:`to_evidence_dict` -- it must never appear in exported evidence
    (see the pilot acceptance tests).
    """

    gateway_url: str
    timeout_seconds: float = 10.0
    mode: Mode = "observe"
    pilot_id: str = "example-pilot"
    integration_id: str = "reference-python-v1"
    evidence_dir: str = "./artifacts/pilot-evidence"
    run_correlation_id: str = field(default_factory=lambda: f"pilot-run-{uuid.uuid4().hex[:12]}")
    api_key: str | None = None
    # F1b: per-identity credentials ``{identity: key}``. A strict Gateway
    # refuses the shared tenant key on /evaluate for EVERY identity, so each
    # identity the pilot submits as must present its OWN registered key. When
    # set, an identity without an entry fails closed (no fallback to
    # ``api_key``). Secret: excluded from evidence and the fingerprint.
    agent_keys: dict[str, str] | None = None

    def __post_init__(self) -> None:
        if not self.gateway_url or not (
            self.gateway_url.startswith("http://") or self.gateway_url.startswith("https://")
        ):
            raise PilotConfigError(f"gateway_url must start with http:// or https://: {self.gateway_url!r}")
        if self.timeout_seconds <= 0:
            raise PilotConfigError(f"timeout_seconds must be positive: {self.timeout_seconds!r}")
        if self.mode not in ("observe", "enforced"):
            raise PilotConfigError(f"mode must be 'observe' or 'enforced': {self.mode!r}")
        if not self.pilot_id:
            raise PilotConfigError("pilot_id is required")
        if not self.integration_id:
            raise PilotConfigError("integration_id is required")
        if not self.evidence_dir:
            raise PilotConfigError("evidence_dir is required")
        if self.agent_keys is not None:
            if not isinstance(self.agent_keys, dict) or not all(
                    isinstance(k, str) and k and isinstance(v, str) and v
                    for k, v in self.agent_keys.items()):
                raise PilotConfigError("agent_keys must map non-empty identity -> non-empty key")

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> PilotConfig:
        """Build a config from ``MCC_PILOT_*`` environment variables.
        Pass ``env`` explicitly in tests instead of mutating ``os.environ``."""
        e = os.environ if env is None else env
        kwargs: dict[str, object] = {}
        if "MCC_PILOT_GATEWAY_URL" in e:
            kwargs["gateway_url"] = e["MCC_PILOT_GATEWAY_URL"]
        else:
            raise PilotConfigError("MCC_PILOT_GATEWAY_URL is required")
        if "MCC_PILOT_TIMEOUT_SECONDS" in e:
            kwargs["timeout_seconds"] = float(e["MCC_PILOT_TIMEOUT_SECONDS"])
        if "MCC_PILOT_MODE" in e:
            kwargs["mode"] = e["MCC_PILOT_MODE"]
        if "MCC_PILOT_ID" in e:
            kwargs["pilot_id"] = e["MCC_PILOT_ID"]
        if "MCC_PILOT_INTEGRATION_ID" in e:
            kwargs["integration_id"] = e["MCC_PILOT_INTEGRATION_ID"]
        if "MCC_PILOT_EVIDENCE_DIR" in e:
            kwargs["evidence_dir"] = e["MCC_PILOT_EVIDENCE_DIR"]
        if "MCC_PILOT_RUN_CORRELATION_ID" in e:
            kwargs["run_correlation_id"] = e["MCC_PILOT_RUN_CORRELATION_ID"]
        if "MCC_PILOT_API_KEY" in e:
            kwargs["api_key"] = e["MCC_PILOT_API_KEY"]
        if e.get("MCC_PILOT_AGENT_KEYS_FILE"):
            kwargs["agent_keys"] = load_agent_keys(e["MCC_PILOT_AGENT_KEYS_FILE"])
        return cls(**kwargs)  # type: ignore[arg-type]

    def to_evidence_dict(self) -> dict[str, object]:
        """The configuration as recorded in an evidence bundle -- ``api_key``
        and ``agent_keys`` (the only secrets; every other field is non-secret
        by design) are always excluded."""
        d = asdict(self)
        d.pop("api_key", None)
        d.pop("agent_keys", None)
        return d

    def fingerprint(self) -> str:
        """A deterministic sha256 of the non-secret configuration, so two
        pilot runs can be compared for configuration drift without ever
        hashing (or exposing) the API key."""
        canonical = json.dumps(self.to_evidence_dict(), sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


__all__ = ["Mode", "PilotConfig", "PilotConfigError"]
