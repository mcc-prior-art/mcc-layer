"""Multi-issuer trust set for signed mandates and approvals.

The trust root for the governance layer: which issuers, and which of their key
ids, are accepted when verifying signed mandates (and approval mandates). It is
*configuration*, never hard-coded keys, and it holds only **public** keys — no
private or otherwise sensitive material lives here.

Design points the deployment requirements call for:

* multiple active keys per issuer (key rotation: add new, retire old);
* per-issuer enable/disable and per-key expiry;
* distinct, explicit outcomes for unknown issuer/kid, expired key, disabled
  issuer, malformed config, and unavailable trust source;
* fail-closed: an unresolved kid yields no trust;
* startup validation that refuses an invalid *pilot* trust configuration rather
  than silently falling back to a development key.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Mapping, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class TrustConfigError(Exception):
    """Raised when trust configuration is malformed/unsafe (refuses startup)."""


class TrustStatus(str, Enum):
    OK = "OK"
    UNKNOWN_KID = "UNKNOWN_KID"
    DISABLED_ISSUER = "DISABLED_ISSUER"
    EXPIRED_KEY = "EXPIRED_KEY"
    REVOKED_KEY = "REVOKED_KEY"


@dataclass
class IssuerKey:
    kid: str
    public_key: Ed25519PublicKey
    not_after: Optional[int] = None  # unix seconds; None = no expiry
    revoked: bool = False


@dataclass
class Issuer:
    issuer_id: str
    keys: List[IssuerKey] = field(default_factory=list)
    enabled: bool = True


@dataclass(frozen=True)
class TrustResolution:
    status: TrustStatus
    reason: str
    issuer_id: Optional[str] = None
    kid: Optional[str] = None
    public_key: Optional[Ed25519PublicKey] = None

    @property
    def ok(self) -> bool:
        return self.status == TrustStatus.OK


def _decode_ed25519(public_key_b64: str) -> Ed25519PublicKey:
    raw = base64.b64decode(public_key_b64)
    if len(raw) != 32:
        raise TrustConfigError("Ed25519 public key must be 32 raw bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


class TrustSet:
    """The set of trusted issuers/keys. Resolution is by kid; the result carries
    a distinct status so callers can report exactly why trust failed."""

    def __init__(self, issuers: Optional[List[Issuer]] = None) -> None:
        self._issuers: Dict[str, Issuer] = {}
        self._kid_index: Dict[str, str] = {}  # kid -> issuer_id
        for issuer in issuers or []:
            self.add_issuer(issuer)

    def add_issuer(self, issuer: Issuer) -> None:
        if issuer.issuer_id in self._issuers:
            raise TrustConfigError(f"duplicate issuer_id {issuer.issuer_id!r}")
        for key in issuer.keys:
            if key.kid in self._kid_index:
                raise TrustConfigError(f"duplicate kid {key.kid!r}")
            self._kid_index[key.kid] = issuer.issuer_id
        self._issuers[issuer.issuer_id] = issuer

    def resolve(self, kid: Optional[str], *, now: int) -> TrustResolution:
        if not kid or kid not in self._kid_index:
            return TrustResolution(TrustStatus.UNKNOWN_KID, "unknown key id", kid=kid)
        issuer = self._issuers[self._kid_index[kid]]
        key = next((k for k in issuer.keys if k.kid == kid), None)
        if key is None:  # pragma: no cover - index invariant
            return TrustResolution(TrustStatus.UNKNOWN_KID, "unknown key id", kid=kid)
        if not issuer.enabled:
            return TrustResolution(TrustStatus.DISABLED_ISSUER, "issuer disabled",
                                   issuer_id=issuer.issuer_id, kid=kid)
        if key.revoked:
            return TrustResolution(TrustStatus.REVOKED_KEY, "key revoked",
                                   issuer_id=issuer.issuer_id, kid=kid)
        if key.not_after is not None and now >= key.not_after:
            return TrustResolution(TrustStatus.EXPIRED_KEY, "key expired",
                                   issuer_id=issuer.issuer_id, kid=kid)
        return TrustResolution(TrustStatus.OK, "trusted", issuer_id=issuer.issuer_id,
                               kid=kid, public_key=key.public_key)

    def active_trusted_keys(self, *, now: int) -> Dict[str, Ed25519PublicKey]:
        """The {kid: public_key} map of currently-usable keys (enabled issuer,
        not revoked, not expired)."""
        out: Dict[str, Ed25519PublicKey] = {}
        for issuer in self._issuers.values():
            if not issuer.enabled:
                continue
            for key in issuer.keys:
                if key.revoked:
                    continue
                if key.not_after is not None and now >= key.not_after:
                    continue
                out[key.kid] = key.public_key
        return out

    # ---- operator mutations (durable via config reload) ----

    def disable_issuer(self, issuer_id: str) -> bool:
        issuer = self._issuers.get(issuer_id)
        if issuer is None:
            return False
        issuer.enabled = False
        return True

    def revoke_key(self, kid: str) -> bool:
        issuer_id = self._kid_index.get(kid)
        if issuer_id is None:
            return False
        for key in self._issuers[issuer_id].keys:
            if key.kid == kid:
                key.revoked = True
                return True
        return False  # pragma: no cover

    def add_runtime_issuer(self, issuer_id: str, kid: str, public_key: Ed25519PublicKey) -> None:
        """Programmatically trust a key (e.g. the gateway's own approver key)."""
        self.add_issuer(Issuer(issuer_id=issuer_id, keys=[IssuerKey(kid=kid, public_key=public_key)]))

    def summary(self) -> List[dict]:
        """Non-sensitive description for operators (no key material)."""
        return [
            {
                "issuer_id": i.issuer_id, "enabled": i.enabled,
                "keys": [{"kid": k.kid, "not_after": k.not_after, "revoked": k.revoked}
                         for k in i.keys],
            }
            for i in self._issuers.values()
        ]

    @property
    def issuer_count(self) -> int:
        return len(self._issuers)


def load_trust_config(data: dict) -> TrustSet:
    """Parse + strictly validate a trust config dict into a TrustSet."""
    if not isinstance(data, dict) or not isinstance(data.get("issuers"), list):
        raise TrustConfigError("trust config must be an object with an 'issuers' list")
    trust = TrustSet()
    for raw in data["issuers"]:
        if not isinstance(raw, dict):
            raise TrustConfigError("each issuer must be an object")
        issuer_id = raw.get("issuer_id")
        if not issuer_id or not isinstance(issuer_id, str):
            raise TrustConfigError("issuer.issuer_id is required")
        raw_keys = raw.get("keys")
        if not isinstance(raw_keys, list) or not raw_keys:
            raise TrustConfigError(f"issuer {issuer_id!r} must have a non-empty 'keys' list")
        keys: List[IssuerKey] = []
        for rk in raw_keys:
            if not isinstance(rk, dict) or not rk.get("kid") or not rk.get("public_key_b64"):
                raise TrustConfigError(f"issuer {issuer_id!r} has a malformed key entry")
            keys.append(IssuerKey(
                kid=str(rk["kid"]),
                public_key=_decode_ed25519(str(rk["public_key_b64"])),
                not_after=rk.get("not_after"),
                revoked=bool(rk.get("revoked", False)),
            ))
        trust.add_issuer(Issuer(issuer_id=issuer_id, keys=keys,
                                enabled=bool(raw.get("enabled", True))))
    return trust


def trust_set_from_env(env: Optional[Mapping[str, str]] = None) -> TrustSet:
    """Load the trust set per ``MCC_ENV`` and ``MCC_TRUST_CONFIG``.

    * ``pilot`` — a valid, non-empty trust config is **required**. A missing,
      unreadable, malformed, or empty config refuses startup (TrustConfigError).
      There is no fallback to a development key.
    * ``dev`` / ``test`` — a config is loaded if present; otherwise an empty
      trust set is returned (mandate verification will simply find no trust).
    """
    env = os.environ if env is None else env
    mcc_env = env.get("MCC_ENV", "dev").strip().lower()
    path = env.get("MCC_TRUST_CONFIG", "").strip()

    if not path:
        if mcc_env == "pilot":
            raise TrustConfigError(
                "MCC_ENV=pilot requires MCC_TRUST_CONFIG; refusing to start without a "
                "trust root (no fallback to a development key)"
            )
        return TrustSet()

    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise TrustConfigError(f"trust config not found at {path}") from exc
    except json.JSONDecodeError as exc:
        raise TrustConfigError(f"trust config at {path} is not valid JSON") from exc

    trust = load_trust_config(data)
    if mcc_env == "pilot" and not trust.active_trusted_keys(now=_now()):
        raise TrustConfigError(
            "MCC_ENV=pilot trust config has no usable (enabled, unexpired) keys; refusing to start"
        )
    return trust


def _now() -> int:
    import time
    return int(time.time())
