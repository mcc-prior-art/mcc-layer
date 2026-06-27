"""Canonical representation of an outbound HTTP action — the thing MCC governs.

One deterministic, flat dict represents an outbound HTTP request. The decision
token is signed over exactly this dict (via the runtime's ``hash_payload`` /
canonical serialization), so the execution gate's payload-hash check binds the
authorization to the exact action. Any difference between the governed action and
the executed request — host, method, path, query, body, governed header, actor,
ids — changes the hash and is denied.

The dict is intentionally **flat** so the existing constraint mechanism
(``max_<field>`` / ``allowed_<field>``) can address governed fields directly:

* envelope fields are top-level: ``method``, ``scheme``, ``host``, ``port``,
  ``path``, ``query``, ``headers``, ``destination_id``, ``action_type``;
* JSON-object body fields are namespaced as ``body.<key>`` (so a policy can
  ``max_body.amount`` / ``allowed_body.currency`` without reaching into a nested
  object, and a CONSTRAIN clamp rewrites them → a new action hash);
* non-JSON bodies are bound by ``__rawbody_sha256__`` only (not clampable).

Reserved keys never collide with body fields because body fields are namespaced.
We reuse ``mcc_core.hash_payload`` (canonical, deterministic) — no parallel
hashing format is introduced.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit

from mcc_core import hash_payload, sha256_hex

ACTION_TYPE = "http.request"

# Headers that are part of the governed binding by default. Everything else the
# caller sends is dropped from the binding (and not forwarded) unless explicitly
# declared governed, so a caller cannot smuggle an ungoverned header past the
# authorization. Hop-by-hop and dangerous headers are never governed/forwarded.
DEFAULT_GOVERNED_HEADERS = ("content-type", "accept")

# RFC 7230 hop-by-hop headers + proxy/host controls we never forward.
HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "trailers", "transfer-encoding", "upgrade",
    "host", "content-length", "expect", "proxy-connection",
})

DEFAULT_PORTS = {"http": 80, "https": 443}
MAX_BODY_BYTES = 1 * 1024 * 1024  # 1 MiB request body cap for the binding


class CanonicalActionError(ValueError):
    """The proposed outbound action is malformed or cannot be canonicalized."""


def _normalize_url(url: str) -> Tuple[str, str, int, str, List[List[str]]]:
    if not isinstance(url, str) or not url.strip():
        raise CanonicalActionError("url is required")
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise CanonicalActionError(f"unsupported scheme {scheme!r}; only http/https")
    if parts.username or parts.password or "@" in (parts.netloc or ""):
        raise CanonicalActionError("URL must not contain embedded credentials")
    host = (parts.hostname or "").lower()
    if not host:
        raise CanonicalActionError("URL has no host")
    try:
        port = parts.port if parts.port is not None else DEFAULT_PORTS[scheme]
    except ValueError as exc:
        raise CanonicalActionError(f"invalid port: {exc}") from exc
    if not (0 < port < 65536):
        raise CanonicalActionError(f"port {port} out of range")
    path = parts.path or "/"
    # Deterministic query: sorted (key, value) pairs.
    query = sorted([k, v] for k, v in parse_qsl(parts.query, keep_blank_values=True))
    return scheme, host, port, path, query


def _governed_headers(
    headers: Optional[Dict[str, str]], governed_names: Tuple[str, ...]
) -> List[List[str]]:
    """Lowercase, drop hop-by-hop/dangerous, keep only governed names, sorted."""
    headers = headers or {}
    governed = {n.lower() for n in governed_names}
    out: List[List[str]] = []
    for name, value in headers.items():
        lname = str(name).lower()
        if lname in HOP_BY_HOP:
            continue
        if lname in governed:
            out.append([lname, str(value)])
    return sorted(out)


def _encode_body(body: Any) -> Dict[str, Any]:
    """Return the flat body contribution to the canonical action.

    JSON object -> namespaced ``body.<key>`` fields (clampable by policy).
    Anything else -> a raw byte binding by sha256 (not clampable).
    """
    if body is None or body == {} or body == "":
        return {"body_kind": "empty"}
    if isinstance(body, dict):
        # The body's content is bound by the namespaced ``body.<key>`` fields plus
        # ``__body_keys__`` (which fixes the key set) — all part of the canonical
        # dict that ``hash_payload`` covers. We deliberately do NOT add a separate
        # raw body hash here: a CONSTRAIN clamp rewrites a ``body.<key>`` value, and
        # a stale raw hash would make the clamped action fail to re-canonicalize.
        raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(raw) > MAX_BODY_BYTES:
            raise CanonicalActionError("request body exceeds size limit")
        flat: Dict[str, Any] = {"body_kind": "json"}
        keys = sorted(str(k) for k in body.keys())
        for k in keys:
            flat[f"body.{k}"] = body[k]
        flat["__body_keys__"] = keys
        return flat
    # Raw (string/bytes) body.
    raw = body.encode("utf-8") if isinstance(body, str) else bytes(body)
    if len(raw) > MAX_BODY_BYTES:
        raise CanonicalActionError("request body exceeds size limit")
    return {
        "body_kind": "raw",
        "__rawbody_b64__": base64.b64encode(raw).decode("ascii"),
        "__rawbody_sha256__": sha256_hex(raw),
    }


def build_canonical_action(
    *,
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    body: Any = None,
    governed_headers: Tuple[str, ...] = DEFAULT_GOVERNED_HEADERS,
) -> Dict[str, Any]:
    """Build the flat, deterministic canonical action for an outbound request.

    This is the payload MCC signs and the gate binds to. It is independent of the
    actor/transaction ids (those bind via the token's own claims), so two
    materially-identical requests produce the same action hash and two different
    ones differ.
    """
    if not isinstance(method, str) or not method.strip():
        raise CanonicalActionError("method is required")
    m = method.strip().upper()
    if m not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
        raise CanonicalActionError(f"unsupported method {m!r}")
    scheme, host, port, path, query = _normalize_url(url)
    action: Dict[str, Any] = {
        "action_type": ACTION_TYPE,
        "method": m,
        "scheme": scheme,
        "host": host,
        "port": port,
        "path": path,
        "query": query,
        "headers": _governed_headers(headers, governed_headers),
        "destination_id": f"{host}:{port}",
    }
    action.update(_encode_body(body))
    return action


def action_hash(action: Dict[str, Any]) -> str:
    """The canonical hash the token is signed over and the gate binds to."""
    return hash_payload(action)


def reconstruct_request(action: Dict[str, Any]) -> Tuple[str, str, Dict[str, str], Any]:
    """Rebuild ``(method, url, headers, body)`` from an authorized canonical action.

    Used by the executor to perform the *exact* authorized request. Because the
    token's payload-hash binds to this dict, a reconstructed request can only
    differ from the authorized one if the dict itself differs — which the gate
    would have rejected.
    """
    scheme = action["scheme"]
    host = action["host"]
    port = int(action["port"])
    path = action.get("path") or "/"
    netloc = host if port == DEFAULT_PORTS.get(scheme) else f"{host}:{port}"
    query = action.get("query") or []
    qs = "&".join(f"{k}={v}" for k, v in query)
    url = f"{scheme}://{netloc}{path}"
    if qs:
        url = f"{url}?{qs}"
    headers = {name: value for name, value in (action.get("headers") or [])}

    kind = action.get("body_kind", "empty")
    body: Any = None
    if kind == "json":
        body = {k[len("body."):]: v for k, v in action.items() if k.startswith("body.")}
    elif kind == "raw":
        body = base64.b64decode(action["__rawbody_b64__"])
    return action["method"], url, headers, body
