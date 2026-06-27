"""SSRF / destination-confusion protection for the egress proxy.

The proxy is an outbound execution component, so it fails closed against
server-side request forgery. Validation runs at submission *and* again at
connect time against the actually-resolved address, and the executor pins the
connection to the validated IP — closing the DNS-rebinding window between
validation and connection.

By default the proxy refuses loopback, link-local, multicast, unspecified, and
private destinations, and any non-http(s) scheme or embedded credentials.
Restrictions are configurable through trusted deployment configuration (never an
implicit permissive default).
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

# A resolver returns a list of (family, ip_str) for a hostname. Injected so SSRF
# logic is deterministically testable without real DNS.
Resolver = Callable[[str, int], List[Tuple[int, str]]]

# RFC 6598 carrier-grade NAT / shared address space. Not flagged private by every
# Python ``ipaddress`` version, so we deny it explicitly (not just via is_private).
SHARED_ADDRESS_SPACE_V4 = ipaddress.ip_network("100.64.0.0/10")


class SSRFError(ValueError):
    """A destination was rejected by the SSRF / destination-safety checks."""


@dataclass(frozen=True)
class DestinationPolicy:
    """Trusted deployment configuration for allowed destinations (fail-closed).

    Default posture: only globally routable public destinations are allowed. The
    overrides below re-admit specific non-public classes for dev/containers
    (``allow_private`` also re-admits CGNAT / RFC 6598 shared address space)."""

    allow_loopback: bool = False
    allow_link_local: bool = False
    allow_private: bool = False
    # If set, the host must be in this allow-set (exact, lowercased) regardless
    # of address class. Empty/None means "any public host".
    allowed_hosts: Optional[frozenset] = None
    allowed_ports: Optional[frozenset] = None


@dataclass(frozen=True)
class ResolvedDestination:
    host: str
    port: int
    # All resolved IPs (validated) and the pinned one the executor must connect to.
    ips: List[str] = field(default_factory=list)
    pinned_ip: str = ""


def _default_resolver(host: str, port: int) -> List[Tuple[int, str]]:
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    out: List[Tuple[int, str]] = []
    for family, _type, _proto, _canon, sockaddr in infos:
        out.append((family, sockaddr[0]))
    return out


def _classify_reject(ip: ipaddress._BaseAddress, policy: DestinationPolicy) -> Optional[str]:
    """Return a rejection reason for an IP under the policy, or None if allowed.

    Default posture: **only globally routable public destinations are allowed.**
    Every non-global class (loopback, link-local, multicast, unspecified, reserved,
    private, CGNAT/shared, documentation, benchmarking, 6to4 relay anycast, …) is
    denied unless an explicit trusted override permits that class. We do not rely
    on ``is_private`` alone — the final ``is_global`` gate catches ranges that
    individual predicates miss (and varies by Python version)."""
    # IPv4-mapped IPv6 (::ffff:a.b.c.d) — classify the embedded v4.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return _classify_reject(ip.ipv4_mapped, policy)
    if ip.is_unspecified:
        return "unspecified address rejected"
    if ip.is_multicast:
        return "multicast address rejected"
    if ip.is_loopback:
        return None if policy.allow_loopback else "loopback address rejected"
    if ip.is_link_local:
        return None if policy.allow_link_local else "link-local address rejected"
    # CGNAT / shared address space (RFC 6598). Deny by default; overridable only
    # via the explicit private override (it is non-public, shared infrastructure).
    if isinstance(ip, ipaddress.IPv4Address) and ip in SHARED_ADDRESS_SPACE_V4:
        return None if policy.allow_private else "shared/CGNAT (100.64.0.0/10) address rejected"
    if ip.is_private:
        return None if policy.allow_private else "private address rejected"
    if getattr(ip, "is_reserved", False):
        return "reserved address rejected"
    # Default-deny: anything not globally routable is refused even if no specific
    # predicate above matched it.
    if not ip.is_global:
        return "non-global (not publicly routable) address rejected"
    return None


def validate_destination(
    host: str,
    port: int,
    *,
    policy: Optional[DestinationPolicy] = None,
    resolver: Optional[Resolver] = None,
) -> ResolvedDestination:
    """Validate a destination and return its resolved, pinned address.

    Fail-closed: any disallowed address class, an unresolvable host, a
    disallowed host/port, or a resolution error raises :class:`SSRFError`.
    Every resolved IP must pass — a host that resolves to even one rejected
    address is rejected (so a public name that also returns 127.0.0.1 cannot
    sneak through).
    """
    policy = policy or DestinationPolicy()
    if not isinstance(host, str) or not host:
        raise SSRFError("missing host")
    host = host.lower().rstrip(".")
    if not (0 < int(port) < 65536):
        raise SSRFError(f"port {port} out of range")
    if policy.allowed_ports is not None and int(port) not in policy.allowed_ports:
        raise SSRFError(f"port {port} not allowed by policy")
    if policy.allowed_hosts is not None and host not in policy.allowed_hosts:
        raise SSRFError(f"host {host!r} not in allowed_hosts")

    # Literal IP host: classify directly (no DNS).
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        reason = _classify_reject(literal, policy)
        if reason:
            raise SSRFError(reason)
        return ResolvedDestination(host=host, port=int(port),
                                   ips=[str(literal)], pinned_ip=str(literal))

    resolve = resolver or _default_resolver
    try:
        resolved = resolve(host, int(port))
    except Exception as exc:  # noqa: BLE001 — resolution failure is fail-closed
        raise SSRFError(f"could not resolve host {host!r}: {exc}") from exc
    if not resolved:
        raise SSRFError(f"host {host!r} did not resolve")

    ips: List[str] = []
    for _family, ip_str in resolved:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError as exc:
            raise SSRFError(f"invalid resolved address {ip_str!r}") from exc
        reason = _classify_reject(ip, policy)
        if reason:
            raise SSRFError(f"{reason} (host {host!r} -> {ip_str})")
        ips.append(str(ip))
    return ResolvedDestination(host=host, port=int(port), ips=ips, pinned_ip=ips[0])
