"""SSRF / destination-safety: fail-closed by default, with DNS-rebinding defence."""

import pytest

from egress_proxy.ssrf import DestinationPolicy, SSRFError, validate_destination


def _resolver(ip):
    return lambda host, port: [(2, ip)]


@pytest.mark.parametrize("ip", [
    "127.0.0.1", "169.254.169.254", "0.0.0.0", "10.1.2.3", "192.168.1.1",
    "172.16.0.1", "224.0.0.1", "::1", "fe80::1",
])
def test_dangerous_literals_rejected_by_default(ip):
    with pytest.raises(SSRFError):
        validate_destination(ip, 80)


def test_public_literal_allowed():
    d = validate_destination("93.184.216.34", 443)
    assert d.pinned_ip == "93.184.216.34"


def test_loopback_allowed_only_by_explicit_policy():
    with pytest.raises(SSRFError):
        validate_destination("127.0.0.1", 80)
    d = validate_destination("127.0.0.1", 80, policy=DestinationPolicy(allow_loopback=True))
    assert d.pinned_ip == "127.0.0.1"


def test_hostname_resolving_to_loopback_rejected():
    # DNS rebinding / confusion: a name that resolves to a private/loopback IP.
    with pytest.raises(SSRFError):
        validate_destination("sneaky.example", 80, resolver=_resolver("127.0.0.1"))


def test_hostname_with_any_bad_ip_rejected():
    # Resolves to one public and one loopback -> rejected (every IP must pass).
    def resolver(host, port):
        return [(2, "93.184.216.34"), (2, "127.0.0.1")]
    with pytest.raises(SSRFError):
        validate_destination("mixed.example", 80, resolver=resolver)


def test_ipv4_mapped_ipv6_loopback_rejected():
    with pytest.raises(SSRFError):
        validate_destination("::ffff:127.0.0.1", 80)


def test_allowed_hosts_enforced():
    pol = DestinationPolicy(allow_loopback=True, allowed_hosts=frozenset({"good.example"}))
    with pytest.raises(SSRFError):
        validate_destination("bad.example", 80, policy=pol, resolver=_resolver("127.0.0.1"))


def test_allowed_ports_enforced():
    pol = DestinationPolicy(allowed_ports=frozenset({443}))
    with pytest.raises(SSRFError):
        validate_destination("93.184.216.34", 80, policy=pol)


def test_unresolvable_host_fails_closed():
    def resolver(host, port):
        raise OSError("nxdomain")
    with pytest.raises(SSRFError):
        validate_destination("nope.example", 80, resolver=resolver)


def test_bad_port_rejected():
    with pytest.raises(SSRFError):
        validate_destination("93.184.216.34", 0)
    with pytest.raises(SSRFError):
        validate_destination("93.184.216.34", 70000)
