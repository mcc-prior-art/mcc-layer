# Secure Governed HTTPS Egress

> Hardens the **existing** governed outbound execution path (the egress proxy's
> `HTTPEgressExecutor`) for HTTPS. No parallel executor, no duplicated governance
> logic — the same gateway/coordinator/gate/consensus/approval/mandate/nonce/
> idempotency/velocity/audit path decides and the same executor performs the call.

See `docs/enforced-http-egress-proxy.md` for the overall egress architecture; this
document covers the HTTPS/TLS/SSRF/redirect hardening of the executor. For
governed credential references (auth headers) and optional mTLS, see
`docs/credential-references-mtls.md`.

-----

## HTTPS-only production mode

Production egress is HTTPS-only. The executor rejects HTTP and any non-`https`
scheme, malformed URLs, missing hostnames, and embedded credentials. There is no
insecure fallback.

- `require_https` defaults **true**; HTTP is permitted only when `allow_http` is
  explicitly enabled (test/dev — e.g. the pilot demo's plain-HTTP echo upstream).
- Scheme/credential/host validation happens both at canonicalization
  (`canonical_action`) and again in the executor before connecting.

## SSRF threat model

Before connecting, the destination is resolved and **every** resolved IP is
validated (`egress_proxy/ssrf.py`); a host that resolves to even one prohibited
address fails closed. Rejected by default:

- `localhost`, loopback IPv4/IPv6 (`127.0.0.0/8`, `::1`);
- private IPv4 (`10/8`, `172.16/12`, `192.168/16`), IPv6 unique-local (`fc00::/7`);
- link-local (`169.254.0.0/16`, `fe80::/10`) including the cloud metadata endpoint
  `169.254.169.254`;
- multicast, unspecified (`0.0.0.0`, `::`), reserved;
- CGNAT / shared address space (`100.64.0.0/10`);
- IPv4-mapped IPv6 forms of any of the above (`::ffff:127.0.0.1`).

Default posture is **allow only globally routable public destinations** (a final
`is_global` gate catches ranges individual predicates miss). Loopback/private/
link-local are re-admitted only by explicit trusted configuration
(`allow_loopback` / `allow_private` / `allow_link_local`), and an `allowed_hosts`
allow-list can pin destinations further. There is no implicit permissive default.

## DNS rebinding protection

The window between validation and connection is closed by **IP pinning**
(`egress_proxy/secure_transport.py`):

1. resolve the hostname and validate the full resolved IP set;
2. connect only to an approved, pre-validated IP (a custom httpcore network
   backend dials the pinned IP and ignores any second client-side DNS lookup);
3. preserve the **original hostname** for TLS SNI and certificate verification
   (httpcore performs `start_tls` against the origin host, not the IP);
4. read the connected peer IP and verify it belongs to the approved set; a
   mismatch closes the connection and fails closed.

So the client cannot be rebound to a fresh, unvalidated address after validation,
and TLS still verifies the certificate against the intended hostname.

## TLS enforcement

The executor builds a strict client context (`build_ssl_context`):

- certificate chain verification (`CERT_REQUIRED`) against trusted CA roots
  (system store, or a configured CA bundle for deterministic tests);
- hostname verification (`check_hostname = True`) with correct SNI;
- TLS 1.2 minimum (configurable to 1.3).

Rejected: expired, self-signed, untrusted-CA, and wrong-host certificates, and any
attempt to disable verification. `verify=False`, `CERT_NONE`, and TLS-warning
suppression are **never** used in the runtime path.

## Safe redirects

Automatic redirect following is **disabled** by default (`follow_redirects=False`,
`max_redirects=0`): the governed action is one request, and a redirect to an
ungoverned destination is not followed — the 3xx is returned to the caller, who
re-governs the new destination. When a positive `max_redirects` is configured,
each hop is handled safely (`validate_redirect`):

- the new URL is validated again (scheme, credentials, host) and re-resolved +
  SSRF-validated (DNS/IP re-checked every hop);
- HTTPS→HTTP downgrades are rejected; non-HTTPS targets are rejected in HTTPS-only
  mode;
- redirects to loopback/private/link-local/metadata are rejected;
- the redirect count is bounded and loops are detected (visited-set);
- on a **cross-origin** redirect, sensitive headers are stripped: `Authorization`,
  `Proxy-Authorization`, `Cookie`, and configured API-key headers
  (`x-api-key`, `x-operator-key`, `api-key`).

## Governance invariants (unchanged)

A request never executes before governance authorization completes, constraints
are applied, the final payload hash is gate-verified, and the durable
pre-actuation audit record is written. The executor is reached only from
`EnforcementCoordinator.enforce`, refuses any call lacking the verified decision
token (`UnauthorizedExecution`), and acts on exactly the authorized canonical
payload — so the executed request matches the governed payload hash. No alternative
network execution path exists.

## Audit evidence

The executor extends the **same** hash-chained audit log with an
`egress_execution` record (post-actuation; the durable pre-actuation record is the
coordinator's and is written first). Order: `pre_actuation` → `egress_execution` →
`actuation_result`. Safe metadata only:

- normalized URL, hostname, port, HTTP method;
- resolved IP set, selected (pinned) IP, connected peer IP;
- TLS validation result + negotiated version;
- redirect chain (status codes) and final destination;
- HTTP status and execution outcome;
- the authorized action hash.

Never logged: authorization values, cookies, API keys, request/response bodies,
or private key material. The chain remains verifiable (`AuditLog.verify_chain`).

## Configuration

| Setting (`MCC_EGRESS_*`) | Default | Meaning |
|---|---|---|
| `REQUIRE_HTTPS` | `true` | HTTPS-only; reject HTTP/other schemes |
| `ALLOW_HTTP` | `false` | test/dev override to permit HTTP |
| `TLS_CA_FILE` | *(system roots)* | trust exactly this CA bundle (tests) |
| `TLS_MIN_VERSION` | `1.2` | `1.2` or `1.3` |
| `MAX_REDIRECTS` | `0` | redirects disabled; >0 follows with per-hop validation |
| `ALLOWED_HOSTS` | *(empty = deny all)* | destination allow-list |
| `ALLOW_LOOPBACK` / `ALLOW_PRIVATE` / `ALLOW_LINK_LOCAL` | `false` | re-admit non-public classes (dev/containers) |

## Known limitations

- **TLS connection pinning vs. SNI**: pinning dials a pre-validated IP while TLS
  verifies the hostname; this fully closes the rebinding window for the validated
  set. Client certificate (mTLS) egress is not implemented.
- **Redirects**: following is opt-in (`max_redirects>0`); the strict, governance-
  correct default is no-follow (re-govern the redirect target).
- **CGNAT**: `100.64.0.0/10` is denied by default and re-admitted only via
  `allow_private`.
- **Docker Compose** demonstrates the network boundary but is not host-level bypass
  resistance — production needs orchestrator/network policy (see
  `docs/enforced-http-egress-proxy.md`).
- The pilot demo uses a plain-HTTP echo upstream (`ALLOW_HTTP=true`); production is
  HTTPS-only by default.
