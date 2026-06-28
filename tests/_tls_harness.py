"""Deterministic local TLS test infrastructure (offline; no public internet).

Mints a throwaway CA and leaf certificates and runs local HTTPS servers, so the
egress executor's TLS verification, SNI/hostname checks, and IP pinning can be
tested against real TLS handshakes with known-good and known-bad certs.

Test scaffolding only — never imported by runtime code. Nothing is committed:
keys/certs are written to per-test temp files.
"""

from __future__ import annotations

import datetime
import socket
import ssl
import tempfile
import threading
import time
from pathlib import Path
from typing import List, Optional, Tuple

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

DAY = datetime.timedelta(days=1)


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def make_ca(common_name: Optional[str] = None) -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    import uuid
    key = ec.generate_private_key(ec.SECP256R1())
    cn = common_name or f"mcc-egress-test-ca-{uuid.uuid4().hex[:8]}"  # unique DN per CA
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - DAY).not_valid_after(_now() + DAY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256()))
    return key, cert


def make_leaf(ca_key, ca_cert, hostname: str, *, not_before=None, not_after=None,
              self_signed: bool = False) -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    issuer = subject if self_signed else ca_cert.subject
    signer = key if self_signed else ca_key
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or (_now() - DAY))
        .not_valid_after(not_after or (_now() + DAY))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .sign(signer, hashes.SHA256()))
    return key, cert


def _write(tmp: Path, name: str, data: bytes) -> str:
    p = tmp / name
    p.write_bytes(data)
    return str(p)


def write_cert_and_key(tmp: Path, cert, key, *, prefix: str) -> Tuple[str, str]:
    certfile = _write(tmp, f"{prefix}.crt", cert.public_bytes(serialization.Encoding.PEM))
    keyfile = _write(tmp, f"{prefix}.key", key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return certfile, keyfile


def write_ca_bundle(tmp: Path, ca_cert) -> str:
    return _write(tmp, "ca.pem", ca_cert.public_bytes(serialization.Encoding.PEM))


def _free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    return port


def serve_https(app, certfile: str, keyfile: str, *, timeout: float = 10.0) -> int:
    """Run a local HTTPS server on 127.0.0.1; return the port once it accepts TLS."""
    port = _free_port()
    threading.Thread(
        target=lambda: uvicorn.run(app, host="127.0.0.1", port=port, ssl_certfile=certfile,
                                   ssl_keyfile=keyfile, log_level="error"),
        daemon=True).start()
    deadline = time.time() + timeout
    ctx = ssl._create_unverified_context()  # liveness probe only (not the executor's context)
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3) as sock:
                with ctx.wrap_socket(sock, server_hostname="probe"):
                    return port
        except Exception:
            time.sleep(0.05)
    raise RuntimeError("HTTPS server did not come up")


def serve_mtls(server_cert: str, server_key: str, client_ca_file: str) -> int:
    """Run a local HTTPS server that REQUIRES a client certificate signed by
    ``client_ca_file`` (mutual TLS). Uses a stdlib http.server with a precisely
    controlled SSLContext (so only the server leaf is sent — no chain pollution)."""
    import http.server

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": true}')

        def log_message(self, *args):  # silence
            pass

    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(server_cert, server_key)
    sctx.load_verify_locations(cafile=client_ca_file)
    sctx.verify_mode = ssl.CERT_REQUIRED
    port = _free_port()
    httpd = http.server.HTTPServer(("127.0.0.1", port), _Handler)
    httpd.socket = sctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.2)
    return port


def host_resolver(mapping):
    """A resolver that maps known hostnames to fixed IPs (deterministic; no DNS)."""
    def resolve(host: str, port: int) -> List[Tuple[int, str]]:
        if host in mapping:
            return [(socket.AF_INET, mapping[host])]
        raise OSError(f"unmapped host {host}")
    return resolve
