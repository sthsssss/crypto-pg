"""Real TLS 1.3 in memory, with a disposable CA and no network listeners.

Teaching-only PKI. Never installs roots into the OS, disables verification,
exports traffic secrets, or retains keys. Requires Python/OpenSSL TLS 1.3.
"""

from __future__ import annotations

import ssl
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@contextmanager
def temporary_pki():
    """Separate CA signing key and server authentication key, per run."""
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Crypto PG temporary CA")])
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.utcnow()

    def builder(subject, issuer, public):
        return (
            x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(public).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
        )

    ca_cert = (
        builder(ca_name, ca_name, ca_key.public_key())
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
        .sign(ca_key, hashes.SHA256())
    )
    server_cert = (
        builder(server_name, ca_name, server_key.public_key())
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
        .sign(ca_key, hashes.SHA256())
    )
    with TemporaryDirectory(prefix="crypto-pg-tls-") as directory:
        cert_path, key_path = Path(directory) / "server.pem", Path(directory) / "server.key"
        cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
        # TemporaryDirectory is private; additionally restrict the key file.
        key_path.touch(mode=0o600)
        key_path.write_bytes(server_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        yield cert_path, key_path, ca_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def run_connection(cert_path, key_path, ca_pem, *, hostname="localhost", trusted=True):
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    for context in (server_ctx, client_ctx):
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
    server_ctx.num_tickets = 0  # Keep post-handshake resumption out of this lab.
    server_ctx.load_cert_chain(cert_path, key_path)
    # No default roots: the client trusts only the generated CA, if requested.
    if trusted:
        client_ctx.load_verify_locations(cadata=ca_pem)

    client_in, client_out, server_in, server_out = (ssl.MemoryBIO() for _ in range(4))
    client = client_ctx.wrap_bio(client_in, client_out, server_hostname=hostname)
    server = server_ctx.wrap_bio(server_in, server_out, server_side=True)

    def transfer(source, destination):
        data = source.read()
        if data:
            destination.write(data)
        return data

    client_done = server_done = False
    for _ in range(100):  # Bound failures: no hanging loop if the lab is edited.
        if not client_done:
            try:
                client.do_handshake()
                client_done = True
            except ssl.SSLWantReadError:
                pass
        transfer(client_out, server_in)
        if not server_done:
            try:
                server.do_handshake()
                server_done = True
            except ssl.SSLWantReadError:
                pass
        transfer(server_out, client_in)
        if client_done and server_done:
            break
    else:
        raise RuntimeError("TLS handshake did not converge")

    request = b"GET /account HTTP/1.1\r\nHost: localhost\r\n\r\n"
    client.write(request)
    wire = transfer(client_out, server_in)
    received = server.read(16384)
    return {
        "version": client.version(), "cipher": client.cipher()[0],
        "request": request, "wire": wire, "received": received,
    }


def main() -> None:
    with temporary_pki() as (cert, key, ca):
        result = run_connection(cert, key, ca)
        print(f"trusted CA + matching hostname: {result['version']} / {result['cipher']}")
        print(f"application record bytes: {len(result['wire'])}")
        print(f"plaintext request visible on wire: {result['request'] in result['wire']}")
        print(f"server received: {result['received']!r}")
        for label, kwargs in (
            ("wrong hostname", {"hostname": "wrong.example"}),
            ("untrusted CA", {"trusted": False}),
        ):
            try:
                run_connection(cert, key, ca, **kwargs)
            except ssl.SSLCertVerificationError as error:
                print(f"{label}: rejected ({error.verify_message})")
            else:
                raise AssertionError(f"Expected certificate rejection: {label}")
    print("Temporary certificate/private-key files removed; OS trust store unchanged.")


if __name__ == "__main__":
    main()
