"""Book chapter 10: arithmetic, wire boundaries, and authentication.

DH/RSA integers are deliberately insecure teaching values. Even the real
X25519 demo lacks peer authentication: do not turn it into a wire protocol.
Only public values / equality checks are printed for the real-key examples.
"""

from __future__ import annotations

import argparse
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def toy_dh() -> dict[str, int]:
    p, g, a, b = 23, 5, 6, 15
    public_a, public_b = pow(g, a, p), pow(g, b, p)
    recovered_a = next(i for i in range(1, p) if pow(g, i, p) == public_a)
    return {
        "public A": public_a,
        "public B": public_b,
        "Alice shared": pow(public_b, a, p),
        "Bob shared": pow(public_a, b, p),
        "attacker recovered a (tiny group only)": recovered_a,
    }


def toy_mitm() -> dict[str, int]:
    p, g, a, b, m = 23, 5, 6, 15, 7
    public_a, public_b, public_m = (pow(g, x, p) for x in (a, b, m))
    return {
        "Mallory public M sent to both peers": public_m,
        "Alice shared with fake Bob": pow(public_m, a, p),
        "Mallory shared with Alice": pow(public_a, m, p),
        "Bob shared with fake Alice": pow(public_m, b, p),
        "Mallory shared with Bob": pow(public_b, m, p),
    }


def toy_rsa() -> dict[str, int]:
    p, q, e, message = 61, 53, 17, 65
    n = p * q
    d = pow(e, -1, (p - 1) * (q - 1))
    ciphertext = pow(message, e, n)
    return {
        "public n": n,
        "public e": e,
        "toy private d": d,
        "message": message,
        "ciphertext": ciphertext,
        "decrypted": pow(ciphertext, d, n),
    }


def derive(shared: bytes, info: bytes) -> bytes:
    # Public, agreed demo context. A new HKDF object is needed for each derive.
    return HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=b"crypto-pg/key-roles/v1", info=info,
    ).derive(shared)


def public_bytes(key: x25519.X25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def x25519_demo() -> dict[str, bool | str]:
    alice = x25519.X25519PrivateKey.generate()
    bob = x25519.X25519PrivateKey.generate()

    # These bytes, not the private-key objects, cross the simulated wire.
    a_wire = public_bytes(alice.public_key())
    b_wire = public_bytes(bob.public_key())
    alice_shared = alice.exchange(x25519.X25519PublicKey.from_public_bytes(b_wire))
    bob_shared = bob.exchange(x25519.X25519PublicKey.from_public_bytes(a_wire))

    alice_send = derive(alice_shared, b"A-to-B/key")
    bob_receive = derive(bob_shared, b"A-to-B/key")
    bob_send = derive(bob_shared, b"B-to-A/key")
    nonce, aad = secrets.token_bytes(12), b"crypto-pg/demo-message/v1"
    plaintext = b"Hello Bob; the AES key was never sent."
    ciphertext = AESGCM(alice_send).encrypt(nonce, plaintext, aad)
    recovered = AESGCM(bob_receive).decrypt(nonce, ciphertext, aad)
    return {
        "public A on wire (hex)": a_wire.hex(),
        "public B on wire (hex)": b_wire.hex(),
        "shared secrets match": alice_shared == bob_shared,
        "A send / B receive keys match": alice_send == bob_receive,
        "opposite direction key differs": alice_send != bob_send,
        "Bob recovered plaintext": recovered == plaintext,
        "peer identity authenticated": False,
    }


def signature_valid(
    public: ed25519.Ed25519PublicKey, message: bytes, signature: bytes
) -> bool:
    try:
        public.verify(signature, message)
    except InvalidSignature:
        return False
    return True


def signature_demo() -> dict[str, bool]:
    private = ed25519.Ed25519PrivateKey.generate()
    public = private.public_key()
    message = b"release:v1;sha256:example-digest"
    signature = private.sign(message)
    stranger_public = ed25519.Ed25519PrivateKey.generate().public_key()
    return {
        "valid message": signature_valid(public, message, signature),
        "changed message": signature_valid(public, message + b"!", signature),
        "wrong public key": signature_valid(stranger_public, message, signature),
    }


def main() -> None:
    demos = {
        "dh": toy_dh, "mitm": toy_mitm, "rsa": toy_rsa,
        "x25519": x25519_demo, "signature": signature_demo,
    }
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("demo", choices=demos)
    args = parser.parse_args()
    if args.demo in {"dh", "mitm", "rsa"}:
        print("TOY ARITHMETIC ONLY: deliberately insecure small integers")
    for label, value in demos[args.demo]().items():
        print(f"{label}: {value}")


if __name__ == "__main__":
    main()
