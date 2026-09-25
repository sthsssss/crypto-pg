"""Unsafe experiment: GCM nonce reuse reveals plaintext relationships."""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def main() -> None:
    key = AESGCM.generate_key(bit_length=256)
    reused_nonce = b"\x00" * 12  # Deliberately unsafe.
    known = b"pay bob   1000 USD"
    secret = b"pay alice 9000 USD"

    known_ct = AESGCM(key).encrypt(reused_nonce, known, None)[:-16]
    secret_ct = AESGCM(key).encrypt(reused_nonce, secret, None)[:-16]

    recovered = xor(xor(known_ct, secret_ct), known)
    print(f"known plaintext:     {known!r}")
    print(f"recovered plaintext: {recovered!r}")
    print("Never reuse a nonce with the same AEAD key.")


if __name__ == "__main__":
    main()
