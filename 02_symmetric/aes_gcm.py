"""Session 1.4: authenticated encryption with AES-256-GCM."""

from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass(frozen=True)
class Envelope:
    version: int
    nonce: bytes
    ciphertext: bytes  # cryptography appends the 16-byte GCM tag here

    def to_json(self) -> str:
        encode = lambda value: base64.urlsafe_b64encode(value).decode("ascii")
        return json.dumps(
            {
                "version": self.version,
                "nonce": encode(self.nonce),
                "ciphertext": encode(self.ciphertext),
            },
            separators=(",", ":"),
        )


def generate_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> Envelope:
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return Envelope(version=1, nonce=nonce, ciphertext=ciphertext)


def decrypt(key: bytes, envelope: Envelope, aad: bytes) -> bytes:
    if envelope.version != 1:
        raise ValueError("unsupported envelope version")
    return AESGCM(key).decrypt(envelope.nonce, envelope.ciphertext, aad)


def main() -> None:
    key = generate_key()
    aad = b"content-type=text/plain;sender=alice"
    plaintext = b"the launch code is 1234"
    first = encrypt(key, plaintext, aad)
    second = encrypt(key, plaintext, aad)

    print(f"same key:       {key.hex()}")
    print(f"first envelope:  {first.to_json()}")
    print(f"second envelope: {second.to_json()}")
    print(f"different nonce: {first.nonce != second.nonce}")
    print(f"different ciphertext: {first.ciphertext != second.ciphertext}")
    print(f"decrypted: {decrypt(key, first, aad).decode('utf-8')}")


if __name__ == "__main__":
    main()
