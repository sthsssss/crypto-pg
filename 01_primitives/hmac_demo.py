"""Session 1.3: integrity and authenticity with HMAC."""

from __future__ import annotations

import hashlib
import hmac
import secrets


def authenticate(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


def verify(key: bytes, message: bytes, tag: bytes) -> bool:
    expected = authenticate(key, message)
    return hmac.compare_digest(expected, tag)


def main() -> None:
    key = secrets.token_bytes(32)
    message = b"transfer=100&to=bob"
    tag = authenticate(key, message)

    print(f"valid message: {verify(key, message, tag)}")
    print(f"tampered message: {verify(key, b'transfer=900&to=bob', tag)}")
    print("HMAC authenticates plaintext; it does not hide it.")


if __name__ == "__main__":
    main()
