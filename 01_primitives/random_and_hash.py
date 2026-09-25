"""Session 1.1: cryptographic randomness and hashing."""

from __future__ import annotations

import hashlib
import secrets


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def differing_bits(left: bytes, right: bytes) -> int:
    if len(left) != len(right):
        raise ValueError("inputs must have equal length")
    return sum((a ^ b).bit_count() for a, b in zip(left, right))


def main() -> None:
    key = secrets.token_bytes(32)
    first = sha256(b"message A")
    second = sha256(b"message B")

    print(f"random 256-bit key: {key.hex()}")
    print(f"SHA-256(message A): {first.hex()}")
    print(f"SHA-256(message B): {second.hex()}")
    print(f"changed digest bits: {differing_bits(first, second)} / 256")


if __name__ == "__main__":
    main()
