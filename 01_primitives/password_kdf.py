"""Session 1.2: password hashing with a salted, costly KDF."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class PasswordRecord:
    salt: bytes
    derived_key: bytes
    n: int = 2**14
    r: int = 8
    p: int = 1


def derive(password: str, salt: bytes, *, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=32,
    )


def register(password: str) -> PasswordRecord:
    salt = secrets.token_bytes(16)
    record = PasswordRecord(salt=salt, derived_key=b"")
    key = derive(password, salt, n=record.n, r=record.r, p=record.p)
    return PasswordRecord(salt=salt, derived_key=key)


def verify(password: str, record: PasswordRecord) -> bool:
    candidate = derive(password, record.salt, n=record.n, r=record.r, p=record.p)
    return hmac.compare_digest(candidate, record.derived_key)


def main() -> None:
    first = register("correct horse battery staple")
    second = register("correct horse battery staple")

    print(f"same password, same derived key? {first.derived_key == second.derived_key}")
    print(f"correct password verifies? {verify('correct horse battery staple', first)}")
    print(f"wrong password verifies? {verify('wrong password', first)}")
    print("Store salt + parameters + derived key; never store the password.")


if __name__ == "__main__":
    main()
