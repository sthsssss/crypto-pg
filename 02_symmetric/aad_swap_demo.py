"""Show how AAD binds ciphertext to a database record identity."""

from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEY = bytes(range(32))  # Fixed only to make this learning demo reproducible.
ALICE_ID = b"user:alice"
BOB_ID = b"user:bob"
ALICE_SECRET = b"alice-api-token"
BOB_SECRET = b"bob-api-token"


def encrypt(aes: AESGCM, plaintext: bytes, aad: bytes | None):
    # Fixed distinct nonces are acceptable only for this deterministic demo.
    nonce = bytes([len(plaintext)]) * 12
    return nonce, aes.encrypt(nonce, plaintext, aad)


def main() -> None:
    aes = AESGCM(KEY)

    print("WITHOUT AAD")
    alice_nonce, alice_encrypted = encrypt(aes, ALICE_SECRET, None)
    bob_nonce, bob_encrypted = encrypt(aes, BOB_SECRET, None)

    # An attacker swaps Bob's encrypted DB columns into Alice's row.
    alice_result = aes.decrypt(bob_nonce, bob_encrypted, None)
    print(f"  Alice row returned: {alice_result!r}")
    print("  swap was not detected")

    print("\nWITH AAD = record identity")
    alice_nonce, alice_encrypted = encrypt(aes, ALICE_SECRET, ALICE_ID)
    bob_nonce, bob_encrypted = encrypt(aes, BOB_SECRET, BOB_ID)

    try:
        # Bob's encrypted value is now checked as if it belonged to Alice.
        aes.decrypt(bob_nonce, bob_encrypted, ALICE_ID)
    except InvalidTag:
        print("  Bob ciphertext in Alice row: InvalidTag")
        print("  swap was detected")

    original = aes.decrypt(alice_nonce, alice_encrypted, ALICE_ID)
    print(f"  Alice's original row: {original!r}")


if __name__ == "__main__":
    main()
