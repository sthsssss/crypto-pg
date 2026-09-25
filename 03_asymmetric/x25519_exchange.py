"""Create a shared AES key without sending that key across the network."""

from __future__ import annotations

import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


PROTOCOL_CONTEXT = b"crypto-playground/x25519-session/v1"


def public_bytes(public_key: x25519.X25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def derive_aes_key(shared_secret: bytes) -> bytes:
    # The Diffie-Hellman result is key material. HKDF turns it into a key
    # scoped to this protocol and purpose.
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=PROTOCOL_CONTEXT,
    ).derive(shared_secret)


def main() -> None:
    # These private keys never leave their owners.
    alice_private = x25519.X25519PrivateKey.generate()
    bob_private = x25519.X25519PrivateKey.generate()

    # These public keys may cross an untrusted network.
    alice_public = alice_private.public_key()
    bob_public = bob_private.public_key()

    print("1. Each side creates a private/public key pair")
    print(f"   Alice public: {public_bytes(alice_public).hex()}")
    print(f"   Bob public:   {public_bytes(bob_public).hex()}")
    print("   Private keys are not transmitted or printed.")

    # Alice combines her private key with Bob's public key. Bob performs the
    # mirror operation. X25519 guarantees both results are equal.
    alice_shared = alice_private.exchange(bob_public)
    bob_shared = bob_private.exchange(alice_public)

    print("\n2. Each side computes a shared secret locally")
    print(f"   Shared secrets equal: {alice_shared == bob_shared}")
    print("   The shared secret itself was never transmitted.")

    alice_aes_key = derive_aes_key(alice_shared)
    bob_aes_key = derive_aes_key(bob_shared)

    print("\n3. Both sides derive the same AES-256 key with HKDF")
    print(f"   AES keys equal: {alice_aes_key == bob_aes_key}")

    plaintext = b"message protected after key exchange"
    aad = b"sender=alice;receiver=bob"
    nonce = secrets.token_bytes(12)

    # Alice encrypts with her derived copy; Bob decrypts with his derived copy.
    encrypted = AESGCM(alice_aes_key).encrypt(nonce, plaintext, aad)
    recovered = AESGCM(bob_aes_key).decrypt(nonce, encrypted, aad)

    print("\n4. Alice uses her AES key; Bob uses his equal AES key")
    print(f"   Nonce:      {nonce.hex()}")
    print(f"   Ciphertext: {encrypted.hex()}")
    print(f"   Bob reads:  {recovered!r}")


if __name__ == "__main__":
    main()
