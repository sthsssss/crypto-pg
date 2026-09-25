"""Expose the counter-mode encryption inside AES-GCM.

This manually reconstructs only GCM's ciphertext generation. It deliberately
leaves authentication-tag generation to AESGCM and is not production code.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Fixed values make every run reproducible and easy to inspect.
KEY = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
)
NONCE = bytes.fromhex("202122232425262728292a2b")  # 12 bytes
PLAINTEXT = b"the launch code is 1234"
AAD = b"sender=alice"
BLOCK_SIZE = 16


def aes_encrypt_one_block(key: bytes, input_block: bytes) -> bytes:
    """Compute AES(key, input_block) for one 16-byte block."""
    if len(input_block) != BLOCK_SIZE:
        raise ValueError("AES input must be exactly 16 bytes")
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(input_block) + encryptor.finalize()


def xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def chunks(data: bytes, size: int):
    for offset in range(0, len(data), size):
        yield data[offset : offset + size]


def counter_block(nonce: bytes, counter: int) -> bytes:
    """For a 96-bit GCM nonce: 12-byte nonce || 4-byte big-endian counter."""
    if len(nonce) != 12:
        raise ValueError("this walkthrough requires a 12-byte nonce")
    return nonce + counter.to_bytes(4, "big")


def build_ciphertext(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    ciphertext_parts: list[bytes] = []

    # GCM reserves nonce || 1 (J0) for tag masking. Plaintext starts at 2.
    for block_number, plaintext_block in enumerate(
        chunks(plaintext, BLOCK_SIZE), start=2
    ):
        aes_input = counter_block(nonce, block_number)
        mask = aes_encrypt_one_block(key, aes_input)
        ciphertext_block = xor(plaintext_block, mask)
        ciphertext_parts.append(ciphertext_block)

        print(f"\nblock {block_number - 1}")
        print(f"  plaintext:     {plaintext_block!r}")
        print(f"  AES input:     {aes_input.hex()}  (nonce || counter)")
        print(f"  AES(key,input):{mask.hex()}  (mask)")
        print(f"  ciphertext:    {ciphertext_block.hex()}  (plaintext XOR mask)")

    return b"".join(ciphertext_parts)


def main() -> None:
    print(f"key:       {KEY.hex()}  ({len(KEY)} bytes, secret)")
    print(f"nonce:     {NONCE.hex()}  ({len(NONCE)} bytes, public)")
    print(f"plaintext: {PLAINTEXT!r}  ({len(PLAINTEXT)} bytes)")

    manual_ciphertext = build_ciphertext(KEY, NONCE, PLAINTEXT)

    # The high-level API returns ciphertext followed by the 16-byte GCM tag.
    encrypted = AESGCM(KEY).encrypt(NONCE, PLAINTEXT, AAD)
    library_ciphertext, tag = encrypted[:-16], encrypted[-16:]

    print("\ncomparison with AESGCM")
    print(f"  manual ciphertext:  {manual_ciphertext.hex()}")
    print(f"  library ciphertext: {library_ciphertext.hex()}")
    print(f"  same ciphertext:    {manual_ciphertext == library_ciphertext}")
    print(f"  authentication tag: {tag.hex()}")

    recovered = AESGCM(KEY).decrypt(NONCE, library_ciphertext + tag, AAD)
    print(f"  decrypted:          {recovered!r}")


if __name__ == "__main__":
    main()
