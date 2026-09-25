# crypto-pg

This repository contains intentionally small experiments. Production systems
should use reviewed protocols and established high-level libraries rather than
inventing cryptographic formats.

The Korean bottom-up guide, [CRYPTOGRAPHY_BOTTOM_UP.md](CRYPTOGRAPHY_BOTTOM_UP.md),
connects these exercises to application-level encryption, KMS/Vault, public-key
cryptography, certificates, TLS, and HTTPS.

## Session 1: primitives and symmetric encryption

Run the examples from this directory:

```bash
python3 01_primitives/random_and_hash.py
python3 01_primitives/password_kdf.py
python3 01_primitives/hmac_demo.py
python3 02_symmetric/aes_gcm.py
python3 02_symmetric/nonce_reuse.py
python3 02_symmetric/gcm_walkthrough.py
python3 02_symmetric/aad_swap_demo.py
python3 03_asymmetric/x25519_exchange.py
pytest
```

### Mental model

| Primitive | Secret input | Main property | Reversible |
|---|---|---|---|
| SHA-256 | No | Fingerprint / integrity when trusted separately | No |
| scrypt | Password | Expensive password-to-key derivation | No |
| HMAC-SHA-256 | Shared key | Integrity and authenticity | No |
| AES-256-GCM | Shared key | Confidentiality, integrity, authenticity | Yes |

An unkeyed hash does not authenticate data: an attacker can replace both a
message and its hash. HMAC solves that problem when both parties share a key.
AES-GCM is an AEAD construction, so it encrypts a plaintext and authenticates
both the ciphertext and optional associated data (AAD).

### AES-GCM inputs

- `key`: secret and uniformly random; 32 bytes in this exercise.
- `nonce`: unique for every encryption under a given key; not secret. We use a
  fresh random 12-byte nonce.
- `plaintext`: encrypted and authenticated.
- `aad`: authenticated but visible, useful for protocol metadata.
- `ciphertext + tag`: output; `cryptography` appends the 16-byte tag.

The `(key, nonce)` pair must never repeat. GCM uses counter mode internally;
reusing the nonce reuses a keystream and exposes relationships between
plaintexts. It also enables authentication forgeries after further analysis.

### Exercises

1. Change one bit of the nonce and confirm that decryption raises `InvalidTag`.
2. Add `Envelope.from_json()` with strict version and field validation.
3. Put `version` in serialized AAD rather than checking it only before decrypt.
   Explain which attack this prevents in a multi-version protocol.
4. Replace the random nonce with a per-key monotonic 96-bit counter. Identify
   the persistence and concurrency requirements this introduces.
5. Benchmark SHA-256 versus scrypt and explain why the slower operation is
   desirable for password verification but undesirable for message hashing.
