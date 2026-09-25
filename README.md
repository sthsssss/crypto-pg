# crypto-pg

This repository contains intentionally small experiments. Production systems
should use reviewed protocols and established high-level libraries rather than
inventing cryptographic formats.

The Korean bottom-up guide, [CRYPTOGRAPHY_BOTTOM_UP.md](CRYPTOGRAPHY_BOTTOM_UP.md),
connects these exercises to application-level encryption, KMS/Vault, public-key
cryptography, certificates, TLS, and HTTPS.

## 나를 위한 Crypto Book

[개정 교재 읽기](CRYPTOGRAPHY_BOTTOM_UP.md)는 개발자를 위한 한국어 학습서입니다.
기술 용어를 생략하지 않고 **문제 → 정의 → 손계산 → 공격 → 코드 → 확인 문제**로
연결합니다. 읽는 순서는 바이트·해시·KDF·HMAC → AES-GCM → 저장과 키 관리 →
DH·X25519·HKDF·서명·RSA → 인증서 → TLS/HTTPS입니다.

특히 비대칭키는 작은 정수의 DH 계산부터 시작합니다. 부록에는 12개 확인 문제와
해설, 용어 찾아보기가 있습니다. [개정 검토 기록](docs/BOOK_REVIEW.md)에서 기존
설명의 공백과 수정 범위를 확인할 수 있습니다.

### Setup (Python 3.10+)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install cryptography pytest
python -m pytest
```

### 비대칭키와 TLS 실습

```bash
python3 03_asymmetric/key_roles_lab.py dh
python3 03_asymmetric/key_roles_lab.py mitm
python3 03_asymmetric/key_roles_lab.py rsa
python3 03_asymmetric/key_roles_lab.py x25519
python3 03_asymmetric/key_roles_lab.py signature
python3 04_tls/tls_memory_lab.py
```

DH/RSA의 작은 정수는 보안용이 아닌 손계산용입니다. 실제 X25519 예제에도 peer
authentication은 없습니다. TLS 예제는 Python `ssl`의 실제 TLS 1.3을 메모리
buffer로 연결하며, 정상 연결·hostname 불일치·미신뢰 CA를 비교합니다. 네트워크를
사용하거나 OS trust store를 변경하지 않으며 임시 인증서/key 파일은 정리합니다.

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
