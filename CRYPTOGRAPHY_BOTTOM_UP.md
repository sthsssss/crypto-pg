# 현대 애플리케이션 암호학: 바이트에서 HTTPS까지

> 대상: 애플리케이션 개발 경험은 있지만 암호학 용어가 아직 하나의 그림으로 연결되지 않은 개발자
>
> 목표: `해시 → 비밀번호 저장 → HMAC → AES-GCM → 키 관리 → 비대칭키 → 인증서 → TLS/HTTPS`를 바텀업으로 연결한다.
> 기준일: 2026-09-25

이 문서에서 가장 중요한 질문은 “어떤 알고리즘이 강한가?”가 아니다.

> **무엇을 누구에게서 보호하려고 하며, 복호화에 필요한 권한은 누가 가지고 있는가?**

암호 알고리즘은 이 질문에 답한 뒤 선택하는 부품이다. AES-GCM을 쓴다는 사실만으로 시스템이 안전해지는 것은 아니다. AES key가 DB와 같은 백업에 들어 있거나, 애플리케이션 서버가 장악되어 key와 plaintext가 모두 노출된다면 알고리즘은 정상적으로 작동하면서도 시스템은 침해된다.

---

## 1. 먼저 전체 지도를 보자

암호학 부품들은 해결하는 문제가 서로 다르다.

| 해결하려는 문제 | 대표 부품 | 핵심 질문 |
|---|---|---|
| 예측 불가능한 값 생성 | CSPRNG, `secrets` | 공격자가 다음 값을 예측할 수 있는가? |
| 데이터 지문 | SHA-256 | 같은 바이트인가? |
| 비밀번호 검증값 저장 | Argon2id, scrypt | DB가 유출되어도 후보 대입을 비싸게 만들었는가? |
| 공유키 기반 메시지 인증 | HMAC | 공유키 보유자가 만든 메시지이며 변조되지 않았는가? |
| 공유키 기반 암호화 | AES-GCM, ChaCha20-Poly1305 | 내용을 숨기고 변조도 거부하는가? |
| 키 재료에서 목적별 키 생성 | HKDF | 원시 비밀값을 특정 프로토콜의 키로 안전하게 바꿨는가? |
| 사전 공유키 없이 비밀 합의 | X25519/ECDH | 네트워크로 비밀을 보내지 않고 같은 비밀을 만들 수 있는가? |
| 공개 검증 가능한 서명 | Ed25519, ECDSA, RSA-PSS | 특정 private key 보유자가 서명했는가? |
| public key와 신원 연결 | X.509 인증서, CA | 이 public key가 정말 이 도메인의 것인가? |
| 안전한 통신 프로토콜 | TLS 1.3 | 위 부품들을 안전한 순서와 형식으로 조립했는가? |

한 줄짜리 관계도는 다음과 같다.

```text
비밀번호 ── Argon2id/scrypt ──→ DB에 verifier 저장

공유 비밀키 + 공개 메시지 ── HMAC ──→ 변조/위조 검출

공유 비밀키 + plaintext ── AES-GCM ──→ nonce + ciphertext + tag

Alice private + Bob public ┐
                           ├─ X25519 ─→ 같은 shared secret ─ HKDF ─→ AES key
Bob private + Alice public ┘

CA가 서명한 인증서 ──→ public key가 특정 도메인의 것임을 검증

키 교환 + 인증서 + 서명 + HKDF + AEAD ──→ TLS
TLS 위에 HTTP ──→ HTTPS
```

---

## 2. 데이터는 언제 위험한가

현대 애플리케이션에서는 데이터를 세 상태로 나누는 것이 유용하다.

### 2.1 전송 중인 데이터(data in transit)

```text
브라우저 ───────── 네트워크 ───────── 서버
```

네트워크 관찰자와 능동적 공격자로부터 보호해야 한다. 일반적으로 TLS가 담당한다.

### 2.2 저장된 데이터(data at rest)

```text
DB, 디스크, 객체 스토리지, 백업, 스냅샷
```

디스크 암호화, DB의 TDE, 클라우드 스토리지 암호화, 애플리케이션 레벨 필드 암호화 등이 담당한다. 각 방식이 막는 공격자는 서로 다르다.

### 2.3 사용 중인 데이터(data in use)

애플리케이션이 API token을 실제로 사용하려면 어느 순간 plaintext가 프로세스 메모리에 존재한다.

```text
ciphertext ── decrypt ──→ plaintext in RAM ──→ 외부 API 호출
```

서버에서 임의 코드를 실행할 수 있는 공격자나 프로세스 메모리를 읽을 수 있는 공격자는 이 순간의 plaintext나 key를 훔칠 수 있다. 일반적인 저장 암호화와 TLS는 이를 해결하지 못한다.

따라서 “암호화했다”는 말만으로는 부족하다. 무엇에 대한 암호화인지 말해야 한다.

```text
TLS 암호화: 네트워크 경로 보호
디스크 암호화: 디스크/스냅샷 단독 유출 보호
애플리케이션 필드 암호화: DB dump 단독 유출 보호
```

---

## 3. 바이트와 이름부터 정확히 구분하기

### 3.1 key

암호 연산의 비밀 입력이다. AES-256 key는 예측 불가능한 32바이트다.

```python
key = AESGCM.generate_key(bit_length=256)
```

사람이 만든 문자열이나 비밀번호를 그대로 AES key로 사용하면 안 된다. 비밀번호에서 key가 필요하면 Argon2id나 scrypt 같은 password KDF를 사용한다.

### 3.2 salt

비밀번호마다 새로 만드는 공개 랜덤값이다.

```text
verifier = scrypt(password, salt, cost_parameters)
```

salt는 비밀번호 대입 자체를 막지 않는다. 같은 후보에 대한 계산을 여러 사용자에게 재사용하거나 미리 계산해 두는 것을 어렵게 한다.

### 3.3 nonce

`number used once`에서 온 이름이다. AES-GCM에서는 같은 key 아래에서 암호화마다 중복되지 않아야 하는 공개값이다. 보통 12바이트를 사용한다.

```text
encrypt(key, nonce, plaintext, aad)
```

nonce는 key가 아니다. nonce가 공개되어도 된다. 하지만 같은 `(key, nonce)` 조합을 재사용하면 GCM의 기밀성과 인증이 무너질 수 있다.

### 3.4 tag

AEAD 암호가 내놓는 인증값이다. AES-GCM 구현은 흔히 다음처럼 반환한다.

```text
ciphertext || 16-byte authentication tag
```

복호화할 때 key, nonce, ciphertext, AAD 중 하나라도 맞지 않으면 tag 검증이 실패해야 한다. 검증되지 않은 plaintext를 사용해서는 안 된다.

### 3.5 AAD

`Additional Authenticated Data`다. 숨기지는 않지만 변조를 거부할 메타데이터다.

```text
plaintext: 암호화되고 인증됨
AAD:       공개 상태지만 인증됨
```

레코드 ID, tenant ID, 데이터 종류, 포맷 버전 등을 AAD에 넣으면 유효한 암호문을 다른 문맥으로 옮겨 붙이는 공격을 막을 수 있다.

### 3.6 Base64와 hex

둘 다 바이트를 문자열로 표현하는 encoding이다. 암호화가 아니다.

```text
raw bytes ── Base64 ──→ 문자열
문자열 ── Base64 decode ──→ 원래 raw bytes
```

누구나 key 없이 되돌릴 수 있다.

---

## 4. SHA-256: 비밀이 없는 데이터 지문

SHA-256은 임의 길이 입력을 32바이트 출력으로 바꾸는 공개 함수다.

```text
SHA-256(message) → 256-bit digest
```

주요 성질은 다음과 같다.

- 같은 입력은 같은 digest를 만든다.
- 입력이 조금만 바뀌어도 출력 전체가 크게 바뀐다.
- digest에서 임의의 원문을 직접 역산하는 실용적 방법은 알려져 있지 않다.
- 서로 다른 두 입력이 같은 digest를 갖는 충돌을 찾기 어렵게 설계되어 있다.

SHA-256에는 비밀 입력이 없다. 공격자도 같은 함수를 계산할 수 있다.

```text
message = "pay 10"
digest  = SHA256(message)
```

공격자는 둘을 함께 바꿀 수 있다.

```text
message = "pay 100000"
digest  = SHA256(message)
```

따라서 신뢰할 수 없는 네트워크에서 `message + SHA256(message)`만 보내는 것은 송신자 인증이 아니다.

SHA-256이 흔히 쓰이는 곳은 파일 지문, 콘텐츠 주소, 디지털 서명 전 입력 축약, HMAC/HKDF 같은 구성요소 내부 등이다.

실습: [`01_primitives/random_and_hash.py`](01_primitives/random_and_hash.py)

---

## 5. 비밀번호는 암호화하지 않고 검증한다

일반적인 로그인 서버는 비밀번호 원문을 다시 꺼낼 필요가 없다. 사용자가 입력한 후보가 맞는지만 확인하면 된다.

가입 시:

```text
salt = random()
verifier = Argon2id(password, salt, parameters)
DB 저장 = salt + parameters + verifier
```

로그인 시:

```text
candidate = Argon2id(submitted_password, stored_salt, stored_parameters)
constant_time_compare(candidate, stored_verifier)
```

DB를 훔친 공격자는 후보를 오프라인에서 대입할 수 있다.

```text
Argon2id("123456", salt) == verifier?
Argon2id("password", salt) == verifier?
...
```

서버에 요청하지 않으므로 rate limit과 계정 잠금이 적용되지 않는다. Argon2id와 scrypt는 후보 하나당 시간과 메모리를 많이 사용하게 해서 이 공격을 비싸게 한다. [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)은 Argon2를 memory-hard password hashing/KDF로 설명한다.

비밀번호와 복구해야 하는 API token은 요구사항이 다르다.

```text
로그인 비밀번호:
원문 복구 불필요 → Argon2id/scrypt verifier

외부 서비스 API token:
나중에 원문 사용 필요 → AES-GCM 등으로 암호화
```

실습: [`01_primitives/password_kdf.py`](01_primitives/password_kdf.py)

---

## 6. HMAC: 공유키를 가진 쪽만 만들 수 있는 인증값

HMAC은 해시 기반 Message Authentication Code다.

```text
tag = HMAC(shared_secret_key, message)
```

Alice와 Bob이 같은 key를 이미 공유한다면 Bob은 tag를 다시 계산할 수 있다.

```text
Alice:
message + HMAC(K, message) 전송

Bob:
received_tag == HMAC(K, received_message)
```

공격자는 message를 볼 수 있지만 K를 모르므로 변조된 message에 맞는 새 tag를 만들 수 없다. HMAC은 내용을 숨기지 않는다.

[RFC 2104](https://www.rfc-editor.org/rfc/rfc2104.html)는 MAC을 비밀키를 공유하는 두 당사자가 전송 정보를 검증하는 메커니즘으로 설명한다.

실습: [`01_primitives/hmac_demo.py`](01_primitives/hmac_demo.py)

---

## 7. AES-GCM: 공유키로 숨기고 변조도 거부한다

AES는 128비트 블록을 변환하는 block cipher다. AES-128/192/256의 숫자는 key 길이를 의미하고, 세 종류 모두 128비트 블록을 처리한다. 이는 [NIST FIPS 197](https://csrc.nist.gov/pubs/fips/197/final)에 정의되어 있다.

AES만으로는 임의 길이 메시지, nonce, 인증 tag 같은 프로토콜이 생기지 않는다. GCM은 AES를 사용하는 AEAD 모드다. [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final)는 GCM을 associated data를 지원하는 authenticated encryption 알고리즘으로 정의한다.

### 7.1 암호화 부분

96비트 nonce를 사용할 때 GCM은 nonce와 증가하는 counter로 16바이트 AES 입력을 만든다.

```text
nonce || counter 2 ── AES(K) ──→ mask 1
nonce || counter 3 ── AES(K) ──→ mask 2
```

각 mask를 plaintext block과 XOR한다.

```text
C1 = P1 XOR mask1
C2 = P2 XOR mask2
```

수신자는 같은 K와 nonce로 같은 mask를 재생성한다.

```text
P1 = C1 XOR mask1
```

### 7.2 인증 부분

GCM은 ciphertext와 AAD를 인증하는 tag를 만든다.

```text
encrypt(K, nonce, plaintext, AAD)
    → ciphertext + tag
```

decrypt는 tag가 맞을 때만 plaintext를 반환해야 한다.

### 7.3 저장 포맷

애플리케이션이 직접 포맷을 만든다면 최소한 다음 정보가 필요하다.

```text
algorithm/version
key identifier or key version
nonce
ciphertext + tag
AAD를 재구성할 수 있는 메타데이터
```

key 자체는 이 레코드에 넣지 않는다.

실습:

- [`02_symmetric/gcm_walkthrough.py`](02_symmetric/gcm_walkthrough.py): counter와 mask를 직접 관찰
- [`02_symmetric/aes_gcm.py`](02_symmetric/aes_gcm.py): 고수준 API
- [`02_symmetric/nonce_reuse.py`](02_symmetric/nonce_reuse.py): nonce 재사용 실패
- [`02_symmetric/aad_swap_demo.py`](02_symmetric/aad_swap_demo.py): 레코드 바꿔치기와 AAD

---

## 8. 현대 애플리케이션은 암호화된 값을 어디에 저장하는가

“보통 Vault나 Secret Manager를 쓰나?”의 답은 다음과 같다.

> 조직과 위협 모델에 따라 다르지만, 운영 환경에서는 key를 소스 코드나 업무 DB에 직접 두는 대신 관리형 KMS/Secret Manager 또는 Vault 같은 중앙 시스템으로 수명주기와 접근 권한을 관리하는 구성이 흔하다. 그러나 이 제품들은 서로 같은 역할이 아니다.

먼저 보호 대상의 종류를 나눠야 한다.

| 보호 대상 | 일반적인 저장 방식 |
|---|---|
| 사용자 로그인 비밀번호 | 업무 DB에 Argon2id/scrypt verifier |
| 애플리케이션의 DB 접속 비밀번호 | Secret Manager/Vault, 가능하면 동적·단기 credential |
| 애플리케이션 자체 API key | Secret Manager/Vault |
| TLS 서버 private key | 인증서 관리 서비스, Secret Manager, KMS/HSM 또는 제한된 파일 |
| 사용자가 맡긴 외부 API token | 업무 DB에 application-level ciphertext; key는 KMS/Vault 등에서 관리 |
| 대용량 파일 | 데이터는 객체 저장소에 암호화; data key는 KMS로 wrapping |
| 디스크·볼륨 전체 | 클라우드/OS/DB가 제공하는 at-rest encryption |

### 8.1 가장 단순한 애플리케이션 레벨 암호화

작은 시스템에서는 하나의 application data key를 Secret Manager에 보관하고 애플리케이션이 시작할 때 가져올 수 있다.

```text
                 workload identity
Application ─────────────────────────→ Secret Manager
     │                                      │
     │            AES key K                 │
     │ ←────────────────────────────────────┘
     │
     │ AES-GCM(K, plaintext)
     ▼
Database: nonce + ciphertext/tag + key_version
```

쓰기:

```text
1. 애플리케이션이 런타임 identity로 Secret Manager 인증
2. AES key K 조회 또는 캐시
3. 레코드마다 새 nonce 생성
4. AES-GCM으로 필드 암호화
5. DB에 nonce, ciphertext/tag, key_version 저장
```

읽기:

```text
1. DB에서 nonce, ciphertext/tag, key_version 조회
2. 버전에 맞는 K 획득
3. AAD를 동일하게 재구성
4. tag 검증과 복호화
5. 필요한 시간 동안만 plaintext 사용
```

장점:

- 구현과 이해가 비교적 단순하다.
- DB dump만 유출된 사고에서 plaintext를 보호한다.
- DB 운영자와 암호키 운영 권한을 분리할 수 있다.

한계:

- 하나의 key가 많은 레코드를 보호하면 key 침해의 blast radius가 크다.
- 애플리케이션 프로세스에는 plaintext key가 존재한다.
- key rotation 때 기존 데이터 재암호화 전략이 필요하다.
- 애플리케이션이 침해되면 정상 권한으로 복호화 API를 호출하거나 메모리의 key를 훔칠 수 있다.

우리 SQLite 실습은 이 구조의 로컬 축소판이다.

```text
환경변수 APP_DATA_KEY_B64 ≈ Secret Manager가 전달한 key
SQLite                    ≈ 업무 DB
```

실습: [`02_symmetric/db_encryption_demo.py`](02_symmetric/db_encryption_demo.py)

### 8.2 Secret Manager란 무엇인가

Secret Manager는 애플리케이션이 사용하는 작은 비밀값을 수명주기와 권한 정책 아래 보관하는 서비스다.

```text
DB password
OAuth client secret
API token
애플리케이션 AES key
서명 private key(환경과 정책에 따라)
```

애플리케이션 소스 코드에 credential을 하드코딩하지 않고 런타임에 권한을 가진 workload가 조회한다. 예를 들어 [AWS Secrets Manager 공식 문서](https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html)는 DB credential, application credential, OAuth token, API key 등의 조회와 rotation을 제공하며, 암호화 key 자체에는 KMS 사용을 권한다.

Secret Manager를 쓴다고 애플리케이션이 secret을 절대 보지 않는 것은 아니다. 조회 후에는 애플리케이션 메모리에 secret이 존재한다.

### 8.3 KMS란 무엇인가

KMS는 Key Management Service다. 일반 secret 문자열보다 **cryptographic key의 생성, 접근 정책, 버전, rotation, 암호 연산, 감사**에 특화되어 있다.

일반적인 KMS root/master key는 plaintext로 애플리케이션에 export되지 않는다. 애플리케이션은 key ID를 지정해 KMS에 encrypt/decrypt 또는 data-key 작업을 요청한다. 구현 세부는 서비스마다 다르다. AWS KMS는 KMS key의 HSM backing key가 plaintext로 HSM 밖에 export되지 않도록 설계되어 있다고 설명한다. [AWS KMS key hierarchy](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html)

```text
Application:
"key ID abc로 이 작은 key를 unwrap해 줘"

KMS/HSM:
정책 확인 → 내부 key 사용 → 결과 반환 → 감사 로그
```

KMS를 사용하는 주된 이유는 단순한 파일 보관 이상의 운영 제어다.

- 애플리케이션별 최소 권한
- key disable/delete/rotation
- key 사용 감사 로그
- HSM 기반 root key 보호
- plaintext root key의 export 방지
- 중앙 정책과 사고 대응

### 8.4 Envelope encryption: 현대적인 대규모 저장 패턴

KMS로 모든 대용량 데이터를 직접 암호화하면 API 호출 지연, 비용, 입력 크기 제한, 가용성 결합이 생길 수 있다. 대신 두 계층의 key를 사용한다.

```text
DEK: Data Encryption Key
     실제 데이터를 AES-GCM으로 암호화하는 일회성/범위 제한 key

KEK: Key Encryption Key
     DEK를 암호화(wrap)하는 상위 key
     KMS/HSM 안에서 중앙 관리
```

암호화 흐름:

```text
                    KMS/HSM
                      │
                      │ KEK는 밖으로 나오지 않음
                      │
새 random DEK ── wrap with KEK ──→ wrapped DEK
      │
      │ AES-GCM
      ▼
plaintext ──→ ciphertext + nonce + tag

DB/Object Storage에 함께 저장:
  ciphertext
  nonce
  wrapped DEK
  KEK/key ID와 version
  algorithm/version
  AAD context
```

복호화 흐름:

```text
DB에서 wrapped DEK + ciphertext 조회
              │
              ▼
KMS에 wrapped DEK 전달 ──→ plaintext DEK를 일시적으로 획득
              │
              ▼
AES-GCM으로 ciphertext 복호화
              │
              ▼
plaintext DEK 메모리에서 제거 가능한 범위에서 신속히 폐기
```

DEK가 암호화된 `wrapped DEK` 형태라면 ciphertext 근처에 저장해도 된다. 공격자는 wrapped DEK를 얻어도 KMS의 KEK 사용 권한이 없으면 unwrap할 수 없다.

[Google Cloud KMS의 envelope encryption 문서](https://cloud.google.com/kms/docs/envelope-encryption)는 데이터를 DEK로 로컬 암호화하고, DEK를 KEK로 wrap한 뒤 encrypted data와 wrapped DEK를 저장하는 구조를 설명한다. KEK는 Cloud KMS를 떠나지 않는다.

이 패턴의 중요한 장점은 key rotation이다. KEK를 바꿀 때 거대한 데이터를 전부 다시 암호화하지 않고 wrapped DEK만 rewrap하는 전략을 사용할 수 있다. 정확한 가능 여부와 절차는 KMS와 데이터 포맷에 따라 설계해야 한다.

### 8.5 Vault란 무엇인가

HashiCorp Vault는 중앙 secret 관리, 동적 credential, PKI, 암호 연산 등을 제공하는 시스템이다. 직접 운영하거나 관리형 형태로 사용할 수 있다.

Vault에는 서로 다른 기능이 있다.

```text
KV secrets engine:
비밀 문자열을 보관하고 조회

Database secrets engine:
DB credential을 동적으로 발급하고 만료

PKI secrets engine:
인증서 발급과 수명주기 관리

Transit secrets engine:
애플리케이션 대신 encrypt/decrypt/sign/HMAC 수행
```

[Vault Transit 공식 문서](https://developer.hashicorp.com/vault/docs/secrets/transit)는 Transit을 “cryptography/encryption as a service”로 설명하며, 애플리케이션 데이터 자체는 Vault에 저장하지 않고 암호 연산 결과를 돌려준다.

```text
Application ── plaintext + key name ──→ Vault Transit
Application ←──── ciphertext ────────── Vault Transit
Application ───── ciphertext ─────────→ 업무 DB
```

복호화 시에는 반대로 ciphertext를 Vault Transit에 보낸다. 애플리케이션이 raw encryption key를 직접 보지 않는 장점이 있지만, Vault 호출의 지연·가용성·권한·처리량을 설계해야 한다.

Vault가 언제나 클라우드 KMS보다 낫거나 반대인 것은 아니다.

```text
관리형 클라우드 KMS/Secret Manager:
운영 부담이 작고 클라우드 IAM/HSM/감사와 통합이 쉬움

Vault:
멀티클라우드/온프레미스, 동적 secret, 일관된 정책 계층에 유용
대신 Vault 자체의 고가용성, unseal, backup, upgrade, 감사 운영 필요
```

### 8.6 Kubernetes Secret은 암호키 금고와 동의어가 아니다

Kubernetes Secret은 secret을 Pod에 파일이나 환경변수로 전달하는 객체다. 그 자체를 KMS/HSM과 동일하게 보면 안 된다.

[Kubernetes 공식 문서](https://kubernetes.io/docs/concepts/configuration/secret/)는 Secret이 기본적으로 API server의 backing store인 etcd에 암호화되지 않은 상태로 저장될 수 있음을 경고하며, encryption at rest, 최소 권한 RBAC, 특정 container로의 접근 제한, 외부 secret store 검토를 권한다.

또한 YAML의 Base64는 기밀성을 제공하지 않는다.

```yaml
data:
  API_KEY: c2VjcmV0
```

이는 누구나 `secret`으로 decode할 수 있다.

### 8.7 스토리지 암호화와 애플리케이션 암호화는 다른 층이다

클라우드 DB나 디스크가 이미 at-rest encryption을 제공해도 애플리케이션 필드 암호화가 추가로 필요할 수 있다.

```text
스토리지/TDE 암호화가 주로 보호:
물리 디스크, 볼륨 snapshot, 스토리지 계층 backup

애플리케이션 필드 암호화가 추가로 보호 가능:
SQL dump, DB 운영 계정, 잘못 노출된 replica/backup, 일부 내부자 경계
```

반대로 애플리케이션 필드 암호화는 쿼리와 인덱싱을 어렵게 하고, key 관리 및 rotation 복잡성을 만든다. 모든 컬럼을 무조건 애플리케이션에서 암호화하는 것이 정답은 아니다.

### 8.8 “일반적인” 운영 아키텍처 예시

규모가 있는 클라우드 애플리케이션의 한 예시는 다음과 같다.

```text
                         ┌─────────────────────┐
                         │ KMS / HSM           │
                         │ KEK + policy + audit│
                         └──────────┬──────────┘
                                    │ unwrap DEK
                                    │ authorized workload only
┌──────────┐   HTTPS   ┌────────────▼──────────┐
│ Browser  │──────────→│ Load Balancer / API   │
└──────────┘           └────────────┬──────────┘
                                    │ TLS or mTLS
                         ┌──────────▼───────────┐
                         │ Application Service │
                         │ plaintext in memory │
                         └───────┬──────────────┘
                                 │ nonce + ciphertext/tag
                                 │ wrapped DEK + metadata
                       ┌─────────▼──────────┐
                       │ Database / Object │
                       │ Storage           │
                       └────────────────────┘
```

그리고 DB password나 외부 SaaS credential처럼 “애플리케이션 자체가 사용하는 secret”은 별도 Secret Manager에서 런타임에 공급할 수 있다.

```text
Secret Manager: 애플리케이션이 사용할 secret 값 보관
KMS: 암호키와 암호 연산/수명주기 관리
업무 DB: 사용자 데이터의 ciphertext 보관
```

---

## 9. Key 관리에서 실제로 어려운 부분

암호화 함수 호출보다 key lifecycle이 더 어렵다.

### 9.1 생성

- CSPRNG로 충분한 길이의 key를 생성한다.
- 사람이 외울 수 있는 비밀번호를 직접 key로 쓰지 않는다.
- 용도별 key를 분리한다. 암호화 key와 서명 key를 같은 raw key로 재사용하지 않는다.

### 9.2 식별과 버전

각 ciphertext가 어느 key와 알고리즘으로 만들어졌는지 알아야 한다.

```json
{
  "format_version": 1,
  "algorithm": "AES-256-GCM",
  "key_id": "customer-data-key",
  "key_version": 3,
  "nonce": "...",
  "ciphertext_and_tag": "..."
}
```

`key_id`는 key 자체가 아니라 이름이다.

### 9.3 전달과 bootstrap identity

“Secret Manager에서 key를 읽는다”는 말은 애플리케이션이 Secret Manager에 자신을 증명해야 한다는 뜻이다.

좋은 환경에서는 장기 access key를 코드에 넣는 대신 workload identity를 사용한다.

```text
VM/service account identity
Kubernetes workload identity
cloud instance identity
short-lived token
```

이를 bootstrap problem이라고 볼 수 있다. 첫 번째 신뢰 자격을 어디서 얻는가의 문제다.

### 9.4 메모리와 캐시

매 레코드마다 KMS를 호출하면 지연과 비용이 커질 수 있다. 반대로 key를 오래 캐시하면 침해 시 노출 창이 커진다. 다음을 명시적으로 결정해야 한다.

- 캐시 단위와 TTL
- 프로세스 재시작 시 동작
- KMS 장애 시 fail-open인가 fail-closed인가
- plaintext DEK의 메모리 체류 시간
- core dump와 debug endpoint 정책

GC 언어에서는 “메모리에서 즉시 완전 삭제”를 보장하기 어렵다. 비밀값의 scope와 수명을 줄이는 것이 현실적인 방어다.

### 9.5 rotation

rotation은 새 key로 새 데이터를 암호화하는 것과 기존 데이터를 처리하는 것을 모두 포함한다.

```text
새 write: key version 4 사용
기존 read: version 1~3도 복호화 가능
background migration: 오래된 ciphertext를 version 4로 재암호화
```

Envelope encryption에서는 KEK rotation과 DEK rotation을 구분해야 한다.

### 9.6 삭제와 복구

key를 잃으면 정상 사용자도 ciphertext를 복호화할 수 없다. key 삭제는 사실상 cryptographic erasure가 될 수 있다. 따라서 다음이 필요하다.

- 삭제 대기 기간
- backup과 disaster recovery
- 지역 장애 전략
- 관리자 권한 분리
- 실수로 disable/delete했을 때 runbook

### 9.7 감사

최소한 다음 이벤트를 관찰해야 한다.

- 누가 어떤 key를 사용했는가
- encrypt/decrypt/unwrap 횟수와 비정상 급증
- 정책 변경
- key disable/delete/rotation
- 실패한 접근

그러나 감사 로그에 plaintext, key, token을 남기면 안 된다.

---

## 10. 비대칭키: “public으로 암호화, private으로 복호화”보다 넓은 개념

비대칭키에서는 서로 수학적으로 연결된 두 key가 있다.

```text
private key: 소유자만 보관
public key:  누구에게나 공개 가능
```

하지만 모든 비대칭 알고리즘이 같은 일을 하는 것은 아니다.

| 목적 | private key로 하는 일 | public key로 하는 일 | 예시 |
|---|---|---|---|
| Key agreement | 상대 public과 shared secret 계산 | 상대에게 전달 | X25519 |
| Digital signature | 메시지에 서명 | 서명 검증 | Ed25519, ECDSA, RSA-PSS |
| Public-key encryption | 해당 없음/복호화 | 짧은 데이터 또는 key 암호화 | RSA-OAEP, KEM 계열 |

`public key로 암호화하고 private key로 복호화한다`는 설명은 RSA 암호화 같은 일부 구성에는 맞지만, X25519 키 교환이나 Ed25519 서명을 설명하지 못한다.

### 10.1 Public key는 private key에서 파생된다

개념적으로:

```text
private a ── one-way public operation ──→ public A
```

public A에서 private a를 되찾기 어려운 수학 구조를 사용한다.

### 10.2 X25519: key를 보내지 않고 같은 비밀을 계산한다

Alice와 Bob이 각자 key pair를 만든다.

```text
Alice: private a, public A
Bob:   private b, public B
```

public key만 교환한다.

```text
Alice ── A ──→ Bob
Alice ←── B ── Bob
```

그다음 각자 계산한다.

```text
Alice: X25519(a, B) → S
Bob:   X25519(b, A) → S
```

두 결과는 같다. shared secret S 자체는 네트워크로 전송하지 않는다. [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html)은 X25519를 32바이트 입력과 출력을 사용하는 scalar multiplication 함수로 정의하고 Diffie-Hellman key agreement에서의 사용을 기술한다.

S를 AES key로 바로 쓰지 않고 HKDF에 넣는다.

```text
S ── HKDF(protocol context, transcript, labels) ──→ AES key, IV, 기타 키
```

HKDF는 원시 key material에서 목적과 문맥이 분리된 key들을 만든다. [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html)

실습: [`03_asymmetric/x25519_exchange.py`](03_asymmetric/x25519_exchange.py)

### 10.3 X25519만으로는 상대의 신원을 모른다

Mallory가 네트워크를 완전히 제어하면 Alice와 Bob의 public key를 바꿔치기할 수 있다.

```text
Alice              Mallory               Bob

 A ───────────────→ 가로챔
                    M1 ─────────────────→ Bob

 Bob의 B ←───────── 가로챔
 Alice ←─────────── M2
```

결과적으로:

```text
Alice ↔ Mallory 사이 shared secret
Mallory ↔ Bob 사이 shared secret
```

Mallory는 Alice의 메시지를 복호화한 뒤 Bob 쪽 key로 다시 암호화할 수 있다. 양쪽은 암호화가 되고 있다는 사실만 볼 뿐 상대가 누구인지 모른다.

따라서 key agreement에는 **authentication**이 필요하다.

### 10.4 전자서명

서명 key pair는 다음처럼 작동한다.

```text
signature = Sign(private_signing_key, message)

Verify(public_verification_key, message, signature)
    → valid 또는 invalid
```

서명은 메시지를 숨기지 않는다. public key를 아는 누구나 검증할 수 있지만 private key가 없으면 새 유효한 서명을 만들 수 없다. Ed25519/EdDSA는 [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html)에 설명되어 있다.

HMAC과 서명의 차이:

```text
HMAC:
같은 secret key를 가진 모든 검증자가 tag도 생성 가능

전자서명:
private key 보유자만 서명
public key 보유자는 검증만 가능
```

### 10.5 Public key만 받았다고 신뢰할 수는 없다

공격자도 자신의 key pair를 만들 수 있다.

```text
Mallory private/public 생성
Mallory가 "이게 example.com의 public key다"라고 주장
```

수학적으로 유효한 public key라는 것과 특정 신원에 속한다는 것은 별개다. 이 간극을 인증서가 메운다.

---

## 11. 인증서: 도메인과 public key를 연결하는 서명된 문서

X.509 인증서는 대략 다음 내용을 가진다.

```text
subject/domain names: example.com, www.example.com
subject public key:   서버의 public key
issuer:               발급한 CA
validity:             not before / not after
key usage:            어떤 목적으로 사용할 수 있는가
serial number
CA signature
```

[RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html)은 인증서를 public key 값을 subject에 바인딩하는 데이터 구조로 설명하며, trusted CA가 인증서에 디지털 서명함으로써 그 바인딩을 주장한다고 설명한다.

브라우저/OS에는 신뢰하는 root CA public key 목록이 미리 들어 있다.

```text
Root CA (브라우저가 미리 신뢰)
   │ signs
   ▼
Intermediate CA certificate
   │ signs
   ▼
example.com certificate
```

브라우저는 일반적으로 다음을 확인한다.

- 인증서 서명 chain이 신뢰 root까지 연결되는가
- 현재 시간이 유효기간 안인가
- 접속한 hostname이 인증서의 이름과 일치하는가
- key usage와 기타 제약이 맞는가
- 구현과 정책에 따라 revocation 정보를 어떻게 처리할 것인가

인증서 자체는 공개 정보다. 비밀은 서버의 certificate private key다.

```text
서버:
certificate 공개 가능
certificate private key 비밀

브라우저:
certificate와 CA chain으로 서버 public key를 신뢰
```

---

## 12. 이제 TLS를 바텀업으로 조립한다

TLS 1.3은 크게 두 프로토콜로 생각할 수 있다.

```text
Handshake protocol:
알고리즘 협상 + shared key material 확립 + 상대 인증

Record protocol:
확립된 대칭키로 실제 애플리케이션 데이터를 보호
```

[TLS 1.3 표준 RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html)은 handshake가 버전과 알고리즘을 협상하고, 선택적으로 상대를 인증하며, shared secret keying material을 확립한 다음 그 key로 application-layer traffic을 보호한다고 설명한다.

### 12.1 HTTPS 이전의 문제

평문 HTTP라면:

```text
Browser ── GET /account ──→ Server
Browser ←─ balance=100 ─── Server
```

네트워크 공격자는 다음을 할 수 있다.

- 요청과 응답 읽기
- 내용을 변경하기
- 가짜 서버인 척 응답하기

필요한 성질은 세 가지다.

```text
기밀성: 내용을 읽지 못하게 한다.
무결성: 내용을 몰래 바꾸지 못하게 한다.
인증: 연결한 상대가 기대한 서버인지 확인한다.
```

### 12.2 TLS 1.3의 단순화한 full handshake

정상적인 서버 인증 handshake를 개념 수준으로 펼치면 다음과 같다.

```text
Browser                                              Server

ClientHello
- 지원 TLS 버전
- 지원 cipher suites
- ephemeral public key A
                         ───────────────────────────→

                                                    ServerHello
                                                    - 선택한 설정
                                                    - ephemeral public key B
                         ←───────────────────────────

Browser: X25519(a, B) → shared secret S
Server:  X25519(b, A) → shared secret S

양쪽: S + handshake transcript를 HKDF에 넣어
      handshake traffic keys 파생

                                                    EncryptedExtensions
                                                    Certificate
                                                    CertificateVerify
                                                    Finished
                         ←════════ encrypted ════════

Browser:
- CA chain/hostname/기간 검증
- certificate public key로 CertificateVerify 서명 검증
- Finished로 handshake transcript와 key 일치 확인

Finished
                         ════════ encrypted ═══════→

양쪽: application traffic keys 파생

HTTP request/response
                         ←════ AEAD encrypted ════→
```

실제 표준에는 더 많은 필드, transcript 처리, resumption, PSK, alerts 등이 있다. 하지만 배운 부품과 연결하는 데 필요한 뼈대는 위와 같다.

### 12.3 ClientHello와 ServerHello: X25519 실습과 연결

브라우저와 서버는 handshake마다 일회성(ephemeral) key pair를 만들 수 있다.

```text
Browser ephemeral private a / public A
Server  ephemeral private b / public B
```

public key share를 교환하고 shared secret을 계산한다.

```text
Browser: X25519(a, B)
Server:  X25519(b, A)
```

이것이 [`x25519_exchange.py`](03_asymmetric/x25519_exchange.py)에서 본 부분이다.

### 12.4 인증서와 CertificateVerify: 중간자 공격을 막는다

키 교환만으로는 Mallory가 public key share를 바꿀 수 있다. 서버는 handshake transcript에 certificate private key로 서명한다. 브라우저는 인증서 안의 검증 public key로 서명을 확인한다.

```text
서버가 증명:
"이 handshake와 ephemeral key share에 참여한 나는
 example.com 인증서 private key를 실제로 가지고 있다."
```

Mallory는 example.com의 certificate private key가 없으므로 자신이 끼워 넣은 key share에 유효한 서명을 만들 수 없다.

여기서 두 종류의 비대칭 key를 구분해야 한다.

```text
서버 certificate signing key:
- 비교적 장기
- 서버 신원 증명
- Secret Manager/KMS/HSM/제한된 파일 등에서 보호

ephemeral X25519 key:
- 연결마다 새로 생성 가능
- shared secret 계산
- 보통 연결 종료 후 폐기
```

TLS 1.3에서 서버 인증서 public key가 HTTP body를 직접 암호화하는 것이 아니다. 인증서 key는 handshake에 서명하고, 실제 데이터는 key agreement와 HKDF로 만든 대칭 traffic key가 보호한다.

### 12.5 HKDF: 하나의 shared secret에서 여러 key를 만든다

TLS는 shared secret 하나를 모든 곳에 그대로 쓰지 않는다. handshake transcript와 label을 포함해 서로 다른 secret/key를 파생한다.

```text
(EC)DHE shared secret
        │
       HKDF
        ├── client handshake traffic secret
        ├── server handshake traffic secret
        ├── client application traffic secret
        ├── server application traffic secret
        └── 각 방향의 key와 IV
```

따라서 client→server와 server→client는 서로 다른 traffic key를 사용한다.

### 12.6 Record protocol: 우리가 배운 AES-GCM과 연결

handshake가 끝나면 HTTP bytes를 TLS record로 나누고 AEAD로 보호한다.

```text
HTTP bytes
   ↓ TLS record framing
TLS plaintext
   ↓ AES-GCM 또는 ChaCha20-Poly1305
TLS ciphertext + authentication tag
   ↓ TCP
network
```

TLS 1.3은 record마다 sequence number와 연결별 IV를 이용해 nonce를 구성한다. 애플리케이션 개발자가 매 HTTP 요청의 GCM nonce를 직접 관리하지 않는다. TLS 구현이 프로토콜 규칙에 따라 처리한다.

tag 검증이 실패하면 record를 정상 데이터로 받아들이지 않는다. 이는 SQLite 실습에서 잘못된 key나 변경된 ciphertext가 `InvalidTag`를 만든 것과 같은 종류의 성질이다.

### 12.7 Forward secrecy

ephemeral Diffie-Hellman private key를 연결 후 폐기하면, 미래에 서버의 certificate private key가 유출되더라도 과거에 녹화한 TLS 트래픽의 shared secret을 바로 복구할 수 없도록 설계할 수 있다. 이것이 forward secrecy의 핵심이다.

certificate private key는 당시 서버 신원을 증명하는 데 쓰였고, 과거 traffic key 자체는 ephemeral key agreement에서 나왔기 때문이다.

### 12.8 HTTPS란 결국 무엇인가

```text
HTTPS = HTTP over TLS
```

새로운 HTTP 암호 알고리즘이 따로 있는 것이 아니다.

```text
HTTP:
GET /users/1
Authorization: Bearer ...
JSON body

TLS:
위 HTTP 바이트를 안전한 record로 운반

TCP/QUIC 등 transport:
TLS record 또는 TLS가 통합된 데이터를 네트워크로 전달
```

브라우저 주소창의 자물쇠는 대략 다음을 의미한다.

- 브라우저와 TLS 종단 사이의 트래픽이 보호된다.
- 인증서 검증을 통해 접속한 hostname과 서버 public key의 연결을 확인했다.

다음까지 보장하지는 않는다.

- 서버 애플리케이션 자체가 선량하다.
- 서버가 받은 데이터를 안전하게 저장한다.
- TLS 종단 뒤 내부 네트워크가 자동으로 안전하다.
- 사용자의 기기가 악성코드에 감염되지 않았다.

---

## 13. 실제 웹 아키텍처에서는 TLS가 어디서 끝나는가

현대 서비스에서는 애플리케이션 프로세스가 직접 인터넷 TLS를 종료하지 않을 수 있다.

```text
Browser
   │ HTTPS
   ▼
CDN / WAF / Load Balancer / Ingress
   │ 내부 TLS 또는 mTLS
   ▼
Application Service
   │ TLS
   ▼
Database / other service
```

### 13.1 TLS termination

브라우저의 TLS 연결이 load balancer에서 종료되면 load balancer는 HTTP plaintext를 볼 수 있다. 이는 기능상 필요할 수 있다.

```text
Browser ↔ [TLS] ↔ Load Balancer ↔ [별도 연결] ↔ App
```

따라서 “HTTPS를 쓴다”는 말만으로 load balancer 이후 구간까지 자동 보호되는 것은 아니다. 내부 구간도 TLS로 다시 연결하거나, 서비스 간 mTLS를 적용하거나, 신뢰 경계와 네트워크 정책으로 보호해야 한다.

### 13.2 mTLS

일반 웹 TLS는 서버가 인증서로 자신을 증명하고, 사용자는 그 후 HTTP 레벨의 password/session/OAuth 등으로 인증하는 경우가 많다.

mTLS에서는 client도 인증서를 제시해 TLS 단계에서 상호 인증한다.

```text
일반 HTTPS:
browser verifies server certificate

mTLS:
client verifies server certificate
server verifies client certificate
```

서비스 간 통신, 관리 plane, 고보안 B2B 연동에서 사용할 수 있지만 인증서 발급·rotation·revocation 운영이 필요하다.

---

## 14. 저장 암호화와 HTTPS를 하나의 요청으로 연결하기

사용자가 웹 UI에서 외부 API token을 등록하는 과정을 보자.

```text
1. Browser
   사용자가 token 입력

2. HTTPS/TLS
   브라우저와 TLS endpoint 사이에서 token 전송 보호

3. Application
   요청을 처리하는 순간 token plaintext가 메모리에 존재

4. Application-level encryption
   DEK 또는 application key로 AES-GCM 암호화

5. Database
   nonce + ciphertext/tag + wrapped DEK/key version 저장

6. Later use
   KMS/Vault 권한으로 key 획득 또는 unwrap
   DB ciphertext 복호화
   token을 외부 API 호출에 잠시 사용
```

각 층의 역할은 다르다.

```text
TLS:
브라우저에서 서버까지 이동 중인 token 보호

DB/storage encryption:
디스크와 snapshot 보호

Application field encryption:
DB에 저장된 token을 DB 단독 유출에서 보호

KMS/Vault/Secret Manager:
복호화 권한과 key lifecycle 관리
```

어느 하나가 다른 것을 완전히 대체하지 않는다.

---

## 15. 위협별로 무엇이 보호되는가

| 공격/사고 | TLS | 스토리지 암호화 | 앱 필드 암호화 + 외부 KMS | 비고 |
|---|---:|---:|---:|---|
| 네트워크 패킷 도청 | 보호 | 무관 | 무관 | TLS 종단 사이 |
| 네트워크 내용 변조 | 보호 | 무관 | 무관 | TLS tag/handshake 검증 |
| 물리 디스크/스냅샷 단독 유출 | 일부 무관 | 보호 | 보호 가능 | key 분리가 전제 |
| SQL dump 유출 | 무관 | 대개 부족 | 보호 가능 | ciphertext만 유출된 경우 |
| DB 관리자 계정 오용 | 무관 | 대개 부족 | 보호 가능 | 앱이 별도 key 권한 보유 시 |
| 애플리케이션 RCE | 부족 | 부족 | 대개 부족 | 앱의 정상 복호화 권한 악용 가능 |
| KMS 권한만 유출 | 무관 | 무관 | 데이터 없으면 제한적 | DB와 결합 시 위험 |
| DB와 KMS 권한 동시 유출 | 무관 | 부족 | 복호화 가능 | 권한 분리와 탐지가 중요 |
| 사용자 단말 악성코드 | 부족 | 무관 | 무관 | plaintext 입력 시점 노출 가능 |

이 표가 보여 주는 핵심은 “암호화”가 하나의 전역 스위치가 아니라는 점이다.

---

## 16. 무엇을 선택할지 빠르게 결정하는 법

### 사용자 비밀번호를 저장한다

```text
Argon2id 또는 scrypt
unique salt
비용 파라미터와 버전 저장
원문/복호화 key 없음
```

### Webhook 요청이 공급자에게서 왔는지 검증한다

공급자와 shared secret을 미리 공유할 수 있다면:

```text
HMAC(secret, timestamp || canonical_request)
timestamp/replay 정책
constant-time tag comparison
```

프로토콜 제공자가 정한 공식 검증 절차를 따른다.

### DB에 외부 API token을 저장하고 나중에 사용한다

```text
AES-GCM application-level encryption
key는 Secret Manager/KMS/Vault 경계에 둠
nonce + ciphertext/tag + key version 저장
tenant/record context를 AAD로 고려
```

규모와 위험도가 커지면 envelope encryption을 고려한다.

### 브라우저와 API 서버가 통신한다

```text
직접 암호 프로토콜을 설계하지 말고 TLS/HTTPS 사용
인증서 검증을 끄지 않음
현대 TLS 라이브러리와 안전한 기본값 사용
```

### 파일을 다른 사람의 public key로 보호한다

대용량 데이터를 public-key 알고리즘으로 직접 암호화하지 않는다.

```text
random DEK 생성
파일을 AEAD로 암호화
수신자의 public-key 메커니즘으로 DEK를 보호
encrypted file + protected DEK 저장/전송
```

이것도 hybrid/envelope 구조다.

### 누가 만든 artifact인지 공개 검증해야 한다

```text
digital signature
signing private key 보호
verification public key 배포와 신뢰 경로 설계
```

---

## 17. 자주 나오는 잘못된 설계

### 소스 코드에 key 하드코딩

```python
KEY = b"production-secret..."
```

Git history, 빌드 artifact, 컨테이너 이미지, 개발자 장비로 복제된다.

### DB에 key와 ciphertext를 나란히 저장

```text
same database row:
key + nonce + ciphertext
```

DB 유출을 위협으로 두었다면 보호 경계가 사라진다.

### AES-GCM nonce 재사용

같은 key에서 nonce가 겹치면 counter mask가 재사용된다. 랜덤 96비트 nonce, 검증된 라이브러리, 시스템의 메시지 수와 충돌 정책을 함께 설계해야 한다.

### 암호화만 하고 인증하지 않음

AES-CTR/CBC 등을 인증 없이 직접 사용하면 ciphertext 조작을 안전하게 거부하기 어렵다. 특별한 상호운용 요구가 없다면 AEAD를 기본으로 선택한다.

### `SHA256(password)`를 비밀번호 저장값으로 사용

너무 빨라 offline guessing에 유리하다. password hashing/KDF를 사용한다.

### Base64를 암호화로 착각

Base64는 가역 encoding이다.

### 인증서 검증 비활성화

TLS 암호화는 되더라도 공격자 서버와 암호화하고 있을 수 있다. hostname과 trust chain 검증이 서버 인증의 핵심이다.

### Public key를 받았다는 이유만으로 소유자를 신뢰

공격자도 key pair를 만들 수 있다. 인증서, pinned key, 사전 배포, SSH known_hosts 같은 별도의 신뢰 바인딩이 필요하다.

### 모든 것을 자체 프로토콜로 구현

암호 부품 각각이 안전해도 조합 순서, transcript binding, replay, downgrade, serialization ambiguity, key separation에서 실패할 수 있다. TLS와 검증된 envelope library처럼 이미 분석된 프로토콜을 우선한다.

---

## 18. 현재 playground 실습 순서

### 1단계: 기본 재료

```bash
python3 01_primitives/random_and_hash.py
python3 01_primitives/password_kdf.py
python3 01_primitives/hmac_demo.py
```

### 2단계: 대칭키와 저장

```bash
python3 02_symmetric/gcm_walkthrough.py
python3 02_symmetric/aes_gcm.py
python3 02_symmetric/nonce_reuse.py
python3 02_symmetric/aad_swap_demo.py
python3 02_symmetric/db_encryption_demo.py --help
```

### 3단계: key agreement

```bash
python3 03_asymmetric/x25519_exchange.py
```

이 실습에서 볼 질문:

```text
Alice private는 어디에 있는가?
Bob private는 어디에 있는가?
네트워크를 통과하는 값은 무엇인가?
shared secret 자체가 전송되는가?
왜 양쪽 HKDF 결과가 같은가?
왜 이것만으로는 Mallory의 중간자 공격을 막지 못하는가?
```

### 이후 추가할 실습

```text
Ed25519 서명/검증
서명 없는 X25519의 중간자 공격
서명으로 handshake transcript 인증
로컬 CA와 서버 인증서 생성/검증
Python ssl로 로컬 TLS client/server
TLS key log + packet 구조 관찰(비밀이 아닌 로컬 실습 환경에서만)
```

---

## 19. 최종 정신 모델

### 저장

```text
복구할 필요 없는 비밀번호
    → password KDF verifier

복구해야 하는 민감 데이터
    → random DEK/application key로 AEAD
    → DB에는 ciphertext metadata
    → key는 별도 권한 경계에서 관리

규모가 큰 데이터
    → DEK로 데이터 암호화
    → KMS의 KEK로 DEK wrapping
    → ciphertext와 wrapped DEK를 함께 저장
```

### 통신

```text
사전 공유키가 있음
    → HMAC 또는 AEAD 가능

사전 공유키가 없음
    → ephemeral Diffie-Hellman으로 shared secret 합의

상대 신원을 모름
    → 서명 + 인증서/신뢰 anchor로 public key를 신원에 바인딩

실제 애플리케이션 통신
    → 이 조합을 직접 만들지 않고 TLS 사용
```

### HTTPS

```text
인증서와 서명:
내가 기대한 서버와 handshake하고 있는가?

X25519/(EC)DHE:
네트워크로 AES key를 보내지 않고 shared secret을 만들 수 있는가?

HKDF:
shared secret에서 방향과 목적이 분리된 traffic key를 만들 수 있는가?

AES-GCM/ChaCha20-Poly1305:
실제 HTTP bytes를 숨기고 변조를 거부할 수 있는가?
```

그래서 HTTPS는 별개의 마법이 아니다.

> 지금까지 배운 난수, 해시, key derivation, 비대칭 key agreement, 전자서명, 인증서, 대칭 AEAD를 네트워크 공격자에 맞서도록 조립한 프로토콜이 TLS이고, 그 위에 HTTP를 올린 것이 HTTPS다.

---

## 20. 공식 참고 자료

- [NIST FIPS 197: Advanced Encryption Standard](https://csrc.nist.gov/pubs/fips/197/final)
- [NIST SP 800-38D: Galois/Counter Mode](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [RFC 2104: HMAC](https://www.rfc-editor.org/rfc/rfc2104.html)
- [RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869.html)
- [RFC 7748: X25519 and X448](https://www.rfc-editor.org/rfc/rfc7748.html)
- [RFC 8032: Ed25519 and Ed448](https://www.rfc-editor.org/rfc/rfc8032.html)
- [RFC 8446: TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html)
- [RFC 9106: Argon2](https://www.rfc-editor.org/rfc/rfc9106.html)
- [RFC 5280: X.509 PKI Certificate and CRL Profile](https://www.rfc-editor.org/rfc/rfc5280.html)
- [AWS Secrets Manager introduction](https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html)
- [AWS KMS key concepts and hierarchy](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html)
- [Google Cloud KMS envelope encryption](https://cloud.google.com/kms/docs/envelope-encryption)
- [HashiCorp Vault Transit secrets engine](https://developer.hashicorp.com/vault/docs/secrets/transit)
- [Kubernetes Secrets](https://kubernetes.io/docs/concepts/configuration/secret/)
