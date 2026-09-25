# 나의 Crypto Book — 바이트에서 비대칭키, 키 관리, HTTPS까지

> 대상: 애플리케이션 개발 경험은 있지만 암호학 용어가 아직 하나의 그림으로 연결되지 않은 개발자
>
> 목표: `해시 → 비밀번호 저장 → HMAC → AES-GCM → 키 관리 → 비대칭키 → 인증서 → TLS/HTTPS`를 바텀업으로 연결한다.
> 개정판: 2 · 기준일: 2026-09-25 · Python 3.10 이상

이 책은 프로그래밍을 처음 배우는 사람을 위한 책이 아니다. 함수, 바이트 배열, DB transaction, HTTP는 알고 있지만 암호학의 수학적 전제와 protocol의 연결을 처음 구축하는 개발자를 위한 책이다. 전문 용어를 생략하지 않고, 그 용어가 가리키는 **입력·출력·소유자·보안 성질**을 설명한다.

읽는 동안 `shop.example`이라는 가상 서비스가 사용자의 외부 API token을 보관하는 상황을 계속 떠올리자. 브라우저는 token을 서버로 보내고, 서버는 DB에 저장하고, worker는 나중에 복원해 사용한다. 이 한 사례에서 저장 암호화와 전송 암호화가 모두 필요해진다.

### 이 책을 읽는 방법

각 개념은 **문제 → 정의 → 작은 계산 → 공격자의 관점 → 실제 API → 확인 문제** 순서로 읽는다. 수학적 계산이 맞다는 것과 실무에 안전하다는 것은 다른 판단이다. 작은 수를 쓰는 DH·RSA 예제는 계산의 구조만 보여 주며, 실제 보안 파라미터는 라이브러리에 맡긴다.

처음 읽을 때는 0~7장으로 이미 실습한 개념을 연결하고, 8~9장에서 저장 아키텍처를 본 뒤, 10장을 충분히 나누어 읽자. 10장의 목표는 `exchange()`가 True를 출력하는 것을 관찰하는 데서 끝나지 않고 그 계산을 손으로 재현하는 것이다. 11~14장이 이를 HTTPS로 연결한다.

### 목차와 독서 경로

| 구간 | 핵심 질문 | 링크 |
|---|---|---|
| 기초 언어 | 키가 다르다는 것은 어떤 연산이 다르다는 뜻인가? | [0장](#foundations), 1~3장 |
| 해시·비밀번호·인증 | 비교값을 저장해도 되는 경우와 안 되는 경우는? | [4장](#hash), [5장](#password), [6장](#mac) |
| 대칭 암호 | key와 nonce가 각각 어디에서 참여하는가? | [7장](#symmetric) |
| 저장과 키 운영 | DB, 프로세스, KMS에는 각각 무엇이 있는가? | [8장](#storage), [9장](#lifecycle) |
| 비대칭 암호 | 다른 private key로 왜 같은 비밀이 계산되는가? | [10장](#asymmetric) |
| 신뢰와 통신 | 공개키가 누구 것인지 어떻게 알고 HTTPS로 연결하는가? | [11장](#certificates), [12장](#tls), 13~14장 |
| 연습과 복습 | 내 말로 설명하고 실험으로 반증할 수 있는가? | [18장](#labs), [연습문제·해설](#exercises), [용어 찾아보기](#glossary) |

### 교재의 전개에서 참고한 점

“최고의 책”을 객관적으로 순위 매기기보다, 저자들이 공개한 구성과 교육 자료에서 이 독자에게 유용한 방식을 골랐다.

- Mike Rosulek의 [The Joy of Cryptography](https://joyofcryptography.com/)는 one-time pad와 security definition에서 시작해 pseudorandomness, 대칭 암호, 비대칭 암호로 확장한다. 여기서는 **공격자가 무엇을 구별할 수 있는가**라는 질문을 도입하는 데 참고했다.
- Paar·Pelzl·Güneysu의 [Understanding Cryptography](https://www.cryptography-textbook.com/)는 기초 원리와 실제 응용을 예제·문제·추가 읽기로 연결한다. 여기서는 **손계산 → 구현 → 확인 문제**라는 학습 단위를 참고했다.
- Boneh·Shoup의 [A Graduate Course in Applied Cryptography](https://toc.cryptobook.us/)는 secret-key, public-key, protocol을 구분해 발전시킨다. 여기서는 **primitive의 보안과 protocol 전체의 보안을 구별**하는 데 참고했다.

책들의 본문을 번역하거나 발췌한 자료는 아니다. 아래 설명, 계산 예제, 서비스 시나리오, 문제는 이 학습 세션을 위해 새로 구성했다. 표준과 제품 동작의 근거는 해당 절에 직접 연결한다.

<a id="foundations"></a>

## 0. 기초 언어 — 정확히 무엇을 계산하고 무엇을 보장하는가

### 0.1 Plaintext도 key도 결국 바이트다

`b"A"`는 한 바이트 `0x41`이고, 비트로는 `01000001`이다. 같은 값을 10진수로 쓰면 65다. `"A"`는 문자열 객체이고, `"A".encode("utf-8")`가 암호 함수에 넣을 바이트다. 문자 수와 바이트 수는 다르다. 예를 들어 `"가"`는 UTF-8에서 3바이트다.

32바이트 AES key를 `hex()`로 출력하면 64글자가 된다. 한 hex 글자가 4비트를 표현하므로 256비트에는 64글자가 필요하다. Base64는 다른 표기법일 뿐 key의 강도가 늘어나지 않는다. 같은 32바이트는 일반적인 padding 포함 Base64로 44글자다.

```python
raw = b"A"
assert raw[0] == 65
assert raw.hex() == "41"
assert len("가".encode("utf-8")) == 3
```

### 0.2 기호를 읽는 법

| 표기 | 의미 | Python에서의 대응 |
|---|---|---|
| `K` | 비밀키 바이트 | `key` |
| `P`, `C` | plaintext, ciphertext 바이트 | `plaintext`, `ciphertext` |
| `N`, `T` | nonce, authentication tag | `nonce`, `tag` |
| `a ∥ b` 또는 `a \|\| b` | 바이트 연결(concatenation) | `a + b` (`bytes`일 때) |
| `x ⊕ y` 또는 `XOR` | 비트별 배타적 논리합 | 정수라면 `x ^ y` |
| `E_K(X)` | key K로 AES 블록 연산 | `aes_encrypt_one_block(K, X)` |
| `x mod n` | n으로 나눈 나머지 | `x % n` |
| `g^a mod p` | 모듈러 거듭제곱 | `pow(g, a, p)`; Python `^`는 거듭제곱이 아님 |

### 0.3 Correctness와 security는 다른 명제다

암호화가 제대로 동작한다는 correctness는 다음 식이다.

```text
Decrypt(K, Encrypt(K, P)) = P
```

하지만 `Encrypt(K, P) = P`로 구현해도 위 식은 성립한다. 원문을 그대로 반환하면 복호화는 잘되지만 보안은 없다. 테스트에서 round-trip 성공만 확인해서는 안 되는 이유다.

Security는 **공격자에게 주어진 정보와 권한으로 어떤 일이 어려운가**라는 별도 명제다. 공격자가 암호문만 관찰하는지, 평문을 선택해 암호화 결과도 받을 수 있는지, DB를 수정할 수 있는지를 먼저 정해야 한다. 이를 threat model이라고 한다.

이 책에서 주로 사용하는 공격자 모델은 다음과 같다.

- passive attacker: 네트워크를 읽지만 내용을 바꾸지 못한다.
- active attacker: 메시지를 바꾸고, 지우고, 삽입하고, 재전송할 수 있다.
- DB-only attacker: DB dump 또는 DB 수정 권한이 있으나 별도 암호키와 KMS 권한은 없다.
- compromised application: 프로세스 실행 권한이나 복호화 서비스 호출 권한까지 장악했다.

같은 구현도 첫 번째 모델에서는 안전하고 두 번째에서는 취약할 수 있다. 뒤에서 인증 없는 DH가 바로 이 차이를 보여 준다.

### 0.4 Confidentiality, integrity, authenticity, authorization

**기밀성(confidentiality)**은 허용되지 않은 관찰자가 내용을 알아내기 어렵다는 성질이다. 보통 길이와 타이밍까지 모두 숨기는 것은 아니다.

**무결성(integrity)**은 허용되지 않은 변경을 받아들이지 않는 성질이다. 공격자가 DB 바이트를 쓰는 행위 자체를 막는 것이 아니라, 변경된 것을 검출하고 사용을 거부한다.

**인증(authenticity/authentication)**은 데이터나 상대가 특정 키 보유자와 연결된다는 성질이다. 키와 실제 사람·도메인의 연결은 별도의 신뢰 절차가 필요하다.

**인가(authorization)**는 인증된 주체에게 무엇을 허용할지 결정한다. TLS 인증서가 유효하다고 특정 사용자의 DB row를 읽을 권한이 생기지는 않는다.

**재전송(replay)**은 예전에 유효했던 메시지를 그대로 다시 보내는 공격이다. 변경하지 않았으므로 MAC/tag만으로는 막히지 않는다. 순번·일회용 challenge·사용 기록 같은 protocol state가 필요하다.

### 0.5 공개된 알고리즘인데 왜 비밀이 유지되는가

암호 알고리즘과 소스 코드는 공격자에게 알려져 있다고 가정한다. 숨기는 것은 key다. 이는 구현을 숨기는 데 의존하지 않고 작은 비밀만 보호하도록 설계하는 원칙이다.

공격자는 `AES(K, X)`라는 함수와 X를 알지만 K를 모른다. 함수 정의를 안다고 모든 파라미터를 아는 것은 아니다. 다만 K가 짧거나 추측 가능하면 후보를 대입할 수 있으므로 “비밀로 둔다”는 조건과 “충분히 예측 불가능하다”는 조건이 모두 필요하다.

### 0.6 엔트로피와 CSPRNG

균등한 n비트 key에는 `2^n`개 후보가 있다. 후보를 중복 없이 탐색하면 평균 약 절반을 조사해야 정답을 찾는다. 반면 32바이트 공간에 `1234`를 넣고 나머지를 0으로 채우면 저장 길이는 256비트여도 실제 후보는 매우 적다.

Entropy는 불확실성을 수량화하는 개념이다. 비밀번호 공격에서는 단순한 문자열 길이보다 흔한 후보에 확률이 얼마나 몰리는지가 중요하다. KDF는 추측 비용을 높이지만 원래 비밀번호에 없던 비밀 정보를 만들어 내지는 않는다.

CSPRNG는 cryptographically secure pseudorandom number generator다. OS에서 관리하는 비밀 상태와 엔트로피를 기반으로, 관찰한 출력만으로 다음 출력을 예측하기 어렵게 만든다. `secrets.token_bytes()`는 이 용도의 OS 난수원을 사용한다. 출력 몇 번이 달라졌다는 실험만으로 CSPRNG의 안전성이 증명되는 것은 아니다.

### 0.7 안전하다는 말에는 확률과 계산량이 포함된다

잘못된 tag가 통과할 확률은 수학적으로 항상 0이 아니다. 암호학은 충분한 파라미터와 사용 한도 아래 성공 확률을 무시할 수준으로 만드는 것을 목표로 한다. 문서의 “거부한다”, “알아낼 수 없다”는 표현은 이런 computational security를 전제로 한다.

**잠깐 확인:** Base64로 길어진 key는 더 강한가? round-trip 테스트만 통과하면 안전한가? 두 질문 모두 아니며, 앞의 문단에서 각각 이유를 설명할 수 있어야 한다.

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

여기서 먼저 다루는 key는 대칭 암호 연산의 비밀 입력이다. AES-256 key는 예측 불가능한 32바이트다. 10장에서 다룰 public key는 이름 그대로 공개할 수 있으므로, `key`라는 단어가 항상 비밀을 뜻하는 것은 아니다.

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

<a id="hash"></a>

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

### 4.1 SHA-256 내부의 데이터 흐름

SHA-256을 `hashlib` 호출 이상의 수준에서 이해하려면 **padding → block → state → round → digest**를 연결하면 된다.

Padding은 입력 뒤에 1비트, 필요한 수의 0비트, 원래 길이를 기록한 64비트를 붙여 전체를 512비트의 배수로 만드는 절차다. 예를 들어 ASCII `abc`는 24비트이며, padding 후에는 512비트 블록 하나가 된다. 해시가 길이를 기록하는 이유는 입력 끝과 블록 경계를 명확히 정의하기 위해서다.

State는 32비트 word 8개, 즉 256비트의 내부 상태다. 공개된 초기 상수에서 시작한다. 각 512비트 블록을 16개의 word로 해석하고, shift·rotate·XOR·덧셈으로 64개의 message schedule word를 만든다. 64라운드는 이 schedule과 상수를 사용해 state를 섞는다. 처리 결과를 이전 state와 합산하고 다음 블록으로 넘어간다. 마지막 state의 8개 word가 digest다. 정확한 연산은 [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)에 정의된다.

```text
입력 abc → padding된 블록 M0
초기 state H0 + M0 → 64 rounds → 최종 state H1 → 32바이트 digest

긴 입력:
H0 + M0 → H1
H1 + M1 → H2
H2 + M2 → H3 → digest
```

단순한 합계와 달리 여러 비트가 복잡하게 상호작용하므로 작은 입력 차이가 출력 전체에 퍼진다. 그러나 avalanche effect만 확인했다고 일방향성이나 충돌 저항성을 증명한 것은 아니다.

#### “섞는다”를 한 라운드만 더 펼쳐 보기

32비트 word 덧셈은 `mod 2^32`다. 넘치는 비트는 버린다. `ROTR(x,n)`은 오른쪽으로 밀려난 비트를 왼쪽으로 되돌리는 rotate이고, `SHR`은 빈자리에 0을 채우는 shift다. 8비트 장난감으로 보면 `10000001`의 오른쪽 1회 rotate는 `11000000`, shift는 `01000000`이다.

working state를 `a,b,c,d,e,f,g,h`라 하면 SHA-256의 라운드 핵심은 다음과 같다. 모든 변수는 32비트이고, 아래의 NOT은 32비트 범위의 비트 반전이다. 덧셈 결과도 모두 32비트로 제한한다.

```text
Ch(e,f,g)  = (e AND f) XOR ((NOT e) AND g)
             # 각 비트에서 e=1이면 f, e=0이면 g를 선택
Maj(a,b,c) = (a AND b) XOR (a AND c) XOR (b AND c)
             # 각 비트에서 세 값의 다수결

Σ0(a) = ROTR(a,2) XOR ROTR(a,13) XOR ROTR(a,22)
Σ1(e) = ROTR(e,6) XOR ROTR(e,11) XOR ROTR(e,25)

T1 = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t]  (mod 2^32)
T2 = Σ0(a) + Maj(a,b,c)                    (mod 2^32)

새 (a,b,c,d,e,f,g,h) = (T1+T2, a, b, c, d+T1, e, f, g)
```

K[t]는 **공개된 라운드 상수**이지 secret key가 아니다. W[t]는 현재 message block에서 확장한 schedule word다. 64라운드 후 working state를 원래 state에 word별로 더한다. 이것으로 “입력 바이트가 어떤 연산을 거쳐 digest에 영향을 미치는가”를 한 층 더 구체적으로 볼 수 있다. 직접 구현할 때는 schedule 생성·endian·padding·32비트 masking까지 맞아야 하므로 여기서는 `hashlib`를 쓴다.

```python
import hashlib
assert hashlib.sha256(b"abc").hexdigest() == (
    "ba7816bf8f01cfea414140de5dae2223"
    "b00361a396177a9cb410ff61f20015ad"
)
```

### 4.2 복호화가 없는데 비밀번호는 왜 알아낼 수 있는가

두 가지 공격을 구별하자.

```text
역산: digest로부터 원문을 직접 계산
추측: candidate를 hash하고 digest와 비교
```

`H("yes")` 또는 `H("no")` 중 하나라는 것을 알면 두 번만 계산하면 된다. 이는 SHA-256을 깨는 것이 아니라 입력 공간이 작다는 사실을 이용한다.

또한 해시는 압축 함수다. 가능한 입력 수가 출력 수보다 많으므로 충돌은 존재한다. 우리가 요구하는 것은 충돌의 부재가 아니라 찾기의 어려움이다.

| 보안 성질 | 공격자에게 주어진 것 | 찾으려는 것 |
|---|---|---|
| preimage resistance | digest y | H(x)=y인 x |
| second-preimage resistance | 특정 입력 x | x와 다른 x', H(x')=H(x) |
| collision resistance | 특정 목표 없음 | 서로 다른 x, x' 중 같은 hash를 갖는 쌍 |

이상적인 n비트 해시에서 일반적인 preimage 탐색은 대략 `2^n`, 아무 충돌 찾기는 birthday effect 때문에 대략 `2^(n/2)` 규모다. “256비트 출력”이 모든 공격에 256비트 보안을 뜻하지 않는다.

**확인 문제:** 다운로드 파일과 hash를 공격자가 모두 교체할 수 있는 웹페이지에서 받으면 왜 검증이 무의미한가? 신뢰한 별도 경로에서 hash를 받았다면 무엇이 달라지는가?

---

<a id="password"></a>

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

### 5.1 `derived_key`는 이름만으로 역할이 정해지지 않는다

KDF는 Key Derivation Function이다. 같은 출력 바이트를 어떤 시스템에서는 암호화 key로 쓰고, 다른 시스템에서는 비밀번호 검증값으로 쓸 수 있다. 파일의 `derived_key`는 후자다. 따라서 이 예제에서는 `password_verifier`로 읽으면 된다.

로그인 서버의 실제 비교는 다음과 같다.

```text
클라이언트 → TLS 안에서 submitted_password 전송
서버 → scrypt(submitted_password, stored_salt) 재계산
서버 → 재계산한 값과 stored_verifier 비교
```

클라이언트가 verifier 자체를 보내고 서버가 DB 값과 바로 비교하는 구조라면 verifier가 bearer credential, 즉 가진 사람이 사용할 수 있는 로그인 비밀이 된다. 두 프로토콜을 혼동하면 “이걸 DB에 저장하면 안 되는 것 아닌가?”라는 의문이 생긴다. **무엇을 서버가 입력으로 받아들이는가**가 차이다.

### 5.2 느리게 만드는 방법: time cost와 memory cost

SHA-256을 여러 번 반복하면 time cost가 증가한다. scrypt는 중간 계산 결과를 큰 메모리에 저장하고 그 내용을 참조하며 섞어, 병렬 공격 장비도 각 후보에 메모리나 재계산 비용을 지불하게 한다. 이는 단순한 `sleep()`과 다르다. 공격자는 sleep을 제거할 수 있지만 동일 출력을 얻는 데 필요한 계산 의존성은 생략할 수 없다.

실습의 파라미터 `N=2^14, r=8, p=1`에서 핵심 메모리 항은 대략 `128*N*r`바이트, 즉 16 MiB다. N은 주요 작업량, r은 내부 블록 크기, p는 병렬화 관련 파라미터다. 정확한 전체 메모리와 시간은 구현에 따라 달라지며 이 값은 운영 권장값이 아니라 작은 실습값이다. `dklen=32`는 출력 길이지 공격 비용 설정이 아니다. [scrypt 명세 RFC 7914](https://www.rfc-editor.org/rfc/rfc7914.html)

비용을 높이면 공격 비용과 함께 로그인 서버의 메모리·CPU·DoS 부담도 증가한다. 실제 설정은 목표 지연, 동시 로그인 수, 장비, 최신 운영 지침을 보고 정한다.

### 5.3 salt가 공개되어도 남는 효과

공격자는 Alice의 salt를 알고 Alice의 비밀번호 후보를 검사할 수 있다. 하지만 그 계산값을 Bob의 다른 salt에 그대로 재사용할 수는 없다. salt는 대입을 불가능하게 하는 것이 아니라 사전계산과 계정 간 계산 공유를 제한한다.

별도 비밀값인 pepper를 추가하는 시스템도 있다. pepper는 DB 밖에서 관리하므로 DB만 유출됐을 때 추가 경계가 된다. 하지만 pepper가 유출되거나 유실됐을 때의 재검증·rotation 문제까지 생긴다. salt와 동일한 개념이 아니다.

**확인 문제:** 해시된 비밀번호와 salt가 모두 유출됐는데도 salt가 쓸모 있는 이유를 설명하자. 그리고 32바이트 출력이 32바이트 균등 난수만큼의 엔트로피를 보장하는지 판단하자.

---

<a id="mac"></a>

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

### 6.1 그냥 SHA256(key ∥ message)를 쓰면 안 되는가

SHA-256은 앞에서 본 것처럼 이전 state에 다음 블록을 이어 처리한다. 단순한 secret-prefix hash는 특정 조건에서 기존 digest와 길이를 이용해 뒤에 데이터를 붙인 메시지의 digest를 계산하는 length-extension 공격을 허용한다. 따라서 “비밀을 앞에 붙였으니 MAC”이라고 결론 내릴 수 없다.

HMAC은 안쪽과 바깥쪽 해시를 결합하는 정의된 구성이다. SHA-256의 경우 key가 64바이트보다 길면 먼저 해시하고, 이후 64바이트보다 짧으면 뒤에 0을 채운다. 이렇게 해시 블록 크기에 맞춘 값을 K0라 하면:

```text
inner = SHA256((K0 XOR ipad) || message)
tag   = SHA256((K0 XOR opad) || inner)

ipad: 0x36을 64번 반복한 바이트열
opad: 0x5c를 64번 반복한 바이트열
```

이 수식은 내부·외부 단계에 다른 입력을 쓰는 구조를 보여 준다. 안전성이 “두 번 hash해서” 자동으로 생기는 것은 아니다. 직접 변형하지 않고 HMAC 구현을 사용한다. 정의는 [RFC 2104 §2](https://www.rfc-editor.org/rfc/rfc2104.html#section-2)를 참고한다.

### 6.2 인증은 정확한 바이트에 대한 것이다

`{"a":1,"b":2}`와 `{"b":2,"a":1}`은 앱에서 같은 객체일 수 있지만 바이트가 다르다. tag를 검증하려면 raw request bytes에 대해 계산하거나, 명확한 canonical serialization 규칙을 합의해야 한다.

또한 `"ab" || "c"`와 `"a" || "bc"`는 같다. 여러 필드를 인증할 때는 고정 길이, 길이 prefix, 검증된 구조화 인코딩 등으로 경계를 정해야 한다.

HMAC은 공유키 보유자 중 누가 만들었는지 구별하지 않는다. Bob도 key를 알므로 Alice와 같은 tag를 만들 수 있다. 또한 유효한 요청을 그대로 재전송하면 tag는 여전히 유효하다. 이 두 한계가 뒤에서 digital signature와 protocol state가 등장하는 이유다.

**확인 문제:** 공격자가 결제 요청 바이트를 하나도 바꾸지 않고 두 번 보내면 HMAC 검증이 두 번째에 실패하는가? 실패하지 않는다. 결제의 중복 실행 방지는 별도 식별자와 서버 상태가 담당한다.

---

<a id="symmetric"></a>

## 7. AES-GCM: 공유키로 숨기고 변조도 거부한다

**이 장의 질문:** 같은 key로 여러 메시지를 암호화하는데, 출력은 달라지고 수신자는 어떻게 정확히 복원하는가?

### 7.0 XOR에서 AES까지: 생략했던 연결

XOR는 같은 비트면 0, 다르면 1을 반환한다. 그래서 `x XOR s XOR s = x`다.

```text
plaintext P = 01000001 = 0x41 = ASCII A
mask      S = 10110110 = 0xb6
cipher    C = 11110111 = 0xf7

C XOR S     = 01000001 = 원래 A
```

이것만으로도 mask를 양쪽이 알면 암호화와 복호화가 된다. 문제는 mask가 안전한가다. 평문만큼 긴 균등 난수 mask를 한 번만 쓰고 비밀로 공유하는 방식이 one-time pad(OTP)다. key를 메시지 길이만큼 미리 전달해야 하므로 대량 통신에는 운영이 어렵다.

우리가 원하는 것은 **짧은 secret key에서 긴 keystream을 재현하는 것**이다. Keystream은 평문과 XOR할 바이트들의 연속이다. 키를 아는 양쪽은 같은 스트림을 만들고, 키를 모르는 관찰자는 스트림을 예측하지 못해야 한다. 실제 stream cipher 또는 AES의 counter mode가 이 역할을 한다. OTP의 정보이론적 보안과 달리, 여기서는 계산량에 근거한 보안을 사용한다.

AES를 이해할 때는 `key로 input block에 대한 permutation을 고른다`고 읽자. Permutation은 가능한 모든 16바이트 값을 일대일로 재배열하는 가역 변환이다. Key를 고정하면 각 입력은 한 출력에 대응하며 역변환도 존재한다. 해시처럼 큰 입력을 작은 출력으로 압축하는 것이 아니다.

```text
E_K: 16-byte block → 16-byte block
D_K: inverse of E_K
D_K(E_K(X)) = X
```

Key schedule은 원래 key에서 round key들을 만들어 낸다. AES-256은 최초 AddRoundKey 후 14라운드를 수행한다. SubBytes는 비선형 byte 치환, ShiftRows는 위치 변경, MixColumns는 한 열의 byte들이 서로 영향을 주게 하는 변환, AddRoundKey는 round key와 XOR하는 단계다. 마지막 라운드에서는 MixColumns를 생략한다. 이 과정에서 **공개된 고정 변환과 비밀 round key의 XOR가 반복**된다. [AES 표준](https://csrc.nist.gov/pubs/fips/197/final)

여기서 state는 16바이트를 4×4 배열로 배치한 것이다. Key schedule은 key를 32비트 word들로 나누고, word의 byte 순환·치환·공개 상수 XOR·앞 word들과의 XOR로 확장해 round key를 만든다. AES-256에서는 원래 8 word를 60 word로 확장해 15개의 16바이트 round key를 얻는다. 새 난수 key를 라운드마다 뽑는 것이 아니다. **동일한 원래 key에서 항상 같은 round key들이 나온다.**

SubBytes의 치환표(S-box)는 256개의 byte 입력 각각에 다른 byte 출력을 대응시키는 고정 표다. 단순한 XOR만 반복하는 선형 구조를 피하게 한다. ShiftRows·MixColumns는 한 byte의 영향이 여러 위치로 퍼지게 한다. Round key는 이 공개 변환들 사이에 비밀 의존성을 계속 넣는다. 개별 단계는 역변환 가능하지만 key 없이 전체의 대응을 계산하기 어려운 구조가 목표다.

내부 표를 외우기보다 두 사실을 확인하자. (1) 같은 key와 같은 block이면 같은 출력이다. (2) key만 같고 block이 다르면 출력도 다르다. Key는 입력 전체가 아니라 함수의 여러 입력 중 하나다.

평문을 16바이트씩 나누어 그대로 AES에 넣으면 같은 평문 block은 같은 ciphertext block이 된다. 이것이 ECB의 패턴 노출이다. 끝의 짧은 block 처리와 변조 검출도 추가로 정해야 한다. 따라서 block cipher를 실제 메시지에 적용하는 mode of operation이 필요하다.

> 학습 경계: 이 장의 손계산은 XOR·counter·입출력 의존성을 설명한다. AES의 S-box나 GCM의 유한체 곱셈까지 구현하는 것은 별도 심화 과제다. 운영 코드는 고수준 AEAD API를 사용한다.

AES는 128비트 블록을 변환하는 block cipher다. AES-128/192/256의 숫자는 key 길이를 의미하고, 세 종류 모두 128비트 블록을 처리한다. 이는 [NIST FIPS 197](https://csrc.nist.gov/pubs/fips/197/final)에 정의되어 있다.

AES만으로는 임의 길이 메시지, nonce, 인증 tag 같은 프로토콜이 생기지 않는다. GCM은 AES를 사용하는 AEAD 모드다. [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final)는 GCM을 associated data를 지원하는 authenticated encryption 알고리즘으로 정의한다.

### 7.1 암호화 부분

이제 Alice와 Bob이 **같은 K를 미리 보유**했다고 가정한다. K를 처음 공유하는 방법은 10장에서 해결한다. nonce N은 Alice가 메시지마다 정하고 공개 전송한다. Counter는 메시지 내부 block 번호에 대응하는 숫자다. Nonce는 메시지 사이를 구분하고 counter는 한 메시지 안의 block을 구분한다.

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

12바이트 nonce일 때 `J0 = N || 00000001`을 만들고, 데이터용 counter는 2부터 시작한다. 오른쪽 4바이트는 big-endian 정수다. 예를 들어 `(2).to_bytes(4, "big")`는 `00 00 00 02`다. 마지막 평문 block이 6바이트라면 mask의 앞 6바이트만 사용한다. CTR 부분은 평문에 padding을 넣을 필요가 없다.

```text
Alice 원래 보유: K             Bob 원래 보유: K
Alice 새로 생성: N             Bob 수신: N, C, tag
Alice 계산: E_K(N || 2)        Bob 계산: E_K(N || 2)
            같은 mask를 각자 계산
Alice: C = P XOR mask          Bob: P = C XOR mask
```

우리 코드의 `aes_encrypt_one_block(key, aes_input)`이 “AES에 넣는다”의 정확한 의미다. `aes_input`은 평문이 아니라 `nonce || counter`라는 16바이트 배열이다. 복호화 때도 **AES의 암호화 함수 E**로 같은 mask를 생성한다. 역함수 D를 쓸 필요는 없다.

같은 key에서 nonce를 재사용하면 `C1 XOR C2 = P1 XOR P2`가 된다. 알려진 P1과 두 암호문으로 `P2 = P1 XOR C1 XOR C2`를 얻는다. `nonce_reuse.py` 실습은 두 평문의 길이가 같은 경우 전체가 복구되는 것을 보여 준다.

랜덤 nonce에는 충돌 가능성이 있다. 균등한 96비트 nonce를 q번 뽑으면 충돌 확률은 작은 q 범위에서 대략 `q(q-1)/2^97`이다. `q=2^32`라면 약 `2^-33`이다. 이 값은 운영 허용량 추천이 아니라 birthday effect 계산 예다. 대규모 시스템은 모든 writer가 한 key로 만든 메시지 수, 충돌 방지, key rotation을 함께 설계해야 한다. 단조 counter를 쓰면 재시작·동시 실행·snapshot 복구에도 중복되지 않도록 해야 한다.

### 7.2 인증 부분

GCM은 ciphertext와 AAD를 인증하는 tag를 만든다.

```text
encrypt(K, nonce, plaintext, AAD)
    → ciphertext + tag
```

decrypt는 tag가 맞을 때만 plaintext를 반환해야 한다.

여기서 GCM은 HMAC을 뒤에 붙인 것이 아니다. GCM 고유의 인증 계산이 있다. 구조만 펼치면 다음과 같다.

```text
H = AES_K(16바이트 0)                  # 인증 계산용 비밀 subkey
U = GHASH_H(AAD, ciphertext, lengths)  # 정해진 유한체 연산으로 누적
T = U XOR AES_K(J0)                   # nonce에 연결된 mask로 보호
```

유한체(finite field)는 정해진 유한 집합 위에서 덧셈·곱셈 등을 정의한 대수 구조다. GHASH는 128비트 블록을 이 구조의 원소로 해석해 누적한다. 세부 곱셈 규칙을 외우지 않아도 tag가 **key, nonce, ciphertext, AAD와 길이**에 의존한다는 것은 읽을 수 있다. [GCM 정의](https://csrc.nist.gov/pubs/sp/800/38/d/final)

AAD가 `record:alice`이면 Bob의 정상 ciphertext를 Alice 자리로 옮겨도 Alice 문맥에서 tag가 맞지 않는다. 다만 공격자가 보내 준 AAD를 아무 검증 없이 그대로 받아들이면 문맥 바인딩이 무력해질 수 있다. 수신자는 현재 요청·tenant·레코드의 **기대하는 문맥**으로 AAD를 구성해야 한다.

같은 행의 과거 ciphertext와 과거 metadata 전체를 되돌리는 rollback은 별개다. 과거에도 유효했던 tag이므로 AEAD 자체로 최신 버전임을 증명하지는 못한다. 외부의 신뢰 가능한 버전 상태가 필요하다.

API는 태그 불일치를 `InvalidTag`로 알린다. 이를 key 오류, nonce 오류, AAD 오류, ciphertext 오류 중 하나로 세분하지 않는 것이 정상이다. 인증이 실패한 데이터는 처리하지 않는다.

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

<a id="storage"></a>

## 8. 현대 애플리케이션은 암호화된 값을 어디에 저장하는가

**이 장의 질문:** `AESGCM(key)`의 key는 누가 만들고, 재시작 후 어디서 찾아오며, DB dump에는 어떤 바이트가 남는가?

“보통 Vault나 Secret Manager를 쓰나?”의 답은 다음과 같다.

> 한 가지 보편적인 배포 정답이나 시장 점유율을 가정하지 않는다. 아래는 공식 서비스들이 지원하는 대표 설계 패턴이다. 선택은 클라우드, 운영 역량, 보호할 데이터, 복호화 권한의 경계에 따라 달라진다.

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

로컬 실습의 실제 SQL 행을 더 구체적으로 보면:

```sql
CREATE TABLE encrypted_secrets (
    id TEXT PRIMARY KEY,
    key_version INTEGER NOT NULL,
    nonce BLOB NOT NULL,
    encrypted_value BLOB NOT NULL
);
```

`BLOB`은 binary large object, 즉 바이트 배열 저장 타입이다. 여기서는 작아도 BLOB을 쓴다. PostgreSQL에서는 `bytea` 등 대응 타입을 쓸 수 있다. `hex(nonce)`로 조회했을 때 보이는 문자열은 표시용이며 실제 SQLite 컬럼에는 raw bytes가 들어 있다. JSON에 넣을 때는 Base64를 사용할 수 있고, 복호화 전에 bytes로 decode한다.

프로세스를 종료하면 메모리의 key는 사라진다. 다음 프로세스가 같은 데이터를 읽으려면 **같은 key를 보관한 외부 저장소**에서 다시 받아야 한다. 환경변수는 전달 수단이다. `export`만 한 key는 그 shell과 자식 프로세스의 환경에 있고 영구 백업이 아니다. 또한 명령에 값을 직접 적으면 shell history에 남을 수 있다.

실습 CLI의 `inspect`가 환경변수를 요구하는 것은 현재 `main()`의 공통 로딩 순서 때문이며, DB의 암호문을 조회하는 데 암호학적으로 key가 필요한 것은 아니다.

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

HSM은 Hardware Security Module이다. 암호 연산과 key 보호를 수행하는 전용 장치/보안 경계다. KMS는 그 위에서 API, identity, policy, version, audit 등을 제공할 수 있는 서비스다. 모든 KMS 설정이 같은 HSM 보장이나 동일한 export 정책을 갖는 것은 아니다. `KMS = key를 환경변수로 내려주는 서비스`로 외우면 envelope encryption을 이해하기 어렵다.

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

DEK를 만드는 위치에는 변형이 있다. 앱이 CSPRNG로 생성해 KMS로 wrap할 수도 있고, AWS KMS의 `GenerateDataKey`처럼 plaintext DEK와 encrypted DEK를 함께 반환받을 수도 있다. KMS는 그 plaintext DEK를 나중에 조회하는 업무 DB로 저장해 주지 않는다. 앱이 wrapped DEK를 보존해야 복호화할 수 있다. [AWS data keys](https://docs.aws.amazon.com/kms/latest/developerguide/data-keys.html)

개념 pseudocode — 실제 SDK 호출과 오류 처리는 서비스별로 다르다:

```python
dek, wrapped_dek = kms_generate_data_key(kek_id, context)
nonce = random_12_bytes()
ciphertext_and_tag = aead_encrypt(dek, nonce, plaintext, aad)
db_insert(record_id, kek_id, wrapped_dek, nonce, ciphertext_and_tag)

# 다른 시점, 다른 프로세스
row = db_select(record_id)
dek = kms_unwrap(row.wrapped_dek, expected_context)
plaintext = aead_decrypt(dek, row.nonce, row.ciphertext_and_tag, expected_aad)
```

여기서 `context`는 KMS가 지원하는 인증 문맥이고 `aad`는 로컬 데이터 암호화 문맥이다. 자동으로 동일시하지 말고 포맷이 양쪽을 어떻게 연결하는지 정의해야 한다. 둘 다 공개 metadata로 취급하고 민감한 token을 넣지 않는다.

**누가 무엇을 갖는가:**

| 위치 | 지속적으로 보관 | 처리 중 일시 보유 |
|---|---|---|
| 업무 DB | nonce, ciphertext/tag, wrapped DEK, key ID, metadata | 없음 |
| 앱 메모리 | 재시작을 넘어서는 보관 아님 | plaintext, plaintext DEK, workload credential |
| KMS 보안 경계 | KEK와 정책·버전 | unwrap/wrap 입력 및 결과 |
| 네트워크 | 전송 기록이 남을 수 있음 | TLS로 보호된 API 요청 |

DEK 범위는 레코드별, 파일별, tenant별 등으로 정할 수 있다. 더 좁으면 노출 범위를 줄이고 metadata와 API 호출량이 늘 수 있다. DEK를 레코드마다 쓰더라도 세션 traffic key와는 용도와 수명주기가 다르다.

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
Browser ── HTTPS ──→ Load Balancer
                           │ 별도 연결: TLS / mTLS
                           ▼
                  Application Service ←── 권한 확인/unwrap ──→ KMS / HSM
                  plaintext와 DEK는                           KEK 보관
                  사용 중 메모리에 존재                        policy/audit
                           │
                           │ nonce + ciphertext/tag
                           │ wrapped DEK + metadata
                           ▼
                  Database / Object Storage
```

그리고 DB password나 외부 SaaS credential처럼 “애플리케이션 자체가 사용하는 secret”은 별도 Secret Manager에서 런타임에 공급할 수 있다.

```text
Secret Manager: 애플리케이션이 사용할 secret 값 보관
KMS: 암호키와 암호 연산/수명주기 관리
업무 DB: 사용자 데이터의 ciphertext 보관
```

---

<a id="lifecycle"></a>

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

예를 들어 VM 실행 시 운영자가 그 VM에 role을 부여하고, 플랫폼이 단기 credential을 공급한다. 앱의 SDK는 그 credential로 KMS 요청에 인증 정보를 붙이고, KMS는 정책을 확인한다. 여기서 신뢰의 출발점은 **VM/워크로드를 실행하고 identity를 부여하는 플랫폼과 관리자**다. 비밀이 저절로 생겨난 것이 아니다. [EC2 role을 통한 애플리케이션 권한](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2.html)

앱이 침해되어 KMS에 정상 인증할 수 있으면 root key를 export하지 못하더라도 decrypt API를 호출할 수 있다. 따라서 root key 비노출과 plaintext 접근 차단은 서로 다른 보장이다.

### 9.4 메모리와 캐시

매 레코드마다 KMS를 호출하면 지연과 비용이 커질 수 있다. 반대로 key를 오래 캐시하면 침해 시 노출 창이 커진다. 다음을 명시적으로 결정해야 한다.

- 캐시 단위와 TTL
- 프로세스 재시작 시 동작
- KMS 장애 시 요청을 실패시킬지, 이미 허용한 수명 안의 캐시로 처리할지
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

KEK 자동 rotation은 모든 기존 wrapped DEK를 즉시 새 버전으로 다시 암호화한다는 뜻이 아니다. 서비스는 과거 ciphertext 복호화를 위해 이전 key material을 유지할 수 있다. 오래된 key가 실제로 유출됐다면, 이미 탈취된 wrapped DEK와 ciphertext의 복사본은 나중의 rewrap만으로 보호되지 않는다.

key를 지워 데이터를 읽을 수 없게 만드는 cryptographic erasure도 모든 key backup·캐시·이미 복호화된 복사본이 통제된다는 조건이 필요하다.

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

<a id="asymmetric"></a>

## 10. 비대칭키: “public으로 암호화, private으로 복호화”보다 넓은 개념

### 먼저, 대칭키만으로 해결하지 못한 문제

8장에서 앱이 DB 데이터를 암호화할 때는 **같은 관리 주체가 key를 만들고 다시 사용**했다. 그런데 처음 방문한 브라우저와 서버는 공유한 AES key가 없다.

서버가 `이 key를 써`라며 평문으로 보내면 도청자도 얻는다. 그 key를 암호화해서 보내려면 또 다른 공유 key가 필요하다. 이것이 **key distribution problem**, 즉 키 분배 문제다. 비대칭 암호는 미리 공유한 비밀 없이 시작할 수 있는 도구를 제공한다. 다만 상대의 **신원까지 저절로 해결하는 것은 아니다**.

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
| Public-key encryption | 자신에게 온 ciphertext 복호화 | 수신자 앞으로 메시지 암호화 | RSA-OAEP |
| Key encapsulation | encapsulation을 열어 shared secret 복구 | 수신자용 encapsulation과 shared secret 생성 | ML-KEM 등 |

`public key로 암호화하고 private key로 복호화한다`는 설명은 RSA 암호화 같은 일부 구성에는 맞지만, X25519 키 교환이나 Ed25519 서명을 설명하지 못한다.

### 10.1 준비 수학: 나머지 연산, 군, 그리고 한 방향으로 쉬운 계산

`x mod p`는 x를 p로 나눈 나머지다. Python의 `%`에 해당한다.

```python
29 % 23                  # 6
(20 + 8) % 23            # 5
pow(5, 6, 23)            # 5**6 % 23 == 8
```

`pow(g, a, p)`는 큰 `g**a`를 전부 만든 다음 나누지 않는다. 거듭제곱을 제곱과 곱셈으로 분해하면서 계속 나머지를 취한다. 따라서 a가 아주 커도 a의 비트 수에 비례하는 횟수의 큰 정수 연산으로 계산할 수 있다.

여기서 “나머지를 취해 정보가 사라지니까 안전한가?”라고 생각하면 절반만 맞다. 공개된 `g, p, A`에 대해 `g**a mod p == A`가 되는 a를 찾는 문제가 어려워야 한다. 나머지 연산 자체가 언제나 어렵다는 뜻이 아니다.

수학에서 **group(군)**은 원소 집합과 연산이 다음 성질을 갖는 구조다.

- 연산 결과가 다시 집합에 속한다: closure, 닫힘.
- `(a·b)·c = a·(b·c)`: associativity, 결합법칙.
- 값을 바꾸지 않는 원소가 있다: identity, 항등원.
- 각 원소의 효과를 취소하는 원소가 있다: inverse, 역원.

예를 들어 소수 p=23일 때 `1..22`를 원소로 하고 곱한 뒤 mod 23을 취하는 연산은 군을 이룬다. 항등원은 1이다. `3×8 mod 23 = 1`이므로 8은 3의 역원이다. 0은 곱셈 역원이 없으므로 이 집합에서 제외한다.

어떤 g를 반복해서 곱했을 때 군의 모든 원소를 만들 수 있으면 g를 **generator(생성원)**라 한다. 그 군은 cyclic group(순환군)이다. g의 거듭제곱이 처음 1로 돌아오는 양의 지수가 g의 **order(위수)**다. 이 책의 작은 예에서 5는 mod 23 곱셈군의 생성원이며 위수는 22다.

핵심적인 비대칭은 다음과 같다.

```text
쉬운 방향:  a → g^a mod p       (빠른 거듭제곱)
어려운 방향: g^a mod p → a      (discrete logarithm, 이산로그)
```

작은 수에서는 역방향도 전부 시도하면 쉽다. 실제 안전성은 **적절하게 선택된 군과 충분히 큰 파라미터에서 알려진 공격이 비싸다**는 데 의존한다. “역함수가 없다”거나 “수학적으로 복구 불가능하다”는 주장이 아니다. DH의 shared secret을 공개값에서 구하기 어렵다는 가정은 더 직접적으로 computational Diffie–Hellman assumption이라 부른다. 이산로그를 풀면 DH도 깰 수 있지만, 두 문제를 무조건 동치라고 여기지는 않는다.

#### Public key는 private key에서 파생된다

개념적으로:

```text
private a ── one-way public operation ──→ public A
```

public A에서 private a를 되찾기 어려운 수학 구조를 사용한다.

### 10.2 작은 수로 계산하는 Diffie–Hellman

아래의 수는 **손으로 검산하기 위한 장난감**이다. 보안용으로 쓰지 않는다.

```text
공통 공개 파라미터: p=23, g=5

Alice                           Bob
private a=6                     private b=15
public A=5^6 mod 23=8            public B=5^15 mod 23=19

              A=8 →
              ← B=19

S=B^a mod 23                    S=A^b mod 23
 =19^6 mod 23                    =8^15 mod 23
 =2                              =2
```

왜 같은가? Alice의 계산은 `(g^b)^a`, Bob의 계산은 `(g^a)^b`다. 둘 다 `g^(ab)`의 나머지다. **같은 알고리즘에 같은 입력을 넣어서가 아니라, 서로 다른 입력의 계산 결과가 같도록 수학 구조를 선택한 것**이다.

도청자가 본 것은 p, g, A, B다. `A×B mod p`는 `g^(a+b)`이지 `g^(ab)`가 아니다. 공개된 값끼리 그냥 곱하면 shared secret이 나오지 않는다. 다만 이 예는 작아서 a 후보 1..22를 전부 넣어 6을 찾을 수 있다. 같은 코드로 그 공격도 확인하자.

```bash
python3 03_asymmetric/key_roles_lab.py dh
```

**확인 질문:** Alice가 Bob의 private b를 받은 적이 있는가? 없다. 서버가 AES key 2를 만들어 보내준 것인가? 아니다. 양쪽이 독립 계산했으며 실제 암호화 key는 뒤의 KDF로 만든다.

### 10.3 타원곡선의 scalar multiplication과 X25519

큰 정수의 거듭제곱 대신 다른 군을 쓸 수 있다. **Elliptic curve cryptography(ECC)**는 정해진 방정식을 만족하는 점들과 특수한 점 O를 원소로 하고, 점의 덧셈을 정의한다. 여기서 O는 항등원(point at infinity)이며 평범한 좌표 `(0, 0)`이 아니다.

예를 들어 작은 유한체 위의 `y² = x³ + 2x + 2 (mod 17)`에서 `G=(5,1)`은 점이다. 좌변은 1, 우변은 137이고 `137 mod 17 = 1`이기 때문이다. 유한체는 덧셈·곱셈·0이 아닌 값으로의 나눗셈을 일관되게 할 수 있는 유한한 집합이다. mod 17에서는 나눗셈을 **역원 곱하기**로 수행한다.

점 덧셈은 `(x1+x2, y1+y2)`가 아니다. 곡선 위에 결과가 남도록 정해진 공식으로 계산한다. G를 자기 자신과 더하는 doubling을 한 번만 계산해 보자.

```text
기울기 λ = (3*x² + 2) / (2*y) mod 17
         = 77 * inverse(2) mod 17
         = 77 * 9 mod 17 = 13        (2*9 mod 17 = 1)

x(2G) = λ² - 2*x mod 17 = 6
y(2G) = λ*(x - x(2G)) - y mod 17 = 3

2G = (6,3),   좌표를 2배 한 (10,2)가 아니다.
```

**Scalar multiplication** `[a]G`는 점 G를 a번 더한다는 뜻이다. 실제로는 doubling과 addition을 조합해 빠르게 계산한다. a는 scalar(스칼라), G는 point(점)다. 곱셈군에서 거듭제곱하던 것을 덧셈 표기의 군에서는 scalar multiplication으로 쓰는 셈이다.

```text
Alice: A=[a]G                 Bob: B=[b]G
Alice: [a]B=[ab]G             Bob: [b]A=[ab]G
```

`G → [a]G` 계산은 빠르지만 G와 A만 보고 a를 알아내는 elliptic-curve discrete logarithm은 적절한 곡선과 크기에서 어렵다. **이 한 관계가 X25519를 이해하는 다리**다. 방금 mod 17 곡선은 설명용이며 Curve25519 자체가 아니다.

X25519는 Curve25519 위에서 key agreement에 쓰는 구체적인 scalar multiplication 함수다. API의 private/public 값은 각각 32바이트로 표현되지만, public 값은 점의 모든 좌표를 단순히 이어 붙인 것이 아니라 특정 좌표의 인코딩이다. private 입력에도 정해진 비트 처리가 있다. 이를 직접 구현하지 않는다. 256비트로 표현한다고 보안 강도가 AES-256과 같다는 뜻은 아니다. X25519는 대략 128비트 수준의 고전적 보안을 목표로 한다. [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html)

이제 라이브러리 API를 읽을 준비가 됐다.

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

### 10.4 HKDF: shared secret과 AES key는 왜 구분하는가

X25519 출력 S는 비밀 key material이다. 하지만 앱은 AES key 하나뿐 아니라 송신용·수신용 key, IV 등을 필요로 할 수 있다. 원시 출력을 잘라서 용도를 섞지 않고, **KDF(key derivation function)**로 규격에 맞는 출력을 만든다.

HKDF는 **HMAC-based Extract-and-Expand Key Derivation Function**이다. SHA-256 버전의 구조를 간략히 보자.

```text
입력: IKM = input keying material, 여기서는 shared secret S

Extract:
PRK = HMAC(salt, IKM)
      └─ 비밀 재료를 고정 길이의 pseudorandom key로 정리

Expand:
T1 = HMAC(PRK, info || 0x01)
T2 = HMAC(PRK, T1 || info || 0x02)
...
OKM = (T1 || T2 || ... )[:요청한 바이트 수]
```

`||`는 byte concatenation이다. salt는 보통 공개 가능하며 프로토콜이 값과 전달 방법을 정한다. HKDF를 단계적으로 조합하는 프로토콜에서는 salt 위치에 앞 단계의 secret을 넣기도 한다. `info`는 `protocol-v1/client-to-server/key` 같은 목적·문맥이다. 같은 IKM·salt·info·길이는 같은 결과를 낸다. info가 다르면 다른 용도의 출력을 얻는 **domain separation**을 할 수 있다. [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html)

HKDF가 정보이론적으로 없는 비밀을 새로 만드는 것은 아니다. 8비트 secret에서 32바이트를 뽑아도 공격자는 입력 256개를 모두 시도할 수 있다. 그래서 HKDF는 충분한 비밀을 가진 입력을 전제로 하며 **비밀번호 저장용 scrypt의 대체물이 아니다**. scrypt는 추측 한 번을 비싸게 만들고, HKDF는 충분히 좋은 secret을 목적별 key로 빠르게 정리한다.

```text
Alice: HKDF(S, salt, info="A→B") → K_ab
Bob:   HKDF(S, salt, info="A→B") → K_ab

Bob:   HKDF(S, salt, info="B→A") → K_ba
Alice: HKDF(S, salt, info="B→A") → K_ba
```

여기서는 양쪽에서 **같은 info를 같은 방향에 붙이는 것**이 중요하다. 각자의 관점으로 단순히 `send`라고 쓰면 서로 반대 방향을 같은 이름으로 착각한다.

```bash
python3 03_asymmetric/key_roles_lab.py x25519
```

이 예제는 private object를 상대에게 전달하지 않고, public bytes를 직렬화·복원한 뒤 S와 K_ab를 계산한다. Alice가 K_ab로 암호화한 메시지를 Bob이 복호화한다. 네트워크를 건너갈 수 있는 값은 public bytes, nonce, ciphertext/tag다. private key와 S, K_ab는 각 프로세스 메모리에 남는다. salt/info는 양쪽이 같은 공개 상수로 이미 알고 있다.

### 10.5 X25519만으로는 상대의 신원을 모른다

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

따라서 능동 공격자가 있는 통신에서 안전한 key agreement에는 **authentication**이 필요하다.

작은 DH 예로 Mallory의 private m=7, public M=`5^7 mod 23=17`이라고 해 보자. Mallory가 양쪽에 자신의 public 17을 보내면:

```text
Alice:   17^6 mod 23 = 12
Mallory:  8^7 mod 23 = 12      ← Alice와 통신할 key material

Bob:     17^15 mod 23 = 15
Mallory: 19^7 mod 23 = 15      ← Bob과 통신할 key material
```

Mallory는 a나 b를 역산하지 않았다. **암호를 깨는 대신 통신 상대를 바꾼 것**이다. 뒤에서 정상 AEAD를 써도 Mallory는 자신이 합의한 key를 알기 때문에 양쪽의 tag를 정상 생성할 수 있다. AEAD의 오류가 아니라, 인증 없는 key agreement의 한계다.

```bash
python3 03_asymmetric/key_roles_lab.py mitm
```

### 10.6 전자서명: 공개 정보로 검증하지만 생성하지는 못한다

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

#### 검증자는 왜 private key 없이 확인할 수 있는가

HMAC 검증은 같은 key로 tag를 다시 계산해 비교했다. 서명에서는 **같은 서명을 다시 만드는 것이 아니라 공개된 수학 관계가 성립하는지 검사**한다.

원리를 보기 위해 Schnorr 계열의 단순화한 식을 보자. 앞에서 본 타원곡선 군의 생성원 G의 위수를 q라 하자. private a에 대해 public A=`[a]G`다.

```text
서명자:
  비밀 scalar r 선택, R=[r]G
  h = Hash(R || A || message)를 정수로 해석해 mod q
  s = (r + h*a) mod q
  signature = (R, s)

검증자:
  같은 R, A, message로 h 계산
  [s]G == R + [h]A 인지 확인
```

정상 서명이라면 왼쪽은 `[r+h*a]G`이고 오른쪽도 `[r]G + [h*a]G`이므로 같다. 검증자가 a를 알아낼 필요는 없다. 공격자가 message를 바꾸면 h도 바뀌며, 그 h에 맞는 관계를 다시 만들어야 한다. 실제 안전성은 이산로그 난이도와 해시·인코딩·검증 규칙 등의 조건에 의존한다. 이 한 줄의 등식 자체가 보안 증명은 아니다.

이 식은 **원리 설명이지 Ed25519 구현 지침이 아니다**. Ed25519는 비밀에서 메시지별 r을 결정적으로 생성하는 절차, 정확한 byte encoding, 점 검증 규칙 등을 지정한다. 이런 서명에서 r을 잘못 재사용하면 private key를 역산할 수 있다. 서명 내부의 비밀 r은 AES-GCM의 공개 nonce와 다른 역할이다. [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html)

실제로는 검증된 API를 쓴다.

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

message = b"release:v1"
private = Ed25519PrivateKey.generate()
public = private.public_key()
signature = private.sign(message)
public.verify(signature, message)  # 성공 시 None, 실패 시 InvalidSignature
```

```bash
python3 03_asymmetric/key_roles_lab.py signature
```

정상 메시지, 바꾼 메시지, 엉뚱한 public key를 차례로 검사한다. **검증자가 공개키를 가지고 있다는 이유로 새 서명까지 만들 수는 없다.** 하지만 shared HMAC key를 가진 검증자는 새 tag를 만들 수 있다. 이것이 배포 서명, 인증서 서명에 public verification이 유용한 이유다.

### 10.7 RSA: “공개키로 암호화”가 실제로 성립하는 예

X25519는 key agreement이지 `encrypt(public_key, message)` 함수가 아니었다. 그 함수가 있는 계열도 보자. 작은 RSA의 산술 골격은 다음과 같다.

```text
비밀 소수 p=61, q=53
n=p*q=3233
φ(n)=(p-1)*(q-1)=3120
e=17 선택, d=2753 선택: e*d mod φ(n) = 1

public: (n,e)              private: d 및 p,q 등의 비밀 파라미터
message 정수 m=65
c=m^e mod n=2790
m=c^d mod n=65
```

φ(n)은 n과 서로소인 나머지의 개수다. e와 φ(n)이 서로소이므로 e의 곱셈 역원 d를 구할 수 있다. 왜 복호화되는지는 `e*d=1+k*φ(n)`이라는 관계에서 출발한다. m과 n이 서로소일 때 Euler 정리에 의해 `m^φ(n) mod n=1`이므로 `m^(e*d) mod n=m`이 된다. 일반적인 `0≤m<n` 전체의 성립은 mod p와 mod q를 각각 확인하고 **Chinese remainder theorem(중국인의 나머지 정리)**으로 결합해 보인다. 이 정리는 서로소인 두 모듈러 조건이 mod p*q에서 하나의 나머지를 정한다는 내용이다.

```bash
python3 03_asymmetric/key_roles_lab.py rsa
```

이 예의 `pow(m,e,n)`은 **textbook RSA**이며 보안용으로 쓰면 안 된다. 결정적이라 같은 평문이 같은 ciphertext를 만들고, 암호문 사이의 대수적 관계도 그대로 남는다. 실제 RSA 암호화는 OAEP 같은 정해진 encoding을 사용한다. RSA-2048/SHA-256 OAEP의 메시지 상한은 `256 - 2*32 - 2 = 190`바이트이므로 큰 JSON이나 파일을 통째로 넣는 도구가 아니다. RSA 서명에는 RSA-PSS 같은 별도 규격을 사용한다. “서명은 private key로 암호화”라는 설명은 일반적으로 틀리다. [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017.html)

큰 데이터는 random 대칭키로 AEAD 암호화하고, 수신자에게 그 key를 안전하게 제공하는 **hybrid encryption(하이브리드 암호화)**을 구성한다. 현대 구성에서는 KEM(key encapsulation mechanism)을 쓰기도 한다. KEM의 encapsulate는 상대 public key로 **encapsulation ciphertext와 shared secret을 함께 생성**하고, 상대는 private key로 decapsulate하여 같은 secret을 얻는다. 임의의 원문을 그대로 암호화하는 API와는 구분한다.

미래 위협에 대해서도 범위를 알아두자. 충분히 큰 오류 보정 양자컴퓨터를 가정하면 RSA와 기존 타원곡선의 난제는 안전성 기반이 약해진다. ML-KEM은 별도의 수학 기반을 사용하는 표준화된 post-quantum KEM이다. 이 책은 X25519로 key agreement 원리를 배우며, 이를 모든 미래 배포의 유일한 선택으로 권하지 않는다. [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)

### 10.8 Public key만 받았다고 신뢰할 수는 없다

공격자도 자신의 key pair를 만들 수 있다.

```text
Mallory private/public 생성
Mallory가 "이게 example.com의 public key다"라고 주장
```

수학적으로 유효한 public key라는 것과 특정 신원에 속한다는 것은 별개다. 이 간극을 인증서가 메운다.

---

<a id="certificates"></a>

## 11. 인증서: 도메인과 public key를 연결하는 서명된 문서

### 11.1 인증서 이전에 남은 질문

10장에서 `Verify(public, message, signature)`가 성공하는 것을 확인했다. 이것은 **그 public에 대응하는 private 보유자가 서명했다**는 검증이다. 그런데 public 자체를 Mallory에게 받았다면 성공한 검증도 Mallory를 확인한 것에 불과하다.

필요한 것은 `shop.example → 이 public key`라는 연결을 신뢰할 근거다. 이를 **identity binding**이라 부른다. public key를 안전한 채널로 미리 배포하거나, 앱에 고정하는 pinning을 할 수도 있다. 처음 방문하는 수많은 웹사이트에서는 certificate authority(CA, 인증기관)의 서명 체계를 이용한다.

### 11.2 인증서 안에 무엇이 있는가

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

브라우저/OS에는 신뢰하는 root CA 인증서들의 목록인 **trust store**가 미리 들어 있다. 각 인증서에 CA public key가 있다.

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

서버 이름은 일반적으로 SAN(subject alternative name) 확장의 DNS 이름으로 검사한다. `https://shop.example`에 접속했다면 **사용자가 접속하려던 shop.example**과 비교해야 한다. 상대가 내민 인증서의 이름으로 기대 hostname을 바꿔 버리면 검증 의미가 없다. [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525.html)

인증서 자체는 공개 정보다. 비밀은 서버 인증서의 public key에 대응하는 private key다. 이것을 편의상 certificate private key라 부르지만, **private key가 인증서 파일 안에 들어 있다는 뜻이 아니다**.

```text
서버:
certificate 공개 가능
certificate private key 비밀

브라우저:
certificate와 CA chain으로 서버 public key를 신뢰
```

### 11.3 Root CA는 누가 인증하는가: 신뢰의 시작점

root 인증서가 self-signed라는 사실이 그 root를 믿을 이유는 아니다. 공격자도 self-signed 인증서를 만들 수 있다. 신뢰는 OS·브라우저의 배포 정책이나 조직의 관리자가 **그 root를 trust store에 넣기로 결정한 것**에서 시작한다. 이 외부 결정을 trust anchor(신뢰 기준점)라고 한다.

chain 검증은 leaf에서 issuer로 올라가며 서명과 CA 제약 등을 확인하고, 로컬에서 이미 신뢰한 anchor에 도달하는 과정이다. 서버가 root까지 보내 주더라도 그것만으로 새 신뢰가 생기지 않는다. 인증서 검증을 끄는 대신, 사설 환경에서는 의도한 사설 CA를 그 client의 trust store에 명시적으로 넣는다.

### 11.4 인증서를 발급받는 단계와 접속할 때의 단계는 다르다

가상의 운영자 관점에서 순서를 보자.

1. 서버용 private/public key pair를 만든다. private는 서버/TLS 종단 또는 보호 서비스에 보관한다.
2. public key와 이름을 담은 CSR(certificate signing request) 등을 통해 발급을 요청한다.
3. CA는 요청자가 도메인을 통제하는지 정해진 절차로 확인한다. 예를 들어 HTTP 응답이나 DNS 레코드에 challenge 값을 게시하도록 한다.
4. CA는 도메인과 public key를 담은 인증서에 **CA 자신의 private key**로 서명한다.
5. 서버는 인증서와 chain을 배치하고, TLS 접속마다 **서버 자신의 private key**로 handshake에 서명한다.

도메인 검증 자동화의 구체적인 예는 [Let's Encrypt의 발급 과정](https://letsencrypt.org/how-it-works/)을 보자. 도메인 통제를 증명하는 것과 해당 회사가 정직하거나 서비스 코드가 안전하다는 것은 다른 주장이다.

두 서명을 분리하자. **CA 서명은 이름과 public key의 연결**, **서버 서명은 지금 연결 중인 상대가 대응하는 private key를 보유함**을 검증하게 한다. CA는 일반적인 각 HTTP 요청에 참여하지 않는다.

### 11.5 인증서만 복사하면 서버를 사칭할 수 있나

인증서는 누구나 복사할 수 있다. 하지만 Mallory가 정상 인증서를 보여 준 뒤 자기 ephemeral key로 진행하면, 그 handshake에 필요한 서버 서명을 만들지 못한다. 이전 연결의 서명을 복사해도 지금 연결의 key share와 transcript가 달라서 맞지 않는다. 이것이 다음 장의 `CertificateVerify`다.

**확인 질문:** CA private, 서버 장기 private, 서버 ephemeral private는 같은 것인가? 아니다. 각각 인증서 발급, 접속 중 신원 증명, 연결용 비밀 합의에 쓰인다.

---

<a id="tls"></a>

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

여기서는 **TLS 1.3, 인증서 기반 서버 인증, ephemeral DH, resumption/0-RTT 없는 첫 접속**을 가정한다. 모든 TLS 접속이 항상 이 모양은 아니다.

Transcript는 지금까지 주고받은 handshake 메시지의 정해진 바이트열을 순서대로 연결한 것이다. 그 hash가 transcript hash다. 메시지의 일부만 인증하면 공격자가 인증되지 않은 알고리즘 선택이나 key share를 바꿀 수 있으므로, **이번 협상 전체**에 서명과 key derivation을 묶는다.

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

서버 Finished까지의 transcript로
각 방향 application traffic secrets/key/IV 파생 가능

Finished
                         ════════ encrypted ═══════→

HTTP request/response
                         ←════ AEAD encrypted ════→
```

client Finished도 **handshake key**로 보호된다. application key를 파생할 수 있는 시점과 모든 인증 확인이 끝나 application data를 보내도 되는 시점은 구분한다. 실제 표준에는 더 많은 필드, transcript 처리, resumption, PSK, alerts 등이 있다. 위 그림은 구현용 명세가 아니라 역할을 분리하기 위한 지도다.

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
서버의 장기 인증용 signing private key (CA의 인증서 발급 key와 다름):
- 비교적 장기
- 서버 신원 증명
- Secret Manager/KMS/HSM/제한된 파일 등에서 보호

ephemeral X25519 key:
- 연결마다 새로 생성 가능
- shared secret 계산
- 보통 연결 종료 후 폐기
```

TLS 1.3에서 서버 인증서 public key가 HTTP body를 직접 암호화하는 것이 아니다. 인증서 key는 handshake에 서명하고, 실제 데이터는 key agreement와 HKDF로 만든 대칭 traffic key가 보호한다.

CA key가 RSA라고 key agreement까지 RSA가 되는 것도 아니다. CA의 인증서 서명 알고리즘, 서버 handshake 서명 알고리즘, ephemeral key agreement, record AEAD는 역할이 다르다.

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

**Finished는 무엇인가?** 지금까지의 transcript hash에 대해 handshake secret에서 파생한 `finished_key`로 계산한 HMAC을 담는다. 서버 서명이 신원과 이번 handshake를 연결한다면, Finished는 handshake 비밀을 실제로 계산한 당사자가 같은 협상 내용을 보고 있는지 확인한다. 공개 인증서 서명과 shared-secret 기반 key confirmation이 서로 다른 검사를 수행하는 셈이다.

예를 들어 `TLS_AES_128_GCM_SHA256`에서 AES-128-GCM은 record 보호, SHA-256은 HKDF와 transcript hash 등에 사용된다. 이름만 보고 “매 HTTP body에 SHA-256 HMAC을 덧붙인다”거나 “key agreement가 RSA다”라고 읽으면 안 된다. TLS 1.3에서는 key agreement group과 signature algorithm을 별도로 협상한다.

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

AES-GCM을 선택한 경우를 기존 실습 변수와 대응시켜 보자.

| 실습의 값 | TLS에서의 대응 |
|---|---|
| key K | 해당 송신 방향 application traffic key |
| nonce N | 해당 방향 write IV XOR 왼쪽을 0으로 채운 record sequence number |
| plaintext P | HTTP bytes의 일부 + inner content type + 선택적 padding |
| AAD | 바깥쪽 TLS record header |
| C + tag | 네트워크로 전달되는 암호화 record payload |

sequence number는 key가 바뀔 때 초기화하고, 같은 key로 번호가 돌아가도록 사용하지 않는다. 수신자도 순번을 관리하므로 기존 record를 중간에 끼워 넣으면 그 위치에서 기대한 nonce와 맞지 않는다. 이것은 **한 연결 안의 record 보호**다. 사용자가 새 연결에서 동일한 결제 요청을 다시 하는 것까지 막지는 않으므로 application idempotency는 별도로 설계한다.

tag 검증이 실패하면 record를 정상 데이터로 받아들이지 않는다. 이는 SQLite 실습에서 잘못된 key나 변경된 ciphertext가 `InvalidTag`를 만든 것과 같은 종류의 성질이다.

### 12.7 Forward secrecy

ephemeral Diffie-Hellman private key를 연결 후 폐기하면, 미래에 서버의 certificate private key가 유출되더라도 과거에 녹화한 TLS 트래픽의 shared secret을 바로 복구할 수 없도록 설계할 수 있다. 이것이 forward secrecy의 핵심이다.

certificate private key는 당시 서버 신원을 증명하는 데 쓰였고, 과거 traffic key 자체는 ephemeral key agreement에서 나왔기 때문이다.

단, 당시의 ephemeral secret이나 TLS key log가 이미 저장·유출되었으면 그 트래픽은 복호화될 수 있다. Forward secrecy는 “미래에 어떤 비밀이든 털려도 괜찮다”가 아니라 **장기 인증키의 사후 유출과 과거 session key를 분리**하는 성질이다.

### 12.8 첫 접속 이후: resumption과 0-RTT의 경계

서버는 다음 접속을 위한 resumption 정보를 발급할 수 있다. PSK(pre-shared key)는 여기서 이전 연결에서 확립한 비밀을 기반으로 할 수 있으므로, 사용자가 처음부터 모든 서버와 key를 직접 나눠야 한다는 뜻은 아니다.

0-RTT early data는 새 handshake가 완성되기 전의 데이터다. 일반적인 1-RTT application data와 replay/forward secrecy 성질이 같지 않다. 따라서 “TLS라서 결제 POST도 중복 실행될 수 없다”라고 추론하지 않는다. 이 책의 실습은 resumption과 early data를 사용하지 않는다. 세부 설계는 TLS 구현과 애플리케이션 정책의 영역으로 남긴다.

### 12.9 HTTPS란 결국 무엇인가

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
TCP 기반 HTTPS에서는 위 HTTP 바이트를 안전한 record로 운반

HTTP/1.1·HTTP/2의 전형적인 HTTPS:
HTTP → TLS records → TCP → IP

HTTP/3:
HTTP → QUIC streams/packets → UDP → IP
(QUIC은 TLS 1.3 handshake/key derivation을 통합하지만 TLS record layer는 쓰지 않음)
```

HTTP/3의 경우 TLS record를 UDP에 그대로 넣는 것이 아니다. QUIC이 자체 packet 보호를 담당한다. [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html)

브라우저가 HTTPS 연결을 정상적으로 검증했다는 것은 대략 다음을 의미한다.

- 브라우저와 TLS 종단 사이의 트래픽이 보호된다.
- 인증서 검증을 통해 접속한 hostname과 서버 public key의 연결을 확인했다.

다음까지 보장하지는 않는다.

- 서버 애플리케이션 자체가 선량하다.
- 서버가 받은 데이터를 안전하게 저장한다.
- TLS 종단 뒤 내부 네트워크가 자동으로 안전하다.
- 사용자의 기기가 악성코드에 감염되지 않았다.

또한 TLS만으로 IP 주소, 트래픽의 크기·시간 등 모든 메타데이터를 숨기지는 않는다. URL path와 body가 암호화된다는 사실을 네트워크 익명성과 혼동하지 않는다.

### 12.10 실제 TLS로 세 가지 가설을 검사한다

```bash
python3 04_tls/tls_memory_lab.py
```

예제는 실행할 때 임시 CA와 `localhost` 서버 인증서를 만들고, Python `ssl`의 실제 TLS 1.3 client/server를 연결한다. `MemoryBIO`는 TLS가 내보내는 바이트와 받아들이는 바이트를 메모리 buffer로 연결하는 인터페이스다. socket 대신 buffer를 운반하므로 네트워크나 관리자 권한이 필요 없으며 **TLS 알고리즘을 흉내 낸 코드가 아니다**. [Python ssl 문서](https://docs.python.org/3/library/ssl.html)

1. 그 CA를 명시적으로 신뢰하고 hostname도 맞으면 handshake와 HTTP bytes 전달이 성공한다.
2. CA는 같지만 기대 hostname을 `wrong.example`로 바꾸면 검증이 실패한다.
3. hostname은 맞아도 해당 CA를 신뢰하지 않으면 검증이 실패한다.

암호화된 application record와 복호화된 HTTP를 따로 관찰한다. 암호문에서 원문 문자열을 찾지 못했다는 결과만으로 보안을 증명하는 것은 아니지만, **앱이 읽는 바이트와 transport가 운반하는 바이트가 다름**을 확인할 수 있다.

생성한 인증서는 해당 실행의 client에서만 신뢰한다. OS trust store를 변경하지 않고 임시 private key 파일도 실행 후 제거한다. 인증서 수명·갱신·실제 DNS·소켓 운영을 다루는 배포 예제는 아니다.

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

<a id="labs"></a>

## 18. 현재 playground 실습 순서

### 실행 준비와 실습 경계

저장소 루트에서 Python 3.10 이상과 TLS 1.3을 지원하는 Python `ssl`/OpenSSL을 사용한다.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install cryptography pytest
python -m pytest
```

패키지 설치에는 인터넷이 필요하지만 아래 신규 비대칭/TLS 실습에는 네트워크가 필요 없다. 기존 시스템에서 이미 의존성을 설치했다면 가상환경 준비를 다시 할 필요는 없다.

`gcm_walkthrough.py`의 고정 key/nonce는 단일 계산을 재현하기 위한 fixture이고, `nonce_reuse.py`는 의도적인 실패 예제다. 비밀을 출력하는 디버깅 패턴까지 운영 코드에 가져가지 않는다. SQLite 실습은 로컬 DB에 쓰므로 기존 데이터를 쓰기 전에 key 보관 상태를 확인한다. 새 TLS 실습은 임시 디렉터리만 사용한다.

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

### 3단계: 비대칭키의 계산과 역할

```bash
python3 03_asymmetric/key_roles_lab.py dh
python3 03_asymmetric/key_roles_lab.py mitm
python3 03_asymmetric/key_roles_lab.py rsa
python3 03_asymmetric/key_roles_lab.py x25519
python3 03_asymmetric/key_roles_lab.py signature
python3 03_asymmetric/x25519_exchange.py
```

예상 결과의 의미:

| 실습 | 핵심 결과 | 결과가 뜻하지 않는 것 |
|---|---|---|
| dh | A=8, B=19, 양쪽 S=2; 공격자도 a=6 복구 | 작은 수 DH가 안전하다는 뜻이 아님 |
| mitm | Alice–Mallory=12, Bob–Mallory=15 | 공격자가 이산로그를 풀었다는 뜻이 아님 |
| rsa | 65 → 2790 → 65 | textbook RSA를 사용해도 된다는 뜻이 아님 |
| x25519 | 방향별 key 일치, Bob 복호화 성공 | public key 소유자를 인증했다는 뜻이 아님 |
| signature | 정상 True, 변조 False, 다른 key False | public key의 신원을 저절로 안다는 뜻이 아님 |

이 실습에서 볼 질문:

```text
Alice private는 어디에 있는가?
Bob private는 어디에 있는가?
네트워크를 통과하는 값은 무엇인가?
shared secret 자체가 전송되는가?
왜 양쪽 HKDF 결과가 같은가?
왜 이것만으로는 Mallory의 중간자 공격을 막지 못하는가?
```

### 4단계: 인증서와 실제 TLS

```bash
python3 04_tls/tls_memory_lab.py
python3 -m pytest
```

대표 출력은 다음과 같다. 협상된 cipher suite 이름은 OpenSSL 환경에 따라 달라질 수 있다.

```text
trusted CA + matching hostname: TLSv1.3 / TLS_AES_256_GCM_SHA384
plaintext request visible on wire: False
server received: b'GET /account HTTP/1.1\r\nHost: localhost\r\n\r\n'
wrong hostname: rejected (...)
untrusted CA: rejected (...)
```

여기까지 끝나면 별도의 key log나 Wireshark 없이도 public key가 인증서로 신원에 연결되고, handshake 이후 HTTP가 대칭 암호로 전달되는 경계를 관찰한 것이다. cipher suite의 SHA384가 낯설다면 SHA-256과 같은 해시 역할을 하되 출력·내부 규격이 다른 SHA-2 계열이라고 읽고, 알고리즘의 역할을 먼저 확인하자.

### 다음 단계로 넘어가는 기준

출력을 똑같이 얻는 것보다 아래 질문에 **값의 위치와 연산**으로 답하는 것이 중요하다.

1. 전송한 값과 전송하지 않은 값을 구분할 수 있는가?
2. tag가 맞는데도 안전하지 않은 상황을 하나 설명할 수 있는가?
3. 서버 인증서의 key와 HTTP용 AES key를 구분할 수 있는가?
4. 암호문을 저장한 DB와 복호화 권한을 가진 앱의 침해 결과를 구분할 수 있는가?

답이 막히면 새 용어를 더 추가하지 말고 해당 장의 손계산 또는 실패 실습으로 돌아간다.

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

---

<a id="exercises"></a>

## 부록 A. 확인 문제와 해설 — 출력 관찰에서 설명으로

먼저 답을 가리고 설명해 보자. 해설과 단어가 같을 필요는 없지만 **공격자가 무엇을 갖고 있고 무엇을 계산하는지**는 들어가야 한다.

### A.1 DB 유출: “서버가 hash 하나 들고 비교하면 되지 않나?”

서버가 `salt, scrypt(password,salt)`를 보관한다. 공격자가 DB를 얻었다. 로그인 서버는 rate limit을 적용한다. 공격자는 왜 여전히 후보를 많이 검사할 수 있나?

**해설:** 자신의 장비에서 salt와 후보 비밀번호를 scrypt에 넣어 유출된 verifier와 비교한다. 서버를 호출하지 않으므로 서버 rate limit이 적용되지 않는다. KDF cost는 이 로컬 계산에 비용을 부과한다. 공격자가 verifier 자체를 로그인 요청으로 제출해도 서버는 그것을 비밀번호 후보로 KDF에 넣으므로 원래 프로토콜에서는 곧바로 로그인되지 않는다. verifier를 그대로 credential로 받는 별도 설계를 하면 이야기가 달라진다. → 5장.

### A.2 Salt를 암호화하면 더 안전해지나?

같은 비밀번호를 쓰는 두 사용자에게 서로 다른 공개 salt가 있다. 출력이 다른 이유와 공격자가 잃는 재사용 기회를 설명하라.

**해설:** KDF 입력이 달라졌으므로 출력도 달라진다. 한 salt에 대해 계산한 후보별 출력표를 다른 salt에 그대로 적용하지 못한다. salt는 비밀이 아니며 숨기는 것이 기본 방어 전제가 아니다. 공개 salt는 입력 비밀번호 자체의 후보 수를 늘리는 것도 아니다. → 5.3절.

### A.3 한 key면 출력도 항상 같아야 하는가?

K는 고정하고 nonce만 바꿨다. Bob이 복호화할 수 있는 이유를 AES 입력 수준에서 설명하라.

**해설:** AES 입력은 `N || counter`다. N이 달라지면 같은 K 아래에서도 mask가 달라진다. Bob은 수신한 N과 이미 가진 K로 동일 mask를 재현하고 ciphertext와 XOR한다. 필요한 것은 과거 메시지와 출력이 같다는 조건이 아니라 **이번 메시지의 양쪽 mask가 같다는 조건**이다. → 7.1절.

### A.4 Nonce 공개와 nonce 재사용은 왜 전혀 다른가?

**해설:** N만으로 `AES_K(N||counter)`를 계산할 수는 없다. 하지만 같은 K,N을 두 번 사용하면 동일 mask S가 재사용되어 `(P1 XOR S) XOR (P2 XOR S) = P1 XOR P2`로 소거된다. 공개 여부와 반복 여부는 다른 조건이다. → `nonce_reuse.py`.

### A.5 AAD를 포함한 row 전체를 바꿔치기하면?

DB의 Alice ciphertext와 `aad="alice"`를 Bob ciphertext와 `aad="bob"`으로 통째로 바꿨다. 앱은 DB에 적힌 AAD를 그대로 decrypt에 넘긴다. 왜 유효할 수 있나?

**해설:** Bob ciphertext는 Bob AAD 아래에서 원래 유효했다. 앱이 현재 요청은 Alice라는 신뢰 문맥을 강제하지 않았기 때문이다. 예상 record/tenant identity에서 AAD를 만들거나 수신 metadata와 기대값을 비교해야 한다. 그래도 같은 row의 과거 유효 버전으로 rollback하는 공격은 최신성 상태 없이 막지 못한다. → 7.2절.

### A.6 KMS가 key를 숨기는데 앱 RCE는 왜 위험한가?

**해설:** RCE(remote code execution)는 앱 권한으로 코드를 실행하는 침해다. 앱이 KMS decrypt/unwrap을 허가받았다면 공격자도 그 권한으로 요청할 수 있다. KEK 자체를 추출하지 못해도 plaintext 또는 DEK를 얻을 수 있다. 보호 경계는 key의 물리적 위치뿐 아니라 **사용 권한**까지 포함한다. → 8~9장.

### A.7 RSA와 X25519의 인터페이스를 구별하라

`X25519.exchange(peer_public)`에 왜 plaintext 인자가 없는가?

**해설:** 메시지 암호화가 아니라 shared secret 합의 연산이기 때문이다. 자기 private와 상대 public으로 S를 계산하고 KDF로 AES key를 만든 후 AEAD에 plaintext를 넣는다. RSA-OAEP의 encrypt는 수신자의 public key로 제한된 크기의 메시지를 암호화하는 다른 인터페이스다. → 10장.

### A.8 Diffie–Hellman에서 S가 같은 이유를 계산하라

p=23, g=5, a=6, b=15에서 A와 B 및 S를 구하라. Mallory가 공개값끼리 곱하면 왜 S가 아닌가?

**해설:** A=8, B=19, `pow(19,6,23)=pow(8,15,23)=2`다. 두 계산의 지수는 ab=90이다. 반면 `8*19 mod 23=14`는 지수 a+b=21에 대응한다. 작은 그룹에서는 후보를 전수조사할 수 있으므로 이 수치는 보안용이 아니다. → 10.2절.

### A.9 HMAC도 서명인데 왜 public key가 필요한가?

**해설:** MAC도 authenticity를 제공하지만 검증자는 shared secret을 알아야 하므로 생성 능력도 갖는다. digital signature는 생성용 private와 검증용 public을 분리한다. 배포 파일을 검증하는 모든 사용자가 제작자의 새 서명을 만들 수 있게 하고 싶지 않으므로 signature가 적합하다. 다만 public key가 누구 것인지는 별도로 신뢰해야 한다. → 10.6절.

### A.10 정상 서버의 인증서를 복사한 Mallory

인증서의 CA 서명은 그대로 유효하다. 그런데 TLS 인증은 왜 실패하는가?

**해설:** 현재 handshake의 transcript에 대해 인증서 public key로 검증되는 `CertificateVerify`를 만들 private key가 없기 때문이다. 자신의 인증서로 바꾸면 기대 hostname 또는 trust chain 검증이 실패한다. 물론 endpoint private key나 신뢰하는 CA가 침해된 상황은 이 전제 밖이다. → 11~12장.

### A.11 Forward secrecy를 침해하는 것은 무엇인가?

공격자가 과거 트래픽을 녹화했다. 나중에 (a) 서버 장기 서명키만 얻은 경우와 (b) 해당 연결의 traffic secret까지 얻은 경우를 비교하라.

**해설:** ephemeral DH가 안전하게 사용되고 일회성 비밀이 폐기되었다면 (a)만으로 과거 DH secret을 계산할 수 없다. (b)는 해당 방향의 traffic key/IV를 파생하는 데 필요한 비밀이므로 과거 기록을 복호화할 수 있다. 운영 환경의 TLS key log는 매우 민감하다. → 12.7절.

### A.12 설계 과제: 사용자가 맡긴 API token

다음 값을 어디에 두고 누가 접근하는지 그려 보자: browser plaintext, TLS traffic key, app plaintext, DEK, wrapped DEK, KEK, DB ciphertext, workload credential.

**해설의 골격:** TLS key는 브라우저와 TLS 종단이 연결용으로 갖는다. 앱은 token plaintext를 받은 뒤 DEK로 필드 암호화한다. DB에는 ciphertext/tag, nonce, wrapped DEK, key 식별자와 context metadata를 둔다. KEK는 KMS 경계에 남고, workload credential은 앱이 unwrap 권한을 행사하게 한다. DEK와 token plaintext는 사용 중 앱 메모리에 존재한다. TLS key를 DB 필드 key로 재사용하지 않는다. 이 설계의 공격 모델은 DB 단독 유출이지 앱 완전 장악까지가 아니다. → 8장·14장.

---

<a id="glossary"></a>

## 부록 B. 용어 찾아보기

| 용어 | 이 책에서의 정확한 역할 | 다시 읽을 곳 |
|---|---|---|
| Primitive / protocol | 암호 기본 연산 / 여러 연산·메시지·상태를 결합한 규칙 | 0장, 12장 |
| CSPRNG / entropy | 예측하기 어려운 난수 생성기 / 입력의 불확실성 | 0.6절 |
| Digest / verifier | 해시 출력 / 후보 비밀번호를 비교하기 위한 저장값 | 4~5장 |
| Salt / pepper | KDF의 공개 구분 입력 / 별도로 보관하는 비밀 입력 | 5.3절 |
| KDF / HKDF | key material 파생 함수 / HMAC 기반 extract-and-expand KDF | 5장, 10.4절 |
| MAC / HMAC | 공유키 기반 인증값 / 해시를 사용한 특정 MAC 구성 | 6장 |
| Block cipher / permutation | 고정 길이 블록 암호 / 일대일 가역 재배열 | 7.0절 |
| XOR / keystream | 비트별 배타적 논리합 / 평문에 XOR하는 mask의 연속 | 7.0절 |
| Nonce / counter / IV | 사용 구분값 / 증가하는 번호 / 모드의 초기화 값 | 7.1절, 12.6절 |
| AEAD / AAD / tag | 부가 데이터 인증을 지원하는 인증 암호 / 공개 인증 문맥 / 검증값 | 7장 |
| DEK / KEK / wrapping | 데이터 암호화 key / key 보호 key / key를 보호해 포장하는 연산 | 8.4절 |
| KMS / HSM | key 관리·연산 서비스 / key 보호를 위한 하드웨어 경계 | 8.3절 |
| Workload identity / IAM | 실행 중 앱의 신원 / 신원·권한 관리 체계 | 9.2절 |
| Group / order / generator | 연산이 정의된 군 / 반복 주기 / 군을 생성하는 원소 | 10.1절 |
| Scalar multiplication | 점을 정수 횟수만큼 군 연산으로 더하는 계산 | 10.3절 |
| Key agreement / KEM | 양쪽 비밀 입력으로 합의 / encapsulation을 통한 공유 비밀 수립 | 10장 |
| Digital signature | private로 생성하고 public으로 검증하는 서명 | 10.6절 |
| PKI / CA / trust anchor | 공개키 신뢰 인프라 / 인증기관 / 사전 결정된 신뢰 기준점 | 11장 |
| CSR / SAN | 인증서 발급 요청 / 인증서에 기록된 이름 확장 | 11장 |
| Transcript / Finished | handshake 바이트 기록 / 협상 내용과 비밀 보유의 확인 메시지 | 12장 |
| Ephemeral / forward secrecy | 일회성 키 수명 / 장기키 사후 유출로부터 과거 연결 보호 | 12.3·12.7절 |
| Termination / mTLS | TLS 연결의 종단 / TLS 단계에서 상호 인증 | 13장 |

IV(initialization vector)는 모드마다 요구사항이 다르다. 이 책의 AES-GCM에서는 API가 받는 nonce를 IV라고 부르기도 하지만, 모든 암호 모드의 IV에 GCM 규칙을 그대로 적용하면 안 된다. TLS의 static write IV는 다시 sequence number와 결합해 per-record nonce를 만든다.

## 부록 C. 여기서 다루지 않은 범위

이 책은 **직접 구현한 암호를 배포하기 위한 매뉴얼이 아니라, 검증된 구현을 올바른 경계에 사용하는 사고 훈련**이다. 다음 내용은 별도 학습이 필요하다.

- 보안 정의와 reduction의 엄밀한 증명, chosen-ciphertext security.
- Side channel: timing/cache/power/fault 공격, constant-time 구현, 안전한 메모리 소거. Python의 `del`은 key 바이트의 물리적 소거를 보장하지 않는다.
- 운영 PKI의 갱신·폐지·투명성 로그·인증서 자동화, TLS resumption 세부 규칙.
- KMS 정책·cross-account 권한·장애 복구·backup 복호화의 실제 운영 검증.
- 암호화된 데이터의 검색, end-to-end encryption, 메신저 ratchet, post-quantum 전환.

알아야 할 경계를 명확히 남기는 것은 설명을 생략하는 것과 다르다. 지금의 목표는 **어떤 비밀이 어느 연산에 참여하고, 누가 무엇을 검증하며, 어떤 공격이 여전히 가능한지** 스스로 추적하는 것이다.
