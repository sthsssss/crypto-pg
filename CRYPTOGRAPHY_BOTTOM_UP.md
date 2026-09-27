# 나의 Crypto Book — 바이트에서 비대칭키, 키 관리, HTTPS까지

> 대상: 애플리케이션 개발 경험은 있지만 암호학 용어가 아직 하나의 그림으로 연결되지 않은 개발자
>
> 목표: `해시 → 비밀번호 저장 → HMAC → AES-GCM → 키 관리 → 비대칭키 → 인증서 → TLS/HTTPS`를 바텀업으로 연결한다.
> 개정판: 5 · 기준일: 2026-09-27 · Python 3.10 이상

암호학을 처음 공부하면 함수 이름은 빠르게 늘어난다. SHA-256, Argon2id, HMAC, AES-GCM, X25519, HKDF, 인증서, TLS. 각각의 정의를 읽을 때는 이해한 것 같은데, 막상 서버 한 대를 설계하려 하면 key가 어디에서 생기고 누가 갖는지, nonce를 왜 저장하는지, 인증서와 AES가 한 연결 안에서 어떻게 만나는지 다시 흐려진다. 이 책은 그 흐려지는 지점을 출발점으로 삼는다.

끝까지 따라갈 대상은 `shop.example`이라는 작은 서비스다. 사용자는 브라우저에서 로그인하고, 외부 서비스의 API token을 맡긴다. 애플리케이션은 그 token을 DB에 보관했다가 worker가 필요할 때 복원해 외부 API를 호출한다. 이 평범한 요구에는 이미 여러 문제가 겹쳐 있다.

```text
사용자 password를 서버가 어떻게 검증할 것인가?
브라우저가 보낸 token을 네트워크에서 누가 읽거나 바꾸지 못하게 하려면?
DB가 유출되어도 token 원문을 감추려면?
암호화 key를 DB와 분리한다는 것은 실제로 어디에 둔다는 뜻인가?
처음 만난 브라우저와 서버는 공유 key 없이 어떻게 안전한 연결을 시작하는가?
브라우저가 받은 public key가 정말 shop.example의 것임을 어떻게 아는가?
```

각 장은 이 질문 중 하나를 해결한다. 그리고 해결할 때마다 아직 남은 문제를 일부러 드러낸다. SHA-256은 데이터 지문을 만들지만 송신자를 인증하지 못한다. HMAC은 변조를 검출하지만 내용을 숨기지 않는다. AES-GCM은 숨기고 변조를 거부하지만 양쪽이 이미 같은 key를 가져야 한다. X25519는 shared secret을 만들지만 상대의 신원을 알려 주지 않는다. 인증서는 public key를 이름에 연결하고, TLS는 이 부품들을 실제 네트워크 순서로 조립한다.

그러므로 이 책에서 가장 중요한 질문은 “이 알고리즘의 내부 라운드는 무엇인가?”가 아니다. 먼저 다음 다섯 가지를 추적한다.

```text
누가 어떤 값을 갖는가?
어떤 bytes가 함수에 들어가는가?
무엇이 출력되고 어디로 이동하는가?
그 결과 공격자가 무엇을 못 하게 되는가?
그래도 아직 무엇은 막지 못하는가?
```

이 다섯 질문이 보이면 수식은 역할을 설명하는 도구가 된다. 보이지 않으면 수식은 암기할 기호가 된다. 첫 독서에서는 역할과 경계를 먼저 세우고, 알고리즘 내부는 필요할 때 선택 심화로 돌아온다.

이 책은 프로그래밍을 처음 배우는 사람을 위한 책이 아니다. 함수, 바이트 배열, DB transaction, HTTP는 알고 있지만 암호학의 수학적 전제와 protocol의 연결을 처음 구축하는 개발자를 위한 책이다. 전문 용어를 생략하지 않고, 그 용어가 가리키는 **입력·출력·소유자·보안 성질**을 설명한다.

### 이 책을 읽는 방법

각 개념은 **문제 → 정의 → 작은 계산 → 공격자의 관점 → 실제 API → 확인 문제** 순서로 읽는다. 수학적 계산이 맞다는 것과 실무에 안전하다는 것은 다른 판단이다. 작은 수를 쓰는 DH·RSA 예제는 계산의 구조만 보여 주며, 실제 보안 파라미터는 라이브러리에 맡긴다.

이 책의 모든 문장을 첫 독서에서 이해할 필요는 없다. 각 장은 다음 세 층으로 읽는다.

```text
1. 핵심 정신 모델
   누가 어떤 값을 가지고, 무엇을 입력해, 어떤 출력을 얻는가?

2. 실습과 통과 기준
   정상 동작과 실패를 실행해 보고 핵심 문장을 내 말로 설명할 수 있는가?

3. 선택 심화
   round, padding, counter, 유한체 연산과 공격의 정확한 성립 과정을 추적한다.
```

첫 독서에서는 **핵심 정신 모델과 통과 기준만 읽고 다음 장으로 이동해도 된다.** `선택 심화`는 앞 장을 통과하기 위한 시험 범위가 아니다. 실습 결과를 이해하지 못했거나 특정 내부 원리가 궁금해졌을 때 돌아오는 참고 절이다. 기술 용어를 숨기지는 않되, 용어의 내부 구현까지 한 번에 이해해야 한다고 요구하지 않는다.

처음 읽을 때는 0~7장에서 각 primitive의 역할과 실패 조건을 연결하고, 8~9장에서 저장 아키텍처를 본 뒤, 10~12장에서 이를 HTTPS로 조립한다. 첫 독서의 10장 목표는 `exchange()`의 두 결과가 왜 같은 용도의 secret인지와 private/public의 소유 경계를 설명하는 것이다. 작은 수의 DH·타원곡선·RSA 손계산은 두 번째 독서에서 재현한다.

### 목차와 독서 경로

| 구간 | 핵심 질문 | 링크 |
|---|---|---|
| 기초 언어 | 키가 다르다는 것은 어떤 연산이 다르다는 뜻인가? | [0장](#foundations), 1~3장 |
| 해시·비밀번호·인증 | 비교값을 저장해도 되는 경우와 안 되는 경우는? | [4장](#hash), [5장](#password), [6장](#mac) |
| 대칭 암호 | key와 nonce가 각각 어디에서 참여하는가? | [7장](#symmetric) |
| 저장과 키 운영 | DB, 프로세스, KMS에는 각각 무엇이 있는가? | [8장](#storage), [9장](#lifecycle) |
| 비대칭 암호 | 다른 private key로 왜 같은 비밀이 계산되는가? | [10장](#asymmetric) |
| 신뢰와 통신 | 공개키가 누구 것인지 어떻게 알고 HTTPS로 연결하는가? | [11장](#certificates), [12장](#tls), 13~14장 |
| 로그인 상태와 토큰 | 로그인 결과를 이후 API 요청에서 어떻게 증명하는가? | [12.10절](#tokens) |
| 연습과 복습 | 내 말로 설명하고 실험으로 반증할 수 있는가? | [18장](#labs), [연습문제·해설](#exercises), [용어 찾아보기](#glossary) |
| 실습 코드 독해 | 내가 실행한 함수에서 실제로 어떤 값이 변하는가? | [부록 D: 함수별 실행 추적](#function-walkthrough) |

#### 처음 한 번만 읽을 때의 빠른 경로

아래 경로는 이 책의 축약본이다. 선택 심화를 건너뛰어도 이후 장의 핵심 설명이 이어지도록 구성한다.

| 장 | 첫 독서에서 읽을 부분 | 처음에는 건너뛸 부분 |
|---|---|---|
| 0~3 | 전체 | 없음 |
| 4 | 장 도입, 4.2, 실습 | 4.1 SHA-256 round |
| 5 | 가입·로그인 흐름, 5.1~5.3 | scrypt `N/r/p` 계산 |
| 6 | 장 도입, 6.2, 실습 | 6.1 length extension과 HMAC 내부 수식 |
| 7 | 7.1, 7.2, 7.6, 실습 | 7.3~7.5 AES/GHASH 내부 |
| 8~9 | 8.1~8.3, 8.7~9.7 | 8.4 envelope encryption의 상세 pseudocode는 두 번째 독서 |
| 10 | 장 도입, X25519 라이브러리 흐름, 10.4~10.6, 10.8 | 10.1~10.2와 10.3 앞부분의 수학, 10.7 RSA 산술 |
| 11 | 전체 | 인증서 세부 필드는 암기하지 않음 |
| 12 | 12.1, 12.2, 12.9, 12.11 | 12.3~12.8 handshake 내부는 두 번째 독서 |
| token | 12.10.1~12.10.5, 12.10.9~12.10.13 | 12.10.6~12.10.8 JWT 서명·검증 상세 |

첫 독서의 목표는 모든 수식을 재현하는 것이 아니라 **각 값의 소유자, 입력, 출력, 보장, 실패 조건**을 말할 수 있게 되는 것이다.

### 독자의 머릿속에서 바뀌어야 하는 그림

이 책의 장들은 용어를 하나씩 추가하는 목록이 아니다. 앞 장에서 만든 멘탈모델이 다음 장에서 조금씩 수정되는 과정이다.

```text
0~3장   암호화 = 어려운 함수
          ↓
        각 값에는 역할·소유자·공개 규칙이 있다

4~7장   digest나 ciphertext 하나가 데이터를 지켜 준다
          ↓
        지문·비밀번호 검증·메시지 인증·인증 암호는 서로 다른 문제다

8~9장   강한 알고리즘과 key 하나를 고르면 끝난다
          ↓
        key의 위치·권한·버전·수명주기가 시스템 보안의 절반이다

10~12장 public key로 암호화하면 HTTPS가 된다
          ↓
        key agreement, signature, certificate, HKDF, AEAD가 각자 한 역할을 맡는다

13~19장 HTTPS와 DB 암호화를 켜면 서비스 전체가 안전하다
          ↓
        데이터가 지나는 모든 신뢰 경계와 남은 공격을 끝까지 추적해야 한다
```

따라서 어느 장에서 막히면 새 용어를 더 외우지 말고, 그 장을 읽기 전과 후에 **누가 무엇을 갖는 그림이 어떻게 달라졌는지** 확인한다. 이 변화가 보이면 다음 장으로 갈 준비가 된 것이다.

# 제1부. 암호를 읽기 위한 언어

첫 번째 부에서는 아직 데이터를 암호화하지 않는다. 대신 이후의 모든 설명을 읽을 공통 언어를 만든다. `bytes`, key, nonce, tag 같은 단어를 정확히 구분하고, 한 알고리즘이 무엇을 보장하며 무엇은 보장하지 않는지 묻는 습관을 세운다.

<a id="foundations"></a>

## 0. 기초 언어 — 정확히 무엇을 계산하고 무엇을 보장하는가

**이 장에서 반드시 이해할 것:** 암호 함수는 문자열이 아니라 bytes를 처리하며, “정상적으로 복호화된다”와 “공격자에게 안전하다”는 서로 다른 주장이다. 알고리즘은 공개되어 있고 비밀로 보호하는 것은 key다. 기밀성·무결성·인증·인가는 서로 바꿔 쓸 수 없는 보안 성질이다.

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

> **0장 통과 기준:** 문자열과 bytes의 차이, correctness와 security의 차이, confidentiality/integrity/authentication/authorization의 차이, 공개 알고리즘에서 무엇을 비밀로 두는지 설명할 수 있으면 1장으로 이동한다. 엔트로피의 수학적 정의를 전개할 필요는 없다.

---

## 1. 먼저 전체 지도를 보자

0장에서 우리는 암호 함수를 “이름”이 아니라 입력·출력·보안 성질로 읽는 언어를 만들었다. 이제 앞으로 만날 도구를 한 장의 지도에 놓아 보자. 이 표를 처음부터 외울 필요는 없다. 다음 장들을 읽다가 현재 위치를 잃었을 때 돌아오는 지도다.

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

이 지도에서 눈여겨볼 것은 각 화살표가 앞 도구의 부족한 점에서 시작한다는 사실이다. Password는 빠른 SHA-256이 아니라 password KDF로 검증하고, 공개 메시지의 출처를 확인하려면 HMAC이나 signature가 필요하며, 네트워크 통신에는 이 부품들을 순서 있게 조립한 TLS가 필요하다. 다음 장에서는 알고리즘보다 먼저, 우리가 보호할 데이터가 어느 순간에 노출되는지 살펴본다.

---

## 2. 데이터는 언제 위험한가

같은 API token도 이동 중일 때, DB에 잠들어 있을 때, worker가 사용하려고 메모리에 꺼냈을 때의 공격자가 다르다. “암호화했는가?”라고 묻기 전에 “지금 데이터가 어느 상태에 있는가?”를 물어야 하는 이유다.

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

`shop.example`의 token은 브라우저에서 서버로 갈 때는 TLS의 보호를 받고, DB에 들어갈 때는 별도의 application key로 암호화될 수 있으며, 외부 API를 호출할 때는 다시 plaintext가 된다. 하나의 암호화가 세 상태를 모두 해결하지 않는다. 다음 장에서는 이 세 구간에서 반복해서 등장할 key·nonce·tag 같은 값에 정확한 이름을 붙인다.

---

## 3. 바이트와 이름부터 정확히 구분하기

암호학 설명이 어려워지는 첫 번째 이유는 서로 다른 값을 모두 “암호키 같은 것”으로 부르는 데 있다. Key, salt, nonce, tag는 길이가 비슷하게 보일 수 있지만 비밀 여부도, 생성 시점도, 재사용 규칙도 다르다. 이제부터는 값의 이름을 보면 그 값의 직업을 떠올릴 수 있어야 한다.

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

> **1~3장 통과 기준:** 보호하려는 데이터가 transit/rest/use 중 어디에 있는지 말할 수 있고, key·salt·nonce·tag·AAD의 소유자와 공개 가능 여부를 구분하며, Base64가 암호화가 아님을 설명할 수 있으면 4장으로 이동한다.

---

# 제2부. 공개 함수에서 공유 비밀까지

이제 실제 primitive를 하나씩 사용한다. 순서는 의도적이다. 먼저 비밀이 전혀 없는 SHA-256을 보고, 낮은 엔트로피의 password를 다루는 방법으로 이동한다. 그다음 shared key가 생기면 메시지의 출처를 확인할 수 있고, 마지막에는 같은 key로 내용까지 숨길 수 있음을 확인한다. 각 도구는 앞 도구의 빈자리를 메우지만, 다른 도구의 역할을 빼앗지는 않는다.

<a id="hash"></a>

## 4. SHA-256: 비밀이 없는 데이터 지문

이제 첫 번째 실제 primitive를 만난다. `shop.example`이 파일이나 설정값이 바뀌었는지 비교하려면 원문 전체 대신 짧고 고정된 지문을 만들고 싶을 수 있다. SHA-256은 이 일을 잘한다. 다만 지문을 만들 수 있다는 사실과 그 지문을 믿을 수 있다는 사실은 다르다.

**이 장에서 반드시 이해할 것:** SHA-256은 key가 없는 공개 함수다. 같은 bytes에는 같은 digest를 만들지만, 공격자도 원하는 입력의 digest를 계산할 수 있다. 따라서 digest만으로 송신자나 데이터의 출처를 인증할 수는 없다.

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

코드와 연결: [D.1 — `sha256()`과 `differing_bits()`](#trace-hash).

> **첫 읽기 경로:** 여기까지 읽고 실습 출력에서 같은 입력/다른 입력의 digest를 비교한 다음 [4.2절](#sha-guessing)로 이동해도 된다. 바로 아래 SHA-256 round 설명은 선택 심화다.

### 4.1 선택 심화: SHA-256 내부의 데이터 흐름

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

<a id="sha-guessing"></a>

### 4.2 다음 장으로 이어지는 핵심: 복호화가 없는데 비밀번호는 왜 알아낼 수 있는가

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

SHA-256을 지나며 얻은 멘탈모델은 **digest는 데이터에서 계산한 공개 지문**이라는 것이다. 지문은 비교에는 유용하지만 신뢰의 출처를 스스로 만들지 못한다. 또한 입력 후보가 적으면 공격자가 후보마다 지문을 계산할 수 있다. 바로 이 성질 때문에 사용자 password를 빠른 SHA-256 하나로 저장해서는 안 된다.

> **4장 통과 기준:** `SHA256(data)`에 secret key 인자가 없다는 것, 공격자가 message와 digest를 함께 바꿀 수 있다는 것, 비밀번호 후보를 hash해 비교하는 일은 복호화가 아니라 추측이라는 것을 설명할 수 있으면 5장으로 이동한다. Padding과 64라운드를 외울 필요는 없다.

---

<a id="password"></a>

## 5. 비밀번호는 암호화하지 않고 검증한다

4장에서 본 공격자는 digest를 거꾸로 푸는 대신 흔한 입력을 앞으로 계산했다. Password 저장은 바로 그 공격을 전제로 설계해야 한다. 서버가 해야 할 일은 password를 나중에 읽어 주는 것이 아니라, 사용자가 다시 제출한 후보가 등록 당시의 값과 같은지 판단하는 것이다.

**이 장에서 반드시 이해할 것:** 서버는 password를 나중에 복구하려고 저장하지 않는다. 가입할 때 만든 verifier를 저장하고, 로그인 때 제출된 후보로 verifier를 다시 계산해 비교한다. verifier는 password 원문이 아니지만 DB가 유출되면 공격자가 후보를 대입해 볼 수 있으므로, 그 대입을 비싸게 만드는 password KDF가 필요하다.

```text
password KDF
    password와 salt를 받아
    의도적으로 시간·메모리를 사용해
    비교용 verifier를 만드는 함수

Argon2id, scrypt
    password KDF의 구체적인 알고리즘
```

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

코드와 연결: [D.2 — `register → derive → verify`](#trace-password).

> **첫 읽기 경로:** 위의 가입·로그인·DB 유출 흐름을 먼저 이해한다. 아래에서는 `derived_key`라는 이름, 공격을 느리게 하는 방법, salt의 역할을 각각 정리한다. scrypt의 정확한 `N/r/p` 비용식은 선택 심화이므로 처음에는 건너뛰어도 된다.

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

#### Argon2id를 읽는 최소한의 구조

Argon2id도 같은 목적의 memory-hard password KDF다. 이름 끝의 `id`는 Argon2i와 Argon2d의 메모리 접근 방식을 결합한 variant임을 뜻한다. 애플리케이션 개발자가 내부 압축 함수를 구현할 필요는 없지만, 어떤 비용을 서버가 선택하는지는 알아야 한다.

```text
Argon2id(
    password,
    salt,
    memory_cost m,
    iterations t,
    parallelism p,
    output_length
) → verifier
```

개념적으로 Argon2id는 큰 메모리 영역을 여러 block으로 채우고, 앞에서 만든 block들을 반복해서 참조·혼합한 뒤 최종 verifier를 만든다. `m`은 사용할 메모리 양, `t`는 그 메모리를 몇 pass 처리할지, `p`는 lane/병렬도다. 출력에서 password를 복구하는 복호화 연산은 없다.

저장 문자열은 구현에 따라 다음처럼 알고리즘과 비용, salt, verifier를 함께 표현할 수 있다.

```text
$argon2id$v=19$m=65536,t=3,p=1$<salt>$<verifier>
```

이 문자열이 알려져도 공격자는 여전히 후보 password마다 Argon2id를 실행해야 한다. 반대로 salt와 parameter가 없으면 정상 서버도 로그인 때 같은 계산을 재현할 수 없다.

Memory-hard라는 성질은 서버에도 비용이다. 한 번의 검증에 64 MiB를 쓰는 설정에서 100건을 동시에 시작하면 Argon2 작업만 이론상 약 6.4 GiB를 요구할 수 있다. 그래서 운영 서버는 로그인 요청을 무제한 병렬 실행하지 않는다.

```text
로그인 endpoint rate limit
        │
        ▼
길이가 제한된 작업 queue
        │
        ▼
동시 실행 수가 제한된 password worker
        │
        ▼
Argon2id verify
```

작은 서비스에서는 이를 애플리케이션 내부의 제한된 worker pool로 시작할 수 있다. 서비스 규모와 보안 경계가 커지면 인증 서비스를 분리할 수 있지만, OOM 방지의 첫 수단은 마이크로서비스 분리가 아니라 **parameter benchmark, rate limit, queue 상한, 동시성 제한**이다. 로그인 성공 뒤의 일반 API 요청은 password KDF를 매번 실행하지 않고 session 또는 access token을 사용한다.

#### 선택 심화: 실습에 사용한 scrypt 파라미터

실습의 파라미터 `N=2^14, r=8, p=1`에서 핵심 메모리 항은 대략 `128*N*r`바이트, 즉 16 MiB다. N은 주요 작업량, r은 내부 블록 크기, p는 병렬화 관련 파라미터다. 정확한 전체 메모리와 시간은 구현에 따라 달라지며 이 값은 운영 권장값이 아니라 작은 실습값이다. `dklen=32`는 출력 길이지 공격 비용 설정이 아니다. [scrypt 명세 RFC 7914](https://www.rfc-editor.org/rfc/rfc7914.html)

비용을 높이면 공격 비용과 함께 로그인 서버의 메모리·CPU·DoS 부담도 증가한다. 실제 설정은 목표 지연, 동시 로그인 수, 장비, 최신 운영 지침을 보고 정한다.

### 5.3 salt가 공개되어도 남는 효과

공격자는 Alice의 salt를 알고 Alice의 비밀번호 후보를 검사할 수 있다. 하지만 그 계산값을 Bob의 다른 salt에 그대로 재사용할 수는 없다. salt는 대입을 불가능하게 하는 것이 아니라 사전계산과 계정 간 계산 공유를 제한한다.

별도 비밀값인 pepper를 추가하는 시스템도 있다. pepper는 DB 밖에서 관리하므로 DB만 유출됐을 때 추가 경계가 된다. 하지만 pepper가 유출되거나 유실됐을 때의 재검증·rotation 문제까지 생긴다. salt와 동일한 개념이 아니다.

**확인 문제:** 해시된 비밀번호와 salt가 모두 유출됐는데도 salt가 쓸모 있는 이유를 설명하자. 그리고 32바이트 출력이 32바이트 균등 난수만큼의 엔트로피를 보장하는지 판단하자.

이 장을 지나면 DB의 `salt + parameters + verifier`를 보며 “password를 저장했다”고 말하지 않게 된다. 대신 “서버가 후보를 재계산할 수 있는 검증 record를 저장했다”고 읽게 된다. Password 문제는 해결했지만, 이제 다른 종류의 입력이 남는다. 서버가 받은 일반 message가 중간에 바뀌지 않았고 공유 key를 가진 쪽에서 왔는지는 어떻게 확인할까?

> **5장 통과 기준:** DB에는 password 대신 `salt + parameters + verifier`를 저장한다는 것, 로그인 때 제출된 password 후보로 같은 계산을 반복한다는 것, salt는 공개되어도 계정 간 계산 재사용을 막는다는 것, Argon2id/scrypt의 목적은 오프라인 추측 한 번의 비용을 높이는 것임을 설명할 수 있으면 6장으로 이동한다. scrypt 비용식을 외울 필요는 없다.

---

<a id="mac"></a>

## 6. HMAC: 공유키를 가진 쪽만 만들 수 있는 인증값

5장의 verifier는 서버가 password 후보를 검사하기 위한 저장값이었다. 이번에는 Alice가 Bob 서버에 `amount=10000`이라는 message를 보냈다고 하자. Bob은 message가 도착했다는 사실뿐 아니라, 전송 중 바뀌지 않았고 둘만 아는 key를 가진 쪽이 만들었다는 사실도 확인하고 싶다. 이때 필요한 도구가 MAC이다.

**이 장에서 반드시 이해할 것:** HMAC은 message를 숨기지 않는다. Alice와 Bob이 같은 secret key를 이미 가지고 있을 때, message와 함께 tag를 보내면 Bob이 같은 계산을 반복해 변조·위조 여부를 검사할 수 있다.

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

코드와 연결: [D.3 — `authenticate()`와 검증](#trace-hmac).

> **첫 읽기 경로:** `hmac_demo.py`에서 정상 message는 통과하고 한 글자 바꾼 message는 실패하는 것을 확인한다. 아래 6.1의 결론만 읽고 접힌 심화 설명은 열지 않은 채 [6.2절](#hmac-boundaries)로 이동해도 된다.

### 6.1 왜 표준 HMAC을 사용해야 하는가

SHA-256 자체에는 key 인자가 없다. 개발자가 `SHA256(secret_key || message)`처럼 secret을 평범한 입력 앞에 붙이면 얼핏 MAC처럼 보이지만, SHA-256의 내부 구조 때문에 특정 조건에서 length-extension 공격을 허용한다. 결론은 “hash에 비밀을 아무 방식으로나 섞으면 MAC이 된다”가 아니다.

HMAC은 key와 message를 해시에 결합하는 방법까지 정의하고 분석한 표준 구성이다. 애플리케이션에서는 `HMAC_SHA256(key, message)`라는 검증된 구현을 호출한다. 첫 독서에서 length-extension의 padding을 계산하거나 `ipad/opad` 수식을 암기할 필요는 없다.

<details>
<summary><strong>선택 심화 펼치기: length extension에서 HMAC 내부 수식까지</strong></summary>

아래 설명은 왜 `SHA256(key || message)`를 직접 만들지 말아야 하는지 공격자의 계산을 끝까지 추적한다. HMAC의 사용법을 이해하기 위한 선행 조건은 아니다.

먼저 서버가 하려는 일을 정확히 잡자. 서버는 다음 두 가지를 확인하려 한다.

- **무결성(integrity):** 메시지가 전송 중에 변조되지 않았는가?
- **인증(authentication):** 공유 key를 가진 사람이 만든 메시지인가?

이는 암호화와 다르다. MAC은 메시지 내용을 숨기지 않는다. 메시지와 함께 전달된 인증값을 이용해 **변조와 위조를 검출**한다.

여기서 먼저 매우 중요한 표기상의 오해를 제거해야 한다. **SHA-256 자체에는 secret key가 없다.** SHA-256의 인터페이스는 본질적으로 다음과 같다.

```text
digest = SHA256(data)
```

SHA-256의 초기 state와 round constant를 포함한 알고리즘 전체는 공개되어 있다. 누구든 같은 `data`를 넣으면 같은 digest를 계산할 수 있다. 뒤에서 쓰는 다음 표기에서 `key`는 SHA-256 함수에 전달하는 별도의 key 인자가 아니다.

```text
SHA256(key || message)
       └───── data 전체 ─────┘
```

호출자가 비밀 바이트열인 `key`를 평범한 `message` 앞에 직접 이어 붙이고, 그 결과 전체를 SHA-256의 유일한 입력 `data`로 넣었을 뿐이다. 즉 이것은 **keyed SHA-256이라는 알고리즘이 아니라, unkeyed SHA-256을 이용해 MAC처럼 써 보려는 임의 구성**이다.

```text
SHA-256:
    SHA256(data)
    → key 인자가 없는 공개 해시 함수

단순 secret-prefix 구성:
    data = secret_key || message
    SHA256(data)
    → 비밀값을 입력 앞에 붙였을 뿐

HMAC-SHA256:
    HMAC_SHA256(secret_key, message)
    → secret_key와 message를 정해진 HMAC 구조로 결합
```

또한 SHA-256 규격에서 round constant를 `K`라고 표기하는 자료가 있지만, 그것들은 공개 상수다. 이 장의 `key`, `K`, `K0`는 Alice와 Bob 서버가 공유하는 **비밀 바이트열**을 뜻하며 SHA-256 내부의 공개 round constant와 전혀 다른 대상이다.

#### 6.1.1 정상적인 검증은 어떻게 보이는가

Alice와 Bob 서버만 다음 비밀키를 알고 있다고 하자.

```text
key = "Alice와 Bob 서버만 아는 비밀"
```

Alice가 송금 메시지를 보낸다.

```text
message = "to=bob&amount=10000"
```

단순한 방법을 생각하면 Alice는 key와 message를 이어 붙여 SHA-256을 계산할 수 있다.

```text
tag = SHA256(key || message)
```

네트워크를 통해 전송되는 것은 다음 두 값이다. key는 전송하지 않는다.

```text
message = "to=bob&amount=10000"
tag     = "a81f..."
```

Bob 서버도 같은 key를 가지고 있으므로 받은 message로 tag를 다시 계산한다.

```text
expected_tag = SHA256(key || received_message)

expected_tag == received_tag ?
```

두 값이 같으면 서버는 “이 공유 key를 가진 누군가가 만들었고, 중간에 바뀌지 않은 메시지”라고 판단한다.

공격자가 송금액만 다음과 같이 바꾸면 어떻게 될까?

```text
원래 message:          to=bob&amount=10000
공격자가 바꾼 message: to=bob&amount=90000
```

공격자는 key를 모르므로 바뀐 message에 맞는 tag를 처음부터 계산할 수 없다. 원래 tag를 그대로 보내면 서버의 재계산 결과와 일치하지 않는다.

```text
SHA256(key || "to=bob&amount=90000") != 원래 tag
```

여기까지만 보면 `SHA256(key || message)`가 안전해 보인다. 그러나 SHA-256의 내부 처리 방식 때문에 **기존 메시지 뒤에 데이터를 추가하는 특수한 변조**가 가능하다.

#### 6.1.2 length extension은 무슨 뜻인가

`length extension`은 그대로 번역하면 **길이 연장**이다. 공격자는 정상적인 `message + tag`를 관찰한 뒤, key를 알아내지 않고도 기존 message 뒤에 내용을 추가하고 그에 맞는 새 tag를 계산하려 한다.

```text
정상 message:
user=simcho&action=view

공격자가 만들고 싶은 message:
user=simcho&action=view&admin=true
```

공격자의 목표는 단순히 message를 수정하는 데서 끝나지 않는다. 수정된 message와 함께 서버 검증을 통과할 **새로운 유효 tag**까지 만드는 것이다.

```text
Alice ── 정상 message + 정상 tag ──→ 공격자 Mallory ── 변조 message + 위조 tag ──→ Bob 서버
```

놀라운 점은 공격자가 key를 복구할 필요가 없다는 것이다.

#### 6.1.3 SHA-256 digest가 계산의 checkpoint가 되는 이유

SHA-256은 전체 입력을 한꺼번에 처리하지 않는다. 입력을 64바이트 블록으로 나누고, 이전 블록을 처리한 state에 다음 블록을 계속 반영한다.

```text
초기 state
    │
    ▼
[64바이트 block 1]
    │
    ▼
중간 state
    │
    ▼
[64바이트 block 2]
    │
    ▼
최종 state = digest
```

개념적으로 표현하면 다음과 같다.

```text
state0 = SHA-256이 정의한 초기값
state1 = Compress(state0, block1)
state2 = Compress(state1, block2)
digest = state2
```

따라서 SHA-256의 최종 digest는 단순한 결과 문자열인 동시에, 일정한 조건에서는 뒤의 블록 계산을 이어갈 수 있는 **checkpoint**처럼 이용될 수 있다.

SHA-256은 입력 끝에 padding도 자동으로 붙인다.

```text
SHA256이 실제로 처리하는 바이트:

key || message || padding(key || message)
```

padding에는 `0x80`, 필요한 수의 `0x00`, 원래 입력의 비트 길이가 들어간다. 공격자는 key의 값은 모르지만 key 길이를 알거나 몇 가지 후보로 추측할 수 있다. key 길이가 정해지면 padding도 계산할 수 있다.

공격자는 공개된 기존 digest를 계산 시작 state로 삼아 추가 데이터만 처리한다.

```text
기존 digest를 state로 사용
          │
          ▼
     "&admin=true" 처리
          │
          ▼
       새로운 digest
```

이것이 length-extension 공격의 핵심이다.

> 기존 digest를 출발점으로 사용해, 기존 입력 뒤에 데이터를 추가한 새로운 digest를 계산한다.

#### 6.1.4 공격자는 실제로 무엇을 보내는가

공격자가 만드는 메시지는 사람이 읽는 단순한 문자열과 정확히 같지는 않다. 기존 입력에 사용됐어야 할 SHA-256 padding도 message의 일부로 포함한다.

```text
forged_message =
    original_message
    || padding(key || original_message)
    || "&admin=true"
```

그리고 기존 digest부터 계산을 이어서 `forged_tag`를 얻는다.

```text
forged_tag =
    기존 digest를 시작 state로 사용해
    "&admin=true"와 새로운 최종 padding까지 처리한 결과
```

공격자는 다음 두 값을 Bob 서버에 보낸다.

```text
message = original_message || old_padding || "&admin=true"
tag     = forged_tag
```

#### 6.1.5 서버는 왜 속는가

서버는 자신이 가진 key를 앞에 붙여 평소처럼 검증한다.

```text
SHA256(key || forged_message)
```

`forged_message`를 펼치면 다음과 같다.

```text
SHA256(
    key
    || original_message
    || old_padding
    || "&admin=true"
)
```

서버가 `key || original_message || old_padding`까지 계산한 state는 바로 공격자가 알고 있던 기존 digest다.

```text
서버의 계산:

초기 state
   │
   ├─ key
   ├─ original_message
   └─ old_padding
          │
          ▼
       기존 digest
          │
          ├─ "&admin=true"
          └─ 새로운 최종 padding
                 │
                 ▼
             forged_tag
```

공격자는 앞부분을 계산하지 않고 공개된 기존 digest부터 시작했다.

```text
공격자의 계산:

기존 digest
    │
    ├─ "&admin=true"
    └─ 새로운 최종 padding
           │
           ▼
       forged_tag
```

두 계산은 같은 지점에서 같은 추가 데이터를 처리하므로 결과가 같다. 서버는 tag가 일치한다는 이유로 공격자가 뒤에 내용을 추가한 메시지를 정상이라고 오인할 수 있다.

#### 6.1.6 모든 `SHA256(key || message)`가 즉시 공격되는가

실제 공격에는 몇 가지 조건이 필요하다.

- SHA-256처럼 length extension이 가능한 구조를 사용할 것
- `SHA256(key || message)` 형태의 secret-prefix hash일 것
- 공격자가 기존 message와 digest를 알 것
- key 길이를 알거나 추측할 수 있을 것
- 메시지 형식과 파서가 중간에 포함된 바이너리 padding을 허용할 것
- 뒤에 데이터를 추가했을 때 애플리케이션에서 의미 있는 변조가 될 것

파서가 padding 바이트를 거부한다면 특정 공격은 실패할 수 있다. 그러나 보안 설계를 “우리 파서가 우연히 막아 줄 것”에 의존해서는 안 된다. 처음부터 MAC 용도로 분석되고 표준화된 HMAC을 사용한다.

#### 6.1.7 HMAC은 무엇이 다른가

HMAC-SHA256은 안쪽과 바깥쪽 해시를 결합한다. SHA-256의 block 크기인 64바이트에 맞게 key를 정규화한 값을 `K0`라 하면 다음과 같다.

```text
inner = SHA256((K0 XOR ipad) || message)
tag   = SHA256((K0 XOR opad) || inner)

ipad: 0x36을 64번 반복한 바이트열
opad: 0x5c를 64번 반복한 바이트열
```

그림으로 보면 다음과 같다.

```text
                    message
                       │
(K0 XOR ipad) ─────────┤
                       ▼
                   SHA-256
                       │
                       ▼
                 inner digest
                   32바이트
                       │
(K0 XOR opad) ─────────┤
                       ▼
                   SHA-256
                       │
                       ▼
                      tag
```

외부에 공개되는 것은 최종 `tag`뿐이다. `inner digest`는 공개되지 않는다.

안쪽 계산만 보면 다음 형태이므로 length extension을 떠올릴 수 있다.

```text
inner = SHA256(inner_key || message)
```

그러나 공격자가 이 계산을 이어가려면 `inner`가 필요하고, HMAC은 그것을 외부에 내보내지 않는다. 외부에 공개되는 값은 `inner`를 다시 비밀값이 포함된 바깥쪽 해시로 감싼 결과다.

```text
tag = SHA256(outer_key || inner)
```

공격자가 공개된 최종 tag에 length extension을 적용해 만들 수 있는 형태는 다음과 같다.

```text
SHA256(outer_key || old_inner || padding || attacker_data)
```

하지만 서버가 변경된 message에 대해 계산하는 HMAC은 다음 형태다.

```text
new_inner = SHA256(inner_key || changed_message)
new_tag   = SHA256(outer_key || new_inner)
```

두 구조가 다르기 때문에 최종 tag에서 계산을 연장해도 변경된 message의 올바른 HMAC tag가 되지 않는다.

#### 6.1.8 K0, ipad, opad는 왜 필요한가

SHA-256의 digest 크기는 32바이트지만 한 번에 처리하는 block 크기는 64바이트다. HMAC은 key를 block 크기에 맞춰 `K0`로 정규화한다.

```text
key가 64바이트보다 길다:
    먼저 SHA256(key)로 32바이트 값을 만들고 뒤를 0으로 채운다.

key가 64바이트보다 짧다:
    뒤를 0으로 채워 총 64바이트로 만든다.
```

그다음 하나의 `K0`에서 서로 다른 두 입력을 만든다.

```text
inner_key = K0 XOR ipad
outer_key = K0 XOR opad
```

`ipad`와 `opad`는 안쪽 해시와 바깥쪽 해시가 서로 다른 역할의 입력을 사용하게 한다. 같은 key를 서로 다른 문맥에서 구분해 사용하는 **domain separation**으로 이해할 수 있다.

HMAC이 안전한 이유를 단순히 “SHA-256을 두 번 했기 때문”이라고 이해하면 안 된다. 다음과 같은 임의 구성은 HMAC이 아니다.

```text
SHA256(SHA256(key || message))
```

HMAC의 안전성은 `ipad/opad`, key 정규화, 내부 해시, keyed outer hash가 결합된 정의된 구조에 기반한다. 직접 변형하지 말고 표준 라이브러리의 HMAC 구현을 사용한다. 정의는 [RFC 2104 §2](https://www.rfc-editor.org/rfc/rfc2104.html#section-2)를 참고한다.

#### 6.1.9 이 절의 핵심

```text
SHA256(key || message)

문제:
기존 digest가 SHA-256 계산의 checkpoint처럼 노출된다.

공격:
공격자는 정상 message와 tag를 관찰한 뒤,
key 없이 message 뒤에 데이터를 추가하고 새 tag를 계산한다.

결과:
조건이 맞으면 서버가 변조된 message를 정상으로 오인한다.
```

반면 HMAC은 내부 digest를 별도의 keyed outer hash로 감싼다.

```text
HMAC(key, message)

기존 tag를 변경된 message의 인증값을 만드는
연장 checkpoint로 사용할 수 없다.
```

따라서 이 문장으로 정리할 수 있다.

> Length extension은 공격자가 정상적인 `message + digest`를 관찰한 뒤, key를 복구하지 않고도 기존 message 뒤에 내용을 추가하고 서버 검증을 통과할 새 digest를 만드는 공격이다. HMAC은 내부 해시 결과를 별도의 keyed outer hash로 감싸 이러한 SHA-256의 구조적 특성이 MAC 위조로 이어지지 않게 한다.

</details>

<a id="hmac-boundaries"></a>

### 6.2 실무 경계: 정확한 바이트, 공유키, replay

`{"a":1,"b":2}`와 `{"b":2,"a":1}`은 앱에서 같은 객체일 수 있지만 바이트가 다르다. tag를 검증하려면 raw request bytes에 대해 계산하거나, 명확한 canonical serialization 규칙을 합의해야 한다.

또한 `"ab" || "c"`와 `"a" || "bc"`는 같다. 여러 필드를 인증할 때는 고정 길이, 길이 prefix, 검증된 구조화 인코딩 등으로 경계를 정해야 한다.

HMAC은 공유키 보유자 중 누가 만들었는지 구별하지 않는다. Bob도 key를 알므로 Alice와 같은 tag를 만들 수 있다. 또한 유효한 요청을 그대로 재전송하면 tag는 여전히 유효하다. 이 두 한계가 뒤에서 digital signature와 protocol state가 등장하는 이유다.

**확인 문제:** 공격자가 결제 요청 바이트를 하나도 바꾸지 않고 두 번 보내면 HMAC 검증이 두 번째에 실패하는가? 실패하지 않는다. 결제의 중복 실행 방지는 별도 식별자와 서버 상태가 담당한다.

이 장을 지나면 HMAC tag를 “메시지에 붙인 암호문”이 아니라 **공유 key로 정확한 message bytes를 인증한 값**으로 보게 된다. 그러나 message는 여전히 평문이다. `shop.example`이 사용자의 API token을 DB에 저장하려면 변조 검출뿐 아니라 내용 자체도 숨겨야 한다. 다음 장에서 confidentiality와 integrity를 하나의 인터페이스로 묶는다.

> **6장 통과 기준:** HMAC의 입력이 `secret key + message`라는 것, 수신자가 같은 key로 tag를 다시 계산한다는 것, HMAC은 message를 숨기거나 replay를 막지 않는다는 것을 설명할 수 있으면 7장으로 이동한다. Length extension의 padding과 `ipad/opad` 수식을 암기할 필요는 없다.

---

<a id="symmetric"></a>

## 7. AES-GCM: 공유키로 숨기고 변조도 거부한다

6장의 HMAC은 봉인이 뜯겼는지는 알려 주지만 상자 안의 내용을 가리지는 않았다. 이제 `shop.example`이 맡아야 할 API token처럼, 공격자에게 보이면 안 되고 바뀐 채로 사용되어서도 안 되는 데이터를 다룬다.

**이 장의 질문:** HMAC은 메시지를 숨기지 않는데, 현대 애플리케이션은 어떻게 메시지를 숨기면서 동시에 변조도 검출하는가? 같은 key를 여러 메시지에 사용해도 출력이 달라지는 이유와 수신자가 원문을 복원하는 방법은 무엇인가?

### 7.1 왜 AES-GCM이 필요한가

6장의 HMAC은 공유 key를 가진 쪽이 만든 tag로 메시지의 변조와 위조를 검출한다. 그러나 message 자체는 그대로 전송되므로 기밀성은 제공하지 않는다.

```text
message + HMAC tag
    ├─ message 내용: 누구나 읽을 수 있음
    └─ 변조·위조: key가 없으면 유효한 새 tag를 만들기 어려움
```

민감한 API token, 개인정보, 결제 정보를 저장하거나 전송하려면 다음 두 성질이 함께 필요하다.

```text
confidentiality:
    key 없는 공격자가 내용을 읽지 못한다.

integrity/authenticity:
    공격자가 ciphertext나 관련 metadata를 바꾸면 검증에 실패한다.
```

암호화만 하고 인증하지 않는 방식도 충분하지 않다. 공격자가 plaintext를 읽지 못하더라도 ciphertext를 조작해 복호화 결과를 바꾸거나, 손상된 데이터를 애플리케이션이 처리하게 만들 수 있기 때문이다. 현대적인 기본 선택은 두 성질을 하나의 정의된 인터페이스로 제공하는 **AEAD(Authenticated Encryption with Associated Data)**다.

AES-GCM은 AES를 사용하는 대표적인 AEAD다. 이름을 두 부분으로 나누어 읽자.

```text
AES:
    secret key로 16바이트 block을 변환하는 block cipher

GCM(Galois/Counter Mode):
    AES를 counter 방식으로 사용해 임의 길이 plaintext를 암호화하고,
    ciphertext와 AAD에 대한 authentication tag도 계산하는 mode
```

AES-128/192/256의 숫자는 key 길이를 뜻하고, 모두 128비트(16바이트) block을 처리한다. AES 자체는 임의 길이 메시지, nonce, AAD, tag를 정의하지 않는다. GCM이 AES를 어떻게 반복 호출하고 결과를 조합할지 정의한다. [AES 표준](https://csrc.nist.gov/pubs/fips/197/final), [GCM 정의](https://csrc.nist.gov/pubs/sp/800/38/d/final)

AES-GCM의 인증 계산은 HMAC을 ciphertext 뒤에 붙인 것이 아니다. AES로 만드는 counter-mode mask와 GHASH라는 GCM 고유의 인증 계산을 하나의 규격으로 결합한다. 애플리케이션은 이를 따로 조립하지 않고 라이브러리의 `encrypt`와 `decrypt` 인터페이스를 사용한다.

### 7.2 AES-GCM의 입력과 출력부터 보자

Alice와 Bob 서버가 같은 secret key `K`를 이미 공유한다고 가정한다. key를 처음 안전하게 공유하는 문제는 10장의 key agreement에서 다룬다.

AES-GCM 암호화의 핵심 입력은 네 가지다.

| 입력 | 비밀인가? | 역할 |
|---|---:|---|
| key `K` | 비밀 | 암호화와 tag 계산의 보안 근거 |
| nonce `N` | 공개 가능 | 같은 key 아래의 각 암호화 사용을 구분 |
| plaintext `P` | 비밀로 만들 대상 | 암호화할 실제 데이터 |
| AAD `A` | 공개 가능 | 숨기지는 않지만 함께 변조를 검출할 문맥 |

암호화는 ciphertext `C`와 authentication tag `T`를 만든다.

```text
(C, T) = AES_GCM_Encrypt(K, N, P, A)
```

저장하거나 전송해야 하는 값은 보통 다음과 같다.

```text
공개 전송·저장:
    nonce N
    ciphertext C
    tag T
    AAD를 재구성할 metadata

비밀로 유지:
    key K

암호화 뒤에는 남기지 않거나 제한해야 함:
    plaintext P
```

Bob 서버는 이미 가진 같은 key와 함께 받은 nonce, ciphertext, 기대하는 AAD, tag를 사용한다.

```text
P 또는 FAIL = AES_GCM_Decrypt(K, N, C, A, T)
```

```text
Alice                                             Bob 서버

K, N, P, A                                        K 보유
    │                                               ▲
    ▼                                               │
AES-GCM encrypt                                     │
    │                                               │
    └──── N, C, A에 필요한 metadata, T ────────────┘
                                                    │
                                              AES-GCM decrypt
                                                    │
                                      tag 유효 ─────┴───── tag 무효
                                          │                    │
                                          ▼                    ▼
                                          P                   FAIL
```

`decrypt`는 tag 검증에 성공했을 때만 plaintext를 반환해야 한다. 인증에 실패한 plaintext를 먼저 애플리케이션에 넘기고 나중에 경고하는 인터페이스로 이해하면 안 된다.

같은 key를 사용해도 nonce가 달라지면 AES에 들어가는 counter block들이 달라지고, plaintext와 XOR할 mask도 달라진다. 따라서 같은 plaintext도 일반적으로 다른 ciphertext가 된다. nonce는 비밀이 아니므로 ciphertext와 함께 Bob에게 전달할 수 있다. Bob은 `K`와 `N`으로 Alice와 같은 mask를 재생성한다.

```text
같은 K + 다른 N
    → 다른 counter block
    → 다른 AES 출력 mask
    → 같은 P라도 다른 C

Bob:
    미리 가진 K + 전달받은 N
    → 동일한 mask 재생성
    → P 복원
```

단, **같은 key에서 nonce를 재사용해서는 안 된다.** nonce의 목적은 무작위 장식이 아니라 한 key 아래에서 암호화 사용을 구분하는 것이다. 재사용하면 기밀성이 무너지고 GCM tag의 안전성도 심각하게 손상된다.

AES-GCM이 제공하지 않는 성질도 구분한다.

- key를 공유한 여러 당사자 중 정확히 누가 만들었는지는 구별하지 않는다.
- 과거의 유효한 ciphertext를 그대로 다시 보내는 replay를 자동으로 막지 않는다.
- 과거 DB 상태 전체로 되돌리는 rollback을 자동으로 막지 않는다.
- endpoint가 장악되어 key와 plaintext를 읽는 공격까지 해결하지 않는다.

> **첫 읽기 경로:** 여기까지 이해했다면 [7.6절의 저장 포맷과 실습](#aes-gcm-practice)으로 바로 이동해도 된다. 다음 세 절은 왜 counter와 XOR가 등장하고 tag가 어떻게 만들어지는지 내부를 추적하는 선택 심화다.

<details>
<summary><strong>선택 심화 펼치기: XOR에서 counter와 GHASH까지</strong></summary>

### 7.3 선택 심화: XOR, keystream, AES block cipher

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

> 학습 경계: 이 장의 손계산은 XOR·counter·입출력 의존성을 설명한다. [D.6](#trace-tag)에서는 선택 심화로 GHASH와 tag를 재구성한다. AES 자체의 구현과 운영 최적화는 다루지 않는다. 운영 코드는 고수준 AEAD API를 사용한다.

### 7.4 선택 심화: GCM의 암호화 부분 — nonce, counter, XOR

7.2절의 가정을 이어 간다. Alice는 메시지마다 nonce `N`을 정해 공개 전송한다. Counter는 메시지 내부 block 번호에 대응하는 숫자다. Nonce는 메시지 사이를 구분하고 counter는 한 메시지 안의 block을 구분한다.

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

### 7.5 선택 심화: GCM의 인증 부분 — GHASH, AAD, tag

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

</details>

<a id="aes-gcm-practice"></a>

### 7.6 실무에서 저장할 값과 확인할 실습

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

코드와 연결: [D.4 — Envelope/API](#trace-envelope), [D.5 — counter와 XOR](#trace-counter), [D.6 — tag](#trace-tag), [D.7 — 실패 실습](#trace-attacks).

이 장에서 AES-GCM은 마침내 `plaintext → nonce + ciphertext + tag`라는 저장 가능한 모양을 만들었다. 그러나 함수 호출은 key `K`가 이미 메모리에 있다는 데서 시작했다. 프로세스가 재시작해도 같은 데이터를 읽으려면 K를 다시 찾아야 하고, DB를 훔친 공격자에게 K까지 같이 주어서는 안 된다. 다음 장의 질문은 알고리즘이 아니라 **key의 거주지와 권한 경계**다.

> **7장 통과 기준:** `K`는 비밀이고 `N/C/T`는 함께 저장·전송할 수 있다는 것, `decrypt`는 tag가 맞을 때만 plaintext를 반환한다는 것, 같은 key에서는 nonce가 절대로 재사용되면 안 된다는 것, AAD는 숨기지 않지만 문맥의 변조를 검출한다는 것을 설명할 수 있으면 8장으로 이동한다. AES round와 GHASH 유한체 곱셈을 설명할 필요는 없다.

---

# 제3부. 암호문보다 어려운 것 — key를 운영하는 시스템

AES-GCM 호출은 몇 줄이면 끝난다. 그러나 `shop.example`이 그 key를 소스 코드나 DB에 함께 넣는 순간, DB 암호화의 보호 경계는 사라진다. 세 번째 부에서는 암호문 자체보다 **복호화 권한이 어디에 있고 시간에 따라 어떻게 변하는지**를 추적한다. 여기서부터 암호학은 함수 사용법이 아니라 애플리케이션 아키텍처가 된다.

<a id="storage"></a>

## 8. 현대 애플리케이션은 암호화된 값을 어디에 저장하는가

**이 장의 질문:** `AESGCM(key)`의 key는 누가 만들고, 재시작 후 어디서 찾아오며, DB dump에는 어떤 바이트가 남는가?

여기서부터 암호학은 함수 호출을 넘어 아키텍처가 된다. `AESGCM(key)` 한 줄은 key가 이미 안전하게 준비됐다고 가정하지만, 운영 시스템은 그 key를 배포하고 재시작 뒤 복구하며 접근 권한과 감사 기록을 남겨야 한다. “DB와 key를 분리한다”는 말을 실제 컴포넌트로 펼쳐 보자.

**이 장에서 반드시 이해할 것:** DB에는 nonce와 ciphertext/tag를 저장할 수 있지만, 그것을 복호화하는 plaintext key를 같은 권한 경계에 그대로 두면 DB 분리 보호의 의미가 약해진다. Secret Manager는 앱이 사용하는 secret을 전달·관리하고, KMS는 cryptographic key와 연산·정책·감사에 특화되어 있다. 실행 중인 앱 메모리에는 필요한 순간 plaintext와 key가 존재할 수 있다.

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

코드와 연결: [D.8 — 환경변수에서 DB까지의 함수 호출](#trace-database).

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

<details>
<summary><strong>선택 심화 펼치기: envelope encryption의 전체 흐름</strong></summary>

### 8.4 선택 심화: Envelope encryption이라는 대규모 저장 패턴

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

</details>

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

이제 `shop.example`의 한 행을 볼 때 DB에는 ciphertext와 복호화 metadata가 있고, Secret Manager나 KMS에는 별도 권한 경계가 있으며, 실제 복호화 순간에는 앱 메모리에 plaintext가 나타난다는 공간 지도가 생겼다. 하지만 key는 한 번 배치하고 끝나는 물건이 아니다. 버전이 바뀌고, rotation되고, 백업되며, 때로는 삭제된다. 다음 장에서는 이 지도를 시간축으로 돌린다.

> **8장 통과 기준:** 업무 DB, 애플리케이션 메모리, Secret Manager, KMS에 각각 무엇이 존재하는지 그릴 수 있고, “KMS를 쓰면 앱이 plaintext를 절대 보지 않는다”가 왜 일반적으로 틀린지 설명할 수 있으면 9장으로 이동한다. Envelope encryption의 SDK pseudocode는 외울 필요가 없다.

---

<a id="lifecycle"></a>

## 9. Key 관리에서 실제로 어려운 부분

암호화 함수 호출보다 key lifecycle이 더 어렵다.

8장은 key가 **어디에 있는가**를 물었다. 9장은 같은 key를 시간에 따라 추적한다. 오늘 생성한 version 3으로 새 데이터를 쓰면서도 어제의 version 2 ciphertext를 읽어야 하고, KMS 장애와 관리자 실수, 삭제와 복구까지 다뤄야 한다. 알고리즘이 맞아도 이 수명주기가 끊기면 데이터는 공격자뿐 아니라 우리에게도 영원히 읽히지 않는다.

**이 장에서 반드시 이해할 것:** 안전한 알고리즘을 골라도 key를 생성·전달·식별·rotation·backup·삭제하는 운영이 실패하면 데이터를 잃거나 공격자에게 복호화 권한을 넘길 수 있다. `key_id`는 key 자체가 아니며, 애플리케이션이 KMS를 호출하려면 먼저 workload identity라는 신뢰 출발점이 필요하다.

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

여기까지의 저장 문제는 한 조직이 key를 생성하고 그 조직의 앱이 다시 사용하는 상황이었다. 이 경계 안에서는 Secret Manager와 IAM으로 key를 전달할 수 있다. 하지만 처음 접속한 사용자의 브라우저와 `shop.example` 서버는 아직 공통 AES key가 없다. 다음 장에서는 **미리 나눈 비밀 없이 어떻게 같은 비밀에 도달하는가**라는 새로운 문제로 넘어간다.

> **9장 통과 기준:** ciphertext가 자신의 `key_version`을 기록해야 하는 이유, 새 write와 기존 read를 함께 처리하는 rotation 방식, key를 잃으면 정상 사용자도 복호화할 수 없다는 사실, KMS 접근 로그에 plaintext를 남기면 안 되는 이유를 설명할 수 있으면 10장으로 이동한다.

---

# 제4부. 처음 만난 두 시스템이 서로를 믿기까지

한 조직 안에서는 IAM과 Secret Manager를 이용해 shared key를 전달할 수 있었다. 인터넷의 브라우저와 서버는 그런 사전 관계가 없다. 네 번째 부의 질문은 두 단계로 나뉜다. **비밀을 보내지 않고 같은 비밀을 만드는 방법**, 그리고 **그 비밀을 정말 의도한 상대와 만들었다고 확인하는 방법**이다. 이 둘을 분리해서 이해해야 TLS가 한 덩어리의 마법처럼 보이지 않는다.

<a id="asymmetric"></a>

## 10. 비대칭키: “public으로 암호화, private으로 복호화”보다 넓은 개념

**이 장에서 반드시 이해할 것:** 비대칭키는 하나의 만능 연산 이름이 아니다. X25519 key agreement, Ed25519 digital signature, RSA-OAEP public-key encryption은 서로 다른 문제와 API를 가진다. Public key는 공개할 수 있지만, 그 public key가 누구의 것인지는 수학만으로 알 수 없다.

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

> **첫 읽기 경로:** 위 표에서 세 역할을 구분했다면 [X25519 라이브러리 흐름](#x25519-api)으로 바로 이동해도 된다. 10.1~10.2와 10.3 앞부분의 타원곡선 손계산은 왜 양쪽 shared secret이 같아지는지 수학적으로 추적하고 싶을 때 읽는 선택 심화다.

<details>
<summary><strong>선택 심화 펼치기:</strong> 군과 작은 Diffie–Hellman 손계산</summary>

첫 독서에서 필요한 결론은 간단하다. 각자 private 값은 보내지 않고 public 값만 교환하지만, 양쪽은 같은 shared secret을 계산할 수 있다. 아래 두 절은 그 등식이 어디에서 오는지 작은 수로 확인한다.

### 10.1 선택 심화: 준비 수학 — 나머지 연산, 군, 한 방향으로 쉬운 계산

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

### 10.2 선택 심화: 작은 수로 계산하는 Diffie–Hellman

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

</details>

### 10.3 타원곡선의 scalar multiplication과 X25519

> **선택 심화 경계:** 아래 작은 곡선의 점 덧셈은 X25519의 수학적 배경이다. 첫 독서에서는 [라이브러리 관점의 X25519 흐름](#x25519-api)으로 건너뛴다.

<details>
<summary><strong>선택 심화 펼치기:</strong> 작은 타원곡선에서 점을 더하는 법</summary>

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

</details>

<a id="x25519-api"></a>

#### 첫 독서 핵심: 라이브러리 관점의 X25519 흐름

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

코드와 연결: [D.9 — `exchange()`와 `derive_aes_key()`](#trace-exchange).

### 10.4 HKDF: shared secret과 AES key는 왜 구분하는가

X25519 출력 S는 비밀 key material이다. 하지만 앱은 AES key 하나뿐 아니라 송신용·수신용 key, IV 등을 필요로 할 수 있다. 원시 출력을 잘라서 용도를 섞지 않고, **KDF(key derivation function)**로 규격에 맞는 출력을 만든다.

> 첫 독서에서는 `S를 AES key로 바로 쓰지 않고 HKDF에 넣어 용도·방향별 key를 만든다`까지만 이해하면 된다. 아래 Extract/Expand 수식은 선택 심화다.

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

#### 선택 심화: 검증자는 왜 private key 없이 확인할 수 있는가

<details>
<summary><strong>선택 심화 펼치기:</strong> 공개키만으로 서명 관계를 검사하는 식</summary>

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

</details>

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

<details>
<summary><strong>선택 심화 펼치기:</strong> RSA 산술과 public-key encryption</summary>

### 10.7 선택 심화: RSA — “공개키로 암호화”가 실제로 성립하는 예

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

</details>

### 10.8 Public key만 받았다고 신뢰할 수는 없다

공격자도 자신의 key pair를 만들 수 있다.

```text
Mallory private/public 생성
Mallory가 "이게 example.com의 public key다"라고 주장
```

수학적으로 유효한 public key라는 것과 특정 신원에 속한다는 것은 별개다. 이 간극을 인증서가 메운다.

10장을 지나며 `public key`에 대한 그림은 하나의 자물쇠에서 **권한을 분리하는 여러 인터페이스**로 바뀌어야 한다. X25519 public key는 shared secret 합의에 참여하고, Ed25519 public key는 서명을 검증하며, RSA-OAEP public key는 제한된 데이터를 암호화할 수 있다. 공통점은 private 값을 공개하지 않고도 상대에게 어떤 연산 능력을 준다는 것이다.

그러나 Mallory도 완벽히 유효한 key pair를 만들 수 있다. 우리가 얻은 public key가 정말 `shop.example`의 것이라는 보장은 아직 없다. 다음 장의 인증서는 새로운 암호화 알고리즘이 아니라, 바로 이 **이름과 key 사이의 끊어진 연결**을 메우는 서명된 문서다.

> **10장 통과 기준:** X25519는 plaintext 암호화가 아니라 shared secret 합의라는 것, shared secret을 HKDF에 넣어 실제 AES key를 만든다는 것, key agreement만으로 상대 신원은 확인되지 않는다는 것, signature는 private으로 생성하고 public으로 검증한다는 것을 설명할 수 있으면 11장으로 이동한다. 군의 공리, 작은 DH 지수 계산, RSA의 Euler 정리는 첫 독서 통과 조건이 아니다.

---

<a id="certificates"></a>

## 11. 인증서: 도메인과 public key를 연결하는 서명된 문서

10장의 마지막에서 암호는 깨지지 않았는데도 중간자 공격이 성공했다. Mallory는 Alice나 Bob의 private key를 훔치지 않았다. 자신의 정상적인 key pair를 내밀며 상대인 척했을 뿐이다. 이 장에서는 계산이 아니라 **이름을 믿는 근거**를 추가한다. 브라우저가 `shop.example`이라는 이름과 서버 public key를 어떤 신뢰 사슬로 연결하는지 따라가 보자.

**이 장에서 반드시 이해할 것:** 인증서는 비밀 파일이 아니라 `이 도메인 이름에는 이 public key가 연결된다`는 CA의 서명된 주장이다. 브라우저는 미리 가진 trust store에서 신뢰를 시작하고, 서버는 인증서에 대응하는 private key를 실제로 가졌음을 TLS handshake에서 증명한다.

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

이제 브라우저는 세 가지를 따로 말할 수 있다. `이 certificate chain은 내가 신뢰한 root로 이어진다`, `인증서의 이름은 내가 접속한 shop.example과 일치한다`, `현재 handshake 상대는 인증서 public key에 대응하는 private key를 실제로 보유한다`. 인증서는 암호문을 만들지 않았지만, **누구와 key agreement를 하는지**에 답했다.

여기까지 배운 부품을 아직 직접 조립하지는 않았다. X25519, signature, certificate, HKDF, AES-GCM의 순서와 바이트 형식을 조금만 틀려도 새 공격이 생긴다. 다음 장에서는 이 부품들을 임의로 조합하지 않고, TLS 1.3이라는 이미 정의되고 분석된 protocol 안에서 한 연결의 시간순으로 다시 만난다.

> **11장 통과 기준:** 인증서는 공개할 수 있고 private key는 별도 비밀이라는 것, root가 self-signed라서가 아니라 trust store에 들어 있어서 신뢰된다는 것, CA의 인증서 서명과 서버의 handshake 서명이 서로 다른 시점과 key를 사용한다는 것을 설명할 수 있으면 12장으로 이동한다.

---

<a id="tls"></a>

## 12. 이제 TLS를 바텀업으로 조립한다

이 장에서 처음 등장하는 핵심 primitive는 없다. 오히려 그 점이 중요하다. 지금까지 따로 배운 부품이 **어떤 순서로 서로의 약점을 메우는지** 보는 조립 장이다. 처음에는 handshake 그림을 한 번에 읽고, 두 번째 독서에서 각 화살표를 앞 장의 함수와 대응시킨다.

**이 장에서 반드시 이해할 것:** TLS handshake는 서버 신원을 확인하고 양쪽이 traffic key를 만들게 한다. 이후 record protocol은 그 대칭키와 AEAD로 HTTP bytes를 암호화·인증한다. 인증서 public key가 HTTP body를 직접 암호화하는 것이 아니다.

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

> **첫 읽기 경로:** 위 handshake 그림에서 `ephemeral key agreement → 인증서 서명 검증 → HKDF → 대칭 AEAD` 흐름을 잡았다면 [12.9절](#https-summary)로 이동한 뒤 12.11 실습을 실행해도 된다. 12.3~12.8은 각 화살표를 기존 실습과 연결하는 두 번째 독서다.

### 12.3 두 번째 독서: ClientHello와 ServerHello — X25519 실습과 연결

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

### 12.4 두 번째 독서: 인증서와 CertificateVerify — 중간자 공격을 막는다

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

### 12.5 두 번째 독서: HKDF — 하나의 shared secret에서 여러 key를 만든다

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

### 12.6 두 번째 독서: Record protocol — 우리가 배운 AES-GCM과 연결

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

### 12.7 두 번째 독서: Forward secrecy

ephemeral Diffie-Hellman private key를 연결 후 폐기하면, 미래에 서버의 certificate private key가 유출되더라도 과거에 녹화한 TLS 트래픽의 shared secret을 바로 복구할 수 없도록 설계할 수 있다. 이것이 forward secrecy의 핵심이다.

certificate private key는 당시 서버 신원을 증명하는 데 쓰였고, 과거 traffic key 자체는 ephemeral key agreement에서 나왔기 때문이다.

단, 당시의 ephemeral secret이나 TLS key log가 이미 저장·유출되었으면 그 트래픽은 복호화될 수 있다. Forward secrecy는 “미래에 어떤 비밀이든 털려도 괜찮다”가 아니라 **장기 인증키의 사후 유출과 과거 session key를 분리**하는 성질이다.

### 12.8 선택 심화: 첫 접속 이후의 resumption과 0-RTT

서버는 다음 접속을 위한 resumption 정보를 발급할 수 있다. PSK(pre-shared key)는 여기서 이전 연결에서 확립한 비밀을 기반으로 할 수 있으므로, 사용자가 처음부터 모든 서버와 key를 직접 나눠야 한다는 뜻은 아니다.

0-RTT early data는 새 handshake가 완성되기 전의 데이터다. 일반적인 1-RTT application data와 replay/forward secrecy 성질이 같지 않다. 따라서 “TLS라서 결제 POST도 중복 실행될 수 없다”라고 추론하지 않는다. 이 책의 실습은 resumption과 early data를 사용하지 않는다. 세부 설계는 TLS 구현과 애플리케이션 정책의 영역으로 남긴다.

<a id="https-summary"></a>

### 12.9 첫 독서 결론: HTTPS란 결국 무엇인가

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

<a id="tokens"></a>

### 12.10 HTTPS 위의 로그인 상태: 세션, Bearer token, JWT

TLS가 HTTP 바이트를 보호한다는 사실까지 이해하면 다음 질문이 남는다.

> 사용자는 한 번 로그인한 뒤, 이후의 각 API 요청에서 자신이 이미 로그인했다는 사실을 어떻게 증명하는가?

**이 절에서 반드시 이해할 것:** 로그인 성공 후에는 password 대신 새로 발급된 session credential을 사용한다. Bearer는 “가진 사람이 사용할 수 있다”는 사용 방식이고, JWT는 token 형식이다. OAuth access token은 JWT일 수도 있고 opaque token일 수도 있다.

매 요청마다 password를 다시 보내고 Argon2id를 실행하는 것은 적절하지 않다. password는 장기 credential이며 노출 지점을 늘리면 안 되고, password KDF는 의도적으로 비싸기 때문이다. 서버는 최초 로그인에 성공하면 **세션을 나타내는 새로운 credential**을 발급한다.

#### 12.10.1 로그인과 이후 API 호출은 서로 다른 단계다

```text
① 로그인

사용자 앱 ── identifier + password ──→ 인증 서버
                                      ├─ password verifier 검사
                                      └─ 로그인 성공
사용자 앱 ←──── 세션 cookie 또는 access token ─── 인증 서버


② 이후 API 호출

사용자 앱 ── 세션 cookie 또는 access token ──→ API 서버
                                              ├─ credential 검증
                                              ├─ 사용자·권한 확인
                                              └─ 요청 처리
```

여기서 password는 최초 인증에 사용되고, 이후 요청은 발급된 세션 credential로 이어진다. 이 구분을 **최초 사용자 인증**과 **인증된 세션의 연속성**으로 생각할 수 있다.

가장 단순한 server-side session은 다음처럼 동작한다.

```text
로그인 성공:
    server가 random session_id 생성
    server 저장소에 session_id → user_id, 만료, 상태 기록
    browser에는 session_id가 든 cookie 전달

이후 요청:
    browser가 session cookie 전송
    server가 session_id로 저장소 조회
    user와 session 상태 복원
```

cookie에는 password를 넣지 않는다. 일반적으로 추측 불가능한 session identifier만 넣고 `Secure`, `HttpOnly`, 적절한 `SameSite` 속성을 사용한다. 이 방식은 뒤에서 설명할 opaque reference token과 닮았지만, browser가 cookie를 자동 첨부한다는 점 때문에 CSRF 모델과 방어가 함께 따라온다.

#### 12.10.2 먼저 네 용어를 서로 분리하자

`access token`, `Bearer`, `JWT`, `opaque token`은 같은 분류 기준의 경쟁 단어가 아니다.

| 용어 | 답하는 질문 |
|---|---|
| access token | 이 값은 무엇을 하기 위한 credential인가? |
| Bearer token | 이 값을 사용할 때 별도의 key 소유 증명이 필요한가? |
| JWT | 토큰 내부 데이터는 어떤 형식으로 표현되는가? |
| opaque token | 토큰을 받은 client가 내부 의미를 해석할 수 있는가? |

따라서 다음 조합이 모두 가능하다.

```text
JWT access token + Bearer 방식
opaque access token + Bearer 방식
JWT이지만 access token이 아닌 ID token
JWT이지만 Bearer 방식이 아닌 별도 proof와 결합된 token
```

`JWT`, `Bearer`, `OAuth`를 동의어로 사용하면 설계를 추적할 수 없게 된다.

OAuth는 token의 바이트 형식을 정의하는 이름이 아니라, 사용자가 자신의 password를 제3자 client에 넘기지 않고 제한된 resource 접근 권한을 위임하는 framework다.

```text
Resource Owner:       권한을 가진 사용자
Client:               사용자를 대신해 API를 사용하려는 앱
Authorization Server: 사용자 동의를 확인하고 access token을 발급
Resource Server:      access token을 받고 보호된 API를 제공
```

```text
사용자(Resource Owner)
        │ 권한 위임
        ▼
Client ── authorization grant ──→ Authorization Server
Client ←────── access token ───── Authorization Server
Client ─────── access token ────→ Resource Server
Client ←──── protected resource ─ Resource Server
```

OAuth access token은 JWT일 수도 있고 opaque token일 수도 있다. OAuth 자체는 둘 중 하나를 강제하지 않는다. 반대로 JWT를 사용한다고 그 시스템이 자동으로 OAuth가 되는 것도 아니다.

#### 12.10.3 Bearer token은 무엇인가

`bearer`는 “소지자”라는 뜻이다. Bearer token은 **그 값을 소지하고 제시하는 것만으로 사용할 수 있는 token**이다. 별도의 private key를 가지고 있다는 증명은 요구하지 않는다.

```http
GET /patients HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOi...
```

서버는 `Bearer` 뒤의 token을 검증하고 허용된 resource를 반환한다. [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html)은 token을 가진 누구든 사용할 수 있으므로 저장과 전송 과정에서 노출되지 않도록 보호해야 한다고 정의한다.

```text
정상 사용자에게 token이 있음
    → 사용 가능

공격자가 token을 복사함
    → 만료·폐기·추가 통제가 없다면 공격자도 사용 가능
```

따라서 Bearer token은 반드시 HTTPS로 전송하고, 로그·URL·오류 메시지·분석 도구에 남기지 않도록 해야 한다. 일반적으로 query string보다 `Authorization` header를 사용한다. 브라우저에서 어디에 보관할지는 XSS와 CSRF를 함께 고려해야 하는 별도 설계 문제다.

세션 cookie도 흔히 “그 cookie를 가진 쪽이 세션을 사용한다”는 점에서는 소지 기반 credential이다. 다만 `Authorization: Bearer`라는 HTTP 인증 scheme으로 전달되는 OAuth Bearer access token과 cookie 기반 세션을 용어상 동일시하지는 않는다.

#### 12.10.4 HS256은 보통 API 요청 자체에 서명하는 것이 아니다

JWT access token을 사용하는 전형적인 흐름은 다음과 같다.

```text
① 로그인·token 발급

사용자 앱 ── identifier/password 또는 OAuth grant ──→ 인증 서버
사용자 앱 ←────────── JWT access token ────────────── 인증 서버
                                              └─ JWT bytes에 MAC/서명


② API 호출

사용자 앱 ── Authorization: Bearer <JWT> ──→ API 서버
                                                └─ JWT 검증 후 처리
```

사용자 앱은 일반적으로 매번 다음 HTTP 요청 전체를 HS256으로 계산하지 않는다.

```text
GET /patients
request headers
request body
```

인증 서버가 HS256으로 보호한 대상은 **JWT token의 header와 payload**다. 사용자 앱은 발급받은 token 문자열을 그대로 API 요청에 실어 보낸다.

```text
HS256이 인증하는 것:
    JWT header || "." || JWT payload

일반적인 Bearer token이 인증하지 않는 것:
    이번 HTTP method, path, body 전체
```

그러므로 Bearer access token을 훔친 공격자는 token을 자신의 다른 API 요청에 붙여 재사용할 수 있다. HTTP 요청 자체를 key에 묶는 webhook HMAC, HTTP Message Signatures, proof-of-possession 방식은 Bearer token과 다른 프로토콜이다.

#### 12.10.5 JWT는 무엇인가

JWT(JSON Web Token)는 JSON claims를 URL-safe한 token으로 표현하는 형식이다. 흔히 보는 compact JWS 형태는 점(`.`)으로 나뉜 세 부분이다. [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html)

```text
base64url(header) . base64url(payload) . base64url(signature-or-MAC)
```

예를 들면 다음과 같은 논리 구조다.

```json
header = {
  "typ": "at+jwt",
  "alg": "RS256",
  "kid": "key-2026-09"
}

payload = {
  "iss": "https://auth.example.com",
  "sub": "user-123",
  "aud": "https://api.example.com",
  "scope": "patients:read",
  "iat": 1790400000,
  "exp": 1790400900,
  "jti": "5fd4..."
}
```

주요 claim의 역할은 다음과 같다.

| claim | 의미 | 검증 질문 |
|---|---|---|
| `iss` | issuer | 내가 신뢰하도록 설정한 인증 서버가 발급했는가? |
| `sub` | subject | 누구에 관한 token인가? |
| `aud` | audience | 이 API 서버가 사용 대상으로 지정됐는가? |
| `exp` | expiration time | 아직 만료되지 않았는가? |
| `iat` | issued at | 언제 발급됐는가? |
| `nbf` | not before | 사용 가능 시점이 지났는가? |
| `jti` | JWT identifier | 이 token 인스턴스의 식별자는 무엇인가? |
| `scope` | 위임된 권한 범위 | 이 API 동작에 필요한 권한이 있는가? |

여기서 Base64url은 암호화가 아니다. header와 payload는 token을 얻은 누구나 decode해 읽을 수 있다.

```text
Base64url decode 가능
    ≠ 위조 가능
    ≠ 기밀성 제공
```

서명 또는 MAC은 payload를 숨기는 것이 아니라, 보호된 bytes가 발급 후 바뀌지 않았음을 검증하게 한다. 민감정보를 “서명된 JWT니까 안전하다”고 넣으면 안 된다. 기밀성이 필요하면 별도의 암호화 설계가 필요하다.

> **첫 읽기 경로:** JWT가 `header.payload.signature-or-MAC` 형식이고 payload는 읽을 수 있다는 것까지 이해했다면 [opaque token 설명](#opaque-token)으로 이동해 중앙 저장 방식과 비교한다. 다음 세 절은 JWT를 실제로 채택하거나 검토할 때 돌아오는 선택 심화다.

<details>
<summary><strong>선택 심화 펼치기:</strong> HS256, 공개키 서명 JWT, claim 검증</summary>

#### 12.10.6 선택 심화: HS256 JWT는 HMAC을 어디에 쓰는가

HS256은 HMAC-SHA256을 사용해 JWS compact serialization을 보호한다.

```text
signing_input =
    base64url(header)
    || "."
    || base64url(payload)

mac = HMAC-SHA256(shared_secret, signing_input)

jwt = signing_input || "." || base64url(mac)
```

이 장에서 배운 HMAC을 그대로 사용하므로 `SHA256(key || message)`의 length-extension 취약 구성이 아니다.

JOSE/JWT 문서와 라이브러리는 마지막 부분을 관용적으로 `signature` 또는 “HS256 서명”이라고 부른다. 그러나 암호학적 권한 구조로 보면 HS256은 **공유키 MAC**이다.

```text
인증 서버:
    shared_secret 보유
    → JWT 생성 가능

API 서버:
    같은 shared_secret 보유
    → JWT 검증 가능
    → 동시에 새 JWT 생성도 가능
```

즉 검증 권한과 발급 권한이 분리되지 않는다. API 서버 하나가 침해되어 shared secret이 유출되면 공격자는 다른 사용자의 token도 만들 수 있다. HS256 key에는 사람이 기억하는 password를 쓰지 않고 충분한 entropy를 가진 secret을 사용해야 한다. [RFC 8725 §3.5](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.5)

작은 단일 backend처럼 발급자와 검증자가 사실상 같은 trust boundary에 있다면 HS256이 항상 잘못된 선택은 아니다. 그러나 여러 독립 API 서버에 검증 권한만 배포하려는 구조에서는 권한 분리가 어렵다.

#### 12.10.7 선택 심화: 공개키 서명 JWT는 발급과 검증 권한을 분리한다

비대칭 서명을 사용하면 인증 서버만 private key를 보유하고 API 서버에는 public key만 배포할 수 있다.

```text
인증 서버
├─ private key 보유
└─ JWT 생성·서명 가능

API server A ─┐
API server B ─┼─ public key만 보유 → 검증 가능, 새 서명 생성 불가
API server C ─┘
```

예를 들어 `RS256`, `ES256`, `EdDSA`는 서로 다른 공개키 서명 계열이다. 이름에 `256`이 들어간다고 모두 같은 연산은 아니다.

- `HS256`: HMAC-SHA256, 공유 secret
- `RS256`: RSA PKCS#1 v1.5 signature + SHA-256
- `ES256`: ECDSA P-256 + SHA-256
- `EdDSA`: JOSE에서 사용하는 Edwards-curve 서명 계열

OAuth JWT access token profile인 [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html)은 JWT access token의 서명을 요구하고, resource server가 검증 정보를 쉽게 얻도록 비대칭 알고리즘 사용을 권장한다. 이는 “모든 JWT는 언제나 비대칭이어야 한다”는 일반 명제가 아니라, **OAuth JWT access token profile에서 여러 resource server가 검증하는 구조**에 대한 권고다.

인증 서버는 public key들을 HTTPS의 JWKS(JSON Web Key Set) endpoint로 공개할 수 있다. JWT header의 `kid`는 여러 public key 중 검증에 사용할 후보를 찾는 식별자다. `kid` 자체가 key의 신뢰성을 증명하지는 않는다. API 서버는 사전에 신뢰하도록 설정한 issuer와 JWKS 위치에서만 key를 받아야 한다.

#### 12.10.8 선택 심화: JWT 검증은 signature 확인 하나로 끝나지 않는다

다음 코드는 충분하지 않다.

```text
signature가 맞다
    → 무조건 요청 허용          # 잘못된 결론
```

API 서버는 적어도 다음 정책을 함께 검사해야 한다.

```text
1. 허용하기로 설정한 algorithm인가?
2. 신뢰하는 issuer의 올바른 key로 signature/MAC이 검증되는가?
3. iss가 기대한 issuer와 정확히 일치하는가?
4. aud에 현재 API가 포함되는가?
5. exp가 지나지 않았고 nbf 조건을 만족하는가?
6. 이 token의 type과 목적이 access token 검증 규칙에 맞는가?
7. 필요한 scope/role이 있는가?
8. 계정·tenant·resource에 대한 애플리케이션 authorization도 통과하는가?
```

token header가 주장하는 `alg`를 그대로 신뢰해서는 안 된다. 서버 설정이 허용하는 algorithm 목록을 고정하고, 다른 algorithm과 `none`은 거부한다. ID token과 access token처럼 목적이 다른 JWT도 서로 다른 검증 규칙으로 분리한다. [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html)

```text
authentication:
    이 token이 신뢰하는 issuer가 발급한 user-123의 token인가?

authorization:
    user-123이 이 patient record를 읽을 수 있는가?
```

유효한 JWT라고 해서 모든 resource 접근이 자동으로 허용되는 것은 아니다.

</details>

<a id="opaque-token"></a>

#### 12.10.9 opaque token은 일반 난수인가

실무의 흔한 opaque access token은 CSPRNG로 만든 충분히 긴 임의 문자열이다.

```text
token = CSPRNG(32 bytes)
```

서버는 token에 대응하는 상태를 저장한다.

```text
token record
├─ token_hash
├─ user_id
├─ client_id
├─ scopes
├─ expires_at
└─ revoked_at
```

client가 보는 token에는 해석할 claims가 없다.

```text
qN7v3v6F...무작위처럼 보이는 값...
```

API 서버는 다음 방법 중 하나로 검사한다.

```text
방법 A: 공유 token 저장소에서 record 조회

방법 B: 인증 서버의 introspection endpoint에 문의
        "이 token이 active인가? 누구의 어떤 권한인가?"
```

OAuth token introspection의 표준 인터페이스는 [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html)에 정의되어 있다.

DB에는 원본 Bearer token 대신 `SHA256(token)`을 lookup key로 저장할 수 있다.

```text
발급:
    raw_token = CSPRNG(32 bytes)
    DB 저장   = SHA256(raw_token)
    client 전달 = raw_token

검증:
    presented_token 수신
    lookup_key = SHA256(presented_token)
    DB에서 lookup_key 조회
```

여기서 빠른 SHA-256을 써도 되는 이유는 token이 사람이 정한 낮은 entropy의 password가 아니라, CSPRNG가 만든 충분히 긴 난수이기 때문이다. DB가 유출되어 hash를 얻어도 공격자가 256-bit token 후보를 사전 대입하는 것은 현실적으로 불가능하다.

단, `opaque`의 정의 자체가 “반드시 순수 난수”라는 뜻은 아니다. client가 내부 구조와 의미를 알 수 없는 reference token이라는 성질이 핵심이다. 난수 reference가 흔하고 단순한 구현이다.

#### 12.10.10 JWT와 opaque token의 운영상 차이

| 항목 | 서명된 JWT access token | opaque reference token |
|---|---|---|
| API 검증 | signature와 claims를 로컬 검증 가능 | 저장소 조회 또는 introspection 필요 |
| 인증 서버 의존 | 매 요청 직접 문의하지 않아도 됨 | 검증 경로가 저장소/인증 서버에 의존 |
| 즉시 폐기 | 별도 denylist/state 없으면 어려움 | record를 revoke하면 반영하기 쉬움 |
| 권한 변경 반영 | 기존 token 만료 전까지 옛 claim이 남을 수 있음 | 중앙 record 변경을 즉시 반영 가능 |
| client의 내용 열람 | payload를 decode해 읽을 수 있음 | 내부 의미를 알 수 없음 |
| 정보 크기 | claims·서명 때문에 비교적 큼 | 보통 짧은 reference 값 |
| key 배포 | 검증 key의 배포·rotation 필요 | token 저장소의 접근·가용성 관리 필요 |

JWT를 “DB 조회가 전혀 없는 token”이라고 단정하면 안 된다. 계정 정지, tenant 상태, 세밀한 resource authorization을 확인하기 위해 결국 DB를 조회할 수도 있다. 반대로 opaque token도 API gateway가 검증 결과를 짧게 cache할 수 있다.

JWT는 자동으로 더 안전하거나 더 현대적인 선택이 아니다. 중앙 상태 조회를 줄이는 대신 즉시 취소와 권한 변경 반영이 어려워지는 trade-off가 있다.

#### 12.10.11 access token, refresh token, ID token을 혼동하지 않는다

OAuth/OIDC 시스템에서는 서로 다른 token이 동시에 나타날 수 있다.

| token | 받는 쪽과 목적 | 일반적인 제출 대상 |
|---|---|---|
| access token | resource에 접근할 권한 | API/resource server |
| refresh token | 새 access token을 발급받기 위한 장기 credential | authorization server |
| ID token | 사용자가 인증됐다는 정보를 client에 전달 | OIDC client |

```text
access token:
    API를 호출하기 위한 credential

refresh token:
    access token을 새로 받기 위한 credential
    일반 API에 보내지 않음

ID token:
    client가 로그인 결과를 확인하기 위한 token
    access token 대신 API에 보내는 값이 아님
```

세 token 모두 JWT일 수도 있지만 반드시 그런 것은 아니다. **JWT는 형식이고, access/refresh/ID는 프로토콜 안에서의 역할**이기 때문이다.

#### 12.10.12 작은 서비스에서는 무엇을 선택하는가

설계의 출발점은 “JWT를 쓸까?”가 아니라 trust boundary와 폐기 요구사항이다.

```text
동일한 browser와 단일 backend:
    server-side session + Secure/HttpOnly/SameSite cookie가 단순하다.

작은 API이고 중앙 조회가 문제되지 않음:
    opaque random token도 자연스럽다.

인증 서버와 여러 resource server가 분리됨:
    비대칭 서명 JWT를 사용하면 검증 public key만 배포할 수 있다.

하나의 작은 trust boundary에서 HS256을 사용:
    가능하지만 shared secret을 가진 모든 검증자가 발급도 가능함을 받아들여야 한다.
```

어떤 방식을 사용하더라도 access token은 짧게 만료시키고, refresh token은 더 강하게 보호·rotation하며, TLS·로그 마스킹·key rotation·정확한 claim 검증을 함께 설계한다. 검증된 프레임워크와 라이브러리를 사용하고 JWT parsing·서명 검증을 직접 구현하지 않는다.

#### 12.10.13 이 절의 핵심

```text
Bearer
    → 가진 사람이 쓸 수 있다는 사용 방식

JWT
    → claims를 담는 token 형식

opaque token
    → client가 내부 의미를 해석하지 못하는 reference token

HS256
    → JWT bytes에 HMAC-SHA256을 적용하는 공유키 방식

공개키 서명 JWT
    → 인증 서버만 private key로 발급하고 API는 public key로 검증
```

그리고 처음 질문으로 돌아가면:

> HS256으로 보호하는 대상은 일반적으로 매번의 API 요청 전체가 아니라 요청에 실어 보내는 JWT access token이다. client는 그 token을 `Authorization: Bearer ...`로 제시한다. Bearer token은 소지 자체가 사용 권한이므로 탈취에 약하며, TLS와 안전한 저장이 필수다.

**확인 문제:** `HS256 JWT`, `Bearer token`, `OAuth access token`이 왜 동의어가 아닌지 설명하자. 그리고 API server 세 곳에 HS256 secret을 배포했을 때 어느 서버가 새 token을 만들 수 있는지 답하자.

> **Token 절 통과 기준:** Bearer는 형식이 아니라 소지 기반 사용 방식이라는 것, JWT payload는 암호화가 아니므로 읽을 수 있다는 것, opaque token은 서버 상태를 가리키는 추측 불가능한 reference가 될 수 있다는 것을 설명할 수 있으면 충분하다. 두 번째 독서에서는 HS256 secret을 가진 검증자가 token 생성도 가능하다는 권한 경계까지 확인한다. 모든 JWT claim을 암기할 필요는 없다.

### 12.11 실제 TLS로 세 가지 가설을 검사한다

```bash
python3 04_tls/tls_memory_lab.py
```

예제는 실행할 때 임시 CA와 `localhost` 서버 인증서를 만들고, Python `ssl`의 실제 TLS 1.3 client/server를 연결한다. `MemoryBIO`는 TLS가 내보내는 바이트와 받아들이는 바이트를 메모리 buffer로 연결하는 인터페이스다. socket 대신 buffer를 운반하므로 네트워크나 관리자 권한이 필요 없으며 **TLS 알고리즘을 흉내 낸 코드가 아니다**. [Python ssl 문서](https://docs.python.org/3/library/ssl.html)

1. 그 CA를 명시적으로 신뢰하고 hostname도 맞으면 handshake와 HTTP bytes 전달이 성공한다.
2. CA는 같지만 기대 hostname을 `wrong.example`로 바꾸면 검증이 실패한다.
3. hostname은 맞아도 해당 CA를 신뢰하지 않으면 검증이 실패한다.

암호화된 application record와 복호화된 HTTP를 따로 관찰한다. 암호문에서 원문 문자열을 찾지 못했다는 결과만으로 보안을 증명하는 것은 아니지만, **앱이 읽는 바이트와 transport가 운반하는 바이트가 다름**을 확인할 수 있다.

생성한 인증서는 해당 실행의 client에서만 신뢰한다. OS trust store를 변경하지 않고 임시 private key 파일도 실행 후 제거한다. 인증서 수명·갱신·실제 DNS·소켓 운영을 다루는 배포 예제는 아니다.

코드와 연결: [D.11 — `temporary_pki()`와 `run_connection()`](#trace-tls).

12장을 끝내며 머릿속에는 한 줄의 파이프가 아니라 두 층이 보여야 한다. Handshake는 인증된 상대와 traffic key를 확립하고, record protocol은 그 key로 HTTP bytes를 계속 보호한다. HTTP의 method·path·cookie·Bearer token은 TLS 안에서 이동하지만, TLS endpoint에 도착하면 애플리케이션이 읽을 수 있는 bytes로 돌아온다. 바로 그 지점부터는 다음 부의 시스템 설계가 책임을 이어받는다.

> **12장 통과 기준:** TLS가 서버 인증, key agreement, key derivation, record AEAD를 조립한 protocol이라는 것, HTTP는 handshake 후 만들어진 대칭 traffic key로 보호된다는 것, TLS가 서버 내부 저장이나 애플리케이션 replay까지 자동으로 해결하지 않는다는 것을 설명할 수 있으면 13장으로 이동한다. Handshake secret tree와 record nonce 계산을 외울 필요는 없다.

---

# 제5부. 함수가 아니라 시스템을 보호한다

TLS handshake가 성공했다고 이야기는 끝나지 않는다. 실제 요청은 CDN, load balancer, 애플리케이션, KMS, DB를 차례로 지나며 여러 번 평문이 되고 다시 보호된다. 마지막 부에서는 카메라를 함수 내부에서 시스템 전체로 당긴다. 이제 질문은 `AES-GCM이 안전한가?`가 아니라 `이 값이 다음 신뢰 경계를 건널 때 누가 볼 수 있는가?`다.

## 13. TLS는 어디까지 보호하는가 — 연결에는 끝점이 있다

브라우저 주소창의 자물쇠는 `브라우저에서 어떤 서버 프로세스까지`의 연결을 말한다. 현대 서비스에서 그 프로세스는 애플리케이션이 아니라 CDN, WAF, load balancer, API gateway 또는 Kubernetes ingress일 수 있다. **TLS는 조직 전체를 덮는 막이 아니라 두 endpoint 사이에 생긴 secure channel**이다.

```text
Browser
   │ TLS connection A
   ▼
CDN / WAF / Load Balancer / Ingress
   │ TLS connection B 또는 보호되지 않은 내부 연결
   ▼
Application Service
   │ TLS connection C
   ▼
Database / other service
```

### 13.1 TLS termination에서 실제로 일어나는 일

브라우저가 보낸 TLS record는 첫 번째 endpoint에서 tag 검증과 복호화를 거친다. 그 endpoint는 routing, WAF 검사, HTTP header 추가 등을 하려면 HTTP plaintext를 볼 수 있어야 한다. 이것을 TLS termination이라고 한다.

```text
Browser ── ciphertext A ──→ Load Balancer
                              │ decrypt
                              ▼
                         HTTP plaintext
                              │ 새 연결에서 다시 encrypt
                              ▼
App     ←─ ciphertext B ──────┘
```

여기서 A와 B는 하나의 긴 TLS tunnel이 아니다. 서로 다른 handshake, certificate, traffic key, sequence number를 가진 **독립된 두 연결**이다. Load balancer는 두 연결 사이에서 plaintext를 보는 trusted intermediary다. 따라서 “인터넷 구간에 HTTPS를 켰다”와 “애플리케이션까지 모든 hop이 암호화됐다”는 같은 문장이 아니다.

TLS 종단은 private key뿐 아니라 복호화된 request body, cookie, Bearer token을 볼 수 있다. Access log나 tracing system이 이 값을 기록하면 전송 암호화는 정상이어도 다른 저장소에서 secret이 유출된다. 그래서 종단의 운영 권한, 로그 마스킹, 내부 연결, 인증서 배포가 모두 trust boundary 설계에 포함된다.

### 13.2 내부 TLS와 mTLS는 무엇을 더하는가

Load balancer와 app 사이에 TLS connection B를 만들면 그 hop의 네트워크 도청·변조를 막을 수 있다. mTLS(mutual TLS)는 여기에 client certificate 검증을 추가한다.

```text
일반적인 browser HTTPS:
browser verifies server certificate

service-to-service mTLS:
client service verifies server certificate
server service verifies client certificate
```

mTLS가 확인하는 것은 보통 `이 연결의 client가 어떤 workload certificate를 소유하는가`다. 최종 사용자 Alice의 로그인 상태나 `Alice가 이 row를 읽을 권한이 있는가`까지 자동으로 증명하지 않는다. Workload identity와 end-user identity는 서로 다른 층이며, 애플리케이션 authorization은 여전히 필요하다.

또한 mTLS는 무료 보안 스위치가 아니다. 누가 인증서를 발급하는지, private key를 어디에 두는지, 짧은 수명의 인증서를 어떻게 rotation하는지, 폐기와 장애를 어떻게 처리할지 운영 체계가 필요하다. 네트워크 위치만 신뢰하는 것보다 강한 신원을 줄 수 있지만 그 신원의 수명주기를 떠안는다.

이 장에서 가져갈 그림은 선명하다. **자물쇠를 보면 먼저 양쪽 endpoint를 손가락으로 짚는다.** 그 사이만 TLS가 직접 보호한다. 다음 장에서는 그 endpoint에서 평문이 된 API token이 DB에 들어가고 다시 사용되는 전 과정을 따라간다.

> **13장 통과 기준:** browser→load balancer와 load balancer→app이 서로 다른 TLS 연결일 수 있다는 것, TLS 종단은 HTTP plaintext를 볼 수 있다는 것, mTLS의 workload 인증이 최종 사용자 authorization을 대체하지 않는다는 것을 설명할 수 있으면 14장으로 이동한다.

---

## 14. 하나의 API token이 저장되고 다시 사용되기까지

이제 책의 처음에 맡겨 둔 `shop.example`의 외부 API token으로 돌아오자. 지금까지의 모든 부품을 한 요청의 시간순으로 놓아 보면 저장 암호화와 HTTPS가 경쟁 기술이 아니라 **서로 다른 구간을 맡은 보호 장치**임이 보인다.

### 14.1 등록 요청: plaintext는 어디에서 나타나는가

Alice가 브라우저에 token을 입력하고 저장 버튼을 누른다.

```text
① Browser memory
   token plaintext
       │ HTTP request bytes
       ▼
② Browser↔TLS endpoint
   TLS traffic key로 record 보호
       │ endpoint에서 decrypt
       ▼
③ Application memory
   인증·인가와 입력 검사를 위해 token plaintext 사용
       │ AES-GCM(K, nonce, token, AAD)
       ▼
④ Database
   record_id, key_version, nonce, ciphertext||tag 저장
```

TLS는 ②의 이동을 보호한다. 그러나 애플리케이션이 값을 처리하려면 ③에서 plaintext가 존재한다. 이것은 암호화 실패가 아니라 요구사항의 결과다. 앱이 token을 한 번도 볼 수 없어야 한다면, 일반적인 server-side 사용 모델이 아니라 client-side/end-to-end encryption 또는 별도의 실행 경계를 설계해야 한다.

AES-GCM을 호출하기 전에 앱은 현재 인증된 user/tenant와 이 record의 용도를 알고 있다. 이 신뢰한 문맥으로 AAD를 만든다. DB에서 읽은 `owner_id`를 아무 검증 없이 되돌려 AAD로 쓰는 대신, 현재 authorization 결과와 예상 record identity를 묶어야 한다.

```text
K: application key 또는 unwrap한 DEK — 비밀
N: 이번 암호화를 위한 nonce — DB 저장 가능
P: 외부 API token — 암호화 전후 앱 메모리에서 수명 최소화
AAD: tenant/record/type/version 문맥 — 공개 가능, 정확히 재구성 필요
C||T: ciphertext와 tag — DB 저장
```

스토리지 계층의 disk encryption은 DB 파일과 snapshot을 보호할 수 있다. 애플리케이션 field encryption은 SQL dump에 ciphertext만 남게 한다. 둘은 공격 지점이 다르므로 함께 존재할 수 있다.

### 14.2 나중의 사용: 복호화 권한은 어떻게 행사되는가

Worker가 외부 API를 호출할 시간이 되면 흐름은 반대로 진행된다.

```text
⑤ Worker가 workload identity로 KMS/Vault 권한 획득
⑥ DB에서 nonce, ciphertext/tag, wrapped DEK, metadata 조회
⑦ KMS로 DEK unwrap 또는 허용된 key 획득
⑧ 기대 AAD로 AES-GCM tag 검증 후 token 복호화
⑨ token을 외부 서비스의 HTTPS 요청에 사용
⑩ plaintext와 DEK reference의 수명을 줄이고 로그에는 남기지 않음
```

⑦에서 KMS가 raw KEK를 내주지 않아도 Worker는 unwrap/decrypt 권한을 행사한다. 그러므로 Worker가 완전히 장악되면 공격자는 같은 API를 호출할 수 있다. 반대로 DB dump만 훔친 공격자는 KMS 권한이 없어 token을 복구하지 못하는 것이 이 구조의 목표다.

⑨에는 새로운 TLS 연결이 생긴다. 사용자의 browser→shop 연결에서 쓴 traffic key나 DB field key를 재사용하지 않는다. 외부 서비스와의 TLS가 token을 이동 중에 보호하고, 외부 서비스는 결국 token plaintext를 받아 사용한다.

이 전체 흐름에서 `암호화된 상태`와 `평문 상태`가 번갈아 나타난다. 좋은 설계는 plaintext가 영원히 사라진다고 약속하지 않는다. **필요한 endpoint에서만, 필요한 시간 동안만 나타나도록 권한과 관찰 가능성을 줄인다.**

> **14장 통과 기준:** 한 token에 대해 TLS traffic key, field-encryption key/DEK, KMS KEK가 서로 다른 key인 이유와 token plaintext가 나타나는 지점을 순서대로 설명할 수 있으면 15장으로 이동한다.

---

## 15. 위협 모델로 다시 읽는 전체 구조

지금까지는 정상 흐름을 따라갔다. 이제 공격자가 한 구성요소씩 가져간다고 가정하자. 이 장의 표는 제품 기능 비교표가 아니라 **공격자가 어느 경계를 넘었는지 추적하는 지도**다. 각 행을 읽을 때 `공격자가 가진 것`과 `아직 없는 것`을 함께 말해야 한다.

| 공격/사고 | TLS | 스토리지 암호화 | 앱 필드 암호화 + 외부 KMS | 남는 판단 |
|---|---:|---:|---:|---|
| 네트워크 패킷 도청 | 보호 | 무관 | 무관 | 정확한 TLS endpoint 사이에서만 |
| 네트워크 내용 변조 | 보호 | 무관 | 무관 | 인증서·tag 검증을 끄지 않아야 함 |
| 물리 디스크/스냅샷 단독 유출 | 무관 | 보호 | 보호 가능 | key가 snapshot과 분리돼야 함 |
| SQL dump 유출 | 무관 | 대개 부족 | 보호 가능 | ciphertext와 KMS 권한이 분리된 경우 |
| DB 관리자 계정 오용 | 무관 | 대개 부족 | 보호 가능 | 앱만 별도 decrypt 권한을 가진 경우 |
| 애플리케이션 RCE | 부족 | 부족 | 대개 부족 | 앱의 정상 복호화 권한을 악용 가능 |
| KMS 권한만 유출 | 무관 | 무관 | 데이터 없이는 제한적 | DB 접근과 결합되면 위험 증가 |
| DB와 KMS 권한 동시 유출 | 무관 | 부족 | 복호화 가능 | 분리·최소권한·탐지가 실패한 상태 |
| 사용자 단말 악성코드 | 부족 | 무관 | 무관 | 입력 전·표시 후 plaintext 노출 가능 |

### 15.1 DB-only 침해와 application 침해는 다른 사건이다

SQL dump만 유출된 공격자는 nonce, ciphertext/tag, key version, wrapped DEK를 얻을 수 있다. 이 값들은 원래 공개 저장을 허용한 metadata다. 공격자가 KMS 권한과 plaintext DEK를 갖지 못했다면 field encryption의 보호 목표가 유지된다.

애플리케이션 RCE에서는 상황이 바뀐다. 앱은 정상 업무를 위해 DB도 읽고 KMS도 호출한다. 공격자는 raw master key를 export하지 않고도 정상 decrypt 경로를 반복 호출하거나, 복호화 직후의 메모리와 응답을 훔칠 수 있다. `KMS를 사용한다`는 사실은 key material의 export를 줄이고 중앙 정책·감사를 제공하지만, **허가된 복호화 주체의 완전 장악**까지 막는 마법은 아니다.

### 15.2 방어층은 완벽해서가 아니라 실패를 분리하기 위해 둔다

Disk encryption, field encryption, IAM, TLS, audit log가 함께 있는 이유는 모두 같은 공격을 네 번 막기 위해서가 아니다. 노트북 분실, snapshot 유출, SQL credential 탈취, 네트워크 도청, 애플리케이션 RCE가 서로 다른 자산 조합을 주기 때문이다.

```text
공격 성공에 필요한 조합을 늘린다
    DB dump만으로는 부족
    KMS role만으로도 부족
    둘을 결합하면 위험

동시에 결합 시도를 제한하고 관찰한다
    least privilege
    decrypt rate/대상 제한
    network boundary
    audit와 이상 징후 탐지
```

따라서 “암호화되어 있나요?”보다 좋은 질문은 “이 공격자가 지금 가진 자산으로 어떤 plaintext까지 도달할 수 있나요?”다. 이것이 앞에서 배운 primitive를 실제 보안 주장으로 바꾸는 문장이다.

> **15장 통과 기준:** DB-only 공격과 app RCE에서 공격자가 가진 능력의 차이, DB와 KMS 권한을 분리하는 목적, 방어층 하나가 모든 위협을 막지 못해도 가치가 있는 이유를 설명할 수 있으면 16장으로 이동한다.

---

## 16. 알고리즘 이름보다 먼저 묻는 설계 질문

새 기능을 설계할 때 바로 `AES냐 RSA냐`를 고르면 문제와 도구가 뒤섞인다. 먼저 아래 질문을 순서대로 통과시키자. 답이 정해지면 사용할 primitive의 범주가 자연스럽게 좁아진다.

### 16.1 원문을 다시 복구해야 하는가

복구할 필요가 없는 사용자 password라면 암호화하지 않는다. Unique salt와 비용 parameter를 사용한 Argon2id/scrypt verifier를 저장한다. 반대로 외부 API token처럼 나중에 원문을 제출해야 한다면 one-way verifier로는 요구사항을 만족할 수 없다. AEAD 암호화와 복호화 key 관리가 필요하다.

```text
원문 복구 불필요 → password KDF verifier
원문 복구 필요   → AEAD + key management
```

### 16.2 누가 생성하고 누가 검증하는가

Webhook 공급자와 우리 서버 둘만 shared secret을 갖고 둘 다 tag 생성 능력을 가져도 된다면 HMAC이 맞을 수 있다. Timestamp와 canonical request를 MAC 입력에 넣고 replay window를 별도로 검사한다. 반면 artifact를 받은 누구나 검증하되 제작자만 새 서명을 만들게 하려면 digital signature가 필요하다.

```text
같은 secret을 가진 폐쇄된 양쪽 → HMAC
private 생성 권한과 public 검증 권한 분리 → digital signature
```

`누가 이 key를 갖는가`를 먼저 그리면 HMAC과 signature의 선택은 성능 비교가 아니라 권한 구조의 선택이 된다.

### 16.3 데이터는 어느 경계를 건너는가

Browser와 API server 사이에는 자체 암호 프로토콜을 만들지 않고 TLS/HTTPS를 사용하며 certificate/hostname 검증을 유지한다. DB에 저장되는 민감 필드는 AEAD로 보호하고 key는 DB와 다른 권한 경계에 둔다. 큰 파일이나 많은 record에는 random DEK로 데이터를 암호화하고 KEK/KMS로 DEK를 wrapping하는 envelope 구조를 고려한다.

다른 사람의 public key로 큰 파일을 보호할 때도 같은 원리가 반복된다.

```text
random DEK 생성
파일은 DEK와 AEAD로 암호화
수신자의 public-key mechanism/KEM으로 DEK를 보호
encrypted file + protected DEK 전달
```

Public-key primitive는 큰 파일 전체를 대신 처리하기보다 대칭키를 안전하게 전달하거나 합의하는 역할을 맡는다.

### 16.4 유효했던 메시지를 다시 보내도 되는가

HMAC, signature, AES-GCM tag가 모두 정상이어도 예전 요청의 정확한 복사본은 여전히 유효할 수 있다. 결제·Webhook·0-RTT처럼 중복 실행이 위험하다면 timestamp, nonce registry, sequence, idempotency key, transaction state 중 무엇이 최신성을 결정하는지 명시한다. Replay는 `더 강한 cipher`가 아니라 protocol state로 막는다.

마지막으로 선택한 알고리즘 이름을 문장에 넣어 보자.

> `누가` 가진 `어떤 key`로 `무슨 bytes`를 처리해 `어떤 공격자`의 `어떤 행동`을 막으며, `무엇은 여전히 못 막는다`.

이 문장을 완성하지 못하면 아직 라이브러리를 고를 때가 아니다.

---

## 17. 실패하는 설계에는 반복되는 오해가 있다

잘못된 구현은 대개 API 이름을 몰라서보다 멘탈모델의 한 문장이 틀려서 생긴다. 아래 사례는 금지 목록으로 외우기보다 **어떤 잘못된 가정이 숨어 있는지** 찾아 읽자.

### 17.1 “비밀값은 코드에 있어도 외부에 출력하지 않으면 된다”

```python
KEY = b"production-secret..."
```

소스 코드의 key는 Git history, 빌드 artifact, 컨테이너 이미지, 개발자 장비로 복제된다. 문제는 문자열 위치가 아니라 접근 경계와 rotation 가능성이다. Runtime identity로 Secret Manager/KMS에서 필요한 권한을 얻도록 설계한다.

### 17.2 “암호문이면 같은 DB에 key를 둬도 된다”

```text
same database row:
key + nonce + ciphertext
```

Nonce와 tag는 같은 row에 있어도 되지만 secret key까지 함께 두면 DB dump 하나로 복호화가 끝난다. DB 단독 유출을 위협으로 정했다면 key를 별도 권한 경계에 두어야 한다. 값이 길고 무작위처럼 보인다고 모두 같은 종류의 metadata는 아니다.

### 17.3 “Nonce는 공개값이므로 아무 값이나 반복해도 된다”

공개 가능성과 재사용 가능은 다른 성질이다. AES-GCM에서 같은 key와 nonce가 겹치면 counter mask가 재사용되고 기밀성과 인증이 무너진다. 검증된 라이브러리, 96-bit nonce 생성 규칙, key당 메시지 수와 충돌/재시작 정책을 함께 설계한다.

### 17.4 “AES로 암호화했으니 변경도 막았다”

AES-CTR이나 CBC 같은 encryption mode를 인증 없이 사용하면 공격자가 ciphertext를 조작했을 때 안전하게 거부한다는 보장이 없다. 특별한 상호운용 제약이 없다면 AES-GCM이나 ChaCha20-Poly1305 같은 AEAD를 기본으로 삼고, tag 검증 전 plaintext를 사용하지 않는다.

### 17.5 “출력 길이가 충분하면 password도 안전하다”

`SHA256(password)`는 32바이트지만 후보 하나를 너무 빠르게 검사할 수 있다. 출력 길이는 password의 엔트로피나 공격 비용이 아니다. Argon2id/scrypt와 unique salt, 서버의 rate limit·동시성 제한을 함께 사용한다. Base64로 한 번 더 감싸도 encoding만 바뀐다.

### 17.6 “TLS가 암호화됐으니 인증서 검증은 생략해도 된다”

Hostname 또는 trust-chain 검증을 끄면 공격자와는 매우 안전하게 암호화된 연결을 만들 수 있다. 문제는 암호 강도가 아니라 상대 신원이다. 같은 이유로 네트워크에서 받은 public key가 수학적으로 유효하다는 사실만으로 그 소유자를 믿을 수 없다. Certificate, pin, 사전 배포, SSH known_hosts 같은 별도의 binding이 필요하다.

### 17.7 “안전한 primitive를 조립하면 안전한 protocol이 된다”

AES-GCM, X25519, Ed25519가 각각 안전해도 메시지 순서와 역할을 직접 정하는 순간 transcript binding, replay, downgrade, serialization ambiguity, key separation 문제가 생긴다. 라이브러리는 primitive의 오용을 일부 막을 뿐 protocol의 의미까지 만들어 주지 않는다. 네트워크에는 TLS, token에는 검증된 인증 framework, envelope encryption에는 cloud/Vault SDK처럼 분석된 구성을 우선한다.

이 장의 공통된 교훈은 단순하다. **보안 성질은 함수 이름에서 시스템 전체로 자동 전파되지 않는다.** 입력, 상태, key 위치, 상대 신원, 실패 처리 중 하나가 틀리면 primitive는 정확히 계산되면서도 시스템은 실패한다.

---

<a id="labs"></a>

## 18. 실습실 — 관찰한 출력을 설명으로 바꾸기

본문을 읽는 것만으로 멘탈모델이 완성되지는 않는다. 이 장은 이미 만든 playground를 책의 순서로 다시 걷는 실습실이다. 목표는 예상 출력과 같은 문자열을 얻는 것이 아니라, 실행 전 결과를 예측하고 실행 후 **어느 입력이 달라져서 어느 보안 성질이 드러났는지** 설명하는 것이다.

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

첫 단계에서는 아직 암호문을 만들지 않는다. `random_and_hash.py`에서 난수와 digest가 서로 독립된 값임을 확인하고, password verifier와 HMAC tag가 같은 “비슷해 보이는 bytes”여도 입력과 목적이 다름을 관찰한다.

```bash
python3 01_primitives/random_and_hash.py
python3 01_primitives/password_kdf.py
python3 01_primitives/hmac_demo.py
```

### 2단계: 대칭키와 저장

두 번째 단계에서는 정상 복호화만 확인하지 않는다. Nonce 재사용과 AAD 바꿔치기를 일부러 실행해, `AESGCM.encrypt()` 한 번의 성공보다 **실패 조건을 지키는 protocol**이 더 중요하다는 사실을 확인한다.

```bash
python3 02_symmetric/gcm_walkthrough.py
python3 02_symmetric/aes_gcm.py
python3 02_symmetric/nonce_reuse.py
python3 02_symmetric/aad_swap_demo.py
python3 02_symmetric/db_encryption_demo.py --help
```

### 3단계: 비대칭키의 계산과 역할

세 번째 단계는 `public key`라는 하나의 말 아래 섞여 있던 역할을 분리한다. 작은 수의 계산은 등식을 눈으로 검산하기 위한 것이고, X25519와 Ed25519 예제는 실제 라이브러리의 서로 다른 API 경계를 보기 위한 것이다.

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

마지막 단계에서는 앞 실습의 부품을 직접 재구현하지 않는다. 실제 TLS state machine에 임시 인증서와 byte transport를 제공하고, 신뢰·hostname·암호화 record라는 세 가설을 각각 실패시켜 본다.

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

## 19. 책을 덮기 전에 — 하나의 요청을 끝까지 설명해 보기

처음에는 SHA-256, HMAC, AES-GCM, X25519, 인증서가 서로 떨어진 명사였다. 이제 마지막으로 `shop.example`의 하루를 처음부터 끝까지 말해 보자. 각 문장에는 누가 가진 key인지, 무엇이 저장·전송되는지, 어떤 공격을 막는지가 들어간다.

### 19.1 Alice가 로그인한다

Alice의 password 원문은 DB에 없다. DB에는 unique salt, Argon2id parameter, verifier가 있다. 서버는 TLS 안에서 받은 password 후보에 같은 KDF를 실행해 verifier를 비교한다. DB 유출 공격자는 복호화할 key를 찾는 것이 아니라 후보 password를 오프라인으로 반복 계산한다. Memory-hard KDF는 그 시도마다 비용을 부과한다.

로그인이 성공하면 서버는 password 대신 사용할 session cookie 또는 access token을 발급한다. 이 값이 Bearer credential이라면 소지한 자가 사용할 수 있으므로 TLS, 안전한 client 저장, 짧은 만료, 로그 마스킹이 중요하다. JWT인지 opaque token인지는 별도의 형식·검증 선택이다.

### 19.2 브라우저가 API token을 전송한다

브라우저는 `shop.example` 인증서의 chain과 hostname을 검증한다. 서버는 certificate private key로 현재 handshake에 참여했음을 증명하고, 양쪽의 ephemeral key agreement 결과는 HKDF를 거쳐 방향별 traffic key가 된다. HTTP body는 certificate public key로 직접 암호화되지 않는다. TLS record의 대칭 AEAD가 실제 bytes를 보호한다.

```text
certificate/signature → 누구와 연결했는가
ephemeral key agreement → 공유 secret을 보내지 않고 만들었는가
HKDF → 방향·목적별 traffic key를 만들었는가
AEAD → HTTP bytes를 숨기고 변조를 거부하는가
```

TLS가 종료되는 load balancer나 app은 token plaintext를 볼 수 있다. 따라서 자물쇠는 “서버 조직 안의 누구도 볼 수 없다”가 아니라 “검증한 TLS endpoint까지의 네트워크 구간이 보호된다”는 뜻이다.

### 19.3 애플리케이션이 token을 저장한다

앱은 random nonce와 DEK/application key로 token을 AES-GCM 암호화하고, record identity와 version을 AAD에 묶는다. DB에는 nonce, ciphertext/tag, key version, 필요하다면 wrapped DEK가 남는다. Nonce와 tag는 공개 가능하지만 key는 별도 Secret Manager/KMS 권한 경계에 둔다.

```text
복구할 필요 없는 password
    → password KDF verifier

나중에 복구해야 하는 token
    → AEAD ciphertext + nonce + tag + metadata

대량의 record와 key lifecycle
    → DEK로 데이터 암호화 + KMS KEK로 DEK wrapping
```

이 구조는 DB dump만 훔친 공격자를 막으려는 것이다. 복호화 권한이 있는 앱이 장악되면 공격자는 KMS API와 정상 decrypt path를 악용할 수 있다. 알고리즘이 실패한 것이 아니라 위협 모델의 경계가 달라진 것이다.

### 19.4 Worker가 token을 다시 사용한다

Worker는 workload identity로 KMS 권한을 얻고, 저장된 key version과 wrapped DEK를 이용해 올바른 DEK를 복구한다. 기대한 AAD로 tag를 검증한 뒤에만 plaintext token을 사용한다. 외부 API 호출은 또 다른 TLS 연결에서 보호된다. Browser 연결의 traffic key, DB field key, 외부 API 연결의 traffic key는 모두 용도와 수명이 다르다.

이제 전체 시스템은 하나의 거대한 암호화 함수가 아니라 다음 경계들의 연속으로 보인다.

```text
Browser plaintext
  → TLS-protected transit
  → TLS endpoint/application plaintext
  → AEAD-protected storage
  → authorized application plaintext
  → 새 TLS-protected transit
  → External service plaintext
```

각 화살표마다 key의 소유자와 공격자가 달라진다. 어떤 구간도 다른 구간의 보안을 자동으로 상속하지 않는다.

### 19.5 마지막으로 스스로 말해야 할 문장

새 암호 기능을 만났을 때 알고리즘 이름부터 묻지 않는다. 다음 문장을 채운다.

> **누가** `_____` key를 갖고, **어떤 bytes** `_____`를 입력해, **무엇** `_____`를 저장하거나 전송한다. 그래서 **공격자** `_____`는 **행동** `_____`을 하기 어렵다. 그러나 **남은 공격** `_____`은 여전히 가능하다.

이 문장에 답하면 SHA-256을 HMAC처럼 오해하지 않고, verifier를 password 원문처럼 여기지 않으며, nonce를 key처럼 숨기지 않고, certificate public key로 HTTP body를 암호화한다고 말하지 않게 된다. 그리고 `KMS를 썼다`, `HTTPS다`, `AES-256이다` 같은 제품·알고리즘 이름만으로 시스템 전체의 안전을 선언하지 않게 된다.

이 책의 최종 멘탈모델은 한 문장으로 줄일 수 있다.

> **암호학은 데이터를 사라지게 하는 마법이 아니라, 특정 공격자에게 특정 능력을 주지 않도록 key·연산·신뢰 경계를 설계하는 기술이다.**

---

## 20. 더 깊이 들어가기 위한 출발점

본문은 이해의 흐름을 위해 일부 protocol 세부와 보안 증명을 의도적으로 경계 밖에 두었다. 실제 구현·설계 결정을 내릴 때는 아래 표준과 제품 문서를 원문으로 확인한다. 이 목록은 본문의 대체물이 아니라, 이제 생긴 멘탈모델을 더 정확한 명세로 확장하기 위한 출발점이다.

### 20.1 표준과 운영 문서

- [NIST FIPS 197: Advanced Encryption Standard](https://csrc.nist.gov/pubs/fips/197/final)
- [NIST SP 800-38D: Galois/Counter Mode](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [RFC 2104: HMAC](https://www.rfc-editor.org/rfc/rfc2104.html)
- [RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869.html)
- [RFC 7748: X25519 and X448](https://www.rfc-editor.org/rfc/rfc7748.html)
- [RFC 8032: Ed25519 and Ed448](https://www.rfc-editor.org/rfc/rfc8032.html)
- [RFC 8446: TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html)
- [RFC 9106: Argon2](https://www.rfc-editor.org/rfc/rfc9106.html)
- [RFC 5280: X.509 PKI Certificate and CRL Profile](https://www.rfc-editor.org/rfc/rfc5280.html)
- [RFC 6750: OAuth 2.0 Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750.html)
- [RFC 7519: JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519.html)
- [RFC 7662: OAuth 2.0 Token Introspection](https://www.rfc-editor.org/rfc/rfc7662.html)
- [RFC 8725: JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725.html)
- [RFC 9068: JWT Profile for OAuth 2.0 Access Tokens](https://www.rfc-editor.org/rfc/rfc9068.html)
- [AWS Secrets Manager introduction](https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html)
- [AWS KMS key concepts and hierarchy](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html)
- [Google Cloud KMS envelope encryption](https://cloud.google.com/kms/docs/envelope-encryption)
- [HashiCorp Vault Transit secrets engine](https://developer.hashicorp.com/vault/docs/secrets/transit)
- [Kubernetes Secrets](https://kubernetes.io/docs/concepts/configuration/secret/)

### 20.2 이 책의 전개에 참고한 공개 교재

이 책의 설명과 예제는 현재 학습 세션을 위해 새로 구성했으며 아래 책을 번역하거나 축약한 것이 아니다. 다만 좋은 암호학 교재가 독자의 사고를 확장하는 순서에서 다음 원칙을 참고했다.

- Mike Rosulek의 [The Joy of Cryptography](https://joyofcryptography.com/)에서 공격자가 무엇을 관찰하고 구별할 수 있는지 먼저 명시하는 태도를 참고했다.
- Paar·Pelzl·Güneysu의 [Understanding Cryptography](https://www.cryptography-textbook.com/)에서 작은 계산, 실제 응용, 확인 문제를 연결하는 학습 단위를 참고했다.
- Boneh·Shoup의 [A Graduate Course in Applied Cryptography](https://toc.cryptobook.us/)에서 primitive의 보안과 protocol 전체의 보안을 분리하는 관점을 참고했다.

---

# 부록. 설명할 수 있는 지식으로 굳히기

본문은 처음부터 끝까지 하나의 논지를 따라갔다. 부록은 일부러 참고 문서처럼 사용하도록 구성한다. 확인 문제로 공격자의 능력을 점검하고, 용어를 다시 찾고, 실제 Python 함수의 입력과 출력을 debugger처럼 추적한다.

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

**해설:** AES 입력은 `N || counter`다. N이 달라지면 같은 K 아래에서도 mask가 달라진다. Bob은 수신한 N과 이미 가진 K로 동일 mask를 재현하고 ciphertext와 XOR한다. 필요한 것은 과거 메시지와 출력이 같다는 조건이 아니라 **이번 메시지의 양쪽 mask가 같다는 조건**이다. → 7.2·7.4절.

### A.4 Nonce 공개와 nonce 재사용은 왜 전혀 다른가?

**해설:** N만으로 `AES_K(N||counter)`를 계산할 수는 없다. 하지만 같은 K,N을 두 번 사용하면 동일 mask S가 재사용되어 `(P1 XOR S) XOR (P2 XOR S) = P1 XOR P2`로 소거된다. 공개 여부와 반복 여부는 다른 조건이다. → `nonce_reuse.py`.

### A.5 AAD를 포함한 row 전체를 바꿔치기하면?

DB의 Alice ciphertext와 `aad="alice"`를 Bob ciphertext와 `aad="bob"`으로 통째로 바꿨다. 앱은 DB에 적힌 AAD를 그대로 decrypt에 넘긴다. 왜 유효할 수 있나?

**해설:** Bob ciphertext는 Bob AAD 아래에서 원래 유효했다. 앱이 현재 요청은 Alice라는 신뢰 문맥을 강제하지 않았기 때문이다. 예상 record/tenant identity에서 AAD를 만들거나 수신 metadata와 기대값을 비교해야 한다. 그래도 같은 row의 과거 유효 버전으로 rollback하는 공격은 최신성 상태 없이 막지 못한다. → 7.5절.

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

### A.13 HS256 JWT가 API 요청을 서명하는가?

사용자 앱이 `Authorization: Bearer <HS256-JWT>`로 `GET /patients`를 호출한다. HS256이 보호하는 bytes와 보호하지 않는 bytes를 구분하라. 또한 API server 세 곳이 모두 HS256 secret을 가진 경우 누가 새 token을 만들 수 있는가?

**해설:** 전형적인 JWT Bearer access token에서 HS256은 JWT의 `base64url(header) || "." || base64url(payload)`에 대한 HMAC을 만든다. HTTP method, path, body 전체를 매 요청마다 HMAC하는 구조가 아니다. 사용자 앱은 발급된 token을 그대로 제시하므로 탈취한 소지자도 재사용할 수 있다. 세 API server는 동일 secret으로 MAC을 검증할 뿐 아니라 새 MAC도 만들 수 있으므로 모두 token 생성 능력을 갖는다. 검증 권한만 분리하려면 인증 서버가 private key로 서명하고 API에는 public key를 주는 비대칭 구조가 적합하다. → 6장·10.6절·12.10절.

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
| Block cipher / permutation | 고정 길이 블록 암호 / 일대일 가역 재배열 | 7.3절 |
| XOR / keystream | 비트별 배타적 논리합 / 평문에 XOR하는 mask의 연속 | 7.3절 |
| Nonce / counter / IV | 사용 구분값 / 증가하는 번호 / 모드의 초기화 값 | 7.2·7.4절, 12.6절 |
| AEAD / AAD / tag | 부가 데이터 인증을 지원하는 인증 암호 / 공개 인증 문맥 / 검증값 | 7.1·7.2·7.5절 |
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
| Access / refresh / ID token | API 접근 권한 / access token 재발급 credential / OIDC 로그인 결과 | 12.10절 |
| Bearer token | 별도의 key 소유 증명 없이 소지자가 사용할 수 있는 token | 12.10절 |
| JWT / claims | JSON 기반 security token 형식 / token이 전달하는 속성·주장 | 12.10절 |
| Opaque token / introspection | client가 해석하지 못하는 reference token / 인증 서버에 활성 상태를 묻는 검증 | 12.10절 |
| HS256 / RS256 | HMAC-SHA256 기반 JWS 보호 / RSA-SHA256 공개키 서명 | 6장, 10.6절, 12.10절 |
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

---

<a id="function-walkthrough"></a>

## 부록 D. 내가 실행한 함수를 입력부터 출력까지 해부하기

### D.0 이 부록의 읽는 방법

본문이 개념의 지도라면 이 부록은 debugger의 실행 경로다. 코드 파일을 옆에 열고 **입력 → 지역 변수 → 라이브러리 호출 → 반환값 → 저장/전송 → 실패** 순서로 따라간다. 함수 문법이 아니라 해당 인자와 순서가 필요한 이유를 설명한다.

아래에서 구별할 세 층은 다음과 같다.

```text
우리 함수:       nonce 생성, record 구성, DB 저장, 오류 처리
라이브러리 API:  AESGCM.encrypt, hashlib.scrypt, private.exchange 등
암호 알고리즘:   counter·XOR·GHASH, memory mixing, scalar multiplication 등
```

우리 코드가 API를 호출한다고 그 내부 알고리즘을 직접 구현한 것은 아니다. 반대로 API가 제공하는 보안 성질만으로 저장·전송 프로토콜의 모든 문제가 해결되는 것도 아니다.

| 읽을 절 | 실습 코드 | 먼저 읽을 본문 |
|---|---|---|
| [D.1](#trace-hash) | `random_and_hash.py` | 0장, 4장 |
| [D.2](#trace-password) | `password_kdf.py` | 5장 |
| [D.3](#trace-hmac) | `hmac_demo.py` | 6장 |
| [D.4](#trace-envelope) | `aes_gcm.py` | 7장 |
| [D.5](#trace-counter) | `gcm_walkthrough.py` | 7.3~7.4절 |
| [D.6](#trace-tag) | 라이브러리에 맡겼던 GCM tag 재구성 | 7.5절, D.5 |
| [D.7](#trace-attacks) | `nonce_reuse.py`, `aad_swap_demo.py` | 7장 |
| [D.8](#trace-database) | `db_encryption_demo.py` | 8~9장 |
| [D.9](#trace-exchange) | `x25519_exchange.py` | 10.1~10.5절 |
| [D.10](#trace-roles) | `key_roles_lab.py` | 10장 |
| [D.11](#trace-tls) | `tls_memory_lab.py` | 11~12장 |

`# book-check: 이름`으로 시작하는 Python 블록은 **각각 독립 실행 가능한 검산 코드**다. 저장소 루트에서 실행하며, `runpy.run_path()`로 기존 파일의 함수를 가져온다. 이때 파일의 `main()`은 실행되지 않는다. `lab["derive"]`는 그 파일에 정의된 `derive` 함수다. 같은 블록들을 테스트에서도 직접 실행하므로, 책의 assert와 실제 함수가 따로 노는 것을 방지한다.

```bash
python3 -m pytest tests/test_function_walkthrough.py -q
```

**안전 경계:** 고정 key·salt·비밀번호와 출력값은 모두 공개된 학습 fixture다. 운영 비밀을 넣거나 출력하지 않는다. 특히 고정 GCM key/nonce로 여러 메시지를 암호화하는 패턴을 복사하지 않는다. 정상 사용법은 기존 고수준 예제처럼 적절한 key 관리와 매번 새로운 nonce를 사용하는 것이다.

<a id="trace-hash"></a>

### D.1 `random_and_hash.py`: 난수 생성과 해시는 서로 다른 계산이다

코드: [`01_primitives/random_and_hash.py`](01_primitives/random_and_hash.py).

`main()`은 난수 key를 한 번 생성하고, 두 메시지를 각각 해시하고, 해시 간 다른 비트 수를 센다. 여기서 첫 번째 함정은 **생성한 key가 `sha256()`에 전달되지 않는다**는 사실이다. 세 줄이 나란히 있다고 key로 메시지를 암호화한 것이 아니다.

```python
key = secrets.token_bytes(32)   # 매 실행에서 새로 생성; 아래 해시 입력에는 없음
first = sha256(b"message A")
second = sha256(b"message B")
```

`sha256(data)`의 유일한 입력은 bytes다. `hashlib.sha256(data)`는 입력을 처리한 hash 객체를 만들고, `.digest()`는 32바이트 결과를 꺼낸다. `.hex()`는 나중에 그 결과를 64글자로 표시할 뿐, 다시 해시하는 연산이 아니다. 같은 입력의 hash는 실행마다 같다. 출력 중 난수 key만 달라져도 이상하지 않다.

`differing_bits(left,right)`는 같은 위치의 두 byte를 XOR하고, 결과에서 1인 비트 수를 모두 합친다. 예를 들어 `0b1010 XOR 0b0011 = 0b1001`이므로 다른 비트는 2개다. 길이 검사는 `zip()`이 짧은 쪽에서 멈춰 일부 입력을 조용히 무시하지 않게 한다.

```python
# book-check: hash
import runpy
lab = runpy.run_path("01_primitives/random_and_hash.py")
first = lab["sha256"](b"message A")
second = lab["sha256"](b"message B")
assert first.hex() == "b0fbd89676741e2deb64016c4467c51489456adf29a9917857fe5e778ecee721"
assert second.hex() == "d34c3b03c73e442266f98f12e31704fae0ecc9ba2b118757ad821ddc2954e260"
assert lab["differing_bits"](first, second) == 131
assert lab["differing_bits"](b"\x0a", b"\x03") == 2
```

**결과 해석:** 131/256은 이 두 입력에서 관찰한 값이지, 모든 입력 변화가 정확히 절반의 비트를 바꾼다는 규칙이 아니다. SHA-256 내부 연산은 4.1절의 padding·schedule·round다. 이 실습은 출력 변화만 관찰하며 collision resistance를 증명하지 않는다.

**직접 바꿔 보기:** `message A`를 두 번 넣으면 `differing_bits`는 0이다. `.digest()` 대신 `.hexdigest()`를 쓰면 타입이 `str`로 바뀌므로 같은 함수에 그대로 넣을 수 없다. 암호 연산의 입력 바이트와 표시 문자열의 차이를 확인하자.

<a id="trace-password"></a>

### D.2 `password_kdf.py`: 저장값을 만들 때와 검증할 때

코드: [`01_primitives/password_kdf.py`](01_primitives/password_kdf.py).

#### `PasswordRecord`: 나중에 재계산할 수 있게 남기는 것

이 dataclass는 `salt`, `derived_key`, `n`, `r`, `p`를 보관한다. 여기서 `derived_key`의 역할은 **password verifier**다. 실제 로그인 서버라면 이 값들을 DB에 직렬화한다. 현재 파일은 메모리 객체만 만들며 DB에 쓰지는 않는다. 출력의 `Store ...`는 운영 원칙을 말하는 문장이지 DB write가 완료됐다는 로그가 아니다.

#### `register(password)`: 최초 등록

```text
str password
  → secrets.token_bytes(16)로 새 salt 생성
  → 빈 derived_key를 가진 임시 record로 기본 비용 파라미터 선택
  → derive(password, salt, n, r, p)
  → 완성된 PasswordRecord 반환
```

임시 `derived_key=b""`는 계산 입력이나 secret이 아니다. 기본 파라미터를 담기 위한 코드 구조일 뿐이며, 마지막에 새 record로 대체된다. `frozen=True`이므로 객체의 필드를 나중에 덮어쓰는 방식이 아니다.

#### `derive(...)`: 라이브러리에 정확히 무엇을 넘기는가

입력 password는 UTF-8 bytes로 바뀐다. scrypt의 실제 입력은 이 bytes, salt, N/r/p, 출력 길이 32바이트다. 같은 여섯 값이면 결과가 같다. Unicode 정규화나 앞뒤 공백 제거를 이 함수가 자동 수행하지 않으므로, 시각적으로 비슷한 문자열이 같은 입력이라고 가정하지 않는다.

`hashlib.scrypt` 안의 큰 흐름은 **PBKDF2로 중간 블록 생성 → ROMix → PBKDF2로 출력 파생**이다. PBKDF2는 HMAC 기반 password KDF인데 scrypt의 바깥 단계에서는 반복 횟수 1로 사용된다. 주된 memory-hard 작업은 ROMix에 있다. ROMix는 길이 `128*r`바이트 상태들을 N개 저장한 뒤, 현재 상태에서 얻은 인덱스로 이전 상태를 선택해 XOR·BlockMix를 반복한다. BlockMix는 64바이트 단위로 Salsa20/8의 덧셈·rotate·XOR 혼합과 재배열을 사용한다. 여기서 Salsa20/8은 사용자 데이터를 암호화하는 용도가 아니라 내부 mixing 함수다. 정확한 규격은 [RFC 7914](https://www.rfc-editor.org/rfc/rfc7914.html)를 따른다.

우리 값에서 중간 상태 하나는 `128*8=1024`바이트, 주된 저장 배열은 `16384*1024=16 MiB`다. 이 중간 메모리는 verifier와 함께 DB에 저장하는 값이 아니다. 후보를 계산하는 동안 필요한 작업 공간이다. `p=1`은 ROMix 작업 묶음 하나를 뜻하며, p를 늘린다고 Python 함수가 자동으로 p개 thread를 띄운다는 뜻은 아니다.

고정 salt로 등록 이후의 계산을 재현해 보자. 이 블록은 **테스트용**이며 실제 `register()`의 랜덤 salt를 고정하도록 코드를 바꾸지 않는다.

```python
# book-check: password
import runpy
lab = runpy.run_path("01_primitives/password_kdf.py")
salt = bytes(range(16))
verifier = lab["derive"]("password", salt, n=2**14, r=8, p=1)
assert verifier.hex() == "ea23095e981e22db97492de26a5e5c794ea8f8b400d1a28803c39199396134c5"
record = lab["PasswordRecord"](salt=salt, derived_key=verifier)
assert lab["verify"]("password", record)
assert not lab["verify"]("Password", record)
```

#### `verify(password,record)`: 이때 salt를 새로 뽑지 않는다

```text
제출된 password + 저장했던 salt + 저장했던 n/r/p
  → derive로 candidate 계산
  → compare_digest(candidate, stored derived_key)
  → True 또는 False
```

등록 때와 동일한 조건에서 후보를 재계산해야 한다. 검증할 때 salt를 새로 만들면 정답 비밀번호라도 비교값이 달라진다. `compare_digest`는 복호화 함수가 아니라 timing leakage를 줄이기 위한 비교 API다. 길이·타입 정보와 모든 시스템 수준 timing 차이를 숨겨 준다는 뜻은 아니다. [Python hmac 문서](https://docs.python.org/3/library/hmac.html#hmac.compare_digest)

**공격자 관점:** DB의 record를 획득하면 위의 `verify`와 같은 계산을 자기 장비에서 후보마다 수행할 수 있다. 안전성은 “검증값을 공개해도 추측이 불가능함”이 아니라 **비밀번호의 예측 난이도와 후보당 비용**이다. 실제 서비스에서는 DB 파라미터·포맷도 검증하고, 동시 요청에 의한 메모리 고갈을 제한해야 한다. 이 학습 함수가 그것까지 구현하지는 않는다.

<a id="trace-hmac"></a>

### D.3 `hmac_demo.py`: 같은 key로 재계산하는 검증

코드: [`01_primitives/hmac_demo.py`](01_primitives/hmac_demo.py).

`authenticate(key,message)`는 `hmac.new(key,message,hashlib.sha256).digest()`를 반환한다. `hashlib.sha256`은 사용할 hash 알고리즘을 고르는 인자다. 이때 `key`는 SHA-256 함수의 숨겨진 옵션으로 들어가는 것이 아니라 **HMAC 구성의 입력**이다.

`verify(key,message,tag)`는 기대 tag를 `authenticate`로 다시 만들고 수신 tag와 비교한다. tag에서 message를 복원하거나 key를 추출하는 단계는 없다. 네트워크로 전달할 것은 message와 tag이고, K는 송수신자가 미리 공유했다고 가정한다.

고정 예에서 `key=b"k"*32`다. ASCII `k`는 `0x6b`이므로 K0 앞 32바이트는 `6b`, 뒤 32바이트는 `00`이다. K0 XOR ipad의 앞부분은 `6b XOR 36 = 5d`, K0 XOR opad의 앞부분은 `6b XOR 5c = 37`이 된다. 이것을 6.1절 수식에 넣으면:

```python
# book-check: hmac
import hashlib
import runpy
lab = runpy.run_path("01_primitives/hmac_demo.py")
key = b"k" * 32
message = b"transfer=100&to=bob"
k0 = key + bytes(32)  # 이 fixture는 원래 key가 64바이트보다 짧다.
inner = hashlib.sha256(bytes(x ^ 0x36 for x in k0) + message).digest()
tag = hashlib.sha256(bytes(x ^ 0x5c for x in k0) + inner).digest()
assert inner.hex() == "ce42a2ba326a342e963ad7ca898ad770cfa2e9daad7fc2d4433a0851d1ad6b68"
assert tag.hex() == "d41e62a6bb972752bb659628134b8551e94779a2562d96847cef566ade207bb5"
assert tag == lab["authenticate"](key, message)
assert lab["verify"](key, message, tag)
assert not lab["verify"](key, b"transfer=900&to=bob", tag)
```

위 코드는 **이 짧은 key에 대한 수식 검산**이지 임의 길이 key를 처리하는 HMAC 대체 구현이 아니다. 실제 함수는 표준 라이브러리의 정규화와 구현을 사용한다.

변조 실험에서는 message를 바꾸고 기존 tag를 그대로 둔다. K를 아는 실습자가 변조 message에 대해 새 tag를 만들면 당연히 검증된다. 공격자가 왜 그 작업을 못 하는지 설명할 때는 **K를 모른다는 전제**를 빠뜨리면 안 된다. 같은 정상 message/tag를 두 번 검증하면 둘 다 True다. 이 함수에는 replay 기록이 없기 때문이다.

<a id="trace-envelope"></a>

### D.4 `aes_gcm.py`: 암호화 함수와 포장 함수의 경계

코드: [`02_symmetric/aes_gcm.py`](02_symmetric/aes_gcm.py).

#### `generate_key()`와 `encrypt()`

`generate_key()`는 256비트, 즉 32바이트 secret을 생성한다. 이 파일의 `main()`에서는 **딱 한 번** 호출한다. 두 번의 `encrypt()`가 서로 다른 key로 실행되는 것이 아니다.

`encrypt(key,plaintext,aad)`는 새 12바이트 nonce를 만들고, `AESGCM(key).encrypt(nonce,plaintext,aad)`로 암호 연산을 수행한 뒤 Envelope에 담는다. key는 Envelope 안에 없다.

| 변수 | 타입·길이 | 다음에 쓰이는 곳 |
|---|---|---|
| `key` | bytes, 32 | AESGCM 객체의 비밀 입력 |
| `nonce` | bytes, 12 | 암호 연산과 Envelope |
| `plaintext` | bytes, 예제에서는 23 | 숨길 입력 |
| `aad` | bytes, 길이 가변 | 인증 문맥; Envelope에 자동 저장되지 않음 |
| 지역 변수 `ciphertext` | bytes, 예제에서는 39 | 실제로는 C 23바이트 + tag 16바이트 |

`cryptography`의 이 API는 ciphertext 뒤에 16바이트 tag를 붙여 반환한다. 변수 이름만 보고 tag가 없는 것으로 오해하지 않는다. [AESGCM API](https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM)

#### `Envelope.to_json()`은 추가 암호화가 아니다

nonce와 C/tag bytes를 URL-safe Base64 문자열로 만들고 version과 함께 JSON에 넣는다. `.decode("ascii")`는 Base64의 ASCII bytes를 JSON에 넣을 문자열로 바꾸는 작업이다. JSON을 받는 쪽은 역으로 Base64 decode를 해야 한다. 원래 plaintext의 문자 인코딩과는 별개다.

현재 파일에는 `from_json()`이 없다. `main()`은 메모리의 Envelope를 직접 `decrypt()`에 넘긴다. JSON 출력만 보고 네트워크 수신·파싱까지 검증했다고 생각하면 안 된다. 아래는 **신뢰한 자기 출력만** 되읽는 검산이며 불신 입력용 parser 구현 예제는 아니다.

```python
# book-check: envelope
import base64
import json
import runpy
lab = runpy.run_path("02_symmetric/aes_gcm.py")
key = lab["generate_key"]()
aad = b"content-type=text/plain;sender=alice"
plaintext = b"the launch code is 1234"
envelope = lab["encrypt"](key, plaintext, aad)
assert len(envelope.nonce) == 12
assert len(envelope.ciphertext) == 23 + 16
obj = json.loads(envelope.to_json())
assert set(obj) == {"version", "nonce", "ciphertext"}
assert base64.urlsafe_b64decode(obj["nonce"]) == envelope.nonce
assert base64.urlsafe_b64decode(obj["ciphertext"]) == envelope.ciphertext
assert lab["decrypt"](key, envelope, aad) == plaintext
```

#### `decrypt()`에서 오류가 갈리는 지점

먼저 version이 1인지 확인한다. 아니면 라이브러리를 부르기 전에 `ValueError`다. 맞으면 key·nonce·C/tag·AAD를 라이브러리에 넘긴다. tag가 검증되지 않으면 `InvalidTag`, 성공하면 plaintext bytes가 반환된다. UI용 UTF-8 decode는 그 뒤의 앱 처리다.

여기서 version 검사는 지원 포맷을 고르는 **정책 검사**이지 version을 tag에 바인딩한 것이 아니다. 이 예제의 AAD에는 version이 자동 포함되지 않는다. 현재 단일 version에서는 다른 version을 거절하지만, 나중에 여러 포맷을 지원할 때는 version과 의미 있는 metadata를 명확히 인증해야 한다.

**확인:** AAD가 Envelope에 없다면 복호화는 어떻게 가능한가? 호출자가 같은 문맥을 다시 제공하기 때문이다. 실제 시스템에서는 그 문맥의 출처와 직렬화 규칙까지 정해야 한다.

<a id="trace-counter"></a>

### D.5 `gcm_walkthrough.py`: plaintext가 AES 입력이 아닌 것을 코드로 확인하기

코드: [`02_symmetric/gcm_walkthrough.py`](02_symmetric/gcm_walkthrough.py).

이 실습은 출력 재현을 위해 KEY와 NONCE를 고정한다. **main() 한 번에서 동일한 계산을 수동 방식과 라이브러리 방식으로 비교하는 장치**다. 고정 nonce를 여러 실제 메시지에 써도 된다는 뜻이 아니다.

#### 작은 함수 네 개의 계약

`chunks(data,16)`은 offset 0,16,32…에서 slice를 반환한다. 마지막 slice는 16바이트보다 짧아도 그대로 반환한다. padding을 넣지 않는다.

`counter_block(nonce,counter)`는 nonce가 12바이트인지 검사한 뒤 `nonce + counter.to_bytes(4,"big")`를 반환한다. `big`은 큰 자릿수 byte가 먼저라는 뜻이다. counter 2는 `00 00 00 02`이며 ASCII 문자열 `b"2"`가 아니다.

`aes_encrypt_one_block(key,input_block)`는 16바이트 여부를 검사하고 AES 블록 연산 한 번을 수행한다. 코드의 `modes.ECB()`는 **한 블록의 E_K 연산에 접근하기 위한 수단**이다. 파일 전체를 ECB로 암호화하는 설계를 권하는 것이 아니다. `update()`가 데이터를 공급하고 `finalize()`가 이 암호 컨텍스트를 마무리한다. 그 둘의 결과를 연결해 한 블록의 출력을 받는다.

`xor(left,right)`는 `zip()` 범위만큼 XOR한다. 여기서는 마지막 짧은 plaintext block 길이만큼 mask를 사용하는 목적에 맞는다. 그러나 범용 유틸리티로서 길이 불일치를 검출하지는 않는다. D.1의 `differing_bits`와 달리 일부러 짧은 길이에 맞춰 동작한다는 것을 알고 읽어야 한다.

#### `build_ciphertext()`의 두 번의 loop를 펼치기

입력 `b"the launch code is 1234"`는 **23바이트**다. 첫 블록은 뒤 공백을 포함한 `b"the launch code "` 16바이트, 둘째는 `b"is 1234"` 7바이트다. loop의 `start=2`는 GCM이 `N || 1`을 tag mask용 J0로 예약하기 때문이다.

```text
KEY = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
N   = 202122232425262728292a2b

첫 블록:
P1         = 746865206c61756e636820636f646520
AES input  = 202122232425262728292a2b00000002
mask1      = d23aa6706c981a0e1a7c42cec118f4f9
C1         = a652c35000f96f60791462adae7c91d9

둘째 블록:
P2         = 69732031323334
AES input  = 202122232425262728292a2b00000003
mask2      = d049ec9c878063ee6cf66c12498a5e09
사용 부분  = d049ec9c878063                 (앞 7바이트)
C2         = b93accadb5b357

반환 C = C1 || C2 = a652c35000f96f60791462adae7c91d9b93accadb5b357
```

첫 byte만 손으로 확인하면 plaintext `0x74` XOR mask `0xd2` = ciphertext `0xa6`이다. 동일 key여도 둘째 블록의 AES 입력은 끝이 3이므로 mask가 다르다. nonce는 AES **입력 블록**에 들어가고 key는 AES **변환을 정하는 입력**으로 들어간다.

```python
# book-check: counter
import runpy
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
lab = runpy.run_path("02_symmetric/gcm_walkthrough.py")
key, nonce, plaintext = lab["KEY"], lab["NONCE"], lab["PLAINTEXT"]
assert list(lab["chunks"](plaintext, 16)) == [b"the launch code ", b"is 1234"]
assert lab["counter_block"](nonce, 2).hex() == "202122232425262728292a2b00000002"
mask1 = lab["aes_encrypt_one_block"](key, lab["counter_block"](nonce, 2))
assert mask1.hex() == "d23aa6706c981a0e1a7c42cec118f4f9"
assert lab["xor"](plaintext[:16], mask1).hex() == "a652c35000f96f60791462adae7c91d9"
manual = lab["build_ciphertext"](key, nonce, plaintext)
encrypted = AESGCM(key).encrypt(nonce, plaintext, lab["AAD"])
assert manual.hex() == "a652c35000f96f60791462adae7c91d9b93accadb5b357"
assert manual == encrypted[:-16]
assert encrypted[-16:].hex() == "1d8ff393a19510e73cd2cb89fe15b51f"
```

#### `main()`의 마지막 비교가 말하는 것

`encrypted[:-16]`은 C, `encrypted[-16:]`은 tag다. `manual == library_ciphertext`는 **counter/XOR 부분이 일치했다**는 결과다. 수동 코드가 tag도 구현했다는 뜻이 아니다. 마지막 `AESGCM.decrypt()`는 라이브러리의 tag 검증까지 거쳐야 성공한다.

**직접 바꿔 보기:** counter를 1부터 시작하도록 임시로 바꾸면 수동 C와 라이브러리 C가 달라진다. key를 바꾸면 mask와 C가 달라진다. AAD만 바꾸면 수동 C는 그대로다. AAD는 이 함수의 인자가 아니며, tag 계산에 참여하기 때문이다. 변형 실험 후에는 원래 코드로 되돌리고 fixture를 다른 데이터 암호화에 재사용하지 않는다.

<a id="trace-tag"></a>

### D.6 선택 심화: `AESGCM.encrypt()`가 만드는 tag까지 따라가기

D.5에서 멈추면 “ciphertext는 알겠는데 tag는 또 마법인가?”라는 질문이 남는다. 여기서는 **96비트 nonce, 128비트 tag**라는 현재 실습 조건에 한정해 tag를 재구성한다. 이것은 일반 GCM 라이브러리나 안전한 저수준 구현을 작성하는 과제가 아니다.

GHASH 입력은 **AAD 뒤의 block padding → C 뒤의 block padding → 두 길이**다. Padding은 각 부분을 16바이트 경계까지 0으로 채운다. 원래부터 경계에 맞으면 더 넣지 않는다. 이 padding은 인증 계산 내부용이지 ciphertext 뒤에 저장할 padding이 아니다.

현재 AAD `b"sender=alice"`는 12바이트, C는 23바이트이므로 총 네 개의 GHASH 블록이 된다.

```text
X1 = AAD 12바이트 + 0 네 바이트
X2 = C의 첫 16바이트
X3 = C의 남은 7바이트 + 0 아홉 바이트
X4 = AAD 비트 길이 96을 8바이트 big-endian으로
     || C 비트 길이 184를 8바이트 big-endian으로
   = 000000000000006000000000000000b8

H  = AES_K(0^128)
Y0 = 0^128
Yi = (Y(i-1) XOR Xi) · H       ← GHASH의 유한체 곱셈
U  = Y4
T  = U XOR AES_K(N || 00000001)
```

`·`는 Python 정수의 `*`가 아니다. 128비트 값을 다항식 계수로 해석하고, 덧셈을 XOR로 하며, 곱셈 결과를 정해진 다항식 `x^128+x^7+x^2+x+1`로 환원하는 GF(2^128) 연산이다. 환원은 결과를 다시 128비트 표현으로 가져오는 역할을 한다. GCM은 byte의 bit를 다항식 계수에 대응시키는 순서까지 정한다. [NIST GCM 명세](https://csrc.nist.gov/pubs/sp/800/38/d/final)

아래 `multiply()`의 128회 반복은 그 곱셈을 드러내기 위한 교육 코드다. x의 bit가 1일 때 해당 항을 XOR하고, 다음 항으로 이동하며 범위를 넘은 부분을 `0xe1 << 120`으로 환원한다. 이 상수는 정해진 bit 표현에서의 환원 상수이며 임의의 magic number가 아니다. Python의 분기·큰 정수 연산은 constant-time 암호 구현으로 취급할 수 없다.

```python
# book-check: gcm_tag
import runpy
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
lab = runpy.run_path("02_symmetric/gcm_walkthrough.py")

def multiply(x, y):
    product = 0
    moving = y
    for bit in range(127, -1, -1):
        if (x >> bit) & 1:
            product ^= moving
        dropped = moving & 1
        moving >>= 1
        if dropped:
            moving ^= 0xe1 << 120
    return product

def pad16(data):
    return data + bytes((-len(data)) % 16)

def teaching_tag(key, nonce, aad, ciphertext):
    # 12-byte nonce, 16-byte tag only. No general-purpose crypto API.
    assert len(nonce) == 12
    aes_block = lab["aes_encrypt_one_block"]
    h = int.from_bytes(aes_block(key, bytes(16)), "big")
    lengths = (len(aad) * 8).to_bytes(8, "big") + (len(ciphertext) * 8).to_bytes(8, "big")
    blocks = pad16(aad) + pad16(ciphertext) + lengths
    state = 0
    for offset in range(0, len(blocks), 16):
        block = int.from_bytes(blocks[offset:offset + 16], "big")
        state = multiply(state ^ block, h)
    j0 = nonce + (1).to_bytes(4, "big")
    return lab["xor"](state.to_bytes(16, "big"), aes_block(key, j0))

key, nonce, aad = lab["KEY"], lab["NONCE"], lab["AAD"]
encrypted = AESGCM(key).encrypt(nonce, lab["PLAINTEXT"], aad)
tag = teaching_tag(key, nonce, aad, encrypted[:-16])
assert tag.hex() == "1d8ff393a19510e73cd2cb89fe15b51f"
assert tag == encrypted[-16:]
```

이제 tag가 어떤 입력을 인증하는지 추적할 수 있다. C나 AAD를 바꾸면 GHASH 입력이 바뀌고, nonce를 바꾸면 J0의 AES mask가 바뀌며, key를 바꾸면 H와 mask가 바뀐다. nonce는 데이터 C를 만드는 과정에도 참여한다.

**해석의 경계:** tag 재구성 성공은 한 fixture에서 명세와 라이브러리 결과가 맞는다는 뜻이다. 구현의 constant-time 성질, 모든 입력 한도, nonce 관리, 오류 처리 안전성을 입증하지 않는다. 실제 복호화는 여전히 `AESGCM.decrypt()`에 맡기고 검증 전 plaintext를 사용하지 않는다. 이 교육 함수에는 decrypt 자체가 없다.

<a id="trace-attacks"></a>

### D.7 `nonce_reuse.py`와 `aad_swap_demo.py`: 정상 API 호출도 틀린 조합이면 실패한다

코드: [`02_symmetric/nonce_reuse.py`](02_symmetric/nonce_reuse.py), [`02_symmetric/aad_swap_demo.py`](02_symmetric/aad_swap_demo.py).

두 파일은 `AESGCM`을 잘못 구현한 예제가 아니다. **정상 AES-GCM API를 어떤 입력·문맥으로 호출했는지**가 보안 성질을 바꾼다는 예제다.

#### `nonce_reuse.py`: `[:-16]`을 자르는 이유

`AESGCM.encrypt()`의 반환은 `C || tag`다. 아래 두 줄은 tag가 아니라 counter-mode ciphertext C 부분만 꺼낸다.

```python
known_ct = AESGCM(key).encrypt(reused_nonce, known, None)[:-16]
secret_ct = AESGCM(key).encrypt(reused_nonce, secret, None)[:-16]
```

두 암호화의 K와 N이 같으므로 첫 block의 mask S도 같다.

```text
known_ct  = known  XOR S
secret_ct = secret XOR S

known_ct XOR secret_ct XOR known
  = (known XOR S) XOR (secret XOR S) XOR known
  = secret
```

`xor()`는 두 입력 길이 중 짧은 쪽까지만 처리한다. 이 파일의 두 plaintext는 모두 18바이트라서 전체를 복원한다. 길이가 다르면 짧은 공통 prefix까지만 이 단순 식으로 복원된다. `reused_nonce = b"\x00" * 12`는 zero nonce가 본질적으로 나빠서가 아니라 **같은 key 아래 두 번 사용했기 때문에** 일부러 위험하다.

```python
# book-check: nonce_reuse
import runpy
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
lab = runpy.run_path("02_symmetric/nonce_reuse.py")
key, nonce = bytes(range(32)), bytes(12)  # 공개 fixture; 운영에서 재사용 금지
known, secret = b"pay bob   1000 USD", b"pay alice 9000 USD"
known_c = AESGCM(key).encrypt(nonce, known, None)[:-16]
secret_c = AESGCM(key).encrypt(nonce, secret, None)[:-16]
assert lab["xor"](lab["xor"](known_c, secret_c), known) == secret
assert len(known_c) == len(known) == len(secret)
```

이 파일은 tag forgery를 구현하지 않는다. GCM nonce reuse는 기밀성 노출뿐 아니라 인증 안전성에도 영향을 주지만, 여기서 관찰하는 직접 결과는 **알고 있는 plaintext 하나로 다른 plaintext를 복구**하는 것이다.

#### `aad_swap_demo.py`: AAD를 누가 결정하는가

`encrypt(aes, plaintext, aad)`는 호출마다 `secrets.token_bytes(12)`로 nonce를 생성하고 `(nonce, C||tag)`를 반환한다. nonce를 반환하는 이유는 나중에 같은 nonce를 수신자가 입력해야 하기 때문이다. AAD는 반환하지 않는다. AAD는 현재 DB row 또는 요청에서 **수신자가 기대하는 값**으로 다시 제공해야 한다.

`WITHOUT AAD`에서 Bob의 `(nonce, C||tag)`는 `aad=None` 아래 정상값이다. 이를 Alice row에서 `aad=None`로 복호화해도 GCM은 “이것이 Alice row여야 한다”는 사실을 알지 못하므로 Bob의 plaintext를 반환한다.

`WITH AAD`에서는 암호화 때 Bob의 ID `b"user:bob"`가 tag에 포함된다. Alice row를 읽는 쪽은 `b"user:alice"`를 기대 AAD로 넣으므로 둘이 불일치하고 `InvalidTag`가 난다. `try/except`는 그 실패를 정상적인 학습 출력으로 바꾼다. 예외를 잡았다는 것은 ciphertext를 성공적으로 읽었다는 뜻이 아니다.

```python
# book-check: aad
import runpy
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
lab = runpy.run_path("02_symmetric/aad_swap_demo.py")
aes = AESGCM(bytes(range(32)))
nonce, encrypted = lab["encrypt"](aes, lab["BOB_SECRET"], lab["BOB_ID"])
assert aes.decrypt(nonce, encrypted, lab["BOB_ID"]) == lab["BOB_SECRET"]
try:
    aes.decrypt(nonce, encrypted, lab["ALICE_ID"])
except InvalidTag:
    pass
else:
    raise AssertionError("record identity swap must fail")
```

이 보장은 앱이 Alice identity를 독립적으로 알고 `ALICE_ID`를 만들어 줄 때만 성립한다. DB의 `aad` 컬럼을 공격자가 바꾼 뒤 그 값을 그대로 decrypt에 넘기면 [A.5의 답](#exercises)처럼 바꿔치기를 검출하지 못할 수 있다. AAD는 “문자열을 한 개 추가하면 안전”이 아니라 **신뢰한 문맥을 tag에 묶는 입력**이다.

<a id="trace-database"></a>

### D.8 `db_encryption_demo.py`: key를 읽고, row identity에 묶고, bytes를 저장한다

코드: [`02_symmetric/db_encryption_demo.py`](02_symmetric/db_encryption_demo.py).

이 파일은 8장의 “앱이 외부에서 key를 얻고 DB에는 암호문을 둔다”는 구조를 SQLite로 축소한 것이다. `APP_DATA_KEY_B64`는 Secret Manager 자체가 아니다. Secret Manager가 앱의 환경에 전달했다고 **가정한 한 전달 경로**다.

#### CLI부터 저장까지의 호출 그래프

```text
generate-key
  main → generate_key_text → AESGCM.generate_key(256 bit)
       → URL-safe Base64 텍스트 출력

store
  main → load_key_from_environment → Base64 decode → raw 32-byte K
       → connect → CREATE TABLE IF NOT EXISTS
       → getpass 입력을 UTF-8 bytes P로 변환
       → store_secret(connection, K, P)
            → random UUID record_id, key_version=1, random 12-byte N
            → associated_data(record_id, 1)
            → AESGCM(K).encrypt(N, P, AAD) = C || tag
            → INSERT(id, version, N, C||tag), commit

read
  main → 같은 K load → retrieve_secret
       → SELECT row → 같은 associated_data 재구성
       → AESGCM(K).decrypt(N, C||tag, AAD) → P
```

`generate_key_text()`의 Base64는 key를 텍스트 환경변수로 운반하기 위한 encoding이다. `load_key_from_environment()`는 존재 여부, Base64 형식, decode된 길이 32를 차례로 검사한다. 첫 두 실패는 우리가 만든 입력 검증 오류이고, 실제 GCM tag 검증은 그 이후 `read`에서 일어난다.

#### `associated_data()`가 row 자체를 묶는 방식

```python
def associated_data(record_id, key_version):
    return f"encrypted_secrets:{record_id}:v{key_version}".encode("ascii")
```

UUID는 ASCII hex·hyphen 문자만 포함하므로 `.encode("ascii")`가 가능하다. `record_id`와 `key_version`은 DB에 별도 컬럼으로도 저장되고, 동일한 값의 bytes가 tag 입력으로도 들어간다. `encrypted_value` 안에 AAD가 자동 저장되는 것은 아니다. read path가 row의 ID/version으로 **정확히 같은 bytes를 재구성**한다.

`store_secret()`이 만든 `record_id`는 암호화 전에 정해진다. 따라서 그것을 AAD에 안전하게 넣을 수 있다. `key_version=1`은 현재 예제에서 상수다. 진짜 rotation 구현이라면 version으로 올바른 key를 선택하고, 이전 version 데이터도 읽는 정책을 추가해야 한다. 현재 함수는 version을 AAD에 넣기는 하지만 여러 key를 관리하지는 않는다.

```python
# book-check: database
import runpy
from pathlib import Path
from tempfile import TemporaryDirectory
lab = runpy.run_path("02_symmetric/db_encryption_demo.py")
key = bytes(range(32))
assert lab["associated_data"]("record-1", 7) == b"encrypted_secrets:record-1:v7"
with TemporaryDirectory() as directory:
    path = Path(directory) / "practice.sqlite3"
    with lab["connect"](path) as connection:
        record_id = lab["store_secret"](connection, key, b"api-token")
        row = connection.execute(
            "SELECT id, key_version, nonce, encrypted_value FROM encrypted_secrets"
        ).fetchone()
        assert row["id"] == record_id and len(row["nonce"]) == 12
        assert b"api-token" not in row["encrypted_value"]
        assert lab["retrieve_secret"](connection, key, record_id) == b"api-token"
```

`connect()`의 `row_factory=sqlite3.Row` 덕분에 `row["nonce"]`처럼 column 이름으로 bytes를 꺼낼 수 있다. SQLite의 `BLOB`은 bytes를 보관하며, `inspect_rows()`의 `hex(...)`는 사람이 보기 위해 SQL에서 텍스트로 표현하는 것뿐이다. `inspect`도 지금은 공통 흐름 때문에 key 환경변수를 요구하지만, `SELECT hex(...)` 자체가 key를 필요로 하지는 않는다.

**실패 지점:** 존재하지 않는 id는 `KeyError`, 틀린 key·nonce·AAD·암호문은 `InvalidTag`를 일으킨다. CLI는 뒤의 경우를 하나의 `Decryption failed` 메시지로 묶는다. 원인을 세분해 공개하면 공격자에게 도움이 될 수 있기 때문이다. 반대로 DB가 완전히 과거 row로 rollback된 경우에는 그 과거 row의 tag가 정상이라 decrypt가 성공한다. 최신성은 별도 상태가 필요하다.

<a id="trace-exchange"></a>

### D.9 `x25519_exchange.py`: private object에서 shared secret, 그리고 AES key까지

코드: [`03_asymmetric/x25519_exchange.py`](03_asymmetric/x25519_exchange.py).

#### 전송 경계와 `public_bytes()`

`X25519PrivateKey.generate()`가 Alice/Bob 각각의 private object를 만든다. `.public_key()`는 대응되는 public object를 만든다. `public_bytes()`는 그 public object를 Raw 32-byte encoding으로 바꾼다. 이 bytes가 네트워크나 메시지 포맷에 들어갈 수 있는 값이다. 실제 수신자는 `X25519PublicKey.from_public_bytes(...)`로 그 bytes를 public object로 복원한다. 이 짧은 파일은 object를 직접 상대에게 넘겨 더 읽기 쉽게 만들었고, D.10의 `key_roles_lab.py`는 byte 경계까지 보여 준다.

```text
Alice private object ── public_key() ──→ Alice public object ── public_bytes() ──→ wire
Bob   private object ── public_key() ──→ Bob public object   ── public_bytes() ──→ wire
```

`alice_private.exchange(bob_public)`과 `bob_private.exchange(alice_public)`은 모두 32-byte shared secret을 반환하며 같아야 한다. 이 파일은 secret을 출력하지 않는다. equal 여부만 출력하는 것은 key material을 로그에 남기지 않는 습관을 보여 준다. [X25519 API](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/x25519/)

#### `derive_aes_key(shared_secret)`의 HKDF 인자

```python
HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"crypto-playground/x25519-session/v1",
).derive(shared_secret)
```

`length=32`은 AES-256 key 길이다. `info`는 이 출력이 이 학습 프로토콜의 session AES key라는 문맥을 붙인다. `salt=None`은 이 API에서 SHA-256 digest 길이만큼의 zero bytes salt를 쓰는 것과 같다. 이는 최소 예제의 결정된 선택이며, 모든 key agreement 프로토콜에 그대로 복사할 설정은 아니다. TLS는 transcript와 여러 단계의 secret을 더 정교하게 HKDF에 결합한다.

이 파일은 양 방향에 하나의 `derive_aes_key` 결과를 쓰므로 Alice→Bob과 Bob→Alice의 traffic key를 분리하지 않는다. 한 방향 메시지만 보여 주는 **최소 key-agreement 실습**이다. 실제 protocol은 role/direction을 `info`에 넣거나 TLS처럼 별도 traffic secret을 파생한다.

```python
# book-check: x25519
import runpy
lab = runpy.run_path("03_asymmetric/x25519_exchange.py")
shared = bytes(range(32))  # 공개 fixture; 실제 DH 출력이 아님
assert lab["derive_aes_key"](shared).hex() == "4c4938acbb758fefce61b4edac0cbb7d07d05106e709b5fc3ac6e11904ae60b7"
alice = lab["x25519"].X25519PrivateKey.generate()
bob = lab["x25519"].X25519PrivateKey.generate()
a_wire = lab["public_bytes"](alice.public_key())
b_wire = lab["public_bytes"](bob.public_key())
alice_shared = alice.exchange(lab["x25519"].X25519PublicKey.from_public_bytes(b_wire))
bob_shared = bob.exchange(lab["x25519"].X25519PublicKey.from_public_bytes(a_wire))
assert len(a_wire) == len(b_wire) == len(alice_shared) == 32
assert alice_shared == bob_shared
assert lab["derive_aes_key"](alice_shared) == lab["derive_aes_key"](bob_shared)
```

`main()`의 마지막 네 줄은 이미 배운 AEAD 호출이다. Alice가 만든 random nonce, plaintext, AAD, `encrypted=C||tag`를 Bob이 자신의 같은 key로 decrypt한다. 여기서 **AES key는 wire로 보낸 적이 없다.** 하지만 public bytes를 Mallory가 바꿔치기할 수 있으므로, 이 파일만으로 peer identity는 인증하지 못한다. 이것이 certificate/서명과 TLS가 필요해지는 정확한 지점이다.

<a id="trace-roles"></a>

### D.10 `key_roles_lab.py`: 작은 수의 반례와 실제 API를 분리하기

코드: [`03_asymmetric/key_roles_lab.py`](03_asymmetric/key_roles_lab.py).

이 파일은 한 함수가 아니라 역할이 다른 다섯 실습을 한 CLI에 모았다. `main()`의 `demos` dictionary는 문자열 subcommand를 함수에 연결한다. `python3 ... dh`는 `toy_dh`, `signature`는 `signature_demo`를 호출한다. dh/mitm/rsa를 선택한 경우에만 “TOY ARITHMETIC ONLY” 경고를 출력한다.

| 함수 | 직접 계산하는 것 | 의도적으로 보여 주는 한계 |
|---|---|---|
| `toy_dh()` | `pow(g, a, p)`와 shared secret | p=23이면 `next(...)` 전수조사로 a를 찾음 |
| `toy_mitm()` | Mallory가 자기 public M을 양쪽에 제시 | Mallory는 a/b를 풀지 않고도 서로 다른 두 secret을 만듦 |
| `toy_rsa()` | `pow(e, -1, phi)`, `pow(m,e,n)` | OAEP 없는 textbook RSA는 배포용 암호가 아님 |
| `x25519_demo()` | public bytes 복원, `exchange`, 방향별 HKDF | `peer identity authenticated: False` |
| `signature_demo()` | private `sign`, public `verify` | public key의 소유자 신원은 별도 문제 |

`toy_dh()`의 `next(i for i in range(1,p) ...)`는 public A가 나오는 첫 exponent 후보를 찾는다. p=23이라 이 공격 코드가 종료한다. 같은 형태를 실제 X25519 private key에 적용할 수 없다는 것이 정확히 파라미터 크기와 군 선택의 의미다.

`x25519_demo()`는 D.9보다 한 단계 더 실제 wire 경계를 흉내 낸다. `a_wire`와 `b_wire`를 `from_public_bytes()`로 다시 object로 만들고, `derive(shared, b"A-to-B/key")`와 `derive(shared, b"B-to-A/key")`로 방향 key를 분리한다. 코드 안의 salt `b"crypto-pg/key-roles/v1"`은 암호문과 함께 보관하지 않아도 양쪽이 미리 알고 있는 protocol 상수다. `AESGCM(alice_send)`와 `AESGCM(bob_receive)`의 key가 같으므로 Bob이 읽을 수 있다.

`signature_valid()`가 `InvalidSignature`만 잡고 False를 반환하는 이유는 실패한 서명이 이 실습에서 예상되는 결과이기 때문이다. private `sign()`은 exception 없이 bytes signature를 만들고, public `verify()`는 정상일 때도 값을 반환하지 않는다(`None`). 그래서 wrapper가 boolean으로 바꾼다.

```python
# book-check: roles
import runpy
lab = runpy.run_path("03_asymmetric/key_roles_lab.py")
assert lab["toy_dh"]()["Alice shared"] == lab["toy_dh"]()["Bob shared"] == 2
mitm = lab["toy_mitm"]()
assert mitm["Alice shared with fake Bob"] == mitm["Mallory shared with Alice"] == 12
assert mitm["Bob shared with fake Alice"] == mitm["Mallory shared with Bob"] == 15
assert lab["toy_rsa"]()["decrypted"] == 65
assert lab["signature_demo"]() == {
    "valid message": True, "changed message": False, "wrong public key": False,
}
```

**코드 독해 질문:** `signature_demo()`의 `stranger_public`이 message를 읽을 수 없는가? 아니다. message는 공개 입력일 수 있다. 그 public key가 서명을 검증하지 못하는 이유는 signature가 다른 private key에서 만들어졌기 때문이다.

<a id="trace-tls"></a>

### D.11 `tls_memory_lab.py`: 임시 PKI와 TLS state machine을 메모리에서 연결하기

코드: [`04_tls/tls_memory_lab.py`](04_tls/tls_memory_lab.py).

이 파일은 TLS를 Python으로 재구현하지 않는다. OpenSSL을 사용하는 Python `ssl`의 실제 TLS state machine에 certificate, private key, input/output byte buffer를 제공한다. 우리가 쓰는 코드는 **환경과 transport를 조립하는 코드**다.

#### `temporary_pki()`: CA와 서버는 다른 private key를 쓴다

함수 시작의 두 `rsa.generate_private_key(...)`는 `ca_key`와 `server_key`를 별도로 생성한다. 내부 `builder(...)`는 subject, issuer, public key, serial, validity만 공통으로 만든다.

```text
ca_cert:
  subject = issuer = temporary CA
  public  = ca_key.public
  sign(ca_key)                 ← self-signed CA certificate

server_cert:
  subject = localhost
  issuer  = temporary CA
  public  = server_key.public
  SAN     = DNS:localhost
  sign(ca_key)                 ← CA가 서버 public key/name binding에 서명
```

서버는 나중에 `server.key`로 TLS `CertificateVerify`에 참여한다. CA private key가 TLS 연결에서 서버 대신 서명하는 것이 아니다. `BasicConstraints`, `KeyUsage`, `ExtendedKeyUsage`, SAN은 각각 CA 여부, key 사용 제한, server-auth 목적, 기대 hostname을 표현한다.

`TemporaryDirectory` 안에 certificate PEM과 private-key PEM을 쓰고 `yield`한다. context를 벗어나면 directory가 제거된다. `key_path.touch(mode=0o600)`은 key file 권한을 추가 제한한다. 이 함수는 OS trust store에 아무 root도 설치하지 않는다. 따라서 다음 함수의 client가 CA PEM을 명시적으로 신뢰해야 한다.

#### `run_connection(...)`: network socket 대신 두 쌍의 MemoryBIO

`SSLContext(PROTOCOL_TLS_SERVER)`와 `SSLContext(PROTOCOL_TLS_CLIENT)`는 서버/클라이언트 보안 기본값을 다르게 구성한다. 양쪽의 minimum/maximum version을 TLS 1.3으로 맞춰 학습 범위를 고정한다. client context에는 default OS root를 추가로 로드하지 않고, `trusted=True`일 때에만 이 임시 CA PEM을 넣는다. `server_ctx.num_tickets=0`은 post-handshake resumption ticket을 없애 첫 handshake에 집중한다.

```text
client SSLObject ─ client_out → client_out bytes → server_in ─ server SSLObject
server SSLObject ─ server_out → server_out bytes → client_in ─ client SSLObject
```

`wrap_bio`가 만든 SSLObject는 `do_handshake()`를 호출할 때 보내야 할 TLS bytes를 `*_out`에 쓴다. `transfer(source,destination)`가 bytes를 읽어 반대편 `*_in`에 넣는다. 아직 상대 bytes가 부족하면 `SSLWantReadError`가 난다. 이는 certificate 검증 실패가 아니라 “다음 network bytes를 기다리는 정상 상태”다. loop가 두 handshake가 끝날 때까지 byte를 왕복시키는 이유다.

handshake 뒤에는 다음 세 줄이 핵심이다.

```python
client.write(request)                  # plaintext HTTP bytes를 TLS에 입력
wire = transfer(client_out, server_in) # TLS ciphertext record bytes를 관찰
received = server.read(16384)          # TLS가 검증·복호화한 plaintext를 앱에 반환
```

`wire`에 request 전체 byte열이 없다는 것은 앱이 준 plaintext와 transport가 보낸 bytes가 다름을 관찰하는 좋은 실습이다. 하지만 단일 문자열 검색은 TLS의 보안 증명이 아니다. TLS record metadata와 길이는 여전히 보일 수 있다.

```python
# book-check: tls
import runpy
import ssl
lab = runpy.run_path("04_tls/tls_memory_lab.py")
with lab["temporary_pki"]() as pki:
    result = lab["run_connection"](*pki)
    assert result["version"] == "TLSv1.3"
    assert result["received"] == result["request"]
    assert result["request"] not in result["wire"]
    try:
        lab["run_connection"](*pki, hostname="wrong.example")
    except ssl.SSLCertVerificationError:
        pass
    else:
        raise AssertionError("hostname mismatch must fail")
```

`trusted=False`면 client가 issuer CA를 trust store에 갖지 않으므로 같은 hostname이어도 실패한다. 반대로 hostname만 맞추고 `check_hostname=False`나 `verify_mode=CERT_NONE`으로 바꾸는 것은 실습의 해결책이 아니라 바로 제거하려는 검증을 없애는 것이다. 이 코드가 실제 인터넷 서버·DNS·load balancer·renewal을 다루지 않는 이유도 12장과 13장의 운영 경계를 다시 읽어야 한다.

### D.12 실습 출력을 볼 때 마지막으로 묻는 다섯 가지

어떤 예제를 다시 실행하든 아래 다섯 질문을 먼저 적어 보자.

1. 이 함수의 **비밀 입력**은 무엇이고, 코드의 어느 변수인가?
2. 외부로 전달하거나 DB에 저장하는 **공개 입력/출력**은 무엇인가?
3. 같은 결과를 재현하려는 쪽은 어떤 값을 이미 갖고, 무엇을 수신하는가?
4. 잘못된 값을 넣으면 어떤 함수가 어떤 예외 또는 False를 내는가?
5. 그 실패 검출이 막지 못하는 공격은 무엇인가? (replay, rollback, peer identity, 앱 RCE 등)

이 다섯 답이 코드 변수명과 함께 나와야 “출력이 통과했다”를 넘어 실제로 함수를 읽은 것이다.
