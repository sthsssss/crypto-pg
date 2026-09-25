# Crypto Book 개정 검토

대상: `CRYPTOGRAPHY_BOTTOM_UP.md` · 2판 · 2026-09-25

## 독자와 편집 원칙

프로그래밍·DB·HTTP를 아는 개발자가 암호학의 입력과 신뢰 경계를 처음 연결하는
상황을 기준으로 검토했다. 쉬운 비유로 전문 용어를 대체하기보다, 용어를 정의한 뒤
작은 계산과 프로세스·저장소의 값 배치로 설명한다. 과거 학습에서 막힌 질문을
장별 핵심 질문과 부록의 확인 문제에 반영했다.

The Joy of Cryptography, Understanding Cryptography, A Graduate Course in
Applied Cryptography의 저자 공개 자료·구성을 참고했다. 참고한 전개 방식과 원문
링크는 교재 머리말에 기록했다. 서열화하거나 본문을 번역·복제한 자료는 아니다.

## 발견한 공백과 반영 내용

| 기존 공백 / 오해 가능성 | 개정 내용 |
|---|---|
| bytes, XOR, correctness와 security의 구별 없이 시작 | 0장: 표기, 바이트, 공격자 모델, entropy, 확률적 보장 |
| SHA-256을 지문이라는 비유로만 이해 | 4장: padding, state, schedule, 라운드 식과 known-answer |
| derived key를 저장하면 비밀번호 저장과 같은지 혼동 | 5장: verifier를 입력으로 받는 프로토콜과 재계산 프로토콜 구별 |
| 느린 해시의 이유가 불명확 | 5장: offline guessing, time/memory cost, salt 재사용 방지 |
| HMAC이 왜 별도 구성인지 설명 부족 | 6장: secret-prefix의 한계, inner/outer 구성, serialization와 replay |
| key와 nonce가 참여하는 연산이 안 보임 | 7장: XOR → keystream → AES permutation → counter → tag |
| 앱/DB/KMS의 key 위치와 최초 권한 문제 | 8~9장: SQL BLOB, DEK/KEK, workload identity, rotation·rollback 경계 |
| X25519 결과가 같다는 진술에 수학적 다리가 없음 | 10장: mod, group, toy DH, 점 doubling/scalar multiplication |
| key agreement·암호화·서명이 하나로 섞임 | 10장: 별도 인터페이스, HKDF, toy RSA, KEM, Ed25519 검증 |
| 암호가 동작하면 상대 인증도 됐다고 오해 | toy MITM, 공개키의 신원, 서명 등식과 CA 역할 구분 |
| 인증서의 서명과 서버 handshake 서명 혼동 | 11장: trust anchor, 발급 절차, CA/서버 key 분리 |
| TLS에 새 용어가 갑자기 등장 | 12장: transcript, Finished, traffic key, record nonce, suite 이름 |
| TLS application key 도출 시점/QUIC 층위가 뭉뚱그려짐 | server Finished 기준 도출, client Finished의 key, QUIC record 차이 명시 |
| 학습 종료 기준과 복습 도구 부족 | 실습별 예상 결과/비보장, 확인 문제 12개와 해설, 용어 찾아보기 |

## 문서와 함께 수정한 코드

- `aad_swap_demo.py`: plaintext 길이 기반 nonce가 같은 key 아래 반복되던 문제를
  실행마다 새 key와 호출마다 새 랜덤 nonce로 수정했다. AAD 유무가 nonce 안전성의
  요구를 바꾸지는 않는다.
- `key_roles_lab.py`: toy DH·MITM·RSA, public bytes 경계를 갖는 실제 X25519/HKDF,
  Ed25519 정상·변조·다른 key 검증을 추가했다.
- `tls_memory_lab.py`: 실제 TLS 1.3을 MemoryBIO로 연결하고 hostname/CA 실패를
  검증한다. CA key와 서버 key를 분리하며 영구 trust 설정을 변경하지 않는다.
- `test_book_labs.py`: 계산값, 인증 실패, HKDF 방향 분리, nonce 회귀, TLS 검증,
  임시 파일 정리, 교재 링크·fence를 검사한다.

## 의도적으로 남긴 경계

수학적 security proof, S-box/GHASH 직접 구현, 운영 PKI 전체, cloud 계정별 KMS 정책,
양자내성 전환 전략까지 완성한 보안 매뉴얼은 아니다. 이 경계와 후속 주제는 교재
부록 C에 명시했다. 실제 KMS 호출이나 원격 TLS 패킷 캡처를 수행한 것으로 설명하지
않는다. 테스트 통과는 교육 예제의 일관성을 확인하며 암호 구현의 안전성 증명을
대체하지 않는다.
