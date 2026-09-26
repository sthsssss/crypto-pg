from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import re
import ssl
import sys

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ROOT = Path(__file__).parents[1]


def load(relative_path):
    path = ROOT / relative_path
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def roles():
    return load("03_asymmetric/key_roles_lab.py")


@pytest.fixture(scope="module")
def tls():
    return load("04_tls/tls_memory_lab.py")


@pytest.fixture(scope="module")
def pki(tls):
    with tls.temporary_pki() as material:
        yield material


def test_small_dh_and_brute_force(roles):
    result = roles.toy_dh()
    assert result["public A"] == 8
    assert result["public B"] == 19
    assert result["Alice shared"] == result["Bob shared"] == 2
    assert result["attacker recovered a (tiny group only)"] == 6
    assert (8 * 19) % 23 == 14 != 2


def test_mitm_creates_two_different_shared_secrets(roles):
    result = roles.toy_mitm()
    assert result["Alice shared with fake Bob"] == result["Mallory shared with Alice"] == 12
    assert result["Bob shared with fake Alice"] == result["Mallory shared with Bob"] == 15


def test_textbook_rsa_arithmetic(roles):
    result = roles.toy_rsa()
    assert result["toy private d"] == 2753
    assert result["ciphertext"] == 2790
    assert result["message"] == result["decrypted"] == 65


def test_curve_doubling_example():
    x, y, p = 5, 1, 17
    slope = (3 * x * x + 2) * pow(2 * y, -1, p) % p
    x2 = (slope * slope - 2 * x) % p
    y2 = (slope * (x - x2) - y) % p
    assert slope == 13
    assert (x2, y2) == (6, 3)
    assert y2**2 % p == (x2**3 + 2 * x2 + 2) % p


def test_hash_known_answer_and_xor_example():
    assert hashlib.sha256(b"abc").hexdigest() == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    assert 0x41 ^ 0xB6 == 0xF7
    assert 0xF7 ^ 0xB6 == 0x41


def test_x25519_public_wire_roundtrip(roles):
    result = roles.x25519_demo()
    assert result["shared secrets match"] is True
    assert result["A send / B receive keys match"] is True
    assert result["opposite direction key differs"] is True
    assert result["Bob recovered plaintext"] is True
    assert result["peer identity authenticated"] is False


def test_hkdf_context_deterministic_but_separates_directions(roles):
    # Deliberately fixed test fixture, not a production secret.
    shared = bytes(range(32))
    send = roles.derive(shared, b"A-to-B/key")
    assert send == roles.derive(shared, b"A-to-B/key")
    other = roles.derive(shared, b"B-to-A/key")
    assert send != other
    nonce = bytes(range(12))
    ciphertext = AESGCM(send).encrypt(nonce, b"message", None)
    with pytest.raises(InvalidTag):
        AESGCM(other).decrypt(nonce, ciphertext, None)


def test_signature_rejects_wrong_message_and_key(roles):
    assert roles.signature_demo() == {
        "valid message": True, "changed message": False, "wrong public key": False,
    }


def test_signature_rejects_altered_signature(roles):
    private = ed25519.Ed25519PrivateKey.generate()
    message = b"test release"
    signature = bytearray(private.sign(message))
    signature[0] ^= 1
    assert not roles.signature_valid(private.public_key(), message, bytes(signature))


def test_aad_demo_generates_nonce_per_call_and_binds_identity(monkeypatch):
    demo = load("02_symmetric/aad_swap_demo.py")
    # Deterministic source catches the old length-based nonce reuse without
    # making a statistical claim from a few random draws.
    samples = [i.to_bytes(12, "big") for i in range(4)]
    pending = iter(samples)
    monkeypatch.setattr(demo.secrets, "token_bytes", lambda n: next(pending) if n == 12 else None)
    aes = AESGCM(AESGCM.generate_key(bit_length=256))
    results = [demo.encrypt(aes, b"equal-length", aad) for aad in (None, None, b"alice", b"bob")]
    assert [nonce for nonce, _ in results] == samples
    nonce, ciphertext = results[-1]
    assert aes.decrypt(nonce, ciphertext, b"bob") == b"equal-length"
    with pytest.raises(InvalidTag):
        aes.decrypt(nonce, ciphertext, b"alice")


def test_gcm_counter_walkthrough_matches_aead(capsys):
    demo = load("02_symmetric/gcm_walkthrough.py")
    expected = AESGCM(demo.KEY).encrypt(demo.NONCE, demo.PLAINTEXT, demo.AAD)
    assert demo.build_ciphertext(demo.KEY, demo.NONCE, demo.PLAINTEXT) == expected[:-16]
    assert demo.counter_block(demo.NONCE, 2)[-4:] == b"\x00\x00\x00\x02"


def test_tls_actual_handshake_and_application_record(tls, pki):
    result = tls.run_connection(*pki)
    assert result["version"] == "TLSv1.3"
    assert result["received"] == result["request"]
    assert result["wire"] and result["request"] not in result["wire"]


def test_tls_rejects_wrong_hostname(tls, pki):
    with pytest.raises(ssl.SSLCertVerificationError) as error:
        tls.run_connection(*pki, hostname="wrong.example")
    assert "hostname" in error.value.verify_message.lower()


def test_tls_rejects_untrusted_ca(tls, pki):
    with pytest.raises(ssl.SSLCertVerificationError) as error:
        tls.run_connection(*pki, trusted=False)
    assert "issuer" in error.value.verify_message.lower()


def test_tls_pki_files_removed_after_context(tls):
    with tls.temporary_pki() as (cert, key, _):
        directory = cert.parent
        assert cert.exists() and key.exists()
        assert key.stat().st_mode & 0o777 == 0o600
    assert not directory.exists()


def test_book_local_links_and_fences():
    book = (ROOT / "CRYPTOGRAPHY_BOTTOM_UP.md").read_text()
    anchors = re.findall(r'<a id="([^"]+)"></a>', book)
    assert len(anchors) == len(set(anchors))
    in_fence = False
    table_width = None
    for line in book.splitlines():
        if line.startswith("```"):
            in_fence = not in_fence
        if not in_fence and line.startswith("|"):
            width = len(re.findall(r"(?<!\\)\|", line))
            if table_width is not None:
                assert width == table_width, line
            table_width = width
        else:
            table_width = None
    assert not in_fence
    # Match Markdown links, not Python indexing such as lab["sha256"](...)
    # in the executable book fixtures.
    for target in re.findall(r"(?<![\w\"'])\[[^\]\n]+\]\(([^)\n]+)\)", book):
        if target.startswith("#"):
            assert target[1:] in anchors, target
        elif not target.startswith(("https://", "http://")):
            assert (ROOT / target).is_file(), target
