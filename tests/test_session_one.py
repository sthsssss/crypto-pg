from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

import pytest
from cryptography.exceptions import InvalidTag


ROOT = Path(__file__).parents[1]


def load(relative_path: str):
    path = ROOT / relative_path
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_hash_is_deterministic_and_fixed_length():
    module = load("01_primitives/random_and_hash.py")
    assert module.sha256(b"hello") == module.sha256(b"hello")
    assert len(module.sha256(b"hello")) == 32


def test_password_kdf_uses_random_salts():
    module = load("01_primitives/password_kdf.py")
    first = module.register("same password")
    second = module.register("same password")
    assert first.salt != second.salt
    assert first.derived_key != second.derived_key
    assert module.verify("same password", first)
    assert not module.verify("different password", first)


def test_hmac_rejects_message_tampering():
    module = load("01_primitives/hmac_demo.py")
    key = b"k" * 32
    tag = module.authenticate(key, b"amount=100")
    assert module.verify(key, b"amount=100", tag)
    assert not module.verify(key, b"amount=900", tag)


def test_aes_gcm_round_trip_and_random_nonce():
    module = load("02_symmetric/aes_gcm.py")
    key = module.generate_key()
    first = module.encrypt(key, b"secret", b"metadata")
    second = module.encrypt(key, b"secret", b"metadata")
    assert first.nonce != second.nonce
    assert first.ciphertext != second.ciphertext
    assert module.decrypt(key, first, b"metadata") == b"secret"


@pytest.mark.parametrize("target", ["ciphertext", "aad", "key"])
def test_aes_gcm_rejects_tampering(target):
    module = load("02_symmetric/aes_gcm.py")
    key = module.generate_key()
    aad = b"sender=alice"
    envelope = module.encrypt(key, b"secret", aad)

    if target == "ciphertext":
        changed = bytearray(envelope.ciphertext)
        changed[0] ^= 1
        envelope = module.Envelope(envelope.version, envelope.nonce, bytes(changed))
    elif target == "aad":
        aad = b"sender=mallory"
    else:
        key = module.generate_key()

    with pytest.raises(InvalidTag):
        module.decrypt(key, envelope, aad)


def test_database_round_trip_and_no_plaintext_at_rest(tmp_path):
    module = load("02_symmetric/db_encryption_demo.py")
    database = tmp_path / "secrets.sqlite3"
    key = bytes(range(32))
    plaintext = b"sk-secret-api-token"

    with module.connect(database) as connection:
        record_id = module.store_secret(connection, key, plaintext)
        row = connection.execute(
            "SELECT nonce, encrypted_value FROM encrypted_secrets WHERE id = ?",
            (record_id,),
        ).fetchone()
        assert plaintext not in row["encrypted_value"]
        assert len(row["nonce"]) == 12
        assert module.retrieve_secret(connection, key, record_id) == plaintext
