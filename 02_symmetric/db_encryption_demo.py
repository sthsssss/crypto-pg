"""Store application secrets in SQLite using an externally supplied AES key.

Learning example only. In production, prefer a managed secret/KMS integration
and a reviewed key-rotation design.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import os
import secrets
import sqlite3
import uuid
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEY_ENV = "APP_DATA_KEY_B64"
DEFAULT_DB = Path(__file__).with_name("encrypted_secrets.sqlite3")


def generate_key_text() -> str:
    key = AESGCM.generate_key(bit_length=256)
    return base64.urlsafe_b64encode(key).decode("ascii")


def load_key_from_environment() -> bytes:
    encoded = os.environ.get(KEY_ENV)
    if not encoded:
        raise SystemExit(f"Set {KEY_ENV} before using this command.")

    try:
        key = base64.b64decode(encoded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SystemExit(f"{KEY_ENV} is not valid Base64.") from exc

    if len(key) != 32:
        raise SystemExit(f"{KEY_ENV} must decode to exactly 32 bytes.")
    return key


def connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS encrypted_secrets (
            id              TEXT PRIMARY KEY,
            key_version     INTEGER NOT NULL,
            nonce           BLOB NOT NULL,
            encrypted_value BLOB NOT NULL
        )
        """
    )
    return connection


def associated_data(record_id: str, key_version: int) -> bytes:
    # Visible context that is authenticated along with the ciphertext.
    return f"encrypted_secrets:{record_id}:v{key_version}".encode("ascii")


def store_secret(connection: sqlite3.Connection, key: bytes, plaintext: bytes) -> str:
    record_id = str(uuid.uuid4())
    key_version = 1
    nonce = secrets.token_bytes(12)
    encrypted_value = AESGCM(key).encrypt(
        nonce,
        plaintext,
        associated_data(record_id, key_version),
    )
    connection.execute(
        """
        INSERT INTO encrypted_secrets (id, key_version, nonce, encrypted_value)
        VALUES (?, ?, ?, ?)
        """,
        (record_id, key_version, nonce, encrypted_value),
    )
    connection.commit()
    return record_id


def retrieve_secret(connection: sqlite3.Connection, key: bytes, record_id: str) -> bytes:
    row = connection.execute(
        """
        SELECT key_version, nonce, encrypted_value
        FROM encrypted_secrets
        WHERE id = ?
        """,
        (record_id,),
    ).fetchone()
    if row is None:
        raise KeyError(record_id)

    return AESGCM(key).decrypt(
        row["nonce"],
        row["encrypted_value"],
        associated_data(record_id, row["key_version"]),
    )


def inspect_rows(connection: sqlite3.Connection) -> None:
    rows = connection.execute(
        """
        SELECT id, key_version, hex(nonce) AS nonce_hex,
               hex(encrypted_value) AS encrypted_hex
        FROM encrypted_secrets
        ORDER BY rowid
        """
    ).fetchall()
    if not rows:
        print("database is empty")
        return

    for row in rows:
        print(f"id:         {row['id']}")
        print(f"key version:{row['key_version']}")
        print(f"nonce:      {row['nonce_hex']}")
        print(f"encrypted:  {row['encrypted_hex']}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("generate-key")
    subparsers.add_parser("store")
    read_parser = subparsers.add_parser("read")
    read_parser.add_argument("record_id")
    subparsers.add_parser("inspect")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.command == "generate-key":
        print(generate_key_text())
        return

    key = load_key_from_environment()
    with connect(args.db) as connection:
        if args.command == "store":
            value = getpass.getpass("Secret to encrypt (input hidden): ").encode("utf-8")
            record_id = store_secret(connection, key, value)
            print(f"stored record id: {record_id}")
            print(f"database: {args.db}")
        elif args.command == "read":
            try:
                value = retrieve_secret(connection, key, args.record_id)
            except KeyError:
                raise SystemExit(f"No record with id {args.record_id}")
            except InvalidTag:
                raise SystemExit("Decryption failed: wrong key or modified database row.")
            print(value.decode("utf-8"))
        else:
            inspect_rows(connection)


if __name__ == "__main__":
    main()
