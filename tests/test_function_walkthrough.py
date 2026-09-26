"""Execute the fixed fixtures printed in appendix D of the personal book."""

from __future__ import annotations

from pathlib import Path
import re

import pytest


ROOT = Path(__file__).parents[1]
BOOK = ROOT / "CRYPTOGRAPHY_BOTTOM_UP.md"
BOOK_CHECK = re.compile(
    r"```python\n# book-check: ([a-z0-9_]+)\n(.*?)\n```", re.DOTALL
)


def test_every_function_walkthrough_fixture_executes(monkeypatch):
    """Keep the book's claimed intermediate values tied to the actual labs."""
    monkeypatch.chdir(ROOT)
    fixtures = BOOK_CHECK.findall(BOOK.read_text())
    names = [name for name, _ in fixtures]
    assert names == [
        "hash", "password", "hmac", "envelope", "counter", "gcm_tag",
        "nonce_reuse", "aad", "database", "x25519", "roles", "tls",
    ]
    for name, source in fixtures:
        namespace = {"__name__": f"book_check_{name}"}
        exec(compile(source, f"<book-check:{name}>", "exec"), namespace)


@pytest.mark.parametrize(
    "anchor",
    [
        "function-walkthrough", "trace-hash", "trace-password", "trace-hmac",
        "trace-envelope", "trace-counter", "trace-tag", "trace-attacks",
        "trace-database", "trace-exchange", "trace-roles", "trace-tls",
    ],
)
def test_walkthrough_anchors_exist(anchor):
    assert f'<a id="{anchor}"></a>' in BOOK.read_text()
