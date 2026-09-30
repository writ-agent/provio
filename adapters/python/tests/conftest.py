from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

FAKE = Path(__file__).with_name("fake_provio.py")


@pytest.fixture
def fake_log(tmp_path, monkeypatch):
    log = tmp_path / "requests.jsonl"
    monkeypatch.setenv("FAKE_PROVIO_LOG", str(log))

    def read() -> list[dict]:
        if not log.exists():
            return []
        return [json.loads(l) for l in log.read_text(encoding="utf-8").splitlines() if l.strip()]

    return read


@pytest.fixture
def fake_bin(monkeypatch, fake_log):
    """Point PROVIO_BIN at the fake gateway (a .py path runs under this interpreter)."""
    monkeypatch.setenv("PROVIO_BIN", str(FAKE))
    return str(FAKE)


@pytest.fixture
def fake_command(fake_log):
    return [sys.executable, str(FAKE)]
