from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.flags.attack import load_attack_map
from sentinel.vault.session import VaultSession


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "sentinel-home"
    home.mkdir()
    monkeypatch.setenv("SENTINEL_HOME", str(home))
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    load_attack_map.cache_clear()
    from sentinel.db import init_db

    init_db()
    yield home


@pytest.fixture
def samples_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture
def reset_api_vault():
    from sentinel_api.main import vault

    vault.lock()
    yield vault
    vault.lock()
