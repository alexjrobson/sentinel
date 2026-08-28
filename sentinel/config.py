from __future__ import annotations

import os
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def home() -> Path:
    override = os.environ.get("SENTINEL_HOME")
    if override:
        return Path(override).expanduser().resolve()
    return Path.home() / ".sentinel"


def data_dir() -> Path:
    path = home()
    path.mkdir(parents=True, exist_ok=True)
    return path


def db_path() -> Path:
    return data_dir() / "sentinel.db"


def vault_path() -> Path:
    return data_dir() / "vault.bin"


def bundled_data() -> Path:
    return Path(__file__).resolve().parent / "data"


def bundled_rules_dir() -> Path:
    return bundled_data() / "rules"


def user_rules_dir() -> Path:
    env = os.environ.get("SENTINEL_RULES")
    if env:
        return Path(env).expanduser().resolve()
    candidate = _repo_root() / "rules"
    if candidate.is_dir():
        return candidate
    return data_dir() / "rules"


def intel_dir() -> Path:
    env = os.environ.get("SENTINEL_INTEL")
    if env:
        return Path(env).expanduser().resolve()
    candidate = _repo_root() / "intel"
    if candidate.is_dir():
        return candidate
    return data_dir() / "intel"


def attack_map_path() -> Path:
    bundled = bundled_data() / "attack.yaml"
    override = _repo_root() / "rules" / "attack.yaml"
    return override if override.is_file() else bundled


def vault_lock_seconds() -> int:
    raw = os.environ.get("SENTINEL_VAULT_LOCK_SECONDS", "300")
    try:
        return max(30, int(raw))
    except ValueError:
        return 300


SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    ".cursor",
    ".pytest_cache",
    ".mypy_cache",
}

STRING_EXTRACT_MAX_BYTES = 10 * 1024 * 1024
ENTROPY_SAMPLE_BYTES = 1 * 1024 * 1024
PE_MAX_BYTES = 50 * 1024 * 1024
HIGH_ENTROPY_THRESHOLD = 7.2
HIGH_ENTROPY_MIN_SIZE = 1024
