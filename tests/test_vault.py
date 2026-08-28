from pathlib import Path

import pytest

from sentinel.vault.crypto import (
    WrongPassword,
    export_backup,
    generate_password,
    init_vault,
    unlock,
    add_entry,
    save,
)


def test_vault_round_trip(tmp_path: Path):
    path = tmp_path / "vault.bin"
    init_vault("correct horse battery", path)
    payload = unlock("correct horse battery", path)
    assert payload["entries"] == []
    add_entry(payload, name="vt", entry_type="api_key", secret="vt-secret")
    save("correct horse battery", payload, path)
    again = unlock("correct horse battery", path)
    assert again["entries"][0]["secret"] == "vt-secret"


def test_wrong_password_fails(tmp_path: Path):
    path = tmp_path / "vault.bin"
    init_vault("right-password", path)
    with pytest.raises(WrongPassword):
        unlock("wrong-password", path)


def test_generate_password_length_and_uniqueness():
    a = generate_password(24)
    b = generate_password(24)
    assert len(a) == 24
    assert a != b


def test_backup_requires_password(tmp_path: Path):
    path = tmp_path / "vault.bin"
    dest = tmp_path / "backup.bin"
    init_vault("pw", path)
    export_backup("pw", dest, path)
    assert dest.read_bytes() == path.read_bytes()
    with pytest.raises(WrongPassword):
        export_backup("nope", dest, path)
