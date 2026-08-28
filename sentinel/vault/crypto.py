from __future__ import annotations

import json
import os
import secrets
import struct
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sentinel.config import vault_path

MAGIC = b"SNTLVAULT1"
VERSION = 1
TIME_COST = 3
MEMORY_COST_KIB = 64 * 1024
PARALLELISM = 2
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32

ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_"


class VaultError(Exception):
    pass


class VaultLocked(VaultError):
    pass


class WrongPassword(VaultError):
    pass


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _derive_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=TIME_COST,
        memory_cost=MEMORY_COST_KIB,
        parallelism=PARALLELISM,
        hash_len=KEY_LEN,
        type=Type.ID,
    )


def _pack(salt: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return (
        MAGIC
        + bytes([VERSION])
        + struct.pack(">I", TIME_COST)
        + struct.pack(">I", MEMORY_COST_KIB)
        + struct.pack(">I", PARALLELISM)
        + struct.pack(">H", len(salt))
        + salt
        + nonce
        + ciphertext
    )


def _unpack(blob: bytes) -> tuple[bytes, bytes, bytes]:
    if not blob.startswith(MAGIC):
        raise VaultError("Not a Sentinel vault file")
    offset = len(MAGIC) + 1 + 12  # version + 3x uint32 params
    salt_len = struct.unpack(">H", blob[offset : offset + 2])[0]
    offset += 2
    salt = blob[offset : offset + salt_len]
    offset += salt_len
    nonce = blob[offset : offset + NONCE_LEN]
    offset += NONCE_LEN
    ciphertext = blob[offset:]
    return salt, nonce, ciphertext


def vault_exists(path: Path | None = None) -> bool:
    return (path or vault_path()).is_file()


def init_vault(password: str, path: Path | None = None) -> Path:
    dest = path or vault_path()
    if dest.exists():
        raise VaultError("Vault already exists")
    dest.parent.mkdir(parents=True, exist_ok=True)
    _write_payload(dest, password, {"entries": []}, salt=os.urandom(SALT_LEN))
    return dest


def _write_payload(path: Path, password: str, payload: dict, salt: bytes) -> None:
    key = _derive_key(password, salt)
    nonce = os.urandom(NONCE_LEN)
    aes = AESGCM(key)
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ciphertext = aes.encrypt(nonce, plaintext, MAGIC)
    path.write_bytes(_pack(salt, nonce, ciphertext))


def unlock(password: str, path: Path | None = None) -> dict[str, Any]:
    dest = path or vault_path()
    if not dest.is_file():
        raise VaultError("Vault does not exist — run vault init first")
    blob = dest.read_bytes()
    salt, nonce, ciphertext = _unpack(blob)
    key = _derive_key(password, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, MAGIC)
    except InvalidTag as exc:
        raise WrongPassword("Incorrect master password") from exc
    return json.loads(plaintext.decode("utf-8"))


def save(password: str, payload: dict[str, Any], path: Path | None = None) -> None:
    dest = path or vault_path()
    blob = dest.read_bytes()
    salt, _, _ = _unpack(blob)
    _write_payload(dest, password, payload, salt)


def list_entries(payload: dict[str, Any], include_secrets: bool = False) -> list[dict[str, Any]]:
    entries = []
    for entry in payload.get("entries", []):
        item = dict(entry)
        if not include_secrets:
            item["secret"] = "••••••••" if item.get("secret") else ""
        entries.append(item)
    return entries


def add_entry(
    payload: dict[str, Any],
    *,
    name: str,
    entry_type: str = "credential",
    username: str = "",
    secret: str = "",
    notes: str = "",
) -> dict[str, Any]:
    entry = {
        "id": str(uuid.uuid4()),
        "type": entry_type,
        "name": name,
        "username": username,
        "secret": secret,
        "notes": notes,
        "updated_at": _utcnow(),
    }
    payload.setdefault("entries", []).append(entry)
    return entry


def delete_entry(payload: dict[str, Any], entry_id: str) -> bool:
    entries = payload.get("entries", [])
    kept = [e for e in entries if e.get("id") != entry_id]
    payload["entries"] = kept
    return len(kept) != len(entries)


def find_entry(payload: dict[str, Any], name: str) -> dict[str, Any] | None:
    name_l = name.lower()
    for entry in payload.get("entries", []):
        if entry.get("name", "").lower() == name_l:
            return entry
    return None


def generate_password(length: int = 20) -> str:
    length = max(8, min(length, 128))
    return "".join(secrets.choice(ALPHABET) for _ in range(length))


def export_backup(password: str, dest: Path, path: Path | None = None) -> Path:
    src = path or vault_path()
    if not src.is_file():
        raise VaultError("Vault does not exist")
    unlock(password, src)  # verify password before copying ciphertext
    dest.write_bytes(src.read_bytes())
    return dest
