from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sentinel.config import vault_lock_seconds
from sentinel.vault import crypto


class VaultSession:
    """In-process unlocked vault with auto-lock. Used by the API (and tests)."""

    def __init__(self) -> None:
        self._password: str | None = None
        self._payload: dict[str, Any] | None = None
        self._unlocked_at: datetime | None = None

    def _touch(self) -> None:
        self._unlocked_at = datetime.now(timezone.utc)

    def _expired(self) -> bool:
        if not self._unlocked_at:
            return True
        return datetime.now(timezone.utc) - self._unlocked_at > timedelta(seconds=vault_lock_seconds())

    def lock(self) -> None:
        self._password = None
        self._payload = None
        self._unlocked_at = None

    @property
    def unlocked(self) -> bool:
        if self._payload is None or self._password is None:
            return False
        if self._expired():
            self.lock()
            return False
        return True

    def status(self) -> dict[str, Any]:
        return {
            "exists": crypto.vault_exists(),
            "unlocked": self.unlocked,
            "lock_seconds": vault_lock_seconds(),
            "entry_count": len(self._payload.get("entries", [])) if self.unlocked and self._payload else 0,
        }

    def init(self, password: str) -> None:
        crypto.init_vault(password)
        self.unlock(password)

    def unlock(self, password: str) -> None:
        self._payload = crypto.unlock(password)
        self._password = password
        self._touch()

    def require(self) -> dict[str, Any]:
        if not self.unlocked or self._payload is None:
            raise crypto.VaultLocked("Vault is locked")
        self._touch()
        return self._payload

    def persist(self) -> None:
        if not self.unlocked or self._password is None or self._payload is None:
            raise crypto.VaultLocked("Vault is locked")
        crypto.save(self._password, self._payload)
        self._touch()

    def entries(self, include_secrets: bool = False) -> list[dict[str, Any]]:
        return crypto.list_entries(self.require(), include_secrets=include_secrets)

    def add(self, **kwargs: Any) -> dict[str, Any]:
        entry = crypto.add_entry(self.require(), **kwargs)
        self.persist()
        return entry

    def delete(self, entry_id: str) -> bool:
        ok = crypto.delete_entry(self.require(), entry_id)
        if ok:
            self.persist()
        return ok

    def secret_named(self, name: str) -> str | None:
        entry = crypto.find_entry(self.require(), name)
        if not entry:
            return None
        return entry.get("secret")
