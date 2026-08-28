from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path


def _iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def mac_timestamps(path: Path) -> dict[str, str | None]:
    """Created / modified / accessed times (MAC). st_ctime is creation on Windows."""
    stat = path.stat()
    return {
        "created_at": _iso(getattr(stat, "st_ctime", None)),
        "modified_at": _iso(stat.st_mtime),
        "accessed_at": _iso(stat.st_atime),
    }
