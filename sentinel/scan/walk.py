from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

from sentinel.config import SKIP_DIRS


def iter_files(target: str | Path) -> Iterator[Path]:
    """Yield files under target, skipping noise directories."""
    path = Path(target).expanduser().resolve()
    if path.is_file():
        yield path
        return
    if not path.is_dir():
        raise FileNotFoundError(f"Scan target not found: {path}")

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for name in files:
            yield Path(root) / name


def list_files_recursive(path: str | Path = ".") -> dict:
    """Nested size map — original Sentinel walker, kept for compatibility."""
    path = str(Path(path))
    files_info: dict = {}
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        sub_dir = files_info
        rel = root[len(path) :].strip(os.sep)
        if rel:
            for part in rel.split(os.sep):
                sub_dir = sub_dir.setdefault(part, {})
        for file_name in files:
            file_path = os.path.join(root, file_name)
            try:
                sub_dir[file_name] = {"size": os.path.getsize(file_path)}
            except OSError:
                sub_dir[file_name] = {"size": None}
    return files_info
