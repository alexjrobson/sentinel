from __future__ import annotations

import json
from pathlib import Path

from sentinel.config import bundled_data, intel_dir


def _load_json(path: Path) -> dict:
    if not path.is_file():
        return {"hashes": []}
    return json.loads(path.read_text(encoding="utf-8"))


def load_hash_iocs() -> list[dict]:
    bundled = _load_json(bundled_data() / "iocs.json")
    user = _load_json(intel_dir() / "known_bad.json")
    hashes = list(bundled.get("hashes", []))
    hashes.extend(user.get("hashes", []))
    return hashes


def lookup_hash(md5: str, sha1: str, sha256: str) -> dict | None:
    md5, sha1, sha256 = md5.lower(), sha1.lower(), sha256.lower()
    for entry in load_hash_iocs():
        if md5 and entry.get("md5", "").lower() == md5:
            return entry
        if sha1 and entry.get("sha1", "").lower() == sha1:
            return entry
        if sha256 and entry.get("sha256", "").lower() == sha256:
            return entry
    return None
