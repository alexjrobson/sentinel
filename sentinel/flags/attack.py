from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

from sentinel.config import attack_map_path


@lru_cache(maxsize=1)
def load_attack_map(path: Path | None = None) -> dict:
    target = path or attack_map_path()
    return yaml.safe_load(target.read_text(encoding="utf-8")) or {}


def rule_meta(rule_id: str) -> dict:
    mapping = load_attack_map().get("rules", {})
    return mapping.get(rule_id, {})


def technique_name(technique_id: str) -> str:
    techniques = load_attack_map().get("techniques", {})
    entry = techniques.get(technique_id) or {}
    return entry.get("name", technique_id)
