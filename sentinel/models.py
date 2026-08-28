from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class FileRecord:
    path: str
    size: int
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    detected_type: str = ""
    extension: str = ""
    magic_mismatch: bool = False
    entropy: float | None = None
    created_at: str | None = None
    modified_at: str | None = None
    accessed_at: str | None = None
    pe_info: dict[str, Any] | None = None
    iocs: dict[str, list[str]] = field(default_factory=dict)
    yara_hits: list[dict[str, Any]] = field(default_factory=list)
    vt: dict[str, Any] | None = None
    error: str | None = None
    id: int | None = None
    case_id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    evidence: str
    attack_ids: list[str] = field(default_factory=list)
    file_id: int | None = None
    file_path: str | None = None
    case_id: int | None = None
    id: int | None = None
    created_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Case:
    name: str
    target_path: str
    id: int | None = None
    created_at: str | None = None
    status: str = "open"
    notes: str | None = None
    file_count: int = 0
    finding_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
