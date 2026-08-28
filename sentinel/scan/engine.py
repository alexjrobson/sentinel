from __future__ import annotations

from pathlib import Path

from sentinel.models import FileRecord
from sentinel.scan.entropy import file_entropy
from sentinel.scan.hashing import hash_file
from sentinel.scan.magic import detect_type, extension_of, magic_mismatch
from sentinel.scan.pe import is_pe, parse_pe
from sentinel.scan.strings import extract_iocs_from_file
from sentinel.scan.timestamps import mac_timestamps
from sentinel.scan.walk import iter_files


def analyze_path(path: Path) -> FileRecord:
    path = path.resolve()
    try:
        size = path.stat().st_size
        header = path.read_bytes()[:16] if size else b""
        md5, sha1, sha256 = hash_file(path)
        detected = detect_type(path, header)
        ext = extension_of(path)
        stamps = mac_timestamps(path)
        record = FileRecord(
            path=str(path),
            size=size,
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            detected_type=detected,
            extension=ext,
            magic_mismatch=magic_mismatch(path, detected),
            entropy=file_entropy(path) if size else 0.0,
            created_at=stamps["created_at"],
            modified_at=stamps["modified_at"],
            accessed_at=stamps["accessed_at"],
            iocs=extract_iocs_from_file(path),
        )
        if is_pe(header):
            record.pe_info = parse_pe(path)
        return record
    except OSError as exc:
        return FileRecord(path=str(path), size=0, error=str(exc))


def scan_target(target: str | Path) -> list[FileRecord]:
    records: list[FileRecord] = []
    for file_path in iter_files(target):
        records.append(analyze_path(file_path))
    return records
