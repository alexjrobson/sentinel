from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from sentinel.config import db_path
from sentinel.models import Case, FileRecord, Finding


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect(path: Path | None = None) -> sqlite3.Connection:
    db = path or db_path()
    db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn: sqlite3.Connection | None = None) -> None:
    own = conn is None
    conn = conn or connect()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            target_path TEXT NOT NULL,
            created_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            notes TEXT,
            file_count INTEGER DEFAULT 0,
            finding_count INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY,
            case_id INTEGER NOT NULL,
            path TEXT NOT NULL,
            size INTEGER,
            md5 TEXT,
            sha1 TEXT,
            sha256 TEXT,
            detected_type TEXT,
            extension TEXT,
            magic_mismatch INTEGER DEFAULT 0,
            entropy REAL,
            created_at TEXT,
            modified_at TEXT,
            accessed_at TEXT,
            pe_info TEXT,
            iocs TEXT,
            yara_hits TEXT,
            vt TEXT,
            error TEXT,
            FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY,
            case_id INTEGER NOT NULL,
            file_id INTEGER,
            rule_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            evidence TEXT,
            attack_ids TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
            FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE SET NULL
        );

        CREATE INDEX IF NOT EXISTS idx_files_case ON files(case_id);
        CREATE INDEX IF NOT EXISTS idx_files_sha256 ON files(sha256);
        CREATE INDEX IF NOT EXISTS idx_findings_case ON findings(case_id);
        """
    )
    conn.commit()
    if own:
        conn.close()


@contextmanager
def session(path: Path | None = None) -> Iterator[sqlite3.Connection]:
    conn = connect(path)
    init_db(conn)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def create_case(conn: sqlite3.Connection, name: str, target_path: str, notes: str | None = None) -> Case:
    created = utcnow()
    cur = conn.execute(
        "INSERT INTO cases (name, target_path, created_at, status, notes) VALUES (?, ?, ?, 'scanning', ?)",
        (name, target_path, created, notes),
    )
    return Case(
        id=cur.lastrowid,
        name=name,
        target_path=target_path,
        created_at=created,
        status="scanning",
        notes=notes,
    )


def finish_case(conn: sqlite3.Connection, case_id: int, file_count: int, finding_count: int) -> None:
    conn.execute(
        "UPDATE cases SET status = 'complete', file_count = ?, finding_count = ? WHERE id = ?",
        (file_count, finding_count, case_id),
    )


def get_case(conn: sqlite3.Connection, case_id: int) -> Case | None:
    row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    return _case_from_row(row) if row else None


def list_cases(conn: sqlite3.Connection) -> list[Case]:
    rows = conn.execute("SELECT * FROM cases ORDER BY id DESC").fetchall()
    return [_case_from_row(r) for r in rows]


def insert_file(conn: sqlite3.Connection, case_id: int, record: FileRecord) -> int:
    cur = conn.execute(
        """
        INSERT INTO files (
            case_id, path, size, md5, sha1, sha256, detected_type, extension,
            magic_mismatch, entropy, created_at, modified_at, accessed_at,
            pe_info, iocs, yara_hits, vt, error
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            case_id,
            record.path,
            record.size,
            record.md5,
            record.sha1,
            record.sha256,
            record.detected_type,
            record.extension,
            int(record.magic_mismatch),
            record.entropy,
            record.created_at,
            record.modified_at,
            record.accessed_at,
            json.dumps(record.pe_info) if record.pe_info else None,
            json.dumps(record.iocs) if record.iocs else None,
            json.dumps(record.yara_hits) if record.yara_hits else None,
            json.dumps(record.vt) if record.vt else None,
            record.error,
        ),
    )
    return int(cur.lastrowid)


def insert_finding(conn: sqlite3.Connection, case_id: int, finding: Finding) -> int:
    cur = conn.execute(
        """
        INSERT INTO findings (case_id, file_id, rule_id, severity, title, evidence, attack_ids, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            case_id,
            finding.file_id,
            finding.rule_id,
            finding.severity,
            finding.title,
            finding.evidence,
            json.dumps(finding.attack_ids),
            utcnow(),
        ),
    )
    return int(cur.lastrowid)


def list_files(conn: sqlite3.Connection, case_id: int) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM files WHERE case_id = ? ORDER BY id", (case_id,)).fetchall()
    return [_file_from_row(r) for r in rows]


def list_findings(conn: sqlite3.Connection, case_id: int, severity: str | None = None) -> list[dict[str, Any]]:
    if severity:
        rows = conn.execute(
            """
            SELECT f.*, files.path AS file_path
            FROM findings f
            LEFT JOIN files ON files.id = f.file_id
            WHERE f.case_id = ? AND f.severity = ?
            ORDER BY
                CASE f.severity
                    WHEN 'critical' THEN 0
                    WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2
                    ELSE 3
                END,
                f.id
            """,
            (case_id, severity.lower()),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT f.*, files.path AS file_path
            FROM findings f
            LEFT JOIN files ON files.id = f.file_id
            WHERE f.case_id = ?
            ORDER BY
                CASE f.severity
                    WHEN 'critical' THEN 0
                    WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2
                    ELSE 3
                END,
                f.id
            """,
            (case_id,),
        ).fetchall()
    return [_finding_from_row(r) for r in rows]


def timeline_events(conn: sqlite3.Connection, case_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT id, path, created_at, modified_at, accessed_at, sha256 FROM files WHERE case_id = ?",
        (case_id,),
    ).fetchall()
    events: list[dict[str, Any]] = []
    for row in rows:
        for kind, ts in (
            ("created", row["created_at"]),
            ("modified", row["modified_at"]),
            ("accessed", row["accessed_at"]),
        ):
            if ts:
                events.append(
                    {
                        "file_id": row["id"],
                        "path": row["path"],
                        "sha256": row["sha256"],
                        "event": kind,
                        "timestamp": ts,
                    }
                )
    events.sort(key=lambda e: e["timestamp"] or "")
    return events


def update_file_vt(conn: sqlite3.Connection, file_id: int, vt: dict[str, Any]) -> None:
    conn.execute("UPDATE files SET vt = ? WHERE id = ?", (json.dumps(vt), file_id))


def _case_from_row(row: sqlite3.Row) -> Case:
    return Case(
        id=row["id"],
        name=row["name"],
        target_path=row["target_path"],
        created_at=row["created_at"],
        status=row["status"],
        notes=row["notes"],
        file_count=row["file_count"] or 0,
        finding_count=row["finding_count"] or 0,
    )


def _file_from_row(row: sqlite3.Row) -> dict[str, Any]:
    def loads(value: str | None) -> Any:
        if not value:
            return None
        return json.loads(value)

    return {
        "id": row["id"],
        "case_id": row["case_id"],
        "path": row["path"],
        "size": row["size"],
        "md5": row["md5"],
        "sha1": row["sha1"],
        "sha256": row["sha256"],
        "detected_type": row["detected_type"],
        "extension": row["extension"],
        "magic_mismatch": bool(row["magic_mismatch"]),
        "entropy": row["entropy"],
        "created_at": row["created_at"],
        "modified_at": row["modified_at"],
        "accessed_at": row["accessed_at"],
        "pe_info": loads(row["pe_info"]),
        "iocs": loads(row["iocs"]) or {},
        "yara_hits": loads(row["yara_hits"]) or [],
        "vt": loads(row["vt"]),
        "error": row["error"],
    }


def _finding_from_row(row: sqlite3.Row) -> dict[str, Any]:
    keys = row.keys()
    return {
        "id": row["id"],
        "case_id": row["case_id"],
        "file_id": row["file_id"],
        "file_path": row["file_path"] if "file_path" in keys else None,
        "rule_id": row["rule_id"],
        "severity": row["severity"],
        "title": row["title"],
        "evidence": row["evidence"],
        "attack_ids": json.loads(row["attack_ids"] or "[]"),
        "created_at": row["created_at"],
    }
