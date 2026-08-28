from __future__ import annotations

from pathlib import Path

from sentinel.db import create_case, finish_case, insert_file, insert_finding, session
from sentinel.flags.engine import evaluate_record
from sentinel.models import Case, FileRecord
from sentinel.scan.engine import analyze_path
from sentinel.scan.walk import iter_files
from sentinel.yara.engine import load_rules, match_file


def run_scan(
    target: str | Path,
    case_name: str,
    notes: str | None = None,
    include_yara: bool = True,
) -> Case:
    target_path = str(Path(target).expanduser().resolve())
    rules = load_rules() if include_yara else []

    with session() as conn:
        case = create_case(conn, case_name, target_path, notes)
        assert case.id is not None
        file_count = 0
        finding_count = 0
        for path in iter_files(target_path):
            record = analyze_path(path)
            if include_yara and not record.error:
                try:
                    record.yara_hits = match_file(path, rules)
                except OSError:
                    record.yara_hits = []
            file_id = insert_file(conn, case.id, record)
            record.id = file_id
            file_count += 1
            for finding in evaluate_record(record):
                finding.file_id = file_id
                insert_finding(conn, case.id, finding)
                finding_count += 1
        finish_case(conn, case.id, file_count, finding_count)
        case.file_count = file_count
        case.finding_count = finding_count
        case.status = "complete"
        return case


def analyze_and_flag(path: Path) -> tuple[FileRecord, list]:
    record = analyze_path(path)
    record.yara_hits = match_file(path)
    findings = evaluate_record(record)
    return record, findings
