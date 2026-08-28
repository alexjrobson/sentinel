from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from sentinel.db import get_case, list_files, list_findings, session, timeline_events
from sentinel.flags.attack import technique_name

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )


def case_bundle(case_id: int) -> dict:
    with session() as conn:
        case = get_case(conn, case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")
        files = list_files(conn, case_id)
        findings = list_findings(conn, case_id)
        timeline = timeline_events(conn, case_id)
    for finding in findings:
        finding["attack"] = [
            {"id": tid, "name": technique_name(tid)} for tid in finding.get("attack_ids") or []
        ]
    return {
        "case": case.to_dict(),
        "files": files,
        "findings": findings,
        "timeline": timeline,
        "product": "Sentinel DFIR Workstation",
        "version": "0.1.0",
    }


def export_json(case_id: int, dest: Path | None = None) -> str:
    payload = case_bundle(case_id)
    text = json.dumps(payload, indent=2)
    if dest:
        dest.write_text(text, encoding="utf-8")
    return text


def export_html(case_id: int, dest: Path | None = None) -> str:
    payload = case_bundle(case_id)
    html = _env().get_template("report.html").render(**payload)
    if dest:
        dest.write_text(html, encoding="utf-8")
    return html
