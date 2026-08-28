from sentinel.db import get_case, list_findings, session
from sentinel.pipeline import run_scan
from sentinel.reports.export import export_html, export_json


def test_scan_samples_creates_case(samples_dir):
    case = run_scan(samples_dir, "unit-demo", notes="pytest")
    assert case.id
    assert case.file_count >= 4
    assert case.finding_count >= 1
    with session() as conn:
        stored = get_case(conn, case.id)
        assert stored is not None
        flags = list_findings(conn, case.id)
    assert any(f["rule_id"] == "eicar_test" for f in flags)


def test_report_export(samples_dir, tmp_path):
    case = run_scan(samples_dir, "report-demo")
    html_path = tmp_path / "report.html"
    json_path = tmp_path / "report.json"
    html = export_html(case.id, html_path)
    data = export_json(case.id, json_path)
    assert "Sentinel forensic report" in html
    assert html_path.read_text(encoding="utf-8") == html
    assert f'"id": {case.id}' in data or f'"id":{case.id}' in data
