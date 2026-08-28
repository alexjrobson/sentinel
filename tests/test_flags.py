from pathlib import Path

from sentinel.flags.engine import evaluate_record
from sentinel.scan.engine import analyze_path
from sentinel.yara.engine import match_file


def test_extension_mismatch_flag(samples_dir: Path):
    record = analyze_path(samples_dir / "not_an_image.png")
    assert record.magic_mismatch
    findings = evaluate_record(record)
    assert any(f.rule_id == "extension_mismatch" for f in findings)


def test_eicar_hash_ioc_and_yara(samples_dir: Path):
    record = analyze_path(samples_dir / "eicar.com.txt")
    record.yara_hits = match_file(samples_dir / "eicar.com.txt")
    findings = evaluate_record(record)
    ids = {f.rule_id for f in findings}
    assert "hash_ioc" in ids
    assert "eicar_test" in ids
    eicar = next(f for f in findings if f.rule_id == "eicar_test")
    assert "T1204.002" in eicar.attack_ids


def test_high_entropy_flag(tmp_path: Path):
    blob = tmp_path / "packed.bin"
    blob.write_bytes(bytes(range(256)) * 8)
    record = analyze_path(blob)
    assert record.entropy is not None and record.entropy >= 7.2
    findings = evaluate_record(record)
    assert any(f.rule_id == "high_entropy" for f in findings)


def test_clean_note_has_no_critical_flags(samples_dir: Path):
    record = analyze_path(samples_dir / "clean_note.txt")
    record.yara_hits = match_file(samples_dir / "clean_note.txt")
    findings = evaluate_record(record)
    assert all(f.severity not in {"critical", "high"} for f in findings)
