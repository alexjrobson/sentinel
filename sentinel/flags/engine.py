from __future__ import annotations

from sentinel.config import HIGH_ENTROPY_MIN_SIZE, HIGH_ENTROPY_THRESHOLD
from sentinel.flags.attack import rule_meta
from sentinel.intel.iocs import lookup_hash
from sentinel.models import FileRecord, Finding


def _finding(rule_id: str, evidence: str, record: FileRecord, **overrides) -> Finding:
    meta = rule_meta(rule_id)
    return Finding(
        rule_id=rule_id,
        severity=overrides.get("severity", meta.get("severity", "low")),
        title=overrides.get("title", meta.get("title", rule_id)),
        evidence=evidence,
        attack_ids=list(overrides.get("attack_ids", meta.get("attack", []))),
        file_path=record.path,
    )


def evaluate_record(record: FileRecord) -> list[Finding]:
    if record.error:
        return []
    findings: list[Finding] = []

    ioc = lookup_hash(record.md5, record.sha1, record.sha256)
    if ioc:
        findings.append(
            _finding(
                "hash_ioc",
                f"{ioc.get('label', 'known-bad')} via {ioc.get('source', 'local IOC list')} "
                f"(sha256={record.sha256})",
                record,
            )
        )

    yara_rule_ids: set[str] = set()
    for hit in record.yara_hits or []:
        meta = hit.get("meta") or {}
        rule_id = meta.get("rule_id") or "yara_hit"
        yara_rule_ids.add(rule_id)
        extra = dict(rule_meta(rule_id))
        findings.append(
            _finding(
                rule_id,
                f"YARA rule {hit.get('rule')} matched strings {hit.get('strings')}"
                + (f" — {meta.get('description')}" if meta.get("description") else ""),
                record,
                severity=meta.get("severity") or extra.get("severity", "medium"),
                title=extra.get("title") or f"YARA: {hit.get('rule')}",
                attack_ids=_split_attack(meta.get("attack")) or extra.get("attack", []),
            )
        )

    if record.magic_mismatch:
        findings.append(
            _finding(
                "extension_mismatch",
                f"extension {record.extension or '(none)'} vs detected type {record.detected_type}",
                record,
            )
        )

    if (
        record.entropy is not None
        and record.size >= HIGH_ENTROPY_MIN_SIZE
        and record.entropy >= HIGH_ENTROPY_THRESHOLD
    ):
        findings.append(
            _finding(
                "high_entropy",
                f"Shannon entropy {record.entropy} bits/byte (threshold {HIGH_ENTROPY_THRESHOLD})",
                record,
            )
        )

    pe = record.pe_info or {}
    suspicious_imports = pe.get("suspicious_imports") or []
    if suspicious_imports:
        findings.append(
            _finding(
                "suspicious_pe_imports",
                "Suspicious imports: " + ", ".join(suspicious_imports[:12]),
                record,
            )
        )

    iocs = record.iocs or {}
    if iocs.get("powershell") and "powershell_encoded" not in yara_rule_ids:
        findings.append(
            _finding(
                "powershell_strings",
                "Extracted: " + ", ".join(iocs["powershell"][:8]),
                record,
            )
        )
    if iocs.get("cmd") and "cmd_interpreter" not in yara_rule_ids:
        findings.append(
            _finding(
                "cmd_strings",
                "Extracted: " + ", ".join(iocs["cmd"][:8]),
                record,
            )
        )
    if iocs.get("urls"):
        findings.append(
            _finding(
                "embedded_urls",
                "URLs: " + ", ".join(iocs["urls"][:6]),
                record,
            )
        )

    vt = record.vt or {}
    stats = vt.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious") or 0)
    if malicious:
        findings.append(
            _finding(
                "vt_malicious",
                f"VirusTotal: {malicious} engines flagged this hash "
                f"(harmless={stats.get('harmless', 0)}, undetected={stats.get('undetected', 0)})",
                record,
            )
        )

    # Composite: YARA + high entropy on the same file.
    has_yara = bool(record.yara_hits)
    has_entropy = any(f.rule_id == "high_entropy" for f in findings)
    if has_yara and has_entropy:
        findings.append(
            _finding(
                "packed_and_yara",
                "Combined signal: YARA match on a high-entropy file (possible packed payload)",
                record,
            )
        )

    return findings


def evaluate_records(records: list[FileRecord]) -> list[Finding]:
    out: list[Finding] = []
    for record in records:
        out.extend(evaluate_record(record))
    return out


def _split_attack(value: str | list | None) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [part.strip() for part in str(value).split(",") if part.strip()]
