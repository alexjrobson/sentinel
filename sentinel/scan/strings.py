from __future__ import annotations

import re
from pathlib import Path

from sentinel.config import STRING_EXTRACT_MAX_BYTES

IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
URL = re.compile(r"https?://[^\s\"'<>]{4,200}", re.IGNORECASE)
EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
WIN_PATH = re.compile(r"[A-Za-z]:\\(?:[^\s\"'<>]{1,80}\\)*[^\s\"'<>]{1,80}")
REGISTRY = re.compile(r"\bHK(?:LM|CU|CR|U|CC)\\[A-Za-z0-9_\\]+", re.IGNORECASE)
BASE64 = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
POWERSHELL = re.compile(r"powershell(?:\.exe)?|Invoke-Expression|IEX\s|FromBase64String|-enc(?:odedcommand)?", re.IGNORECASE)
CMD = re.compile(r"cmd(?:\.exe)?(?:\s+/c)?|wscript(?:\.exe)?|cscript(?:\.exe)?", re.IGNORECASE)

PRINTABLE = re.compile(rb"[\x20-\x7e]{6,}")
UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")


def _extract_raw_strings(data: bytes, limit: int = 400) -> list[str]:
    found: list[str] = []
    for match in PRINTABLE.finditer(data):
        found.append(match.group().decode("ascii", errors="ignore"))
        if len(found) >= limit:
            return found
    for match in UTF16.finditer(data):
        found.append(match.group().decode("utf-16le", errors="ignore"))
        if len(found) >= limit:
            break
    return found


def extract_iocs(data: bytes) -> dict[str, list[str]]:
    text = "\n".join(_extract_raw_strings(data))
    buckets: dict[str, list[str]] = {
        "ipv4": _unique(IPV4.findall(text)),
        "urls": _unique(URL.findall(text)),
        "emails": _unique(EMAIL.findall(text)),
        "windows_paths": _unique(WIN_PATH.findall(text)),
        "registry": _unique(REGISTRY.findall(text)),
        "base64": _unique(BASE64.findall(text))[:20],
        "powershell": _unique(POWERSHELL.findall(text)),
        "cmd": _unique(CMD.findall(text)),
    }
    return {k: v for k, v in buckets.items() if v}


def extract_iocs_from_file(path: Path, max_bytes: int = STRING_EXTRACT_MAX_BYTES) -> dict[str, list[str]]:
    with path.open("rb") as handle:
        data = handle.read(max_bytes)
    return extract_iocs(data)


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        key = item.lower()
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out[:50]
