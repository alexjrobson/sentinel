from __future__ import annotations

from pathlib import Path
from typing import Any

import pefile

from sentinel.config import PE_MAX_BYTES
from sentinel.scan.entropy import shannon_entropy

SUSPICIOUS_IMPORTS = {
    "virtualalloc",
    "virtualprotect",
    "virtualallocex",
    "writeprocessmemory",
    "createremotethread",
    "ntunmapviewofsection",
    "winexec",
    "shellexecutea",
    "shellexecutew",
    "urldownloadtofilea",
    "urldownloadtofilew",
    "internetopena",
    "internetopenw",
    "cryptencrypt",
    "rtldecompressbuffer",
    "loadlibrarya",
    "getprocaddress",
}


def is_pe(header: bytes) -> bool:
    return header.startswith(b"MZ")


def parse_pe(path: Path, max_bytes: int = PE_MAX_BYTES) -> dict[str, Any] | None:
    size = path.stat().st_size
    if size > max_bytes:
        return {"skipped": True, "reason": "file too large for PE parse"}
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            ]
        )
    except Exception as exc:  # pefile raises many exception types
        return {"error": str(exc)}

    imports: list[str] = []
    suspicious: list[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("ascii", errors="ignore") if entry.dll else ""
            for imp in entry.imports:
                name = imp.name.decode("ascii", errors="ignore") if imp.name else ""
                if name:
                    imports.append(f"{dll}!{name}")
                    if name.lower() in SUSPICIOUS_IMPORTS:
                        suspicious.append(f"{dll}!{name}")

    sections = []
    for section in pe.sections:
        raw = section.get_data()
        name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
        sections.append(
            {
                "name": name,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": shannon_entropy(raw[:65536]) if raw else 0.0,
            }
        )

    compile_time = None
    try:
        compile_time = pe.FILE_HEADER.dump_dict()["TimeDateStamp"]["Value"]
    except Exception:
        compile_time = hex(pe.FILE_HEADER.TimeDateStamp)

    machine = pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
    return {
        "machine": machine,
        "compile_time": compile_time,
        "is_dll": bool(pe.is_dll()),
        "is_exe": bool(pe.is_exe()),
        "imports": imports[:80],
        "suspicious_imports": suspicious,
        "sections": sections,
        "imphash": _imphash(pe),
    }


def _imphash(pe: pefile.PE) -> str | None:
    try:
        return pe.get_imphash() or None
    except Exception:
        return None
