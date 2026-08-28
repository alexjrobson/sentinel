from __future__ import annotations

from pathlib import Path

import filetype

# Extensions we treat as "image/document" for mismatch flagging.
IMAGE_EXT = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico"}
DOC_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".gz", ".tar"}
EXEC_EXT = {".exe", ".dll", ".sys", ".scr", ".com"}

KIND_TO_EXTS = {
    "jpg": IMAGE_EXT,
    "jpeg": IMAGE_EXT,
    "png": IMAGE_EXT,
    "gif": IMAGE_EXT,
    "bmp": IMAGE_EXT,
    "webp": IMAGE_EXT,
    "pdf": {".pdf"},
    "zip": {".zip"},
    "gz": {".gz", ".tgz"},
    "exe": EXEC_EXT,
    "elf": {".elf", ".so", ".bin", ""},
    "docx": {".docx"},
    "xlsx": {".xlsx"},
    "pptx": {".pptx"},
}


def detect_type(path: Path, header: bytes | None = None) -> str:
    if header:
        guess = filetype.guess(header)
    else:
        guess = filetype.guess(str(path))
    if guess:
        return guess.extension
    # Fallback: MZ / ELF / PDF magic
    sample = header if header is not None else path.read_bytes()[:8]
    if sample.startswith(b"MZ"):
        return "exe"
    if sample.startswith(b"\x7fELF"):
        return "elf"
    if sample.startswith(b"%PDF"):
        return "pdf"
    return "unknown"


def extension_of(path: Path) -> str:
    return path.suffix.lower()


def magic_mismatch(path: Path, detected: str) -> bool:
    """True when the extension claims a type the content does not support."""
    ext = extension_of(path)
    if not ext:
        return False
    allowed = KIND_TO_EXTS.get(detected)
    if allowed and ext not in allowed:
        return True
    if ext in IMAGE_EXT and detected not in {"jpg", "jpeg", "png", "gif", "bmp", "webp"}:
        return True
    if ext in EXEC_EXT and detected not in {"exe"}:
        return True
    if ext == ".pdf" and detected != "pdf":
        return True
    if ext in ARCHIVE_EXT and detected not in {"zip", "gz", "rar", "7z"}:
        return True
    return False
