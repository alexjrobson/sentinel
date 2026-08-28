from __future__ import annotations

import os
from typing import Any

import httpx

VT_URL = "https://www.virustotal.com/api/v3/files/{hash}"


class VirusTotalError(Exception):
    pass


def resolve_api_key(vault_secret: str | None = None) -> str | None:
    return vault_secret or os.environ.get("VIRUSTOTAL_API_KEY") or None


def lookup_virustotal(file_hash: str, api_key: str, timeout: float = 20.0) -> dict[str, Any]:
    """Hash-only lookup. Never uploads file bytes."""
    if not api_key:
        raise VirusTotalError("No VirusTotal API key configured")
    url = VT_URL.format(hash=file_hash)
    headers = {"x-apikey": api_key, "accept": "application/json"}
    try:
        response = httpx.get(url, headers=headers, timeout=timeout)
    except httpx.HTTPError as exc:
        raise VirusTotalError(f"VirusTotal request failed: {exc}") from exc

    if response.status_code == 404:
        return {"found": False, "hash": file_hash}
    if response.status_code == 401:
        raise VirusTotalError("VirusTotal API key rejected")
    if response.status_code == 429:
        raise VirusTotalError("VirusTotal rate limit exceeded")
    if response.status_code >= 400:
        raise VirusTotalError(f"VirusTotal HTTP {response.status_code}: {response.text[:200]}")

    data = response.json().get("data", {})
    attrs = data.get("attributes", {})
    return {
        "found": True,
        "hash": file_hash,
        "meaningful_name": attrs.get("meaningful_name"),
        "last_analysis_stats": attrs.get("last_analysis_stats") or {},
        "popular_threat_classification": attrs.get("popular_threat_classification"),
        "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
    }
