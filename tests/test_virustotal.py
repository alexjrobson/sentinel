from unittest.mock import patch

import httpx

from sentinel.intel.virustotal import lookup_virustotal, resolve_api_key


def test_resolve_prefers_vault_secret(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "env-key")
    assert resolve_api_key("vault-key") == "vault-key"
    assert resolve_api_key(None) == "env-key"


def test_lookup_is_hash_only_and_handles_404():
    captured: dict = {}

    def fake_get(url, **kwargs):
        captured["url"] = url
        captured["content"] = kwargs.get("content") or kwargs.get("data")
        return httpx.Response(404, json={"error": "NotFound"})

    with patch("sentinel.intel.virustotal.httpx.get", side_effect=fake_get):
        result = lookup_virustotal("deadbeefcafebabe", "fake-key")

    assert result["found"] is False
    assert captured["url"].endswith("/deadbeefcafebabe")
    assert "/files/" in captured["url"]
    assert captured["content"] is None
