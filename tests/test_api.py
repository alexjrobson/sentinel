from fastapi.testclient import TestClient

from sentinel_api.main import app


def test_health(reset_api_vault):
    with TestClient(app) as client:
        res = client.get("/api/health")
        assert res.status_code == 200
        assert res.json()["ok"] is True


def test_scan_and_report(samples_dir, reset_api_vault):
    with TestClient(app) as client:
        res = client.post(
            "/api/scan",
            json={"path": str(samples_dir), "case": "api-demo", "notes": "api test"},
        )
        assert res.status_code == 200, res.text
        case_id = res.json()["id"]
        detail = client.get(f"/api/cases/{case_id}")
        assert detail.status_code == 200
        assert detail.json()["findings"]
        html = client.get(f"/api/cases/{case_id}/report.html")
        assert html.status_code == 200
        assert b"Sentinel forensic report" in html.content


def test_vault_api(reset_api_vault):
    with TestClient(app) as client:
        assert client.get("/api/vault/status").json()["exists"] is False
        created = client.post("/api/vault/init", json={"password": "test-master-pw"})
        assert created.status_code == 200
        assert created.json()["unlocked"] is True
        added = client.post(
            "/api/vault/entries",
            json={"name": "virustotal", "type": "api_key", "secret": "demo-key"},
        )
        assert added.status_code == 200
        listed = client.get("/api/vault/entries?secrets=true")
        assert listed.json()[0]["secret"] == "demo-key"
        client.post("/api/vault/lock")
        locked = client.get("/api/vault/entries")
        assert locked.status_code == 401
        bad = client.post("/api/vault/unlock", json={"password": "nope"})
        assert bad.status_code == 401
