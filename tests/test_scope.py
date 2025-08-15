import asyncio
from fastapi.testclient import TestClient
from app.main import app
from app import db, scanner


def test_scope_registration(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    with TestClient(app) as client:
        r = client.post("/org/scope", json={"kind": "domain", "value": "example.com"})
        assert r.status_code == 200
        scopes = asyncio.run(db.list_scope())
        assert scopes and scopes[0]["value"] == "example.com"


def test_start_scan_enforces_scope(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    with TestClient(app) as client:
        r = client.post("/scan", json={"domain": "example.com"})
        assert r.status_code == 400
        client.post("/org/scope", json={"kind": "domain", "value": "example.com"})
        async def fake_scan(domain):
            return {"host_ips": {}, "open_ports": [], "fingerprints": {}}
        monkeypatch.setattr(scanner, "scan_domain", fake_scan)
        r2 = client.post("/scan", json={"domain": "example.com"})
        assert r2.status_code == 200
        assert "scan_id" in r2.json()
