import asyncio
from fastapi.testclient import TestClient
from app import db, main, fix_queue

def test_owner_propagates_to_fix_queue(tmp_path, monkeypatch):
    db.DB_PATH = str(tmp_path / "test.db")
    asyncio.run(db.init_db())
    scan_id = asyncio.run(db.create_scan("example.com"))
    client = TestClient(main.app)
    payload = {
        "scan_id": scan_id,
        "host": "h1",
        "ip": "1.1.1.1",
        "owner_email": "owner@example.com",
        "criticality": 5,
        "data_class": "PII"
    }
    resp = client.post("/org/scope", json=payload)
    assert resp.status_code == 200
    fix_queue.FIX_QUEUE.clear()
    called = {}
    def fake_jira(*args, **kwargs):
        called["called"] = True
    monkeypatch.setattr(fix_queue, "open_jira_ticket", fake_jira)
    asyncio.run(db.add_finding(scan_id, "h1", "1.1.1.1", 80, "tcp", "high", "issue", "desc", {}))
    assert fix_queue.FIX_QUEUE
    entry = fix_queue.FIX_QUEUE[0]
    assert entry["owner_email"] == "owner@example.com"
    assert called.get("called")
