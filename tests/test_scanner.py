import asyncio
import httpx
from app.scanner import http_fingerprint

def test_http_fingerprint_parses_uppercase_title(monkeypatch):
    class DummyClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, exc_type, exc, tb):
            pass
        async def get(self, url, headers):
            return httpx.Response(200, text="<HTML><TITLE>HELLO</TITLE></HTML>")
    monkeypatch.setattr(httpx, "AsyncClient", lambda *args, **kwargs: DummyClient())
    fp = asyncio.run(http_fingerprint("example.com", "1.2.3.4", "http"))
    assert fp["title"] == "HELLO"

def test_http_fingerprint_detects_hsts(monkeypatch):
    class DummyClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, exc_type, exc, tb):
            pass
        async def get(self, url, headers):
            return httpx.Response(200, text="<html></html>", headers={"Strict-Transport-Security": "max-age=0"})
    monkeypatch.setattr(httpx, "AsyncClient", lambda *args, **kwargs: DummyClient())
    fp = asyncio.run(http_fingerprint("example.com", "1.2.3.4", "https"))
    assert fp["hsts"] is True
