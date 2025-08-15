import asyncio
from app import main


class DummyDB:
    def __init__(self):
        self.calls = []

    async def add_finding(self, *args, **kwargs):
        self.calls.append((args, kwargs))


async def _run_test():
    out = {
        "open_ports": [
            ("example.com", "1.2.3.4", 80),
            ("example.com", "1.2.3.4", 443),
        ],
        "fingerprints": {
            "example.com|1.2.3.4|80": {"status": 301, "hsts": True},
            "example.com|1.2.3.4|443": {"status": 200, "hsts": True},
        },
    }
    db = DummyDB()
    stats = {"score": 100, "penalties": []}
    scan_id = 1
    for (host, ip, port) in out["open_ports"]:
        if port in main.RISKY:
            await db.add_finding(
                scan_id,
                host,
                ip,
                port,
                "tcp",
                "high",
                f"Internet-exposed service on {port}",
                "Restrict exposure or require VPN; verify auth; move behind WAF/bastion.",
                {},
            )
            stats["score"] -= 10
            stats["penalties"].append(f"Risky port {port} exposed")
    fp_map = out.get("fingerprints", {})
    for (host, ip, port) in out["open_ports"]:
        if port not in (80, 8080, 443, 8443):
            continue
        key = f"{host}|{ip}|{port}"
        fp = fp_map.get(key, {})
        https_ok = main.has_https(out["open_ports"], host, ip)
        if port in (80, 8080) and (not https_ok or not fp.get("hsts")):
            sev = "medium" if https_ok else "high"
            reason = "No HSTS" if https_ok else "No HTTPS available"
            await db.add_finding(
                scan_id,
                host,
                ip,
                port,
                "http",
                sev,
                f"Plain HTTP exposed ({reason})",
                "Enable HTTPS and Strict-Transport-Security or redirect all HTTP to HTTPS.",
                fp,
            )
            if not https_ok:
                stats["score"] -= 5
                stats["penalties"].append("HTTP without HTTPS")
    assert db.calls == []


def test_redirect_to_https_with_hsts_no_finding():
    asyncio.run(_run_test())
