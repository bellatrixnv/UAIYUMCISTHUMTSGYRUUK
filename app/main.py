import asyncio, json, os, time
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from pydantic import BaseModel
from . import db, scanner
from .report import render_report
from .panel import render_panel
from .cspm_aws import run_checks
import pdfkit

app = FastAPI(title="SMBSEC MVP", version="0.1.0")

class ScanRequest(BaseModel):
    domain: str

class AWSConnector(BaseModel):
    role_arn: str
    external_id: str

RISKY = {3389, 5432, 6379, 3306, 9200, 27017}

def has_https(open_ports, host, ip):
    return any(h == host and i == ip and p in (443, 8443) for (h, i, p) in open_ports)

@app.on_event("startup")
async def startup():
    await db.init_db()

@app.post("/scan")
async def start_scan(req: ScanRequest):
    domain = req.domain.strip().lower()
    if not domain or " " in domain or "." not in domain:
        raise HTTPException(400, "Invalid domain")
    scan_id = await db.create_scan(domain)
    async def run():
        stats = {"hosts":0,"open":0,"score":100,"penalties":[],"bonuses":[]}
        try:
            out = await scanner.scan_domain(domain)
            for host, ips in out["host_ips"].items():
                if not ips:
                    await db.upsert_asset(scan_id, host, None)
                for ip in ips:
                    await db.upsert_asset(scan_id, host, ip)
                    stats["hosts"] += 1
            for (host, ip, port) in out["open_ports"]:
                if port in RISKY:
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
                https_ok = has_https(out["open_ports"], host, ip)
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
            for key, info in out.get("tls", {}).items():
                h, ip, p = key.split("|"); p = int(p)
                if info:
                    days = info.get("days_to_expiry")
                    proto = info.get("protocol","")
                    if isinstance(days, int):
                        if days < 0:
                            await db.add_finding(scan_id, h, ip, p, "tls", "high",
                                "Expired TLS certificate", "Certificate notAfter date is in the past", info)
                            stats["score"] -= 15
                            stats["penalties"].append("Expired TLS cert")
                        elif days < 14:
                            await db.add_finding(scan_id, h, ip, p, "tls", "medium",
                                "TLS certificate expiring soon", f"Cert expires in {days} days", info)
                    if proto and proto.startswith("TLSv1.3"):
                        stats["score"] += 2
                        stats["bonuses"].append("TLS 1.3 detected")
            for key, banner in out.get("ssh", {}).items():
                if banner:
                    h, ip, p = key.split("|"); p = int(p)
                    await db.add_finding(scan_id, h, ip, p, "ssh", "info",
                        "SSH service banner", banner, {"banner": banner})
        except Exception as e:
            await db.finish_scan(scan_id, "error", {"error": str(e)})
            return
        await db.finish_scan(scan_id, "done", stats)
    asyncio.create_task(run())
    return {"scan_id": scan_id, "status": "running"}

@app.get("/", response_class=HTMLResponse)
async def panel():
    scans = await db.list_scans()
    html = render_panel(scans)
    return HTMLResponse(html)

async def _build_report(scan_id:int, s:dict):
    import aiosqlite
    async with aiosqlite.connect(os.path.join(os.path.dirname(__file__), "..", "data.db")) as conn:
        conn.row_factory = aiosqlite.Row
        a = await conn.execute("SELECT host, ip, last_seen FROM assets WHERE scan_id=?", (scan_id,))
        assets = [dict(r) for r in await a.fetchall()]
    f = await db.list_findings(scan_id)
    stats = json.loads(s.get("stats_json", "{}"))
    html = render_report(scan_id, s["domain"], s["finished_at"] or int(time.time()), assets, f, stats)
    out_dir = os.path.join(os.path.dirname(__file__), "..", "reports")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"scan_{scan_id}.html")
    with open(out_path, "w", encoding="utf-8") as fp:
        fp.write(html)
    return html, out_dir

@app.get("/scans/{scan_id}")
async def get_scan(scan_id:int):
    s = await db.get_scan(scan_id)
    if not s: raise HTTPException(404, "Not found")
    f = await db.list_findings(scan_id)
    return {"scan": s, "findings": f}

@app.get("/report/{scan_id}", response_class=HTMLResponse)
async def get_report(scan_id:int):
    s = await db.get_scan(scan_id)
    if not s: raise HTTPException(404, "Not found")
    if s["status"] not in ("done","error"):
        return HTMLResponse("<h3>Scan still running...</h3>")
    html,_ = await _build_report(scan_id, s)
    return HTMLResponse(html)

@app.get("/report/{scan_id}/pdf")
async def get_report_pdf(scan_id:int):
    s = await db.get_scan(scan_id)
    if not s: raise HTTPException(404, "Not found")
    if s["status"] not in ("done","error"):
        raise HTTPException(400, "Scan still running")
    html,out_dir = await _build_report(scan_id, s)
    pdf_path = os.path.join(out_dir, f"scan_{scan_id}.pdf")
    pdfkit.from_string(html, pdf_path)
    return FileResponse(pdf_path, media_type="application/pdf", filename=f"scan_{scan_id}.pdf")

@app.post("/connect/aws")
async def connect_aws(conn: AWSConnector):
    await db.add_connector_aws(conn.role_arn.strip(), conn.external_id.strip())
    return {"status": "ok"}

@app.post("/cspm/aws/run")
async def cspm_run():
    conns = await db.get_connectors('aws')
    if not conns:
        raise HTTPException(400, "No AWS connector configured")
    role_arn = conns[0]["role_arn"]
    external_id = conns[0]["external_id"]
    scan_id = await db.create_scan("aws")
    try:
        results = run_checks(role_arn, external_id)
        for it in results:
            title = it["issue"]
            res = it["resource"]
            sev = "high" if "AdministratorAccess" in title or "Public" in title else "medium"
            await db.add_finding(scan_id, host=res, ip=None, port=None, proto="aws", severity=sev,
                                 title=title, description=f"AWS check flagged: {res}", evidence=it)
        await db.finish_scan(scan_id, "done", {"count": len(results)})
    except Exception as e:
        await db.finish_scan(scan_id, "error", {"error": str(e)})
    return {"scan_id": scan_id}
