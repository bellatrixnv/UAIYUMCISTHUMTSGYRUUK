import asyncio, json, socket
from typing import Iterable
import httpx
import dns.resolver
from .probers import get_tls_cert_info, get_ssh_banner

DEFAULT_PORTS = [80, 443, 22, 25, 110, 143, 465, 587, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443]

async def fetch_crtsh_subdomains(domain:str)->set[str]:
    q = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains:set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.get(q, headers={"User-Agent":"smbsec-mvp/1.0"})
            if r.status_code == 200:
                for row in r.json():
                    name_value = row.get("name_value","")
                    for entry in name_value.split("\n"):
                        entry = entry.strip().lower().rstrip(".")
                        if entry.endswith(domain):
                            subdomains.add(entry)
    except Exception:
        pass
    subdomains.add(domain)
    return subdomains

def resolve_host(host:str)->list[str]:
    ips:list[str] = []
    try:
        for rdata in dns.resolver.resolve(host, "A"):
            ips.append(rdata.to_text())
    except Exception:
        pass
    try:
        for rdata in dns.resolver.resolve(host, "AAAA"):
            ips.append(rdata.to_text())
    except Exception:
        pass
    return ips

async def tcp_connect(ip:str, port:int, timeout:float=1.0)->bool:
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False

async def http_fingerprint(host:str, ip:str, scheme:str)->dict:
    url = f"{scheme}://{host}/"
    try:
        async with httpx.AsyncClient(timeout=5, verify=(scheme=="https")) as c:
            r = await c.get(url, headers={"Host":host, "User-Agent":"smbsec-mvp/1.0"})
            return {
                "status": r.status_code,
                "server": r.headers.get("server",""),
                "title": (r.text.split("<title>")[1].split("</title>")[0][:200]
                          if "<title>" in r.text.lower() else "")
            }
    except Exception as e:
        return {"error": str(e)[:200]}

async def bounded_gather(coros:Iterable, limit:int=200):
    sem = asyncio.Semaphore(limit)
    async def run(coro):
        async with sem:
            return await coro
    return await asyncio.gather(*[run(c) for c in coros])

async def scan_domain(domain:str):
    subs = await fetch_crtsh_subdomains(domain)
    host_ips:dict[str,list[str]] = {}
    for h in sorted(subs):
        host_ips[h] = resolve_host(h)

    tcp_results = []
    for h, ips in host_ips.items():
        for ip in ips or [None]:
            for p in DEFAULT_PORTS:
                if ip:
                    tcp_results.append((h, ip, p))
    open_ports:set[tuple[str,str,int]] = set()
    results = await bounded_gather([tcp_connect(ip, p) for (_, ip, p) in tcp_results], limit=500)
    for (h, ip, p), ok in zip(tcp_results, results):
        if ok:
            open_ports.add((h, ip, p))

    http_fp_tasks = []
    for (h, ip, p) in open_ports:
        if p in (80, 8080):
            http_fp_tasks.append(http_fingerprint(h, ip, "http"))
        elif p in (443, 8443):
            http_fp_tasks.append(http_fingerprint(h, ip, "https"))
    http_fps = await bounded_gather(http_fp_tasks, limit=100)

    fp_iter = iter(http_fps)
    fingerprints:dict[tuple[str,str,int], dict] = {}
    for (h, ip, p) in open_ports:
        if p in (80,8080,443,8443):
            fingerprints[(h,ip,p)] = next(fp_iter, {})

    tls_info = {}
    for (h, ip, p) in open_ports:
        if p in (443, 8443):
            try:
                tls_info[f"{h}|{ip}|{p}"] = get_tls_cert_info(h, p)
            except Exception:
                tls_info[f"{h}|{ip}|{p}"] = {}

    ssh_targets = [(h, ip, p) for (h, ip, p) in open_ports if p == 22]
    ssh_banners = await bounded_gather([get_ssh_banner(ip, 22) for (_, ip, _) in ssh_targets], limit=100)
    ssh_map = {}
    for (h, ip, p), banner in zip(ssh_targets, ssh_banners):
        ssh_map[f"{h}|{ip}|{p}"] = banner

    return {
        "host_ips": host_ips,
        "open_ports": list(open_ports),
        "fingerprints": {f"{h}|{ip}|{p}": fp for (h,ip,p), fp in fingerprints.items()},
        "tls": tls_info,
        "ssh": ssh_map
    }
