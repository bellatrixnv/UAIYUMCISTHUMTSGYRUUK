import socket, ssl, datetime, asyncio

def get_tls_cert_info(host: str, port: int = 443, timeout: float = 3.0) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    info = {}
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            cipher = ssock.cipher()
            proto = ssock.version()
            info["protocol"] = proto
            info["cipher"] = cipher[0] if cipher else ""
            info["issuer"] = " ".join(["=".join(t) for tup in cert.get("issuer", []) for t in tup])
            info["subject"] = " ".join(["=".join(t) for tup in cert.get("subject", []) for t in tup])
            not_after = cert.get("notAfter")
            if not_after:
                dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                info["not_after"] = dt.isoformat() + "Z"
                info["days_to_expiry"] = (dt - datetime.datetime.utcnow()).days
    return info

async def get_ssh_banner(ip: str, port: int = 22, timeout: float = 2.0) -> str:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        data = await asyncio.wait_for(reader.readline(), timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return data.decode(errors="ignore").strip()[:200]
    except Exception:
        return ""
