import os
import httpx

async def send_digest(scan_id:int, trans:dict[str,set[str]]):
    webhook = os.environ.get("SLACK_WEBHOOK")
    if not webhook:
        return
    parts = []
    if trans.get("new"):
        lines = "\n".join(sorted(trans["new"]))
        parts.append(f"*New findings:*\n{lines}")
    if trans.get("resolved"):
        lines = "\n".join(sorted(trans["resolved"]))
        parts.append(f"*Resolved findings:*\n{lines}")
    if trans.get("regressed"):
        lines = "\n".join(sorted(trans["regressed"]))
        parts.append(f"*Regressed findings:*\n{lines}")
    if not parts:
        return
    text = f"Scan {scan_id} findings summary:\n" + "\n\n".join(parts)
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            await c.post(webhook, json={"text": text})
    except Exception:
        pass
