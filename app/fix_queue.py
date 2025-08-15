from __future__ import annotations
import os
import httpx

FIX_QUEUE: list[dict] = []

def add(finding_id:int, owner_email:str|None, severity:str, title:str, description:str) -> dict:
    entry = {
        "finding_id": finding_id,
        "owner_email": owner_email,
        "severity": severity,
        "title": title,
        "description": description,
    }
    FIX_QUEUE.append(entry)
    return entry

def open_jira_ticket(finding_id:int, title:str, description:str, owner_email:str|None):
    url = os.environ.get("JIRA_URL")
    user = os.environ.get("JIRA_USER")
    token = os.environ.get("JIRA_TOKEN")
    if not url or not user or not token:
        return None
    payload = {
        "fields": {
            "project": {"key": "SEC"},
            "summary": title,
            "description": description,
            "issuetype": {"name": "Task"},
        }
    }
    if owner_email:
        payload["fields"]["reporter"] = {"emailAddress": owner_email}
    resp = httpx.post(f"{url}/rest/api/2/issue", json=payload, auth=(user, token))
    resp.raise_for_status()
    data = resp.json()
    return data.get("key")
