import json
import re
from app.report import render_report


def test_fix_queue_sorted():
    scores = [5, 1, 9, 3, 7, 8]
    findings = []
    for idx, sc in enumerate(scores):
        findings.append({
            "severity": "low",
            "host": f"h{idx}",
            "ip": None,
            "port": None,
            "title": f"t{idx}",
            "description": f"d{idx}",
            "risk_score": sc,
            "controls_json": json.dumps({"iso27001": [], "cis_controls": []})
        })
    html = render_report(1, "example.com", 0, [], findings, {})
    m = re.search(r"<h2>Fix Queue</h2>\s*<table.*?>(.*?)</table>", html, re.S)
    assert m, "Fix Queue section missing"
    section = m.group(1)
    rows = re.findall(
        r"<tr>\s*<td>.*?</td>\s*<td>.*?</td>\s*<td>.*?</td>\s*<td>(.*?)</td>\s*<td>.*?</td>\s*</tr>",
        section,
        re.S,
    )
    scores_rendered = [float(x) for x in rows]
    assert scores_rendered == sorted(scores, reverse=True)[:5]
