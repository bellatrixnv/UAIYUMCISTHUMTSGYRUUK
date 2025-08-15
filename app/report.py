from jinja2 import Template
from datetime import datetime

TPL = Template("""
<!doctype html><html><head>
<meta charset="utf-8">
<title>SMBSEC Report – Scan {{ scan_id }}</title>
<style>
 body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; }
 h1,h2 { margin: 0.2rem 0; }
 code { background:#f5f5f5; padding:2px 4px; }
 table { border-collapse: collapse; width:100%; margin:1rem 0;}
 th,td { border:1px solid #ddd; padding:8px; font-size: 14px; }
 th { background:#fafafa; text-align:left; }
 .sev-high { color:#b10000; font-weight:700; }
 .sev-medium { color:#a36a00; font-weight:700; }
 .sev-low { color:#1d6f42; font-weight:700; }
</style>
</head><body>
<h1>Security Scan Report</h1>
<p><strong>Scan ID:</strong> {{ scan_id }} &nbsp; | &nbsp; <strong>Domain:</strong> {{ domain }}
 &nbsp; | &nbsp; <strong>Finished:</strong> {{ finished }}</p>
<p><a href="/report/{{ scan_id }}/pdf">Download PDF</a></p>

{% if stats %}
<h2>Compliance Score</h2>
<p><strong>Score:</strong> {{ stats.score }}</p>
<meter min="0" max="120" value="{{ stats.score }}" style="width:300px"></meter>
<p><small>100 = baseline good score. Penalties reduce it; bonuses can raise above 100.</small></p>
{% if stats.penalties %}
<p>Penalties:</p>
<ul>{% for p in stats.penalties %}<li>{{ p }}</li>{% endfor %}</ul>
{% endif %}
{% if stats.bonuses %}
<p>Bonuses:</p>
<ul>{% for b in stats.bonuses %}<li>{{ b }}</li>{% endfor %}</ul>
{% endif %}
{% endif %}

<h2>Assets</h2>
<table><tr><th>Host</th><th>IP</th><th>Last Seen</th></tr>
{% for a in assets %}
<tr><td>{{ a.host }}</td><td>{{ a.ip or '' }}</td><td>{{ a.last_seen }}</td></tr>
{% endfor %}
</table>

<h2>Findings</h2>
<table><tr><th>Severity</th><th>Host</th><th>IP</th><th>Port</th><th>Title</th><th>Details</th></tr>
{% for f in findings %}
<tr>
  <td class="sev-{{ f.severity }}">{{ f.severity }}</td>
  <td>{{ f.host }}</td>
  <td>{{ f.ip or '' }}</td>
  <td>{{ f.port or '' }}</td>
  <td>{{ f.title }}</td>
  <td><code>{{ f.description }}</code></td>
</tr>
{% endfor %}
</table>

</body></html>
""")

def render_report(scan_id:int, domain:str, finished_ts:int, assets:list[dict], findings:list[dict], stats:dict|None)->str:
    fmt = datetime.utcfromtimestamp(finished_ts).strftime("%Y-%m-%d %H:%M:%S UTC")
    return TPL.render(scan_id=scan_id, domain=domain, finished=fmt, assets=assets, findings=findings, stats=stats or {})
