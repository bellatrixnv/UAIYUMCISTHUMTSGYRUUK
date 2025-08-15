from jinja2 import Template

TPL = Template("""
<!doctype html><html><head>
<meta charset="utf-8"><title>SMBSEC Scans</title>
<style>
 body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin:2rem; }
 table { border-collapse: collapse; width:100%; margin:1rem 0; }
 th,td { border:1px solid #ddd; padding:8px; font-size:14px; }
 th { background:#fafafa; text-align:left; }
 a { color:#0645ad; text-decoration:none; }
</style>
</head><body>
<h1>Scan Overview</h1>
<table>
<tr><th>ID</th><th>Domain</th><th>Status</th><th>Started</th><th>Finished</th><th>Report</th></tr>
{% for s in scans %}
<tr>
  <td>{{ s.id }}</td>
  <td>{{ s.domain }}</td>
  <td>{{ s.status }}</td>
  <td>{{ s.started_at }}</td>
  <td>{{ s.finished_at or '' }}</td>
  <td><a href="/report/{{ s.id }}">view</a></td>
</tr>
{% endfor %}
</table>
</body></html>
""")

def render_panel(scans:list[dict]) -> str:
    return TPL.render(scans=scans)
