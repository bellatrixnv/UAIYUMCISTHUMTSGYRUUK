# SMBSEC Attack Surface Scanner

Minimal cloud-native attack surface scanner with asynchronous FastAPI backend, SQLite storage, and HTML reporting.

## Features
- Subdomain discovery via crt.sh
- DNS resolution and TCP port scanning
- HTTP fingerprinting (status, server header, title)
- TLS inspection and SSH banner grabbing
- Basic compliance score (risky ports, HTTP without HTTPS, TLS issues, TLS 1.3 bonus)
- AWS connector (assume-role) checking for public S3 buckets and AdministratorAccess users/groups

## Usage
```bash
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Trigger a scan:
```bash
curl -s -X POST http://127.0.0.1:8000/scan -H 'content-type: application/json' -d '{"domain":"example.com"}'
```

View scans and reports:
```bash
xdg-open http://127.0.0.1:8000/ 2>/dev/null || open http://127.0.0.1:8000/
# open a specific report
xdg-open http://127.0.0.1:8000/report/1 2>/dev/null || open http://127.0.0.1:8000/report/1
```

Reports are HTML files saved under `reports/scan_<id>.html`. Use your browser's "Save as PDF" to export if needed.

Add AWS connector and run CSPM checks:
```bash
curl -s -X POST http://127.0.0.1:8000/connect/aws -H 'content-type: application/json' \
  -d '{"role_arn":"arn:aws:iam::123456789012:role/SMBSECReadOnly","external_id":"EXTERNAL"}'
curl -s -X POST http://127.0.0.1:8000/cspm/aws/run
```
