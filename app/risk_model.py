from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List
import yaml

class RiskModel:
    """Risk scoring and control mapping for findings."""
    def __init__(self, mapping_file: str | Path | None = None):
        if mapping_file is None:
            mapping_file = Path(__file__).resolve().parent / "mappings" / "controls.yaml"
        self.mapping_path = Path(mapping_file)
        with open(self.mapping_path, "r", encoding="utf-8") as f:
            self.control_map: Dict[str, Dict[str, List[str]]] = yaml.safe_load(f)

    def categorize(self, finding: Dict[str, Any]) -> List[str]:
        tags: List[str] = []
        service = str(finding.get("service", "")).lower()
        port = finding.get("port")
        if finding.get("tls_expired"):
            tags.append("tls_expired")
        if service in ("http", "https") and finding.get("scheme") == "http":
            tags.append("http_no_tls")
        if service == "rdp" or port == 3389:
            tags.append("rdp_exposed")
        db_ports = {5432, 3306, 1433, 27017}
        if service in ("postgres", "mysql", "mssql", "mongodb") or port in db_ports:
            tags.append("db_exposed")
        if service == "ssh" and finding.get("banner"):
            tags.append("ssh_banner_leak")
        return tags

    def map_controls(self, finding: Dict[str, Any]) -> List[Dict[str, str]]:
        mapped: List[Dict[str, str]] = []
        ftype = finding.get("type")
        if not ftype:
            for tag in self.categorize(finding):
                if tag in self.control_map:
                    ftype = tag
                    break
        if ftype and ftype in self.control_map:
            info = self.control_map[ftype]
            for iso in info.get("iso27001", []):
                mapped.append({"framework": "ISO27001", "control": iso})
            for cis in info.get("cis", []):
                mapped.append({"framework": "CIS", "control": cis})
        return mapped

    def score(self, finding: Dict[str, Any], asset_ctx: Dict[str, Any]) -> float:
        severity = float(finding.get("severity_weight", 1))
        exposure = float(finding.get("exposure", 1))
        criticality = float(asset_ctx.get("criticality", 1))
        exploitability = float(finding.get("exploitability_hint", 1))
        return severity * exposure * criticality * exploitability
