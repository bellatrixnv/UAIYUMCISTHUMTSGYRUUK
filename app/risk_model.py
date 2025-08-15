from __future__ import annotations
import json
from dataclasses import dataclass
from typing import Dict, List, Tuple, Any, Optional
from pathlib import Path

# Simple loader for mappings
def load_mappings() -> Dict[str, Any]:
    # Prefer JSON for speed; fall back to YAML if present
    json_path = Path(__file__).resolve().parent.parent / "rules" / "findings_map.json"
    if json_path.exists():
        return json.loads(json_path.read_text(encoding="utf-8"))
    try:
        import yaml  # optional
        yml_path = Path(__file__).resolve().parent.parent / "rules" / "findings_map.yaml"
        return yaml.safe_load(yml_path.read_text(encoding="utf-8"))
    except Exception:
        return {"mappings": {}}

MAPPINGS = load_mappings().get("mappings", {})

# ---- Domain types -----------------------------------------------------------

@dataclass
class AssetContext:
    criticality: int = 3           # 1..5
    data_class: str = "P1"         # P0..P3
    internet_exposed: bool = True  # external ASM implies True unless proven internal
    owner_email: Optional[str] = None

# Expected normalized finding fields (align to your DB rows):
# finding = {
#   "type": "tcp"|"http"|"tls"|"ssh"|"aws"|..., 
#   "host": "foo.example.com",
#   "ip": "1.2.3.4" | None,
#   "port": 443 | None,
#   "severity": "info/low/medium/high/critical" (optional - pre-scan),
#   "title": "...",
#   "description": "...",
#   "evidence_json": {...}  # dict
# }

class RiskModel:
    @staticmethod
    def categorize(finding: Dict[str, Any]) -> str:
        """Return canonical finding_type for mapping/controls."""
        t = finding.get("type", "")
        port = finding.get("port")
        title = (finding.get("title") or "").lower()

        # Open TCP ports -> specific classes
        if t == "tcp" and port:
            if port == 3389:
                return "open_port_rdp"
            if port in (3306,):
                return "open_port_db_mysql"
            if port in (5432,):
                return "open_port_db_postgres"
            # fallthrough: generic open port isn't mapped; keep scoring via severity

        # HTTP without TLS sibling
        if t == "http":
            if (
                "plain http exposed" in title
                or "http 200" in title
                or ("http " in title and " on port 80" in title)
            ):
                # We'll confirm HTTPS absence in score()
                return "http_no_tls"

        # TLS expired/expiring
        if t == "tls":
            ev = finding.get("evidence_json") or {}
            days = ev.get("days_to_expiry")
            if isinstance(days, int) and days < 0:
                return "tls_expired"

        # SSH banner
        if t == "ssh":
            return "ssh_banner_leak"

        # AWS cloud issues
        if t == "aws":
            title = (finding.get("title") or "").lower()
            if "public s3" in title or "public bucket" in title:
                return "s3_public_bucket"
            if "administratoraccess" in title:
                return "iam_user_admin_access"
            if "0.0.0.0/0" in finding.get("description",""):
                return "sg_all_open_0_0_0_0"

        return ""  # unmapped type

    @staticmethod
    def map_controls(finding_type: str) -> Dict[str, List[str]]:
        m = MAPPINGS.get(finding_type, {})
        return {
            "iso27001": m.get("iso27001", []),
            "cis_controls": m.get("cis_controls", [])
        }

    @staticmethod
    def _base_severity_weight(sev: str) -> float:
        return {"info": 0.1, "low": 1.0, "medium": 4.0, "high": 7.0, "critical": 10.0}.get(sev, 1.0)

    @staticmethod
    def _mapped_default_severity_weight(finding_type: str) -> float:
        default_sev = MAPPINGS.get(finding_type, {}).get("default_severity")
        if default_sev:
            return RiskModel._base_severity_weight(default_sev)
        return 0.0

    @staticmethod
    def score(
        finding: Dict[str, Any],
        asset_ctx: AssetContext,
        sibling_https_open: bool = True
    ) -> Tuple[float, Dict[str, Any]]:
        """
        Compute a quantitative score (higher=worse), return (score, details).
        Uses:
          - mapped default severity, or explicit finding severity
          - exposure: internet_exposed
          - asset criticality & data class
          - http_no_tls penalty if no HTTPS sibling exists
        """
        finding_type = RiskModel.categorize(finding)
        sev = (finding.get("severity") or "").lower()
        base = RiskModel._base_severity_weight(sev) if sev else 0.0
        mapped = RiskModel._mapped_default_severity_weight(finding_type)
        baseline = max(base, mapped)

        # Exposure multiplier
        exposure = 1.5 if asset_ctx.internet_exposed else 1.0

        # Criticality multiplier (1..5 -> 0.8..1.6)
        crit_mult = 0.6 + (asset_ctx.criticality * 0.2)

        # Data class multiplier
        data_mult = {"P0": 0.9, "P1": 1.0, "P2": 1.2, "P3": 1.4}.get(asset_ctx.data_class, 1.0)

        # Special condition: http_no_tls without HTTPS
        tls_penalty = 0.0
        if finding_type == "http_no_tls" and not sibling_https_open:
            tls_penalty = 2.0

        # Cap & shape
        raw_score = (baseline * exposure * crit_mult * data_mult) + tls_penalty
        score = min(10.0, round(raw_score, 2))

        details = {
            "finding_type": finding_type,
            "base_component": baseline,
            "exposure_mult": exposure,
            "criticality_mult": round(crit_mult, 2),
            "data_mult": data_mult,
            "tls_penalty": tls_penalty,
            "controls": RiskModel.map_controls(finding_type)
        }
        return score, details
