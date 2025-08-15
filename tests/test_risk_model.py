from app.risk_model import RiskModel

mapping_file = 'app/mappings/controls.yaml'

rm = RiskModel(mapping_file)

def test_categorize_and_map_controls():
    finding = {"service": "rdp", "port": 3389}
    tags = rm.categorize(finding)
    assert "rdp_exposed" in tags
    controls = rm.map_controls({"type": "rdp_exposed"})
    assert {"framework": "ISO27001", "control": "A.13.1.1"} in controls
    assert {"framework": "CIS", "control": "9.1"} in controls

def test_score():
    finding = {"severity_weight": 5, "exposure": 2, "exploitability_hint": 1.5}
    asset = {"criticality": 3}
    score = rm.score(finding, asset)
    assert score == 5 * 2 * 3 * 1.5
