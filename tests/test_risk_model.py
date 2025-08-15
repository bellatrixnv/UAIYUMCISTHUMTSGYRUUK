from app.risk_model import RiskModel, AssetContext

def test_categorize_and_controls_rdp():
    f = {"type":"tcp","port":3389,"host":"rdp.example.com","title":"Internet-exposed service on 3389"}
    ctx = AssetContext(criticality=4, data_class="P2", internet_exposed=True)
    score, det = RiskModel.score(f, ctx)
    assert det["finding_type"] == "open_port_rdp"
    assert score > 6
    assert "iso27001" in det["controls"]

def test_http_no_tls_penalty():
    f = {"type":"http","port":80,"host":"www.example.com","title":"Plain HTTP exposed (No HTTPS available)"}
    ctx = AssetContext(criticality=3, data_class="P1", internet_exposed=True)
    score_no_https, _ = RiskModel.score(f, ctx, sibling_https_open=False)
    score_with_https, _ = RiskModel.score(f, ctx, sibling_https_open=True)
    assert score_no_https > score_with_https

def test_tls_expired_is_high():
    f = {"type":"tls","port":443,"host":"foo","title":"Expired TLS certificate",
         "evidence_json":{"days_to_expiry": -1}}
    ctx = AssetContext(criticality=3, data_class="P1", internet_exposed=True)
    score, det = RiskModel.score(f, ctx)
    assert det["finding_type"] == "tls_expired"
    assert score >= 7
