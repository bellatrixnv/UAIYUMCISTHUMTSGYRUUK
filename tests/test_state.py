from app.state import state_transition

def test_new():
    assert state_transition(None, "open") == "new"

def test_resolved():
    assert state_transition("open", None) == "resolved"

def test_regressed():
    assert state_transition("resolved", "open") == "regressed"

def test_unchanged():
    assert state_transition("open", "open") is None
