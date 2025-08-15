from app.state_transition import state_transition

def test_state_transition_basic():
    prev = {"a","b","c"}
    curr = {"b","c","d"}
    out = state_transition(prev, curr)
    assert out["new"] == {"d"}
    assert out["resolved"] == {"a"}
    assert out["regressed"] == set()
