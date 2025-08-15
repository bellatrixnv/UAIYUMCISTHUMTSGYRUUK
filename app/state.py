from typing import Optional

def state_transition(prev: Optional[str], curr: Optional[str]) -> Optional[str]:
    """Return state change given previous and current states.

    States are represented as "open" or "resolved". A missing state is ``None``.
    Returns "new", "resolved", "regressed" or ``None`` when there is no change.
    """
    if prev is None and curr == "open":
        return "new"
    if prev == "open" and curr is None:
        return "resolved"
    if prev == "resolved" and curr == "open":
        return "regressed"
    return None
