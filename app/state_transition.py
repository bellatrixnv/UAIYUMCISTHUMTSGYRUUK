from __future__ import annotations
from typing import Dict, Iterable, Set, Tuple

def state_transition(prev: Iterable[str], curr: Iterable[str]) -> Dict[str, Set[str]]:
    """
    Pure function that compares two sets of dedupe_keys (strings)
    and returns which findings are new / resolved / regressed.
    - new: in curr but not in prev
    - resolved: in prev but not in curr
    - regressed: appeared again after being absent (callers track a 'seen_before' set)
      -> Here we approximate by returning empty; callers can inject regressed by history.
    """
    prev_set, curr_set = set(prev), set(curr)
    return {
        "new": curr_set - prev_set,
        "resolved": prev_set - curr_set,
        "regressed": set()  # optional: fill from caller's long-term history
    }
