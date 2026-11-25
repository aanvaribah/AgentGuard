"""
Text helpers to help format things for the agent.
"""

from agent_guard.core.events import Event, Row
from agent_guard.core.taxonomy import CATEGORIES
from agent_guard.triage.incidents import Incident


def clean(s: object) -> str:
    """Log fields are attacker-influenced: no control characters (terminal escapes) reach the screen."""
    return "".join(ch if ch.isprintable() else "\ufffd" for ch in " ".join(str(s).split()))


def clip(s: object, n: int) -> str:
    s = clean(s)
    return s if len(s) <= n else s[: n - 1] + "…"


def short(session_id: str, width: int = 14) -> str:
    return session_id if len(session_id) <= width else "…" + session_id[-(width - 1):]


def category_label(category: str | None) -> str:
    return f"{category} {CATEGORIES[category]}" if category in CATEGORIES else "uncategorized"


def provenance_text(kind: str, sources: list[int], shared: list[str]) -> str:
    seqs = ",".join(map(str, sources))
    if kind == "derived":
        return f"derived from seq {seqs} ({clip(', '.join(shared), 60)})"
    return f"after untrusted content (seq {seqs})"


def verdict_label(r: "Row | Event") -> str:
    if r.decision == "error":
        return "analyst failed"
    if r.source == "signature":
        return f"SIGNATURE {r.label}"
    return category_label(r.label)


def members_text(inc: Incident, arrow: str) -> str:
    rest = [s for s in inc.members if s != inc.root]
    return f"seq {inc.root}" + (f" {arrow} {', '.join(map(str, rest))}" if rest else "")


def impact_text(score: float | None, vector: str | None) -> str:
    return f"impact {score:.1f} {vector}" if score is not None else "impact n/a"
