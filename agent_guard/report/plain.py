"""
Plain output.
"""

from agent_guard.core.events import Event, Snapshot
from agent_guard.report.reporter import Reporter
from agent_guard.report.text import (
    clean,
    clip,
    impact_text,
    members_text,
    provenance_text,
    short,
    verdict_label,
)
from agent_guard.triage.incidents import ranked


class PlainView:
    """One line per event and fixed columns, then the ranked incidents on exit."""
    def __init__(self, source: "Reporter | None" = None):
        self.source = source
        self._closed = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        if self.source is not None and not self._closed:
            try:
                print(self.summary(self.source.snapshot()), flush=True)
            except BrokenPipeError:
                pass
        return False

    @staticmethod
    def summary(snap: Snapshot) -> str:
        found = ranked(snap)
        lines = ["", f"Ranked incidents ({len(found)})"]
        for n, (sid, inc) in enumerate(found, start=1):
            rows = snap.sessions[sid]
            top, root = rows[inc.top], rows[inc.root]
            count = f" ({len(inc.alerts)} alerts)" if len(inc.alerts) > 1 else ""
            lines.append(f"{n:>3}. {impact_text(top.impact, top.impact_vector):<30}  {short(sid):<14}  "
                         f"{members_text(inc, '->'):<20}  {verdict_label(top)}{count}")
            if inc.root != inc.top:
                lines.append(f"{'':<5}root cause: seq {root.seq} {root.tool} {clip(root.target, 60)}")
        for e in snap.integrity:
            lines.append(f"     TAMPER  {clean(e.target)}: {clean(e.message)}")
        return "\n".join(lines)

    def on_event(self, e: Event) -> None:
        if self._closed:
            return
        try:
            print(self.format(e), flush=True)
        except BrokenPipeError:
            self._closed = True

    @staticmethod
    def format(e: Event) -> str:
        t = e.time[11:19]
        if e.kind == "integrity":
            return f"{t}  {'INTEGRITY':<14}  {clean(e.target)}: {clean(e.message)}"
        if e.kind == "system":
            return f"{t}  {e.level.name.upper():<14}  {clean(e.message)}"

        head = f"{t}  {short(e.session_id):<14}  seq {e.seq:>4}  {clip(e.tool, 26):<26}  {e.decision.upper():<10}" #type: ignore
        impact = impact_text(e.impact, e.impact_vector)
        if e.decision == "alert" and e.source == "signature":
            tail = f"{verdict_label(e)}  {impact}  {clip(e.reasoning or 'target ' + str(e.target), 100)}"
        elif e.decision == "alert":
            evidence = ",".join(map(str, e.evidence)) or "-"
            tail = f"{verdict_label(e)}  {impact}  evidence {evidence}  \"{clip(e.reasoning or '', 160)}\""
        elif e.decision == "error":
            tail = f"treated as alert, {impact}: {clip(e.reasoning or '', 160)}"
        elif e.decision == "cleared":
            tail = f"score {e.score:.2f}  \"{clip(e.reasoning or '', 120)}\""
        else:
            tail = f"score {e.score:.2f}  target {clip(e.target, 60)}"
        if e.provenance:
            tail += f"  provenance {provenance_text(e.provenance, e.provenance_sources, e.provenance_shared)}"
        if e.caused_by:
            tail += f"  caused by seq {','.join(map(str, e.caused_by))}"
        return f"{head}  {tail}"
