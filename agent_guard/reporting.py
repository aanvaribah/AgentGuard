"""
I swear that this is the CLOSEST I will get to front-end development. Once
we're going for a super cool live-demo or something like that and back-end
is all ready to go, we can have Alex's agent handle some sort of live 
front-end or generated HTML report but I REFUSE SUCH FRIVOLITIES. I have
*standards*.

This whole file is mostly vibe-coded, so please keep that in mind when
casting the due judgement on the general state of things.
"""

import copy
import json
import logging
import threading
import traceback as tb
from collections import deque
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from agent_guard.agent.prompts import CATEGORIES
from agent_guard.causality import NO_LINKS, Links
from agent_guard.models import Decision, Event, Incident, Level, LogLine, Row, Snapshot
from agent_guard.provenance import ProvenanceFlag
from agent_guard.ranking import Impact, rank_key


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _clean(s: object) -> str:
    """Log fields are attacker-influenced: no control characters (terminal escapes) reach the screen."""
    return "".join(ch if ch.isprintable() else "\ufffd" for ch in " ".join(str(s).split()))


def _clip(s: object, n: int) -> str:
    s = _clean(s)
    return s if len(s) <= n else s[: n - 1] + "…"


def _short(session_id: str, width: int = 14) -> str:
    return session_id if len(session_id) <= width else "…" + session_id[-(width - 1):]


def category_label(category: str | None) -> str:
    return f"{category} {CATEGORIES[category]}" if category in CATEGORIES else "uncategorized"


def _provenance_text(kind: str, sources: list[int], shared: list[str]) -> str:
    seqs = ",".join(map(str, sources))
    if kind == "derived":
        return f"derived from seq {seqs} ({_clip(', '.join(shared), 60)})"
    return f"after untrusted content (seq {seqs})"


def verdict_label(r: "Row | Event") -> str:
    if r.decision == "error":
        return "analyst failed"
    if r.source == "signature":
        return f"SIGNATURE {r.label}"
    return category_label(r.label)


class Reporter:
    def __init__(self):
        self._lock = threading.Lock()
        self._path: Path | None = None
        self._view = None
        self._sessions: dict[str, dict[int, Row]] = {}
        self._activity: dict[str, int] = {}
        self._tick = 0
        self._integrity: list[Event] = []
        self._notices: deque[Event] = deque(maxlen=3)
        self._write_failed = False

    def configure(self, events_path: Path, view) -> None:
        self._path = events_path
        self._view = view

    #
    # Producers
    #

    def call(self, log: LogLine, decision: Decision, score: float, *, source: str | None = None,
             label: str | None = None, evidence=(), reasoning: str | None = None,
             provenance: ProvenanceFlag | None = None, impact: Impact | None = None,
             caused_by: Links = NO_LINKS) -> None:
        self._emit(Event(
            kind="call", time=_now(), level=Level.CRITICAL if decision in ("alert", "error") else Level.INFO,
            session_id=log.session_id, seq=log.seq, tool=f"{log.server}.{log.tool_name}",
            target=log.target_resource, decision=decision, source=source, score=round(score, 3),
            label=label, evidence=list(evidence), reasoning=reasoning,
            provenance=provenance.kind.value if provenance else None,
            provenance_sources=list(provenance.sources) if provenance else [],
            provenance_shared=list(provenance.shared) if provenance else [],
            impact=round(impact.score, 3) if impact else None,
            impact_vector=impact.vector if impact else None,
            impact_basis=impact.basis if impact else None,
            caused_by=list(caused_by.parents),
            caused_by_reasons=list(caused_by.reasons),
        ))

    def integrity(self, path, message: str) -> None:
        self._emit(Event(kind="integrity", time=_now(), level=Level.CRITICAL, target=str(path), message=message))

    def system(self, level: Level | str, message: str, traceback: str | None = None) -> None:
        self._emit(Event(kind="system", time=_now(), level=Level(level), message=message, traceback=traceback))

    #
    # State (Dijkstra was so right)
    #

    def _emit(self, e: Event) -> None:
        with self._lock:
            failure = self._write(e)
            for event in (e, failure) if failure else (e,):
                self._apply(event)
                if self._view:
                    self._view.on_event(event)

    def _write(self, e: Event) -> Event | None:
        """Appends to the event log. A failure is returned as a notice instead of raised,
        so the event is still displayed; it's reported once until writes recover."""
        if not self._path:
            return None
        try:
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(e), ensure_ascii=False) + "\n")
        except OSError as err:
            if self._write_failed:
                return None
            self._write_failed = True
            return Event(kind="system", time=_now(), level=Level.CRITICAL,
                         message=f"Event log write failed ({err}). Events are still "
                                 f"shown but not recorded to {self._path}.")
        self._write_failed = False
        return None

    def _apply(self, e: Event) -> None:
        if e.kind == "integrity":
            self._integrity.append(e)
            return
        if e.kind == "system":
            self._notices.append(e)
            return

        rows = self._sessions.setdefault(e.session_id, {}) # type: ignore
        self._tick += 1
        self._activity[e.session_id] = self._tick # type: ignore

        # Provenance and causal links are decided once, by dispatch, on a call's first
        # event; later verdict events for the same call don't repeat them, so they are
        # only set here.
        row = rows.get(e.seq) or rows.setdefault(  # type: ignore
            e.seq, Row(e.seq, e.tool, e.target, e.score, e.decision,  # type: ignore
                       provenance=e.provenance, provenance_sources=list(e.provenance_sources),
                       caused_by=list(e.caused_by), first_seen=e.time)
        )
        row.decision, row.score, row.source, row.label = e.decision, e.score, e.source, e.label # type: ignore
        row.evidence, row.reasoning = e.evidence, e.reasoning
        if e.impact is not None:
            row.impact, row.impact_vector = e.impact, e.impact_vector
        if e.decision == "alert":
            for s in e.evidence:
                if s != e.seq and s in rows:
                    rows[s].linked_by.add(e.seq) # type: ignore

    def snapshot(self) -> Snapshot:
        with self._lock:
            return Snapshot(
                copy.deepcopy(self._sessions),
                sorted(self._sessions, key=self._activity.__getitem__),
                list(self._integrity),
                list(self._notices),
            )

    #
    # Convenience methods
    #

    def critical(self, message: str) -> None:
        self.system(Level.CRITICAL, message)

    def warning(self, message: str) -> None:
        self.system(Level.WARNING, message)

    def info(self, message: str) -> None:
        self.system(Level.INFO, message)


reporter = Reporter()


class LibraryLogHandler(logging.Handler):
    """All reporting is done through the reporter."""

    def emit(self, record: logging.LogRecord) -> None:
        level = Level.CRITICAL if record.levelno >= logging.ERROR else Level.WARNING
        try:
            message = record.getMessage()
        except (TypeError, ValueError):
            self.handleError(record)
            return
        trace = "".join(tb.format_exception(*record.exc_info)) if record.exc_info else None
        reporter.system(level, f"[{record.name}] {message}", traceback=trace)


def ranked(snap: Snapshot) -> list[tuple[str, Incident]]:
    """Every incident across sessions, highest priority first (see ranking.rank_key)."""
    found = [(sid, inc) for sid in snap.order for inc in incidents(snap.sessions[sid])]
    return sorted(found, key=lambda item: rank_key(
        item[1].impact, len(item[1].alerts), item[1].first_seen, item[1].root))


def _members_text(inc: Incident, arrow: str) -> str:
    rest = [s for s in inc.members if s != inc.root]
    return f"seq {inc.root}" + (f" {arrow} {', '.join(map(str, rest))}" if rest else "")


def _impact_text(score: float | None, vector: str | None) -> str:
    return f"impact {score:.1f} {vector}" if score is not None else "impact n/a"


def incidents(rows: dict[int, Row]) -> list[Incident]:
    """Groups calls linked by causal edges (content flow and resource reuse; see
    causality.py) and keeps the groups that contain an alert. The analyst's cited
    evidence never joins groups; alerts it points to are listed as citations."""
    parent: dict[int, int] = {}

    def find(x: int) -> int:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for r in rows.values():
        find(r.seq)
        for p in r.caused_by:
            if p in rows:
                parent[find(r.seq)] = find(p)

    groups: dict[int, list[int]] = {}
    for s in rows:
        groups.setdefault(find(s), []).append(s)

    out = []
    for members in groups.values():
        members.sort()
        alerts = [s for s in members if rows[s].decision in ("alert", "error")]
        if not alerts:
            continue
        top = min(alerts, key=lambda s: (-(rows[s].impact or 0.0), s))
        inside = set(members)
        cites = sorted({e for s in alerts for e in rows[s].evidence
                        if e in rows and e not in inside and rows[e].decision in ("alert", "error")})
        root = members[0]
        out.append(Incident(root, members, alerts, top, rows[top].impact, rows[root].first_seen, cites))
    return out


#
# Views
#


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
            lines.append(f"{n:>3}. {_impact_text(top.impact, top.impact_vector):<30}  {_short(sid):<14}  "
                         f"{_members_text(inc, '->'):<20}  {verdict_label(top)}{count}")
            if inc.root != inc.top:
                lines.append(f"{'':<5}root cause: seq {root.seq} {root.tool} {_clip(root.target, 60)}")
        for e in snap.integrity:
            lines.append(f"     TAMPER  {_clean(e.target)}: {_clean(e.message)}")
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
            return f"{t}  {'INTEGRITY':<14}  {_clean(e.target)}: {_clean(e.message)}"
        if e.kind == "system":
            return f"{t}  {e.level.name.upper():<14}  {_clean(e.message)}"

        head = f"{t}  {_short(e.session_id):<14}  seq {e.seq:>4}  {_clip(e.tool, 26):<26}  {e.decision.upper():<10}" #type: ignore
        impact = _impact_text(e.impact, e.impact_vector)
        if e.decision == "alert" and e.source == "signature":
            tail = f"{verdict_label(e)}  {impact}  {_clip(e.reasoning or 'target ' + str(e.target), 100)}"
        elif e.decision == "alert":
            evidence = ",".join(map(str, e.evidence)) or "-"
            tail = f"{verdict_label(e)}  {impact}  evidence {evidence}  \"{_clip(e.reasoning or '', 160)}\""
        elif e.decision == "error":
            tail = f"treated as alert, {impact}: {_clip(e.reasoning or '', 160)}"
        elif e.decision == "cleared":
            tail = f"score {e.score:.2f}  \"{_clip(e.reasoning or '', 120)}\""
        else:
            tail = f"score {e.score:.2f}  target {_clip(e.target, 60)}"
        if e.provenance:
            tail += f"  provenance {_provenance_text(e.provenance, e.provenance_sources, e.provenance_shared)}"
        if e.caused_by:
            tail += f"  caused by seq {','.join(map(str, e.caused_by))}"
        return f"{head}  {tail}"


class LiveView:
    """Such a fancy TUI that you'd think I'm a Rust dev."""

    def __init__(self, source: Reporter, *, watch: str, mirror: str, model: str,
                 max_rows: int = 14, max_sessions: int = 2, max_incidents: int = 6,
                 console: Console | None = None):
        self.source = source
        self.watch, self.mirror, self.model = watch, mirror, model
        self.max_rows, self.max_sessions = max_rows, max_sessions
        self.max_incidents = max_incidents
        self._live = Live(
            console=console or Console(), get_renderable=self.render,
            refresh_per_second=4, redirect_stdout=True, redirect_stderr=True,
        )

    def __enter__(self):
        self._live.start()
        return self

    def __exit__(self, *exc):
        self._live.refresh()
        self._live.stop()
        return False

    def on_event(self, e: Event) -> None:
        pass  # Live re-renders from the reporter's state on its own schedule

    def render(self) -> Panel:
        snap = self.source.snapshot()
        found = ranked(snap)
        body = [self._alerts(snap, found)]
        for sid in reversed(snap.order[-self.max_sessions:]):
            body.append(self._session(sid, snap.sessions[sid])) # type: ignore
        return Panel(
            Group(*body),
            title=Text.assemble(("AgentGuard", "bold"), f" · watching {self.watch} · mirror {self.mirror} · analyst {self.model}"),
            title_align="left",
            subtitle=self._footer(snap, found),
            subtitle_align="left",
            box=box.ROUNDED,
        )

    def _alerts(self, snap: Snapshot, found: list[tuple[str, Incident]]) -> Panel:
        grid = Table.grid(expand=True)
        grid.add_column(ratio=1)

        for e in snap.integrity:
            grid.add_row(Text.assemble(
                (" TAMPER ", "bold white on red"), "  ",
                (f"{e.time[11:19]}  {_clean(e.target)}: {_clean(e.message)}", "red"),
            ))

        shown = found[:self.max_incidents]  # highest impact first

        for n, (sid, inc) in enumerate(shown, start=1):
            rows = snap.sessions[sid]
            r, root = rows[inc.top], rows[inc.root]
            impact = f"{r.impact:.1f}" if r.impact is not None else " n/a"
            line = Text.assemble(
                (f"{n:>2}. ", "bold"), (f"{impact:>4} ", "bold red"), (f"{r.impact_vector or '':<20} ", "red"),
                (f"{_short(sid)}  ", "dim"), (_members_text(inc, "→"), "bold"), "   ", (verdict_label(r), "red"),
            )
            if len(inc.alerts) > 1:
                line.append(f"   {len(inc.alerts)} alerts", style="red")
            if inc.cites:
                line.append(f"   cites {', '.join(map(str, inc.cites))}", style="dim red")
            grid.add_row(line)

            if inc.root != inc.top:
                grid.add_row(Text(f"    root cause: seq {root.seq} {root.tool} → {_clip(root.target, 60)}", style="dim"))
            detail = _clip(r.reasoning, 100) if r.reasoning else f"→ {_clip(r.target, 70)}"
            grid.add_row(Text(f"    seq {r.seq} {r.tool}: {detail}", style="dim"))

        if len(found) > len(shown):
            grid.add_row(Text(f"… {len(found) - len(shown)} lower-ranked incidents", style="dim"))

        alerting = bool(snap.integrity or found)
        return Panel(
            grid if alerting else Text("No alerts", style="green"),
            title="Incidents, ranked by chain impact (CVSS v3.1)", title_align="left", box=box.SQUARE,
            border_style="red" if alerting else "green",
        )

    def _session(self, sid: str, rows: dict[int, Row]) -> Table:
        t = Table(box=box.SIMPLE_HEAD, expand=True, pad_edge=False,
                  title=Text(sid, style="bold"), title_justify="left")
        t.add_column("seq", justify="right", no_wrap=True, width=7)
        t.add_column("tool", no_wrap=True, overflow="ellipsis", max_width=26)
        t.add_column("target", ratio=1, min_width=24, no_wrap=True, overflow="ellipsis")
        t.add_column("score", justify="right", no_wrap=True, width=5)
        t.add_column("verdict", no_wrap=True, overflow="ellipsis", max_width=32)
        t.add_column("provenance", no_wrap=True, overflow="ellipsis", max_width=14)

        lines = self._collapse(rows)
        hidden = max(0, len(lines) - self.max_rows)
        if hidden:
            t.add_row("", Text(f"… {hidden} earlier rows", style="dim"), "", "", "", "")
        for item in lines[hidden:]:
            if isinstance(item, tuple):
                first, last, n = item
                t.add_row(Text(f"{first}–{last}", style="dim"), Text(f"{n} suppressed", style="dim"),
                          "", "", Text("·", style="dim"), "")
                continue
            r = item
            style = "red" if r.decision in ("alert", "error") else ("dim" if r.decision == "suppressed" else "")
            t.add_row(str(r.seq), _clip(r.tool, 26), _clean(r.target), f"{r.score:.2f}", self._verdict(r),
                      self._provenance(r), style=style)
        return t

    @staticmethod
    def _collapse(rows: dict[int, Row]) -> list:
        """Runs of two or more plain suppressed calls collapse into one row."""
        out: list = []
        run: list[Row] = []

        def flush():
            if len(run) == 1:
                out.append(run[0])
            elif run:
                out.append((run[0].seq, run[-1].seq, len(run)))
            run.clear()

        for r in sorted(rows.values(), key=lambda r: r.seq):
            if r.decision == "suppressed" and not r.linked_by:
                run.append(r)
            else:
                flush()
                out.append(r)
        flush()
        return out

    @staticmethod
    def _provenance(r: Row) -> Text:
        if r.provenance == "derived":
            return Text(f"from {', '.join(map(str, r.provenance_sources))}", style="magenta")
        if r.provenance == "context":
            return Text("after untrusted", style="dim magenta")
        return Text("")

    @staticmethod
    def _verdict(r: Row) -> Text:
        if r.linked_by and r.decision not in ("alert", "error"):
            return Text(f"linked → {', '.join(map(str, sorted(r.linked_by)))}", style="red")
        return {
            "suppressed": Text("·", style="dim"),
            "reviewing": Text("reviewing…", style="yellow"),
            "cleared": Text("cleared", style="green"),
            "alert": Text(verdict_label(r), style="bold red"),
            "error": Text("analyst failed", style="bold magenta"),
        }[r.decision]

    def _footer(self, snap: Snapshot, found: list) -> Text:
        rows = [r for s in snap.sessions.values() for r in s.values()]
        n = lambda d: sum(r.decision == d for r in rows)
        footer = Text(
            f" {len(rows)} calls · {n('suppressed')} suppressed · {n('reviewing')} reviewing · "
            f"{len(found)} incidents · {len(snap.integrity)} tamper "
        )
        if snap.notices:
            note = snap.notices[-1]
            footer.append(f"· {note.level}: {_clip(note.message, 80)} ",
                          style="yellow" if note.level == "warning" else "bold red")
        return footer
