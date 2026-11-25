"""
The live TUI, rendered from the reporter's state on rich's own refresh schedule.
"""

from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from agent_guard.core.events import Event, Row, Snapshot
from agent_guard.report.reporter import Reporter
from agent_guard.report.text import clean, clip, members_text, short, verdict_label
from agent_guard.triage.incidents import Incident, ranked


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
                (f"{e.time[11:19]}  {clean(e.target)}: {clean(e.message)}", "red"),
            ))

        shown = found[:self.max_incidents]  # highest impact first

        for n, (sid, inc) in enumerate(shown, start=1):
            rows = snap.sessions[sid]
            r, root = rows[inc.top], rows[inc.root]
            impact = f"{r.impact:.1f}" if r.impact is not None else " n/a"
            line = Text.assemble(
                (f"{n:>2}. ", "bold"), (f"{impact:>4} ", "bold red"), (f"{r.impact_vector or '':<20} ", "red"),
                (f"{short(sid)}  ", "dim"), (members_text(inc, "→"), "bold"), "   ", (verdict_label(r), "red"),
            )
            if len(inc.alerts) > 1:
                line.append(f"   {len(inc.alerts)} alerts", style="red")
            if inc.cites:
                line.append(f"   cites {', '.join(map(str, inc.cites))}", style="dim red")
            grid.add_row(line)

            if inc.root != inc.top:
                grid.add_row(Text(f"    root cause: seq {root.seq} {root.tool} → {clip(root.target, 60)}", style="dim"))
            detail = clip(r.reasoning, 100) if r.reasoning else f"→ {clip(r.target, 70)}"
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
            t.add_row(str(r.seq), clip(r.tool, 26), clean(r.target), f"{r.score:.2f}", self._verdict(r),
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
            footer.append(f"· {note.level}: {clip(note.message, 80)} ",
                          style="yellow" if note.level == "warning" else "bold red")
        return footer
