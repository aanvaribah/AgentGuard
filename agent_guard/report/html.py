"""
Static HTML reports, built from an event log (agentguard-events.jsonl): an index page for
the whole log and one page per session. AgentGuard rewrites them every time it exits;
they can also be built by hand:

    python -m agent_guard.report.html mirror/agentguard-events.jsonl -o mirror/reports

Pages are self-contained (no scripts, no external resources, a CSP that forbids both)
and print cleanly, so the browser's Print -> Save as PDF gives a PDF. Every value from
the log is attacker-influenced and is escaped; session ids only reach file names after
sanitizing.
"""

import argparse
import hashlib
import html
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, field, fields
from datetime import datetime
from pathlib import Path

from agent_guard.core.events import Event, Level, Row, Snapshot
from agent_guard.core.taxonomy import CATEGORIES
from agent_guard.detect.scoring import ALERT_THRESH, REVIEW_THRESH
from agent_guard.report.reporter import Reporter
from agent_guard.report.text import clean, provenance_text, verdict_label
from agent_guard.triage.incidents import Incident, ranked

MODEL_EVENT = re.compile(r"^(?P<role>\w+) model (?P<name>\S+), digest (?P<digest>\S+)$")
EVENT_FIELDS = {f.name for f in fields(Event)}


@dataclass
class Detail:
    """What the reporter's rows leave out: the explanations behind a call's links and impact."""
    caused_by_reasons: list[str] = field(default_factory=list)
    provenance_shared: list[str] = field(default_factory=list)
    impact_basis: str | None = None


@dataclass
class Run:
    path: Path
    snap: Snapshot
    details: dict[tuple[str, int], Detail]
    events: list[Event]
    notices: list[Event]
    skipped: int   # lines that weren't valid events

    def only(self, sid: str) -> "Run":
        """The same run, restricted to one session's calls. System and integrity events
        aren't tied to a session, so they stay."""
        snap = Snapshot({sid: self.snap.sessions[sid]}, [sid], self.snap.integrity, self.snap.notices)
        return Run(self.path, snap, {k: v for k, v in self.details.items() if k[0] == sid},
                   [e for e in self.events if e.session_id in (sid, None)], self.notices, self.skipped)

    @property
    def calls(self) -> list[tuple[str, Row]]:
        return [(sid, r) for sid in self.snap.order for r in sorted(self.snap.sessions[sid].values(), key=lambda r: r.seq)]


def load(path: Path) -> Run:
    """Replays an event log through a fresh reporter, so the report groups and ranks
    exactly as the live views did."""
    rep = Reporter()
    events, notices, details, skipped = [], [], {}, 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
            e = Event(**{k: v for k, v in raw.items() if k in EVENT_FIELDS})
            e.level = Level(e.level)
        except (json.JSONDecodeError, TypeError, ValueError):
            skipped += 1
            continue
        events.append(e)
        rep._apply(e)
        if e.kind == "system":
            notices.append(e)
        elif e.kind == "call" and e.session_id is not None and e.seq is not None:
            d = details.setdefault((e.session_id, e.seq), Detail())
            if not d.caused_by_reasons and e.caused_by_reasons:   # set on a call's first event only
                d.caused_by_reasons = list(e.caused_by_reasons)
            if not d.provenance_shared and e.provenance_shared:
                d.provenance_shared = list(e.provenance_shared)
            if e.impact_basis:
                d.impact_basis = e.impact_basis
    return Run(path, rep.snapshot(), details, events, notices, skipped)


#
# Rendering
#


def esc(value: object) -> str:
    return html.escape(clean(value), quote=True)


def _impact(r: Row) -> str:
    if r.impact is None:
        return '<span class="muted">n/a</span>'
    return f'<b>{r.impact:.1f}</b> <code>{esc(r.impact_vector)}</code>'


def _verdict(r: Row) -> str:
    cls = {"alert": "bad", "error": "bad", "cleared": "ok", "reviewing": "warn"}.get(r.decision, "muted")
    text = verdict_label(r) if r.decision in ("alert", "error") else r.decision
    return f'<span class="{cls}">{esc(text)}</span>'


def _call_rows(run: Run, sid: str, seqs: list[int], *, root: int | None = None) -> str:
    rows = run.snap.sessions[sid]
    out = []
    for s in seqs:
        r, d = rows[s], run.details.get((sid, s), Detail())
        links = "<br>".join(esc(x) for x in d.caused_by_reasons) or esc(", ".join(map(str, r.caused_by)))
        prov = esc(provenance_text(r.provenance, r.provenance_sources, d.provenance_shared)) if r.provenance else ""
        notes = []
        if r.reasoning:
            notes.append(esc(r.reasoning))
        if r.decision in ("alert", "error") and d.impact_basis:
            notes.append(f'<span class="muted">impact: {esc(d.impact_basis)}</span>')
        if r.evidence and r.source == "analyst":
            notes.append(f'<span class="muted">evidence: seq {esc(", ".join(map(str, r.evidence)))}</span>')
        mark = ' <span class="tag">root</span>' if s == root else ""
        out.append(
            f'<tr class="{r.decision}"><td class="num">{s}{mark}</td><td><code>{esc(r.tool)}</code></td>'
            f'<td class="target">{esc(r.target)}</td><td class="num">{r.score:.2f}</td><td>{_verdict(r)}</td>'
            f'<td>{_impact(r) if r.decision in ("alert", "error") else ""}</td>'
            f'<td>{prov}</td><td>{links}</td><td>{"<br>".join(notes)}</td></tr>'
        )
    return "\n".join(out)


CALL_COLS = ("<colgroup><col style=\"width:6%\"><col style=\"width:12%\"><col style=\"width:19%\">"
             "<col style=\"width:5%\"><col style=\"width:12%\"><col style=\"width:10%\"><col style=\"width:11%\">"
             "<col style=\"width:11%\"><col style=\"width:14%\"></colgroup>")
CALL_HEAD = ("<tr><th>seq</th><th>tool</th><th>target</th><th>score</th><th>verdict</th>"
             "<th>impact</th><th>provenance</th><th>caused by</th><th>notes</th></tr>")


def _incident(run: Run, n: int, sid: str, inc: Incident) -> str:
    rows = run.snap.sessions[sid]
    top, root = rows[inc.top], rows[inc.root]
    cites = f' · cites seq {esc(", ".join(map(str, inc.cites)))}' if inc.cites else ""
    impact = f"{inc.impact:.1f}" if inc.impact is not None else "n/a"
    root_line = (f'<p>Root cause: seq {root.seq} <code>{esc(root.tool)}</code> → {esc(root.target)}</p>'
                 if inc.root != inc.top else "")
    return f"""
<section class="incident">
  <h3><span class="rank">{n}</span> {esc(verdict_label(top))}
    <span class="score">{impact}</span> <code>{esc(top.impact_vector or "")}</code></h3>
  <p class="muted">{esc(sid)} · {len(inc.members)} calls · {len(inc.alerts)} alert{"s" if len(inc.alerts) != 1 else ""}
    · first seen {esc(inc.first_seen)}{cites}</p>
  {root_line}
  <table class="calls">{CALL_COLS}<thead>{CALL_HEAD}</thead><tbody>
  {_call_rows(run, sid, inc.members, root=inc.root)}
  </tbody></table>
</section>"""


def _summary(run: Run, found: list) -> str:
    calls = [r for _, r in run.calls]
    reviewed = {(e.session_id, e.seq) for e in run.events if e.kind == "call" and e.decision == "reviewing"}
    count = Counter(r.decision for r in calls)
    by_source = Counter(r.source for r in calls if r.decision == "alert")
    cards = [
        ("calls", len(calls)), ("suppressed", count["suppressed"]), ("sent to analyst", len(reviewed)),
        ("cleared", count["cleared"]), ("signature alerts", by_source["signature"]),
        ("analyst alerts", by_source["analyst"]), ("analyst failures", count["error"]),
        ("still reviewing", count["reviewing"]), ("incidents", len(found)), ("tamper events", len(run.snap.integrity)),
    ]
    bad = {"signature alerts", "analyst alerts", "analyst failures", "incidents", "tamper events"}
    return "".join(f'<div class="card{" hot" if k in bad and v else ""}"><b>{v}</b><span>{k}</span></div>'
                   for k, v in cards)


def _models(run: Run) -> str:
    seen = {}
    for e in run.notices:
        m = MODEL_EVENT.match(e.message or "")
        if m:
            seen[m["role"]] = (m["name"], m["digest"])
    if not seen:
        return '<span class="muted">not recorded in this event log</span>'
    return " · ".join(f'{esc(role)} <code>{esc(name)}@{esc(digest[:12])}</code>' for role, (name, digest) in seen.items())


def session_file(sid: str) -> str:
    """A safe, unique file name for a session's page. Session ids come from the log, so
    anything but letters, digits, '.', '_' and '-' is replaced, and a hash of the full id
    keeps distinct sessions (and the index) from colliding."""
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", sid).lstrip(".")[:80] or "session"
    return f"{stem}-{hashlib.sha256(sid.encode()).hexdigest()[:8]}.html"


def _span(run: Run) -> str:
    times = [e.time for e in run.events if e.time]
    return f"{esc(min(times))} to {esc(max(times))}" if times else "no events"


def _page(title: str, header: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<style>{CSS}</style>
</head>
<body>
<header>
  {header}
  <p class="muted">Generated {esc(datetime.now().astimezone().isoformat(timespec="seconds"))}</p>
</header>
{body}
</body>
</html>
"""


def _integrity(run: Run) -> str:
    rows = "".join(f'<tr><td>{esc(e.time)}</td><td>{esc(e.target)}</td><td>{esc(e.message)}</td></tr>'
                   for e in run.snap.integrity)
    if not rows:
        return '<p class="ok">No tampering detected.</p>'
    return f'<table><thead><tr><th>time</th><th>file</th><th>finding</th></tr></thead><tbody>{rows}</tbody></table>'


def _skipped(run: Run) -> str:
    if not run.skipped:
        return ""
    return (f'<p class="bad">{run.skipped} line{"s" if run.skipped != 1 else ""} of the event log '
            f'could not be read and were left out.</p>')


METHOD = f"""
<section class="method">
  <h2>Method</h2>
  <p>Each call is scored from a tool-risk prior and deterministic signatures (path traversal, argument
    injection, forged analyst data tags). Scores above {ALERT_THRESH} alert; scores from {REVIEW_THRESH}
    to {ALERT_THRESH} go to the LLM analyst; lower scores are suppressed. Impact is the CVSS v3.1 Impact
    subscore of what an alerting call did or attempted, from fixed tables; the analyst never sets it.
    A call the analyst failed to judge is treated as an alert. Incidents are calls linked by content
    flow or resource reuse that include at least one alert, rooted at the earliest call, and ranked by
    chain impact (the highest impact of any alert in the incident), then number of alerts, then
    earliest root.</p>
  <p>Analyst categories (OWASP Top 10 for Agentic Applications):</p>
  <ul>{"".join(f"<li><b>{k}</b> {html.escape(v)}</li>" for k, v in CATEGORIES.items())}</ul>
</section>"""


def render_session(run: Run, sid: str) -> str:
    """One session's page: its incidents in full, then every call."""
    sub = run.only(sid)
    found = ranked(sub.snap)
    incidents = "".join(_incident(sub, n, s, inc) for n, (s, inc) in enumerate(found, start=1)) \
        or '<p class="ok">No incidents.</p>'
    tamper = (f'<p class="bad">{len(run.snap.integrity)} tamper event(s) are in this event log; '
              f'see the <a href="index.html">index</a>. This session\'s log may not be what the agent did.</p>'
              if run.snap.integrity else "")
    header = f"""<p><a href="index.html">← All sessions</a></p>
  <h1>Session {esc(sid)}</h1>
  <p>Events {_span(sub)}</p>
  <p>Models: {_models(run)}</p>
  {tamper}{_skipped(run)}"""
    body = f"""
<section><div class="cards">{_summary(sub, found)}</div></section>
<section>
  <h2>Incidents</h2>
  {incidents}
</section>
<section>
  <h2>All calls</h2>
  <table class="calls">{CALL_COLS}<thead>{CALL_HEAD}</thead><tbody>
  {_call_rows(sub, sid, sorted(sub.snap.sessions[sid]))}
  </tbody></table>
</section>
{METHOD}"""
    return _page(f"AgentGuard: session {clean(sid)}", header, body)


def _ranking_row(run: Run, n: int, sid: str, inc: Incident) -> str:
    rows = run.snap.sessions[sid]
    top, root = rows[inc.top], rows[inc.root]
    impact = (f'<b>{inc.impact:.1f}</b> <code>{esc(top.impact_vector)}</code>' if inc.impact is not None
              else '<span class="muted">n/a</span>')
    return (f'<tr><td class="num">{n}</td><td>{impact}</td><td><a href="{esc(session_file(sid))}">{esc(sid)}</a></td>'
            f'<td>seq {inc.root} <code>{esc(root.tool)}</code></td><td>{esc(verdict_label(top))}</td>'
            f'<td class="num">{len(inc.alerts)}</td></tr>')


def _first_seen(run: Run, sid: str) -> str:
    return min((r.first_seen for r in run.snap.sessions[sid].values()), default="")


def render_index(run: Run) -> str:
    """The whole log: every session, the ranked incidents across sessions, integrity and
    warnings. Incident details live on the session pages."""
    found = ranked(run.snap)
    sessions = []
    for sid in sorted(run.snap.order, key=lambda s: _first_seen(run, s)):
        sub = run.only(sid)
        inc = ranked(sub.snap)
        rows = run.snap.sessions[sid].values()
        alerts = sum(r.decision in ("alert", "error") for r in rows)
        top = f"{inc[0][1].impact:.1f}" if inc and inc[0][1].impact is not None else ""
        sessions.append(
            f'<tr class="{"alert" if alerts else ""}"><td><a href="{esc(session_file(sid))}">{esc(sid)}</a></td>'
            f'<td>{_span(sub)}</td><td class="num">{len(rows)}</td><td class="num">{alerts}</td>'
            f'<td class="num">{len(inc)}</td><td class="num">{top}</td></tr>')
    ranking = "".join(_ranking_row(run, n, sid, inc) for n, (sid, inc) in enumerate(found, start=1))
    notices = "".join(
        f'<tr class="{e.level}"><td>{esc(e.time)}</td><td>{esc(e.level)}</td><td>{esc(e.message)}</td></tr>'
        for e in run.notices if e.level != Level.INFO)
    header = f"""<h1>AgentGuard report</h1>
  <p class="muted">From <code>{esc(run.path)}</code></p>
  <p>Events {_span(run)}</p>
  <p>Models: {_models(run)}</p>
  {_skipped(run)}"""
    body = f"""
<section><div class="cards">{_summary(run, found)}</div></section>
<section>
  <h2>Sessions</h2>
  {f'<table><thead><tr><th>session</th><th>events</th><th>calls</th><th>alerts</th><th>incidents</th><th>top impact</th></tr></thead><tbody>{"".join(sessions)}</tbody></table>'
   if sessions else '<p class="muted">No sessions.</p>'}
</section>
<section>
  <h2>Incidents, all sessions</h2>
  {f'<table><thead><tr><th>#</th><th>chain impact</th><th>session</th><th>root cause</th><th>top alert</th><th>alerts</th></tr></thead><tbody>{ranking}</tbody></table>'
   if ranking else '<p class="ok">No incidents.</p>'}
</section>
<section>
  <h2>Log integrity</h2>
  {_integrity(run)}
</section>
<section>
  <h2>Warnings and errors</h2>
  {f'<table><thead><tr><th>time</th><th>level</th><th>message</th></tr></thead><tbody>{notices}</tbody></table>'
   if notices else '<p class="ok">None.</p>'}
</section>
{METHOD}"""
    return _page("AgentGuard report", header, body)


CSS = """
:root { --fg: #1d2330; --muted: #667085; --line: #d9dee7; --bad: #b42318; --ok: #067647; --warn: #b54708;
        --bg-bad: #fef3f2; --bg-soft: #f7f8fa; }
* { box-sizing: border-box; }
body { font: 14px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; color: var(--fg); margin: 0 auto;
       max-width: 1200px; padding: 32px 24px; }
h1 { margin: 0 0 4px; font-size: 26px; }
h2 { margin: 32px 0 8px; font-size: 19px; border-bottom: 1px solid var(--line); padding-bottom: 4px; }
h3 { margin: 18px 0 6px; font-size: 15px; }
p { margin: 4px 0; }
code { font: 12px ui-monospace, SFMono-Regular, Menlo, monospace; }
.muted { color: var(--muted); }
.bad { color: var(--bad); font-weight: 600; }
.ok { color: var(--ok); }
.warn { color: var(--warn); }
.cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 8px; }
.card { border: 1px solid var(--line); border-radius: 6px; padding: 10px 12px; background: var(--bg-soft); }
.card b { display: block; font-size: 22px; }
.card span { color: var(--muted); font-size: 12px; }
.card.hot { border-color: var(--bad); background: var(--bg-bad); }
.card.hot b { color: var(--bad); }
.incident { border: 1px solid var(--line); border-left: 4px solid var(--bad); border-radius: 6px;
            padding: 10px 14px; margin: 12px 0; }
.rank { display: inline-block; min-width: 24px; text-align: center; background: var(--bad); color: #fff;
        border-radius: 4px; margin-right: 6px; }
.score { color: var(--bad); margin-left: 6px; }
.tag { font-size: 10px; background: var(--fg); color: #fff; border-radius: 3px; padding: 0 4px; }
table { width: 100%; border-collapse: collapse; margin: 6px 0; font-size: 12.5px; }
th, td { text-align: left; vertical-align: top; padding: 4px 6px; border-bottom: 1px solid var(--line); }
th { background: var(--bg-soft); font-weight: 600; }
td.num { text-align: right; white-space: nowrap; }
table.calls { table-layout: fixed; }
td { overflow-wrap: anywhere; }
tr.alert td, tr.error td, tr.critical td { background: var(--bg-bad); }
tr.suppressed td { color: var(--muted); }
.method { color: var(--muted); }
a { color: #1849a9; }
@media print { a { color: inherit; text-decoration: none; } }
@page { size: landscape; margin: 12mm; }
@media print {
  body { padding: 0; max-width: none; font-size: 11px; }
  .incident h3, .incident p { break-after: avoid; }
  h2 { break-after: avoid; }
  tr { break-inside: avoid; }
}
"""


def write_reports(events_path: Path, out_dir: Path) -> Run:
    """Rewrites the report directory from the event log: index.html plus one page per
    session. Pages left from earlier runs are removed first, so the directory always
    matches the log."""
    run = load(events_path)
    out_dir.mkdir(parents=True, exist_ok=True)
    for old in out_dir.glob("*.html"):
        old.unlink()
    for sid in run.snap.order:
        (out_dir / session_file(sid)).write_text(render_session(run, sid), encoding="utf-8")
    (out_dir / "index.html").write_text(render_index(run), encoding="utf-8")
    return run


def main() -> int:
    parser = argparse.ArgumentParser(description="Write HTML reports from an AgentGuard event log.")
    parser.add_argument("events", type=Path, help="agentguard-events.jsonl from a mirror directory")
    parser.add_argument("-o", "--output", type=Path, default=None,
                        help="Output directory (default: reports/ next to the event log)")
    args = parser.parse_args()
    out = args.output or args.events.with_name("reports")
    try:
        run = write_reports(args.events, out)
    except OSError as e:
        print(f"Can't write the reports: {e}", file=sys.stderr)
        return 1
    print(f"Wrote {out / 'index.html'} and {len(run.snap.order)} session page(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
