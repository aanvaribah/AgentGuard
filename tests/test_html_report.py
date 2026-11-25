"""
HTML reports: an index and one page per session, built from an event log, ranked like
the live views, and safe to open whatever the log contains.
"""

import re

from agent_guard.core.records import LogLine
from agent_guard.lineage.causality import Links
from agent_guard.report.html import (
    load,
    render_index,
    render_session,
    session_file,
    write_reports,
)
from agent_guard.report.reporter import Reporter
from agent_guard.triage.impact import Impact

HOSTILE = '<script>alert(1)</script><img src=x onerror=alert(2)>"\x1b[2J'


def log(seq: int, tool="memory.memory_set", target="memory://n/k", session="s1") -> LogLine:
    server, name = tool.split(".")
    return LogLine.from_dict({
        "timestamp": "2026-11-24T12:00:00Z", "session_id": session, "server": server, "tool_name": name,
        "arguments": {}, "target_resource": target, "result_status": "success", "scenario_tag": "clean",
        "duration_ms": 1.0, "result_summary": "ok", "task_id": "t", "seq": seq, "annotations": [],
    })


def run_log(tmp_path):
    """A small run: a fetch that leads to an analyst alert, an unrelated signature alert,
    a cleared call, a tamper event and model digests."""
    path = tmp_path / "agentguard-events.jsonl"
    rep = Reporter()
    rep.configure(path, None)
    rep.info("analyst model qwen2.5:7b, digest 845dbda0ea48" + "0" * 52)
    rep.call(log(1, "fetch.fetch", "https://intranet.example/poisoned"), "suppressed", 0.05)
    rep.call(log(2), "reviewing", 0.3, caused_by=Links((1,), ("carries content returned by seq 1",)))
    rep.call(log(2), "alert", 0.3, source="analyst", label="ASI06", evidence=[1, 2], reasoning="copies source",
             impact=Impact("H", "H", "N", "C", "persists into memory that later sessions trust"))
    rep.call(log(3, "git.git_diff", HOSTILE), "alert", 1.0, source="signature", label="argument_injection",
             reasoning=f"pathspec {HOSTILE}", impact=Impact("N", "H", "L", "C", "git writes a file"))
    rep.call(log(4), "reviewing", 0.3)
    rep.call(log(4), "cleared", 0.3, source="analyst", reasoning="routine")
    rep.call(log(1, session="s2"), "suppressed", 0.05)
    rep.integrity(tmp_path / "corpus" / "s1.jsonl", "file shrank")
    rep.warning("Embeddings unavailable")
    return path


def test_session_page_ranks_its_incidents_and_explains_them(tmp_path):
    page = render_session(load(run_log(tmp_path)), "s1")
    first, second = page.index("ASI06 Memory &amp; Context Poisoning"), page.index("SIGNATURE argument_injection")
    assert first < second, "the 5.8 chain outranks the 4.7 alert"
    assert "Root cause: seq 1" in page and "carries content returned by seq 1" in page
    assert "persists into memory that later sessions trust" in page
    assert "qwen2.5:7b@845dbda0ea48" in page
    assert "1 tamper event(s)" in page and 'href="index.html"' in page


def test_session_pages_hold_only_their_own_calls(tmp_path):
    run = load(run_log(tmp_path))
    page = render_session(run, "s2")
    assert "No incidents." in page and "copies source" not in page and "Session s2" in page


def test_index_links_every_session_and_ranks_across_them(tmp_path):
    page = render_index(load(run_log(tmp_path)))
    for sid in ("s1", "s2"):
        assert f'href="{session_file(sid)}"' in page
    assert page.index("ASI06 Memory &amp; Context Poisoning") < page.index("SIGNATURE argument_injection")
    assert "file shrank" in page and "Embeddings unavailable" in page


def test_session_ids_cannot_escape_the_report_directory(tmp_path):
    names = {session_file(s) for s in ("../../etc/passwd", "index", "a/b", "a_b", "..", "<script>")}
    assert len(names) == 6
    for name in names:
        assert re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9._-]*-[0-9a-f]{8}\.html", name), name
    assert "index.html" not in names


def test_write_reports_replaces_the_directory(tmp_path):
    out = tmp_path / "reports"
    out.mkdir()
    (out / "stale-session-00000000.html").write_text("old", encoding="utf-8")
    run = write_reports(run_log(tmp_path), out)
    assert sorted(p.name for p in out.iterdir()) == sorted(["index.html", *(session_file(s) for s in run.snap.order)])


def test_log_content_cannot_inject_markup_or_scripts(tmp_path):
    run = load(run_log(tmp_path))
    page = render_index(run) + render_session(run, "s1")
    assert "<script" not in page.lower() and "<img" not in page.lower()
    assert "&lt;script&gt;" in page and "\x1b" not in page
    assert re.search(r"<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">", page)


def test_unreadable_lines_are_counted_not_fatal(tmp_path):
    path = run_log(tmp_path)
    with open(path, "a", encoding="utf-8") as f:
        f.write("not json\n{\"kind\": \"call\", \"level\": \"loud\", \"time\": \"x\"}\n")
    run = load(path)
    assert run.skipped == 2 and len(run.calls) == 5
    assert "2 lines of the event log could not be read" in render_index(run)


def test_empty_log(tmp_path):
    empty = tmp_path / "agentguard-events.jsonl"
    empty.write_text("", encoding="utf-8")
    write_reports(empty, tmp_path / "reports")
    page = (tmp_path / "reports" / "index.html").read_text(encoding="utf-8")
    assert "No sessions." in page and "No incidents." in page and "not recorded in this event log" in page
