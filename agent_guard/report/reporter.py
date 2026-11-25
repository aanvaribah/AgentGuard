"""
We don't do GUIs here. TUI implementation, see report/plain.py
for the plain output.
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

from agent_guard.core.events import Decision, Event, Level, Row, Snapshot
from agent_guard.core.records import LogLine
from agent_guard.lineage.causality import NO_LINKS, Links
from agent_guard.lineage.provenance import ProvenanceFlag
from agent_guard.triage.impact import Impact


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


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

        # Provenance and causal links are decided once, by the pipeline, on a call's first
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
