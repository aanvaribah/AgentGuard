"""
AG output records. Events written to agentguard-events.jsonl and the per-call
rows that the reporter keeps for display and incident grouping.
"""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal

Decision = Literal["suppressed", "reviewing", "cleared", "alert", "error"]


class Level(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class Event:
    kind: Literal["call", "integrity", "system"]
    time: str
    level: Level = Level.INFO
    session_id: str | None = None
    seq: int | None = None
    tool: str | None = None
    target: str | None = None
    decision: Decision | None = None
    source: str | None = None  # signature or analyst
    score: float | None = None
    label: str | None = None  # signature names or analyst category
    evidence: list[int] = field(default_factory=list)
    reasoning: str | None = None
    message: str | None = None
    traceback: str | None = None  # used for internal errors
    provenance: str | None = None
    provenance_sources: list[int] = field(default_factory=list)
    provenance_shared: list[str] = field(default_factory=list)
    impact: float | None = None
    impact_vector: str | None = None
    impact_basis: str | None = None
    caused_by: list[int] = field(default_factory=list)
    caused_by_reasons: list[str] = field(default_factory=list)


@dataclass
class Row:
    seq: int
    tool: str
    target: str
    score: float
    decision: Decision
    source: str | None = None
    label: str | None = None
    evidence: list[int] = field(default_factory=list)
    reasoning: str | None = None
    linked_by: set[int] = field(default_factory=set)
    provenance: str | None = None
    provenance_sources: list[int] = field(default_factory=list)
    impact: float | None = None
    impact_vector: str | None = None
    caused_by: list[int] = field(default_factory=list)
    first_seen: str = ""


@dataclass
class Snapshot:
    sessions: dict[str, dict[int, Row]]
    order: list[str]  # session ids, least recently active first
    integrity: list[Event]
    notices: list[Event]
