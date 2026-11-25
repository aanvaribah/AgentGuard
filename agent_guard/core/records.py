"""
AG audit-log record and where path arguments land.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Status(Enum):
    ERROR   = "error"
    SUCCESS = "success"
    BLOCKED = "blocked"


@dataclass
class LogLine:
    arguments: dict[str, Any]
    result_status: Status
    result_summary: str
    server: str
    tool_name: str
    target_resource: str
    seq: int
    timestamp: datetime
    duration_ms: float
    task_id: str
    session_id: str
    scenario_tag: str
    annotations: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, line: dict) -> "LogLine":
        c = cls(**line)
        c.result_status = Status(line["result_status"])
        c.timestamp = datetime.fromisoformat(line["timestamp"])
        return c


@dataclass(frozen=True)
class ResolvedPath:
    """Where a given path argument truly lands."""
    arg: str
    raw: str
    resolved: str | None
    inside: bool
