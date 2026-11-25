"""
What the analyst is shown: a log record without ground truth (scenario_tag,
annotations) or task_id, and the findings it may cite.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from agent_guard.core.records import LogLine, ResolvedPath, Status


@dataclass(frozen=True)
class AgentView:
    arguments: dict[str, Any]
    result_status: Status
    result_summary: str
    server: str
    tool_name: str
    target_resource: str
    resolved_paths: tuple[ResolvedPath, ...]
    seq: int
    timestamp: datetime
    duration_ms: float
    session_id: str

    @classmethod
    def from_log_line(cls, line: LogLine, resolved_paths: tuple[ResolvedPath, ...]) -> "AgentView":
        shared = {f: getattr(line, f) for f in cls.__dataclass_fields__ if f != "resolved_paths"}
        return cls(**shared, resolved_paths=tuple(resolved_paths))


@dataclass(frozen=True)
class Finding:
    seq: int
    source: str
    label: str
    detail: str
