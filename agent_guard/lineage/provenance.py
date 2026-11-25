"""
Provenance flags (as requested). Essentially, we just want to see if a mutating call
has content from an untrusted source earlier in the task. An untrusted source is any
call that returns content the agent didn't write (fetch, memory_get). Mutating calls
(anything outside the set of read-only tools) get:
    1. DERIVED: Arguments share distinctive content with the an untrusted source.
    2. CONTEXT: An untrusted source was read earlier, but no content in the arguments.
    3. None: No untrusted source earlier in the task (or the call is read-only)

Results are only the first 200 characters of each tool output (ADOP's constraint,
not ours).
"""

from dataclasses import dataclass, field
from enum import StrEnum

from agent_guard.core.records import LogLine, Status
from agent_guard.detect.priors import LOW_RISK_TOOLS
from agent_guard.lineage.tokens import flowed, strings, tokens

UNTRUSTED_SOURCES = frozenset({("fetch", "fetch"), ("memory", "memory_get")})
MAX_SOURCES = 20        # untrusted results remembered per task instance
MAX_SHARED_SHOWN = 5


class Provenance(StrEnum):
    DERIVED = "derived"
    CONTEXT = "context"


@dataclass(frozen=True)
class ProvenanceFlag:
    kind: Provenance
    sources: tuple[int, ...]   # seqs of the untrusted calls (DERIVED: the ones content came from)
    shared: tuple[str, ...]    # a few shared tokens, to explain a DERIVED flag

    def describe(self) -> str:
        seqs = ", ".join(map(str, self.sources))
        if self.kind is Provenance.DERIVED:
            return f"derived from seq {seqs} ({', '.join(self.shared)})"
        return f"after untrusted content (seq {seqs})"


@dataclass
class _Source:
    seq: int
    tokens: frozenset[str]


@dataclass
class _Task:
    task_id: str
    sources: list[_Source] = field(default_factory=list)


def is_mutating(log: LogLine) -> bool:
    key = (log.server, log.tool_name)
    return key not in LOW_RISK_TOOLS and key not in UNTRUSTED_SOURCES


class ProvenanceTracker:
    """Feed it every record of a session, in seq order. A new task instance starts
    whenever task_id changes, so nothing carries over between tasks. task_id is held
    in memory only, to detect that change; it is never reported."""

    def __init__(self) -> None:
        self._tasks: dict[str, _Task] = {}

    def observe(self, log: LogLine) -> ProvenanceFlag | None:
        task = self._tasks.get(log.session_id)
        if task is None or task.task_id != log.task_id:
            task = self._tasks[log.session_id] = _Task(log.task_id)

        flag = None
        if is_mutating(log) and task.sources:
            arg_tokens = tokens(" ".join(strings(log.arguments)))
            derived = [(s, s.tokens & arg_tokens) for s in task.sources]
            derived = [(s, shared) for s, shared in derived if flowed(shared)]
            if derived:
                shared = sorted(set().union(*(sh for _, sh in derived)))
                flag = ProvenanceFlag(Provenance.DERIVED, tuple(s.seq for s, _ in derived),
                                      tuple(shared[:MAX_SHARED_SHOWN]))
            else:
                flag = ProvenanceFlag(Provenance.CONTEXT, tuple(s.seq for s in task.sources), ())

        if (log.server, log.tool_name) in UNTRUSTED_SOURCES and log.result_status == Status.SUCCESS:
            task.sources.append(_Source(log.seq, tokens(log.result_summary)))
            del task.sources[:-MAX_SOURCES]

        return flag
