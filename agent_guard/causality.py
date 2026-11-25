"""
Causal links between calls, used to group alerts into incidents rooted at their cause.

Two kinds of edge, both deterministic (the analyst's cited evidence is shown, but never
creates an edge, so the LLM cannot reshape the ranking):

  content   the call's arguments carry content returned by an untrusted source earlier
            in the same task (a DERIVED provenance flag; see provenance.py)
  reuse     the call touches a resource (file or memory key) that an earlier call in the
            same session wrote, in this task or an earlier one. This is how a poisoned
            memory note or a planted file in one task leads to an action in a later one.

A resource's writer is the last successful write_file or memory_set to it; a later write
to the same resource replaces the writer rather than linking to it.

Edges stay within a session. Memory persists across sessions in ADOP, so poisoning that
spans sessions is not linked here. Like the provenance tracker, the index lives in
memory, so links to calls made before an AgentGuard restart are not recovered.
"""

import re
from dataclasses import dataclass
from typing import Any

from agent_guard.models import LogLine, ResolvedPath, Status
from agent_guard.provenance import Provenance, ProvenanceFlag

# Targets that name a tool rather than a resource: the host's "server:tool" fallback,
# and descriptive targets like "testbed-repo (working tree)".
GENERIC_KEY_RE = re.compile(r"^[a-z_]+:[a-z_]+$|^.+ \(.+\)$")

WRITERS = frozenset({("filesystem", "write_file"), ("memory", "memory_set")})


def _norm(p: str) -> str:
    p = p.strip().replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.rstrip("/") or "."


def resource_keys(arguments: dict[str, Any], target_resource: str,
                  resolved_paths: tuple[ResolvedPath, ...]) -> set[str]:
    """Identifiers for what a call touched: resolved paths, URLs, memory keys. Paths are
    compared by where they land, so git_init "." (the project root, "..") and git_add "."
    (the repository, ".") are not the same resource."""
    if resolved_paths:
        keys = {r.resolved for r in resolved_paths if r.resolved is not None}
    else:
        keys = {_norm(target_resource)}
    if "url" in arguments:
        keys.add(_norm(str(arguments["url"])))
    if "namespace" in arguments and "key" in arguments:
        keys.add(f"memory://{arguments['namespace']}/{arguments['key']}")
    return {k for k in keys if k != "." and not GENERIC_KEY_RE.match(k)}


@dataclass(frozen=True)
class Links:
    parents: tuple[int, ...]   # seqs of the calls this one follows from
    reasons: tuple[str, ...]   # one explanation per parent, same order

    def __bool__(self) -> bool:
        return bool(self.parents)


NO_LINKS = Links((), ())


class CausalTracker:
    """Feed it every record of a session, in seq order."""

    def __init__(self) -> None:
        self._writers: dict[str, dict[str, int]] = {}  # session -> resource key -> writer seq

    def observe(self, log: LogLine, resolved: tuple[ResolvedPath, ...],
                provenance: ProvenanceFlag | None) -> Links:
        writers = self._writers.setdefault(log.session_id, {})
        keys = resource_keys(log.arguments, log.target_resource, resolved)
        writes = (log.server, log.tool_name) in WRITERS
        reasons: dict[int, str] = {}

        if provenance is not None and provenance.kind is Provenance.DERIVED:
            for s in provenance.sources:
                reasons[s] = f"carries content returned by seq {s}"
        if not writes:
            for key in sorted(keys):
                s = writers.get(key)
                if s is not None and s != log.seq:
                    reasons.setdefault(s, f"uses {key}, written by seq {s}")

        if writes and log.result_status == Status.SUCCESS:
            for key in keys:
                writers[key] = log.seq

        parents = tuple(sorted(reasons))
        return Links(parents, tuple(reasons[s] for s in parents))
