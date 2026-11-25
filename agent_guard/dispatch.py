"""
This is where the magic happens. Signature-based results
get dispatched to agents, which then further evaluate based on
other evidence. Scoring itself lives in scoring.py.
"""

from agent_guard.models import AgentView, LogLine
from agent_guard.paths import Resolver
from agent_guard.provenance import ProvenanceTracker
from agent_guard.ranking import signature_impact
from agent_guard.registry import registry
from agent_guard.reporting import reporter
from agent_guard.scoring import assess

# Records arrive here in seq order per session (resume() replays files before the
# observer starts, then watchdog delivers appends on one thread), as the tracker needs.
provenance = ProvenanceTracker()


def dispatch_finding(resolver: Resolver, log: LogLine) -> None:
    """Scores a log, reports the decision, and passes it to the registry."""
    a = assess(resolver, log)
    prov = provenance.observe(log)
    view = AgentView.from_log_line(log, a.resolved)

    if a.decision == "alert":
        reporter.call(log, "alert", a.score, source="signature",
                      label=", ".join(a.confidences.signatures()) or "combined score",
                      evidence=[log.seq], reasoning="; ".join(a.details) or None, provenance=prov,
                      impact=signature_impact(log, a))
    elif a.decision == "review":
        reporter.call(log, "reviewing", a.score, provenance=prov)
    else:
        reporter.call(log, "suppressed", a.score, provenance=prov)

    registry.submit(log, view, a.confidences, a.decision)
