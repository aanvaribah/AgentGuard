"""
This is where the magic happens. Signature-based results
get dispatched to agents, which then further evaluate based on
other evidence. Scoring itself lives in detect/scoring.py.
"""

from agent_guard.analyst.registry import registry
from agent_guard.analyst.view import AgentView
from agent_guard.core.records import LogLine
from agent_guard.detect.paths import Resolver
from agent_guard.detect.scoring import assess
from agent_guard.lineage.causality import CausalTracker
from agent_guard.lineage.provenance import ProvenanceTracker
from agent_guard.report.reporter import reporter
from agent_guard.triage.impact import signature_impact

# Records arrive here in seq order per session (resume() replays files before the
# observer starts, then watchdog delivers appends on one thread), as the tracker needs.
provenance = ProvenanceTracker()
causes = CausalTracker()


def dispatch_finding(resolver: Resolver, log: LogLine) -> None:
    """Scores a log, reports the decision, and passes it to the registry."""
    a = assess(resolver, log)
    prov = provenance.observe(log)
    links = causes.observe(log, a.resolved, prov)
    view = AgentView.from_log_line(log, a.resolved)

    if a.decision == "alert":
        reporter.call(log, "alert", a.score, source="signature",
                      label=", ".join(a.confidences.signatures()) or "combined score",
                      evidence=[log.seq], reasoning="; ".join(a.details) or None, provenance=prov,
                      impact=signature_impact(log, a), caused_by=links)
    elif a.decision == "review":
        reporter.call(log, "reviewing", a.score, provenance=prov, caused_by=links)
    else:
        reporter.call(log, "suppressed", a.score, provenance=prov, caused_by=links)

    registry.submit(log, view, a.confidences, a.decision)
