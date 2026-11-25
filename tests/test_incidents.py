"""
Incident grouping and ranking: causal links join calls into incidents rooted at the
earliest call; chain impact, then alert count, then the earliest root decide the order.
"""

from agent_guard.core.events import Row, Snapshot
from agent_guard.triage.incidents import incidents, ranked


def row(seq, decision="suppressed", *, impact=None, caused_by=(), evidence=(), source=None):
    return Row(seq, "tool.x", f"target-{seq}", 0.3, decision, source=source, evidence=list(evidence), # type: ignore
               impact=impact, caused_by=list(caused_by), first_seen=f"2026-11-24T12:{seq:02d}:00")


def snapshot(**sessions) -> Snapshot:
    return Snapshot({sid: {r.seq: r for r in rows} for sid, rows in sessions.items()},
                    list(sessions), [], [])


def by_root(found):
    return {inc.root: inc for inc in found}


def test_reference_injection_chain_is_rooted_at_the_fetch():
    rows = [
        row(11),                                                          # fetch of the poisoned readme
        row(12, "alert", impact=4.7, source="signature"),                 # --output injection, no edges
        row(14, "alert", impact=5.8, caused_by=[11], source="analyst"),   # ASI06 exfiltration
        row(15, "cleared", caused_by=[11]),
        row(21, "alert", impact=4.0, source="signature"),
    ]
    found = by_root(incidents({r.seq: r for r in rows}))
    assert sorted(found) == [11, 12, 21]
    chain = found[11]
    assert (chain.members, chain.alerts, chain.top, chain.impact) == ([11, 14, 15], [14], 14, 5.8)
    assert [inc.root for _, inc in ranked(snapshot(s=rows))] == [11, 12, 21]


def test_cross_task_poisoning_is_one_incident():
    rows = [row(1), row(2, "reviewing", caused_by=[1]), row(3, caused_by=[2]),
            row(4, "alert", impact=6.0, caused_by=[3], source="analyst")]
    (inc,) = incidents({r.seq: r for r in rows})
    assert (inc.root, inc.members, inc.alerts) == (1, [1, 2, 3, 4], [4])


def test_chain_impact_is_the_worst_alert_and_ties_go_to_more_alerts():
    rows = [
        row(1), row(2, "alert", impact=3.6, caused_by=[1]), row(3, "alert", impact=4.0, caused_by=[1]),
        row(5, "alert", impact=4.0),
    ]
    found = ranked(snapshot(s=rows))
    assert [(inc.root, inc.impact, len(inc.alerts)) for _, inc in found] == [(1, 4.0, 2), (5, 4.0, 1)]


def test_ties_go_to_the_earliest_root_across_sessions():
    found = ranked(snapshot(late=[row(30, "alert", impact=4.0)], early=[row(10, "alert", impact=4.0)]))
    assert [(sid, inc.root) for sid, inc in found] == [("early", 10), ("late", 30)]


def test_analyst_evidence_cites_but_never_merges():
    rows = [row(12, "alert", impact=4.7, source="signature"),
            row(20, "alert", impact=3.6, evidence=[12, 20], source="analyst")]
    found = by_root(incidents({r.seq: r for r in rows}))
    assert sorted(found) == [12, 20]
    assert found[20].cites == [12]


def test_groups_without_alerts_are_not_incidents_and_failures_count_as_alerts():
    rows = [row(1), row(2, "reviewing", caused_by=[1]), row(5), row(6, "error", impact=1.4, caused_by=[5])]
    (inc,) = incidents({r.seq: r for r in rows})
    assert (inc.root, inc.alerts) == (5, [6])
