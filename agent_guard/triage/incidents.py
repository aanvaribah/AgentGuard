"""
Calls are joined by causal links that contain at least one alert. Root is the
earliest call in the chain.

Incidents are ranked by the highest impact of its alerts. Ties are broken by which
chain has more alerts first, then which chain has the earliest root.
"""

from dataclasses import dataclass

from agent_guard.core.events import Row, Snapshot


@dataclass(frozen=True)
class Incident:
    """Causally linked calls containing at least one alert, rooted at the earliest."""

    root: int
    members: list[int]
    alerts: list[int]
    top: int
    impact: float | None
    first_seen: str
    cites: list[int]


def rank_key(impact: float | None, alerts: int, first_seen: str, root: int) -> tuple:
    """Incident sort key, highest priority first: chain impact, then number of alerts,
    then the earliest root (by time, then seq)."""
    return (-(impact or 0.0), -alerts, first_seen, root)


def incidents(rows: dict[int, Row]) -> list[Incident]:
    """Groups calls linked by causal edges (content flow and resource reuse; see
    lineage/causality.py) and keeps the groups that contain an alert. The analyst's cited
    evidence never joins groups; alerts it points to are listed as citations."""
    parent: dict[int, int] = {}

    def find(x: int) -> int:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for r in rows.values():
        find(r.seq)
        for p in r.caused_by:
            if p in rows:
                parent[find(r.seq)] = find(p)

    groups: dict[int, list[int]] = {}
    for s in rows:
        groups.setdefault(find(s), []).append(s)

    out = []
    for members in groups.values():
        members.sort()
        alerts = [s for s in members if rows[s].decision in ("alert", "error")]
        if not alerts:
            continue
        top = min(alerts, key=lambda s: (-(rows[s].impact or 0.0), s))
        inside = set(members)
        cites = sorted(
            {
                e
                for s in alerts
                for e in rows[s].evidence
                if e in rows
                and e not in inside
                and rows[e].decision in ("alert", "error")
            }
        )
        root = members[0]
        out.append(
            Incident(
                root,
                members,
                alerts,
                top,
                rows[top].impact,
                rows[root].first_seen,
                cites,
            )
        )
    return out


def ranked(snap: Snapshot) -> list[tuple[str, Incident]]:
    """Every incident across sessions, highest priority first (see rank_key)."""
    found = [(sid, inc) for sid in snap.order for inc in incidents(snap.sessions[sid])]
    return sorted(
        found,
        key=lambda item: rank_key(
            item[1].impact, len(item[1].alerts), item[1].first_seen, item[1].root
        ),
    )
