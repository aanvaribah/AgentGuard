"""
Ranking: the CVSS v3.1 Impact subscore, the analyst category table, and alert order.
"""

from datetime import UTC, datetime

import pytest

from agent_guard.core.records import LogLine, Status
from agent_guard.triage.impact import Impact, analyst_impact, combine
from agent_guard.triage.incidents import rank_key


def _impact(vector: str) -> Impact:
    parts = dict(p.split(":") for p in vector.split("/"))
    return Impact(parts["C"], parts["I"], parts["A"], parts["S"], "test")


def _log(server: str, tool: str) -> LogLine:
    return LogLine({}, Status.SUCCESS, "", server, tool, "", 1, datetime.now(UTC), 1.0, "s", "t", "clean", [])


# Impact subscores as NVD publishes them (one decimal), for the same C/I/A and Scope.
@pytest.mark.parametrize("vector, nvd", [
    ("C:H/I:H/A:H/S:U", 5.9),
    ("C:H/I:H/A:H/S:C", 6.0),
    ("C:H/I:N/A:N/S:U", 3.6),
    ("C:H/I:N/A:N/S:C", 4.0),
    ("C:L/I:L/A:N/S:U", 2.5),
    ("C:N/I:N/A:N/S:U", 0.0),
    ("C:N/I:N/A:N/S:C", 0.0),
])
def test_cvss_impact_subscore(vector, nvd):
    assert f"{_impact(vector).score:.1f}" == f"{nvd:.1f}"


def test_combine_takes_the_worst_of_each_component():
    c = combine(_impact("C:H/I:N/A:N/S:U"), _impact("C:N/I:L/A:L/S:C"))
    assert c.vector == "C:H/I:L/A:L/S:C"


@pytest.mark.parametrize("tool, category, vector", [
    ("memory.memory_set", "ASI06", "C:H/I:H/A:N/S:C"),   # exfiltration into memory
    ("filesystem.write_file", "ASI04", "C:H/I:H/A:H/S:C"),  # unvetted dependency
    ("git.git_commit", "ASI01", "C:N/I:H/A:N/S:U"),
    ("filesystem.read_text_file", "ASI03", "C:H/I:N/A:N/S:U"),
    ("filesystem.write_file", "ASI05", "C:H/I:H/A:H/S:C"),  # e.g. a git hook
    ("filesystem.write_file", "NONE", "C:N/I:L/A:N/S:U"),   # alert without a category: tool base
    ("git.git_add", None, "C:N/I:L/A:N/S:U"),               # analyst failed: tool base
    ("shell.exec_command", None, "C:H/I:H/A:H/S:U"),        # unknown tool: worst case
])
def test_analyst_impact(tool, category, vector):
    server, name = tool.split(".")
    assert analyst_impact(_log(server, name), category).vector == vector


def test_rank_order():
    # (chain impact, number of alerts, root first seen, root seq)
    incidents = {
        "highest impact":            (5.8, 1, "2026-11-24T12:00:30", 30),
        "tie, more alerts":          (4.7, 3, "2026-11-24T12:00:40", 40),
        "tie, earliest root":        (4.7, 1, "2026-11-24T12:00:10", 10),
        "tie, later root":           (4.7, 1, "2026-11-24T12:00:20", 20),
        "lower impact, many alerts": (4.0, 9, "2026-11-24T12:00:01", 1),
        "unrated":                   (None, 1, "2026-11-24T12:00:00", 0),
    }
    order = sorted(incidents, key=lambda k: rank_key(*incidents[k]))
    assert order == [
        "highest impact", "tie, more alerts", "tie, earliest root", "tie, later root",
        "lower impact, many alerts", "unrated",
    ]
