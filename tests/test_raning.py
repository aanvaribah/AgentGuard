"""
Ranking: the CVSS v3.1 Impact subscore, the analyst category table, and alert order.
"""

import pytest
from datetime import datetime

from agent_guard.models import LogLine, Status
from agent_guard.ranking import Impact, analyst_impact, combine, rank_key


def _impact(vector: str) -> Impact:
    parts = dict(p.split(":") for p in vector.split("/"))
    return Impact(parts["C"], parts["I"], parts["A"], parts["S"], "test")


def _log(server: str, tool: str) -> LogLine:
    return LogLine({}, Status.SUCCESS, "", server, tool, "", 1, datetime.now(), 1.0, "s", "t", "clean", [])


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
    # (impact, provenance, source, seq) -> expected position
    alerts = {
        "low impact":                (4.0, None, "signature", 30),
        "highest impact":            (5.8, None, "analyst", 10),
        "tie, derived":              (4.7, "derived", "analyst", 20),
        "tie, signature":            (4.7, None, "signature", 21),
        "tie, analyst, newer":       (4.7, None, "analyst", 25),
        "tie, analyst, older":       (4.7, None, "analyst", 22),
        "unrated":                   (None, None, None, 40),
    }
    order = sorted(alerts, key=lambda k: rank_key(*alerts[k]))
    assert order == [
        "highest impact", "tie, derived", "tie, signature",
        "tie, analyst, newer", "tie, analyst, older", "low impact", "unrated",
    ]
