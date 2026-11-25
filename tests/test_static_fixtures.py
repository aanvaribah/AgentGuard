"""
Deterministic checks of AgentGuard's scoring against the static corpus in
tests/unit_tests/: tool priors, signatures, scores, the alert/review/suppress
decision, the provenance flag, causal links and the impact vector of every
signature alert. No Ollama, threads or file watching involved.

The corpus location comes from configs/unit_test.json, the same config used to run
AgentGuard itself over this corpus (python main.py -c configs/unit_test.json).
"""

import json
from pathlib import Path

import pytest

from agent_guard.causality import CausalTracker
from agent_guard.config import load_file
from agent_guard.models import LogLine
from agent_guard.paths import Resolver
from agent_guard.provenance import ProvenanceTracker
from agent_guard.ranking import signature_impact
from agent_guard.scoring import assess

ROOT = Path(__file__).resolve().parent.parent
CONFIG = load_file(ROOT / "configs" / "unit_test.json")
CORPUS: Path = CONFIG["corpus"]
AGENT_ROOT: Path = CONFIG["agent_root"]
SERVER_CWD: Path = CONFIG.get("server_cwd") or AGENT_ROOT.parent

SCHEMA_FIELDS = {
    "timestamp", "session_id", "server", "tool_name", "arguments", "target_resource", "result_status",
    "scenario_tag", "duration_ms", "result_summary", "task_id", "seq", "annotations",
}
FIXTURE_FILES = sorted(CORPUS.glob("*.jsonl"))
EXPECTED = json.loads((CORPUS / "expected_results.json").read_text(encoding="utf-8"))["records"]
RESOLVER = Resolver(AGENT_ROOT, SERVER_CWD)


def _records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


RECORDS = {(p.name, r["seq"]): r for p in FIXTURE_FILES for r in _records(p)}


def test_corpus_is_present():
    assert FIXTURE_FILES, f"no fixtures in {CORPUS}; run tests/make_fixtures.py"
    assert AGENT_ROOT.is_dir(), f"{AGENT_ROOT} must exist (commit tests/unit_tests/testbed-repo/.gitkeep)"


def test_every_record_has_exactly_one_expectation():
    expected_keys = [(e["file"], e["seq"]) for e in EXPECTED]
    assert len(expected_keys) == len(set(expected_keys)), "duplicate expectations"
    assert set(expected_keys) == set(RECORDS)


@pytest.mark.parametrize("path", FIXTURE_FILES, ids=lambda p: p.name)
def test_fixture_file_is_a_valid_single_session_log(path):
    records = _records(path)
    assert {r["session_id"] for r in records} == {records[0]["session_id"]}
    assert [r["seq"] for r in records] == list(range(1, len(records) + 1))
    for r in records:
        assert set(r) == SCHEMA_FIELDS, f"seq {r['seq']}: fields differ from the ADOP log schema"
        LogLine.from_dict(dict(r))  # must parse the way AgentGuard parses live records


@pytest.mark.parametrize("exp", EXPECTED, ids=lambda e: f"{e['file']}:{e['seq']}")
def test_expected_result(exp):
    log = LogLine.from_dict(dict(RECORDS[(exp["file"], exp["seq"])]))
    a = assess(RESOLVER, log)
    why = f"{exp['file']} seq {exp['seq']}: {exp['why']}"
    assert a.decision == exp["decision"], why
    assert sorted(a.confidences.signatures()) == exp["signatures"], why
    assert a.score == pytest.approx(exp["score"]), why
    if exp["detail_contains"]:
        assert exp["detail_contains"] in "; ".join(a.details), why
    if a.decision == "alert":
        assert signature_impact(log, a).vector == exp["impact"], why
    else:
        assert exp["impact"] is None, f"{why}: only alerts are rated"


@pytest.mark.parametrize("path", FIXTURE_FILES, ids=lambda p: p.name)
def test_provenance_and_causal_links(path):
    """Both depend on earlier records, so each file is replayed in seq order."""
    expected = {e["seq"]: e for e in EXPECTED if e["file"] == path.name}
    provenance, causes = ProvenanceTracker(), CausalTracker()
    for r in _records(path):
        log = LogLine.from_dict(dict(r))
        flag = provenance.observe(log)
        links = causes.observe(log, RESOLVER.resolve(log), flag)
        exp = expected[r["seq"]]
        why = f"{path.name} seq {r['seq']}: {exp['why']}"
        got = None if flag is None else {"kind": flag.kind.value, "sources": list(flag.sources)}
        assert got == exp["provenance"], why
        assert list(links.parents) == exp["caused_by"], why
