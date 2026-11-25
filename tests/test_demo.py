"""
Demo mode: the workspace is a valid AgentGuard setup, the feeder writes the script as
ADOP would, and the script exercises every signature.
"""

import json
from collections import defaultdict

from agent_guard import demo
from agent_guard.config import resolve
from agent_guard.core.records import LogLine
from agent_guard.detect.paths import Resolver
from agent_guard.detect.scoring import assess
from agent_guard.lineage.causality import CausalTracker
from agent_guard.lineage.provenance import ProvenanceTracker


def test_workspace_passes_config_validation(tmp_path):
    ws = demo.prepare(tmp_path)
    cfg = resolve(None, {"corpus": str(ws.corpus), "agent_root": str(ws.agent_root),
                         "server_cwd": str(ws.server_cwd), "mirror_root": str(ws.mirror),
                         "model": None, "plain": True})
    assert cfg.corpus == ws.corpus.resolve() and cfg.mirror_root == ws.mirror.resolve()


def test_feeder_writes_the_script_as_adop_logs(tmp_path):
    feeder = demo.Feeder(tmp_path, interval=0.001)
    feeder.run()
    assert feeder.written == len(demo.load_script())
    by_session = defaultdict(list)
    for path in sorted(tmp_path.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            log = LogLine.from_dict(json.loads(line))
            assert path.stem == log.session_id
            by_session[log.session_id].append(log.seq)
    assert sorted(by_session) == ["session-01", "session-02"]
    for seqs in by_session.values():
        assert seqs == list(range(1, len(seqs) + 1))


def test_feeder_stops_when_asked(tmp_path):
    feeder = demo.Feeder(tmp_path, interval=60.0)
    feeder.stop.set()
    feeder.run()
    assert feeder.written == 0 and not list(tmp_path.iterdir())


def test_script_exercises_every_signature(tmp_path):
    ws = demo.prepare(tmp_path)
    resolver = Resolver(ws.agent_root, ws.server_cwd)
    fired = defaultdict(set)
    for rec in demo.load_script():
        a = assess(resolver, LogLine.from_dict({**rec, "timestamp": "2026-11-25T12:00:00Z"}))
        for sig in a.confidences.signatures():
            fired[sig].add((rec["session_id"], rec["seq"]))
    assert fired["path_traversal"] == {("session-01", 21)}
    assert fired["argument_injection"] == {("session-01", 12), ("session-02", 6)}
    assert fired["fence_forgery"] == {("session-02", 5)}


def test_session_02_links_the_hook_back_to_the_poisoned_page(tmp_path):
    """fetch 1 -> memory_set 2 -> (next task) memory_get 3 -> hook 4, so an analyst alert
    on the hook is rooted at the poisoned page."""
    ws = demo.prepare(tmp_path)
    resolver, prov, causes = Resolver(ws.agent_root, ws.server_cwd), ProvenanceTracker(), CausalTracker()
    parents = {}
    for rec in demo.SESSION_02:
        log = LogLine.from_dict({**rec, "timestamp": "2026-11-25T12:00:00Z"})
        parents[log.seq] = causes.observe(log, resolver.resolve(log), prov.observe(log)).parents
    assert {s: p for s, p in parents.items() if p} == {2: (1,), 3: (2,), 4: (3,)}
