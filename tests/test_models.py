"""
Ensure we have the correct digests.
"""

from types import SimpleNamespace

import httpx

from agent_guard.analyst.models import inspect

# Full digests are 64 hex digits; only the 12-digit prefix is pinned.
QWEN = "845dbda0ea48" + "0" * 52
NOMIC = "0a109f422b47" + "0" * 52


class FakeClient:
    def __init__(self, installed=None, down=False):
        self.installed, self.down = installed or {}, down

    def list(self):
        if self.down:
            raise httpx.ConnectError("connection refused")
        return SimpleNamespace(models=[SimpleNamespace(model=k, digest=v) for k, v in self.installed.items()])


def one(name, client):
    (m,) = inspect({"analyst": name}, client)
    return m


def test_pinned_build_matches_by_prefix():
    m = one("qwen2.5:7b", FakeClient({"qwen2.5:7b": QWEN}))
    assert (m.status, m.label, m.problem) == ("pinned", "qwen2.5:7b@845dbda0ea48", None)


def test_sha256_prefix_is_ignored():
    assert one("qwen2.5:7b", FakeClient({"qwen2.5:7b": "sha256:" + QWEN})).status == "pinned"


def test_moved_tag_is_a_mismatch():
    m = one("qwen2.5:7b", FakeClient({"qwen2.5:7b": "deadbeef" * 8}))
    assert m.status == "mismatch"
    assert "845dbda0ea48" in (m.problem or "") and m.label.endswith("(not the pinned build)")


def test_untagged_names_match_latest():
    m = one("llama3", FakeClient({"llama3:latest": NOMIC}))
    assert (m.status, m.digest) == ("unpinned", NOMIC)


def test_missing_and_unreachable():
    assert one("qwen2.5:7b", FakeClient({"nomic-embed-text:v1.5": NOMIC})).status == "missing"
    m = one("qwen2.5:7b", FakeClient(down=True))
    assert (m.status, m.label) == ("unknown", "qwen2.5:7b@? (Ollama unreachable)")
