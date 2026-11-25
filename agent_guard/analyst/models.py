"""
Model pins! Ollama pulls by tag, but tags can move to different weights so we need to
track the digest of the model.

    python -m agent_guard.analyst.models           pull the pinned models and verify them
    python -m agent_guard.analyst.models --check   verify only
"""

import argparse
import sys
from dataclasses import dataclass
from typing import Any

import httpx
import ollama

from agent_guard.config import DEFAULT_MODEL, EMBED_MODEL, PINNED

UNREACHABLE = (ConnectionError, httpx.TransportError)


def _tagged(name: str) -> str:
    """Ollama lists an untagged model as name:latest."""
    return name if ":" in name.rsplit("/", 1)[-1] else f"{name}:latest"


def _bare(digest: str) -> str:
    return digest.removeprefix("sha256:")


@dataclass(frozen=True)
class ModelInfo:
    role: str                 # "analyst" or "embedding"
    name: str
    digest: str | None        # full digest of the installed model; None if missing or unknown
    pinned: str | None        # digest prefix AgentGuard was tested with; None if not pinned
    reachable: bool = True

    @property
    def status(self) -> str:
        if not self.reachable:
            return "unknown"
        if self.digest is None:
            return "missing"
        if self.pinned is None:
            return "unpinned"
        return "pinned" if self.digest.startswith(self.pinned) else "mismatch"

    @property
    def label(self) -> str:
        """Name and short digest, as `ollama list` shows them."""
        digest = self.digest[:12] if self.digest else "?"
        note = {"mismatch": " (not the pinned build)", "unpinned": " (unpinned)",
                "missing": " (not installed)", "unknown": " (Ollama unreachable)"}.get(self.status, "")
        return f"{self.name}@{digest}{note}"

    @property
    def problem(self) -> str | None:
        """What to tell the user, if anything is wrong."""
        return {
            "unknown": f"Ollama is unreachable, so the {self.role} model ({self.name}) can't be checked. "
                       f"Start Ollama (`ollama serve` or the Ollama app).",
            "missing": f"The {self.role} model {self.name} is not installed. "
                       f"Run `python -m agent_guard.analyst.models` or `ollama pull {self.name}`.",
            "mismatch": f"The {self.role} model {self.name} has digest {(self.digest or '')[:12]}, "
                        f"but AgentGuard was tested with {self.pinned}; results may differ.",
            "unpinned": f"The {self.role} model {self.name} is not pinned; "
                        f"its digest {(self.digest or '')[:12]} is recorded in the event log.",
        }.get(self.status)


def inspect(models: dict[str, str], client: Any = None) -> list[ModelInfo]:
    """ModelInfo for each role -> model name, from what Ollama has installed."""
    client = client or ollama.Client()
    try:
        installed = {_tagged(m.model): _bare(m.digest) for m in client.list().models if m.model and m.digest}
    except UNREACHABLE:
        return [ModelInfo(role, name, None, PINNED.get(_tagged(name)), reachable=False)
                for role, name in models.items()]
    return [ModelInfo(role, name, installed.get(_tagged(name)), PINNED.get(_tagged(name)))
            for role, name in models.items()]


def pull(name: str, client: Any) -> None:
    last = ""
    for p in client.pull(name, stream=True):
        if p.status != last:
            print(f"  {name}: {p.status}", flush=True)
            last = p.status


def main() -> int:
    parser = argparse.ArgumentParser(description="Pull AgentGuard's Ollama models and verify their digests.")
    parser.add_argument("--check", action="store_true", help="Only verify the installed models; don't pull.")
    args = parser.parse_args()

    models = {"analyst": DEFAULT_MODEL, "embedding": EMBED_MODEL}
    client = ollama.Client()
    if not args.check:
        try:
            for name in models.values():
                pull(name, client)
        except UNREACHABLE:
            print("Ollama is unreachable. Start it (`ollama serve` or the Ollama app) and try again.", file=sys.stderr)
            return 1

    failed = False
    for m in inspect(models, client):
        ok = m.status == "pinned"
        failed |= not ok
        print(f"{'ok ' if ok else 'BAD'}  {m.role:<9}  {m.label}")
        if m.problem:
            print(f"     {m.problem}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
