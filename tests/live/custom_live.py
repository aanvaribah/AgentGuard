"""Live mode: the primary, student-facing way to run this testbed. Put
this in the root of adop-cyse/ and use it to run custom task JSON files.

This is infrastructure, not a graded assignment (see README.md) -- each
team runs it in their own local environment. It resets testbed-repo/ to
baseline, then drives the full fixed synthetic task set (all six tasks,
clean and poisoned) through a real, locally-run LLM (via Ollama) deciding
for itself which tools to call, against the four pinned MCP servers. Every
call is captured by the Observability and Audit Layer exactly as in the
reference corpus, split into corpus/live-session-<id>/clean.jsonl and
.../poisoned.jsonl.

Requires Ollama running locally with a tool-calling-capable model pulled.
See README.md "Requirements".

Run with: python -m adop_testbed.scripts.live_mode [--model MODEL_NAME]
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import uuid
import json

from pathlib import Path

from adop_testbed.audit.logger import AuditLogger, SessionSequencer
from adop_testbed.host.agent_host import TASKS_PATH
from adop_testbed.host.llm_agent_host import DEFAULT_MODEL, OllamaLiveAgentHost
from adop_testbed.sandbox import PROJECT_ROOT
from adop_testbed.scripts.reset_testbed import reset_testbed
from adop_testbed.types import SyntheticTask

def load_tasks(path: str) -> list[SyntheticTask]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return [SyntheticTask(**t) for t in raw]

async def run_live_session(tasks_path: str, model: str | None = None) -> None:
    reset_testbed()

    session_id = f"custom-live-{datetime.date.today().isoformat()}-{uuid.uuid4().hex[:6]}"
    session_dir = PROJECT_ROOT / "corpus" / f"{session_id}"
    sequencer = SessionSequencer()
    clean_logger = AuditLogger(session_dir / "clean.jsonl", session_id=session_id, sequencer=sequencer)
    poisoned_logger = AuditLogger(session_dir / "poisoned.jsonl", session_id=session_id, sequencer=sequencer)
    await clean_logger.init()
    await poisoned_logger.init()

    tasks = load_tasks(tasks_path)
    async with OllamaLiveAgentHost({"clean": clean_logger, "poisoned": poisoned_logger}, model=model) as host:
        print(f"Live session {session_id} -- model: {host.model}\n")
        for task in tasks:
            print(f"--- {task.id} ({task.scenario_tag}): {task.title} ---")
            print(f"--- {task.instruction} ---")
            summary = await host.run_task_live(task)
            print(summary.strip() or "(no summary text returned)")
            print()

    print(f"Wrote {clean_logger.out_file.relative_to(PROJECT_ROOT)} ({clean_logger.count} records)")
    print(f"Wrote {poisoned_logger.out_file.relative_to(PROJECT_ROOT)} ({poisoned_logger.count} records)")
    print(
        "\ntestbed-repo/ was left as the model modified it -- run "
        "`python -m adop_testbed.scripts.reset_testbed` before your next live session "
        "if you want a clean baseline again."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default=None, help=f"Ollama model to use (default: ${{ADOP_OLLAMA_MODEL}} or {DEFAULT_MODEL!r})")
    parser.add_argument("--tasks", default=None, required=True, help=f"Path to tasks")
    args = parser.parse_args()
    asyncio.run(run_live_session(args.tasks, model=args.model))


if __name__ == "__main__":
    main()

