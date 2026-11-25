"""
Entry point: python -m agent_guard (or python main.py).
"""

import argparse
import logging
import sys
import time
from pathlib import Path

from watchdog.observers import Observer

from agent_guard.analyst.models import ModelInfo, inspect
from agent_guard.analyst.registry import registry
from agent_guard.config import EMBED_MODEL, ConfigError, resolve
from agent_guard.ingest.watcher import AGEventHandler
from agent_guard.report.live import LiveView
from agent_guard.report.plain import PlainView
from agent_guard.report.reporter import LibraryLogHandler, reporter

BANNER = r"""
    _                    _    ____                     _
   / \   __ _  ___ _ __ | |_ / ___|_   _  __ _ _ __ __| |
  / _ \ / _` |/ _ \ '_ \| __| |  _| | | |/ _` | '__/ _` |
 / ___ \ (_| |  __/ | | | |_| |_| | |_| | (_| | | | (_| |
/_/   \_\__, |\___|_| |_|\__|\____|\__,_|\__,_|_|  \__,_|
        |___/
"""


def print_banner(watch_path: Path, agent_root: Path, mirror_root: Path, config_file: Path | None,
                 models: list[ModelInfo]) -> None:
    print(BANNER)
    print(f"  config   : {config_file or '(none, command line only)'}")
    print(f"  watching : {watch_path}")
    print(f"  sandbox  : {agent_root}")
    print(f"  mirror   : {mirror_root}")
    print(f"  models   : {', '.join(f'{m.role} {m.label}' for m in models)}")
    print(f"  {'-' * 40}\n")


def report_models(models: list[ModelInfo]) -> None:
    for m in models:
        reporter.info(f"{m.role} model {m.name}, digest {m.digest or 'unknown'}")
    for m in models:
        if m.problem is None:
            continue
        if m.role == "analyst" and m.status in ("missing", "mismatch"):
            reporter.critical(m.problem)
        else:
            reporter.warning(m.problem)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="File watching and static analysis script.",
        epilog="Settings come from --config (default: configs/default.json); "
               "any flag given here overrides the config file.",
    )
    parser.add_argument("-c", "--config", type=str, default=None,
                        help="JSON config file (default: configs/default.json, if present).")
    parser.add_argument("-p", "--path", type=str, default=None,
                        help="Path to the directory you want to watch (typically adop-cyse/corpus/).")
    parser.add_argument("-a", "--agent-root", type=str, default=None,
                        help="Path to the agent root (typically adop-cyse/testbed-repo/).")
    parser.add_argument("-s", "--server-cwd", type=str, default=None,
                        help="Working directory of the MCP server process "
                        "(defaults to parent of agent-root).")
    parser.add_argument("-m", "--mirror-root", type=str, default=None,
                        help="Directory for log mirrors, AG logs, and the RAG DB (default: mirror/ in the AgentGuard directory).")
    parser.add_argument("--model", default=None, help="Ollama model for the analyst.")
    parser.add_argument("--plain", action=argparse.BooleanOptionalAction, default=None,
                        help="Disable the TUI (--no-plain forces it on, overriding the config).")
    args = parser.parse_args()

    try:
        cfg = resolve(args.config, {
            "corpus": args.path,
            "agent_root": args.agent_root,
            "server_cwd": args.server_cwd,
            "mirror_root": args.mirror_root,
            "model": args.model,
            "plain": args.plain,
        })
    except ConfigError as e:
        parser.error(str(e))

    models = inspect({"analyst": cfg.model, "embedding": EMBED_MODEL})
    plain = cfg.plain or not sys.stdout.isatty()
    labels = " · ".join(f"{m.role} {m.label}" for m in models)
    view = PlainView(reporter) if plain else LiveView(reporter, watch=str(cfg.corpus), mirror=str(cfg.mirror_root), models=labels)
    if plain:
        print_banner(cfg.corpus, cfg.agent_root, cfg.mirror_root, cfg.config_file, models)

    logging.basicConfig(level=logging.WARNING, handlers=[LibraryLogHandler()], force=True)

    event_handler = AGEventHandler(
        str(cfg.agent_root), str(cfg.corpus), str(cfg.mirror_root),
        str(cfg.server_cwd) if cfg.server_cwd else None,
    )
    report_models(models)
    registry.configure(cfg.mirror_root / "history.sqlite3", model=cfg.model)
    reporter.configure(cfg.mirror_root / "agentguard-events.jsonl", view)

    observer = Observer()
    observer.schedule(event_handler, str(cfg.corpus), recursive=True)

    with view:
        event_handler.resume()
        observer.start()
        try:
            while observer.is_alive():
                time.sleep(1)
            reporter.critical("File observer stopped. No longer guarding.")
        except KeyboardInterrupt:
            pass
        finally:
            observer.stop()

    observer.join()


if __name__ == "__main__":
    main()
