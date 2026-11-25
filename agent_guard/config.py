"""
Configuration! So we have a JSON file that gives settings rather than 8 million
billion trillion flags provided by the shell. If any flags are passed, they override
config file settings. CLI flags > config > built-in defaults.
"""

import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = REPO_ROOT / "configs" / "default.json"
DEFAULT_MODEL = "qwen2.5:7b"  # Ollama model for the analyst
EMBED_MODEL = "nomic-embed-text:v1.5"

PINNED = {
    "qwen2.5:7b": "845dbda0ea48",
    "nomic-embed-text:v1.5": "0a109f422b47",
}

# key -> (kind, built-in default). "path?" may be null; for mirror_root, null means
# "use a fresh temporary directory", which keeps repeated test runs independent.
SCHEMA: dict[str, tuple[str, Any]] = {
    "corpus": ("path", None),
    "agent_root": ("path", None),
    "server_cwd": ("path?", None),
    "mirror_root": ("path?", REPO_ROOT / "mirror"),
    "model": ("str", DEFAULT_MODEL),
    "plain": ("bool", False),
}
REQUIRED = ("corpus", "agent_root")
CLI_FLAGS = {
    "corpus": "-p/--path",
    "agent_root": "-a/--agent-root",
    "server_cwd": "-s/--server-cwd",
    "mirror_root": "-m/--mirror-root",
    "model": "--model",
    "plain": "--plain",
}


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Config:
    corpus: Path
    agent_root: Path
    server_cwd: Path | None
    mirror_root: Path
    model: str
    plain: bool
    config_file: Path | None
    temp_mirror: bool
    origins: dict[str, str] = field(
        default_factory=dict
    )  # key -> where its value came from


def _as_path(value: str, base: Path) -> Path:
    p = Path(value).expanduser()
    return p if p.is_absolute() else base / p


def load_file(path: Path) -> dict[str, Any]:
    """Reads and type-checks a config file, returns the keys it sets."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {path}") from None
    except json.JSONDecodeError as e:
        raise ConfigError(f"{path}: invalid JSON ({e})") from None
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: expected a JSON object at the top level")

    out: dict[str, Any] = {}
    for key, value in raw.items():
        if key.startswith("_"):
            continue
        if key not in SCHEMA:
            known = ", ".join(SCHEMA)
            raise ConfigError(f"{path}: unknown key {key!r} (known keys: {known})")
        kind, _ = SCHEMA[key]
        if value is None:
            if kind != "path?":
                raise ConfigError(f"{path}: {key!r} cannot be null")
            out[key] = None
        elif kind in ("path", "path?"):
            if not isinstance(value, str) or not value:
                raise ConfigError(f"{path}: {key!r} must be a non-empty string path")
            out[key] = _as_path(value, path.parent)
        elif kind == "str":
            if not isinstance(value, str) or not value:
                raise ConfigError(f"{path}: {key!r} must be a non-empty string")
            out[key] = value
        elif kind == "bool":
            if not isinstance(value, bool):
                raise ConfigError(f"{path}: {key!r} must be true or false")
            out[key] = value
    return out


def resolve(config_path: str | None, cli: dict[str, Any]) -> Config:
    """Merges defaults, the config file and command-line values, then validates.

    config_path: the --config value, or None to use configs/default.json if it exists.
    cli: command-line values by config key; None means "not given".
    """
    if config_path is not None:
        file_path: Path | None = Path(config_path).expanduser().resolve()
    elif DEFAULT_CONFIG.exists():
        file_path = DEFAULT_CONFIG
    else:
        file_path = None

    values = {k: default for k, (_, default) in SCHEMA.items()}
    origins = {k: "built-in default" for k in SCHEMA}

    if file_path is not None:
        for k, v in load_file(file_path).items():
            values[k], origins[k] = v, str(file_path)

    for k, v in cli.items():
        if v is None:
            continue
        values[k] = Path(v).expanduser() if SCHEMA[k][0] in ("path", "path?") else v
        origins[k] = f"command line ({CLI_FLAGS[k]})"

    missing = [k for k in REQUIRED if values[k] is None]
    if missing:
        where = f"in {file_path}" if file_path else "in a config file (--config)"
        raise ConfigError(
            "; ".join(
                f"{k} is not set: give {CLI_FLAGS[k]} or set {k!r} {where}"
                for k in missing
            )
        )

    temp_mirror = values["mirror_root"] is None
    if temp_mirror:
        values["mirror_root"] = Path(tempfile.mkdtemp(prefix="agentguard-mirror-"))
        origins["mirror_root"] = (
            f"{origins['mirror_root']} (null: fresh temporary directory)"
        )

    cfg = Config(
        corpus=values["corpus"].resolve(),
        agent_root=values["agent_root"].resolve(),
        server_cwd=values["server_cwd"].resolve() if values["server_cwd"] else None,
        mirror_root=values["mirror_root"].resolve(),
        model=values["model"],
        plain=values["plain"],
        config_file=file_path,
        temp_mirror=temp_mirror,
        origins=origins,
    )
    _validate(cfg)
    return cfg


def _validate(cfg: Config) -> None:
    for key in ("corpus", "agent_root"):
        p = getattr(cfg, key)
        if not p.is_dir():
            raise ConfigError(
                f"{key} {p} does not exist or is not a directory (from {cfg.origins[key]})"
            )
    if cfg.server_cwd is not None and not cfg.server_cwd.is_dir():
        raise ConfigError(
            f"server_cwd {cfg.server_cwd} does not exist or is not a directory "
            f"(from {cfg.origins['server_cwd']})"
        )
    for protected in (cfg.corpus, cfg.agent_root.parent):
        if cfg.mirror_root.is_relative_to(protected):
            raise ConfigError(
                f"mirror_root {cfg.mirror_root} must not be inside {protected}; "
                f"the testbed can write there (from {cfg.origins['mirror_root']})"
            )
