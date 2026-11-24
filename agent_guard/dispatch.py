"""
This is where the magic happens. Signature-based results 
get dispatched to agents, which then further evaluate based on
other evidence.
"""

from typing import Any

from agent_guard.models import (
    LOW_RISK,
    LOW_RISK_TOOLS,
    TOOL_RISK,
    UNKNOWN_TOOL_RISK,
    AgentView,
    Confidences,
    LogLine,
    ResolvedPath,
)
from agent_guard.paths import Resolver
from agent_guard.registry import registry
from agent_guard.reporting import reporter

OPTION_POSITIONS: dict[tuple[str, str], tuple[tuple[str, str, str], ...]] = {
    ("git", "git_diff"): (("ref", "whole", "HEAD"), ("pathspec", "split", ".")),
    ("git", "git_init"): (("target_path", "whole", ""),),
}

ABBREVIATES = {"git_init"}

KNOWN_OPTIONS: dict[str, dict[str, str]] = {
    "git_diff": {
        "--output": "writes the diff to a file of the agent's choosing",
        "--no-index": "compares arbitrary files, including ones outside the repository",
        "--ext-diff": "runs an external diff program",
        "--textconv": "runs configured text-conversion programs",
    },
    "git_init": {
        "--template": "copies hooks from a directory of the agent's choosing; hooks run on later git commands",
        "--separate-git-dir": "puts the repository data at a path of the agent's choosing",
    },
}

ALERT_THRESH = 0.8
REVIEW_THRESH = 0.1


def dispatch_finding(resolver: Resolver, log: LogLine) -> None:
    """Scores a log and passes it to the registry."""
    resolved = resolver.resolve(log)
    escape, escape_detail = path_escape(resolved)
    injection, inj_details = argument_injection(log)
    details = [d for d in (escape_detail, inj_details) if d]
    confidences = Confidences(
        tool_risk=tool_risk(log.server, log.tool_name),
        path_traversal=escape,
        argument_injection=injection,
    )
    view = AgentView.from_log_line(log, resolved)
    score = confidences.overall

    if score > ALERT_THRESH:
        decision = "alert"
        details = [d for d in (escape_detail, "--output flag smuggled into git_diff" if injection else None) if d]
        reporter.call(log, "alert", score, source="signature",
                      label=", ".join(confidences.signatures()) or "combined score",
                      evidence=[log.seq], reasoning="; ".join(details) or None)
    elif score >= REVIEW_THRESH:
        decision = "review"
        reporter.call(log, "reviewing", score)
    else:
        decision = "suppress"
        reporter.call(log, "suppressed", score)

    registry.submit(log, view, confidences, decision)


#
# RISK CALCULATION HELPERS
#


def _argv_entries(value: Any, how: str) -> list[str]:
    """The argv entries the server builds from an argument. A list (which the server
    would reject) is still checked element by element, since an attempt counts."""
    items = [str(v) for v in value] if isinstance(value, (list, tuple)) else [str(value)]
    if how == "split":
        return [tok for item in items for tok in item.split()]
    return items


def _describe_option(tool_name: str, token: str) -> str:
    name = token.split("=", 1)[0]
    for known, effect in KNOWN_OPTIONS.get(tool_name, {}).items():
        # git init accepts unambiguous abbreviations (--sep); git diff does not (--outp).
        if name == known or (tool_name in ABBREVIATES and len(name) >= 3 and known.startswith(name)):
            return f"is git option {known}, which {effect}"
    return f"is parsed by git as option {name}"


#
# RISK CALCULATIONS
#


def tool_risk(server: str, tool_name: str) -> float:
    if (server, tool_name) in TOOL_RISK:
        return TOOL_RISK[(server, tool_name)]
    if (server, tool_name) in LOW_RISK_TOOLS:
        return LOW_RISK
    return UNKNOWN_TOOL_RISK


def path_escape(resolved: tuple[ResolvedPath, ...]) -> tuple[float, str | None]:
    """Binary check for path traversal attempts."""
    for r in resolved:
        if r.resolved is None:
            return 1.0, f"{r.arg} {r.raw!r} is unresolvable"
        if not r.inside:
            return 1.0, f"{r.arg} {r.raw!r} resolves to {r.resolved!r}, outside the sandbox"
    return 0.0, None


def argument_injection(fline: LogLine) -> tuple[float, str | None]:
    """Signature for the argument-injection half of CVE-2025-68144, generalized: any
    agent-supplied argv entry that starts with "-" in a position git parses as an
    option (before a "--") is an injection attempt, whatever the option is."""
    positions = OPTION_POSITIONS.get((fline.server, fline.tool_name))
    if not positions:
        return 0.0, None

    for arg, how, default in positions:
        for tok in _argv_entries(fline.arguments.get(arg, default), how):
            if tok == "--":
                return 0.0, None  # git stops parsing options here; everything after is a path
            if tok.startswith("-"):
                return 1.0, f"{arg} {tok!r} {_describe_option(fline.tool_name, tok)}"
    return 0.0, None
