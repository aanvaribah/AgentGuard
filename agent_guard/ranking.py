"""
Alert ranking by impact: the CVSS v3.1 Impact subscore of what each alerting call did,
or attempted (an attempt counts the same as a success).

The Confidentiality, Integrity and Availability ratings and the Scope come from fixed
tables, never from the LLM: signature alerts are rated by what the call reached
(outside the sandbox, or an injected git option), analyst alerts by the tool's action
class raised by the category's default rating. Scope is Changed when the action
reaches beyond the authority of the tool that was called: outside the sandbox, code
that runs later, or memory that later sessions trust.

This is the CVSS Impact subscore applied to an observed action, not a full CVSS rating:
exploitability is not scored, since the call already happened. Scores are compared
unrounded and shown to one decimal, as NVD shows Impact subscores.

Ties are broken by provenance (content derived from an untrusted source first), then
signature before analyst, then the most recent call.
"""

from dataclasses import dataclass

from agent_guard.models import LOW_RISK_TOOLS, LogLine
from agent_guard.scoring import Assessment, injected_option

WEIGHT = {"N": 0.0, "L": 0.22, "H": 0.56}   # CVSS v3.1 C/I/A weights
ORDER = "NLH"


@dataclass(frozen=True)
class Impact:
    c: str
    i: str
    a: str
    scope: str   # "U" (unchanged) or "C" (changed)
    basis: str   # why this vector, in words

    @property
    def score(self) -> float:
        """CVSS v3.1 Impact subscore, unrounded."""
        iss = 1 - (1 - WEIGHT[self.c]) * (1 - WEIGHT[self.i]) * (1 - WEIGHT[self.a])
        if self.scope == "U":
            value = 6.42 * iss
        else:
            value = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        return max(0.0, value)

    @property
    def vector(self) -> str:
        return f"C:{self.c}/I:{self.i}/A:{self.a}/S:{self.scope}"

    def display(self) -> str:
        return f"{self.score:.1f} {self.vector}"


def combine(*impacts: Impact) -> Impact:
    """Component-wise maximum: a call that does several things is rated by the worst."""
    pick = lambda vals: max(vals, key=ORDER.index)
    return Impact(
        pick([x.c for x in impacts]), pick([x.i for x in impacts]), pick([x.a for x in impacts]),
        "C" if any(x.scope == "C" for x in impacts) else "U",
        "; ".join(dict.fromkeys(x.basis for x in impacts)),
    )


#
# Tables
#

def action_class(server: str, tool_name: str) -> str:
    if (server, tool_name) in LOW_RISK_TOOLS:
        return "read"
    if (server, tool_name) in {("git", "git_add"), ("git", "git_init")}:
        return "git-write"
    if (server, tool_name) == ("memory", "memory_set"):
        return "memory"
    if (server, tool_name) in {("filesystem", "write_file"), ("git", "git_commit")}:
        return "write"
    return "unknown"


# What a call of each class does inside the sandbox (analyst alerts start here).
BASE = {
    "read": Impact("L", "N", "N", "U", "reads inside the repository"),
    "write": Impact("N", "L", "N", "U", "changes the repository"),
    "git-write": Impact("N", "L", "N", "U", "changes git state"),
    "memory": Impact("N", "L", "N", "U", "writes to memory"),
    "unknown": Impact("H", "H", "H", "U", "unknown tool (rated as worst case)"),
}

# The same classes reaching outside the sandbox (path signature).
OUTSIDE = {
    "read": Impact("H", "N", "N", "C", "reads outside the sandbox"),
    "write": Impact("N", "H", "N", "C", "writes outside the sandbox"),
    "git-write": Impact("N", "L", "N", "C", "creates or stages git data outside the sandbox"),
    "memory": Impact("N", "L", "N", "C", "writes to memory outside the sandbox"),
    "unknown": Impact("H", "H", "H", "C", "unknown tool acting outside the sandbox"),
}

# Injected git options (argument-injection signature), by canonical option name.
OPTIONS = {
    "--output": Impact("N", "H", "L", "C", "git writes a file of the agent's choosing"),
    "--no-index": Impact("H", "N", "N", "C", "git reads files outside the repository"),
    "--ext-diff": Impact("H", "H", "H", "C", "git runs an external program"),
    "--textconv": Impact("H", "H", "H", "C", "git runs configured conversion programs"),
    "--template": Impact("H", "H", "H", "C", "planted hooks run on later git commands"),
    "--separate-git-dir": Impact("N", "L", "N", "C", "git data placed outside the repository"),
}
UNKNOWN_OPTION = Impact("L", "L", "N", "U", "git option with no known effect")

# Analyst categories: the least each category implies, raised onto the tool's base.
CATEGORY = {
    "ASI01": Impact("N", "H", "N", "U", "acts on a goal other than the operator's"),
    "ASI02": Impact("N", "H", "N", "U", "tool used outside its purpose"),
    "ASI03": Impact("H", "N", "N", "U", "reaches resources the work does not need"),
    "ASI04": Impact("H", "H", "H", "C", "unvetted third-party code enters the build"),
    "ASI05": Impact("H", "H", "H", "C", "content written where it will execute"),
    "ASI06": Impact("H", "H", "N", "C", "persists into memory that later sessions trust"),
    "ASI08": Impact("N", "H", "N", "U", "builds on a confirmed problem"),
    "ASI10": Impact("H", "H", "L", "U", "sustained action against the operator"),
}


def signature_impact(log: LogLine, a: Assessment) -> Impact:
    cls = action_class(log.server, log.tool_name)
    parts = []
    if a.confidences.path_traversal >= 0.5:
        parts.append(OUTSIDE[cls])
    if a.confidences.argument_injection >= 0.5:
        parts.append(OPTIONS.get(injected_option(log) or "", UNKNOWN_OPTION))
    return combine(*parts) if parts else BASE[cls]


def analyst_impact(log: LogLine, category: str | None) -> Impact:
    """For analyst alerts, and for calls the analyst failed to judge (category None)."""
    base = BASE[action_class(log.server, log.tool_name)]
    return combine(base, CATEGORY[category]) if category in CATEGORY else base


def rank_key(impact: float | None, provenance: str | None, source: str | None, seq: int) -> tuple:
    """Sort key, highest priority first."""
    prov = {"derived": 0, "context": 1}.get(provenance or "", 2)
    src = {"signature": 0, "analyst": 1}.get(source or "", 2)
    return (-(impact or 0.0), prov, src, -seq)
