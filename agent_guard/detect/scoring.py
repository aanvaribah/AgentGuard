"""
Deterministic scoring: tool-risk priors and signatures combine into one score, and
the score decides where a call goes.

Everything here is a pure function of a log record and the sandbox layout, with no
I/O, threads or model calls, so it can be unit tested against static fixtures.
"""

from dataclasses import dataclass, fields
from typing import Literal

from agent_guard.core.records import LogLine, ResolvedPath
from agent_guard.detect.paths import Resolver
from agent_guard.detect.priors import tool_risk
from agent_guard.detect.signatures import argument_injection, path_escape

Route = Literal["alert", "review", "suppress"]

ALERT_THRESH = 0.8   # alert when the overall score is ABOVE this
REVIEW_THRESH = 0.1  # send to the analyst when the score is at least this


@dataclass(frozen=True)
class Confidences:
    tool_risk: float = 0.0
    path_traversal: float = 0.0
    argument_injection: float = 0.0

    @property
    def overall(self) -> float:
        product = 1.0
        for clsfield in fields(self):
            v = getattr(self, clsfield.name)
            if not (0.0 <= v <= 1.0):
                raise ValueError(f"{clsfield.name} must be in [0,1], got {v}")

            product *= (1 - float(getattr(self, clsfield.name)))

        return 1 - product

    def signatures(self) -> list[str]:
        """Names of the signature checks (required for the clanker)"""
        return [f.name for f in fields(self) if f.name != "tool_risk" and getattr(self, f.name) >= 0.5]


@dataclass(frozen=True)
class Assessment:
    decision: Route
    confidences: Confidences
    resolved: tuple[ResolvedPath, ...]
    details: tuple[str, ...]  # one explanation per signature that fired

    @property
    def score(self) -> float:
        return self.confidences.overall


def assess(resolver: Resolver, log: LogLine) -> Assessment:
    """Scores one record and decides where it goes."""
    resolved = resolver.resolve(log)
    escape, escape_detail = path_escape(resolved)
    injection, injection_detail = argument_injection(log)
    confidences = Confidences(
        tool_risk=tool_risk(log.server, log.tool_name),
        path_traversal=escape,
        argument_injection=injection,
    )
    score = confidences.overall
    if score > ALERT_THRESH:
        decision: Route = "alert"
    elif score >= REVIEW_THRESH:
        decision = "review"
    else:
        decision = "suppress"
    details = tuple(d for d in (escape_detail, injection_detail) if d)
    return Assessment(decision, confidences, resolved, details)
