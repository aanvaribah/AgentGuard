"""
Token matching shared by provenance and history retrieval: how AgentGuard decides that
content returned by one call reappears in the arguments of a later call.

Shared tokens are weighted by how distinctive they are. An identifier-like token (one
containing a digit or any of - . _ / :, such as a package name, path, host or version)
counts as FLOW_MIN on its own, so a single dependency name carried from a fetched page
into package.json is enough. Plain words count 1 each, and common function words are
ignored, so prose that merely shares "this", "with" and "from" does not count.
"""

import re
from collections.abc import Iterable, Iterator
from typing import Any

TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_./:-]{3,}")
IDENTIFIER_RE = re.compile(r"[0-9_./:-]")
FLOW_MIN = 3  # weight at which content counts as having flowed

STOPWORDS = frozenset([
    "about", "above", "after", "again", "also", "although", "among", "another",
    "because", "been", "before", "being", "below", "between", "both", "cannot", "could",
    "does", "doing", "down", "during", "each", "either", "else", "even", "ever",
    "every", "from", "further", "have", "having", "here", "hers", "herself", "himself",
    "however", "into", "itself", "just", "least", "less", "many", "more", "most",
    "much", "must", "neither", "never", "none", "only", "other", "otherwise", "ours",
    "over", "same", "should", "since", "some", "such", "than", "that", "their",
    "theirs", "them", "themselves", "then", "there", "these", "they", "this", "those",
    "though", "through", "thus", "under", "until", "upon", "very", "were", "what",
    "when", "where", "whether", "which", "while", "whom", "whose", "will", "with",
    "within", "without", "would", "your", "yours", "yourself",
])


def strings(obj: Any) -> Iterator[str]:
    """Every string value in a nested arguments structure."""
    if isinstance(obj, dict):
        for v in obj.values():
            yield from strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from strings(v)
    elif obj is not None:
        yield str(obj)


def tokens(text: str) -> frozenset[str]:
    return frozenset(t for t in TOKEN_RE.findall(text.lower()) if t not in STOPWORDS)


def weight(shared: Iterable[str]) -> int:
    return sum(FLOW_MIN if IDENTIFIER_RE.search(t) else 1 for t in shared)


def flowed(shared: Iterable[str]) -> bool:
    return weight(shared) >= FLOW_MIN
