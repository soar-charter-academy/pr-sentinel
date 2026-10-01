"""Model output is input, and it is validated like input.

Three of the four model-driven steps in Tier 3 (recon, role synthesis,
plausibility pruning, PR-aware selection) ask a model to *name* things, and
those names then travel. A role name becomes a persona name, which becomes a
line in a PR comment, a key in a config file, a label the explorer searches
the DOM for. A model that returns ``"../../etc/passwd"`` or
``"http://evil/x"`` or four thousand roles must not be able to turn any of
that into a path, a URL, a shell argument or an unbounded loop.

So every name crosses this module first. The rule is deliberately strict and
deliberately dumb: lowercase, ASCII, hyphen-separated, short, or rejected.
A name that does not survive is dropped, never repaired — a repaired name is
a name nobody asked for, attached to a claim somebody will read as ours.

Nothing here knows what a role or an archetype is. It knows what a safe
short identifier looks like, which is the only thing worth having one copy
of.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Sequence

#: Lowercase, starts with a letter, hyphen-separated. No dots, no slashes, no
#: colons, no spaces, no unicode. That excludes every path, every URL and
#: every shell metacharacter by construction rather than by blocklist.
NAME_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")

MAX_NAME_CHARS = 40
MAX_TEXT_CHARS = 400
MAX_LIST_ITEMS = 64

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

#: Matched *before* normalisation, so that a value which only looks like a
#: name after we have stripped its slashes is still refused. Normalising
#: `../../x` into `x` and then accepting it would be the bug.
_PATH_OR_URL = re.compile(
    r"""
    [a-zA-Z][a-zA-Z0-9+.-]*://   # scheme
  | ^\s*[a-zA-Z]:[\\/]           # windows drive
  | \.\.                         # traversal
  | [/\\]                        # any separator
  | ^\s*~                        # home
  | ^\s*-                        # could be read as a flag
  """,
    re.VERBOSE,
)


def looks_like_path_or_url(value: Any) -> bool:
    """True when a value must never be treated as a bare identifier."""
    return bool(_PATH_OR_URL.search(str(value or "")))


def clean_name(value: Any, *, max_chars: int = MAX_NAME_CHARS) -> str | None:
    """Normalise a model-supplied identifier, or return None.

    Returning None rather than raising is the whole point: a single bad name
    in a list of thirty costs that one entry, not the step. Callers filter.
    """
    if not isinstance(value, str):
        return None
    if looks_like_path_or_url(value):
        return None
    candidate = _CONTROL.sub("", value).strip().lower()
    candidate = re.sub(r"[\s_]+", "-", candidate)
    candidate = re.sub(r"[^a-z0-9-]", "", candidate)
    candidate = re.sub(r"-{2,}", "-", candidate).strip("-")
    if not candidate or len(candidate) > max_chars:
        return None
    return candidate if NAME_PATTERN.match(candidate) else None


def clean_text(value: Any, *, max_chars: int = MAX_TEXT_CHARS) -> str:
    """Flatten model prose for rendering into a comment.

    Control characters go, newlines collapse, length is capped. The text is
    still untrusted after this — it is prose written by a model about a repo
    an attacker may control — but it can no longer corrupt a Markdown table
    or carry an ANSI escape into somebody's terminal.
    """
    if not isinstance(value, str):
        return ""
    text = _CONTROL.sub(" ", value)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > max_chars:
        text = text[: max_chars - 1].rstrip() + "…"
    return text


def cap(items: Any, limit: int = MAX_LIST_ITEMS) -> list[Any]:
    """Coerce a model's "list" to a bounded list.

    A model asked for roles can answer with a dict, a string, or ten thousand
    entries. All three are survivable; none of them is allowed to reach a
    loop.
    """
    if items is None:
        return []
    if isinstance(items, (str, bytes, dict)):
        return []
    if not isinstance(items, Sequence) and not isinstance(items, (list, tuple, set)):
        return []
    return list(items)[: max(0, limit)]


def clean_names(
    values: Any,
    *,
    allowed: Iterable[str] | None = None,
    limit: int = MAX_LIST_ITEMS,
) -> list[str]:
    """Clean a list of names, deduplicate, and optionally confine to a set.

    `allowed` is how a step says "you may only choose from what I gave you".
    Pruning and PR-aware selection both work that way, because a model
    inventing a thirteenth archetype is a model whose answer cannot be run.
    """
    permitted = {str(a) for a in allowed} if allowed is not None else None
    out: list[str] = []
    seen: set[str] = set()
    for raw in cap(values, limit):
        name = clean_name(raw)
        if name is None or name in seen:
            continue
        if permitted is not None and name not in permitted:
            continue
        seen.add(name)
        out.append(name)
    return out
