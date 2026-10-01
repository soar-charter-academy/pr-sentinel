"""The review context: everything a tier needs, assembled once.

The one non-obvious thing here is `UntrustedText`. PR titles, descriptions and
comments are attacker-controlled input to a system holding credentials
(DESIGN s10). Rather than rely on remembering that at each call site, the
hostile fields are wrapped in a type whose `__str__` is deliberately awkward,
so that interpolating one into a prompt by accident is hard and reading
`.render_as_data()` at the point of use is easy.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Any

from .config import Config
from .diff import ChangedFile, Diff, read_file_at


class UntrustedText:
    """Text that originated outside the repo's trust boundary.

    PR content is data, never instructions. This wrapper exists so that the
    only way to put it into a model prompt is to call `render_as_data()`,
    which fences it and labels it.
    """

    __slots__ = ("_value", "_label")

    def __init__(self, value: str | None, label: str = "untrusted") -> None:
        self._value = value or ""
        self._label = label

    @property
    def raw(self) -> str:
        """The underlying text. Safe for regex scanning and length checks;
        not safe to concatenate into an instruction context."""
        return self._value

    def __bool__(self) -> bool:
        return bool(self._value.strip())

    def __len__(self) -> int:
        return len(self._value)

    def __repr__(self) -> str:
        return f"UntrustedText({self._label}, {len(self._value)} chars)"

    def __str__(self) -> str:
        # Loud on purpose: if this shows up in output, a call site skipped
        # the fencing step.
        return f"<{self._label}: use .render_as_data() or .raw>"

    def render_as_data(self, max_chars: int = 4000) -> str:
        from .tier2.sanitize import fence_untrusted

        return fence_untrusted(self._value, label=self._label, max_chars=max_chars)


@dataclass
class PullRequest:
    number: int | None = None
    title: UntrustedText = field(default_factory=lambda: UntrustedText("", "pr-title"))
    body: UntrustedText = field(default_factory=lambda: UntrustedText("", "pr-body"))
    author: str | None = None
    is_draft: bool = False
    base_ref: str = "main"
    head_ref: str = "HEAD"
    head_sha: str | None = None
    base_sha: str | None = None
    labels: list[str] = field(default_factory=list)
    repo: str | None = None
    html_url: str | None = None

    @classmethod
    def from_github_event(cls, event: dict[str, Any]) -> PullRequest:
        pr = event.get("pull_request") or {}
        base = pr.get("base") or {}
        head = pr.get("head") or {}
        repo = (event.get("repository") or {}).get("full_name")
        return cls(
            number=pr.get("number"),
            title=UntrustedText(pr.get("title"), "pr-title"),
            body=UntrustedText(pr.get("body"), "pr-body"),
            author=((pr.get("user") or {}).get("login")),
            is_draft=bool(pr.get("draft")),
            base_ref=base.get("ref") or "main",
            head_ref=head.get("ref") or "HEAD",
            head_sha=head.get("sha"),
            base_sha=base.get("sha"),
            labels=[lbl.get("name", "") for lbl in (pr.get("labels") or [])],
            repo=repo,
            html_url=pr.get("html_url"),
        )

    @classmethod
    def from_env(cls) -> PullRequest | None:
        """Build from GITHUB_EVENT_PATH when running inside Actions."""
        import json

        path = os.environ.get("GITHUB_EVENT_PATH")
        if not path or not Path(path).is_file():
            return None
        try:
            event = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if "pull_request" not in event:
            return None
        return cls.from_github_event(event)


@dataclass
class ReviewContext:
    repo_root: Path
    config: Config
    diff: Diff
    pr: PullRequest
    packs: list[Any] = field(default_factory=list)  # list[Pack]; avoids a cycle
    lore: str | None = None
    head_ref: str = "HEAD"

    @cached_property
    def changed_paths(self) -> list[str]:
        return [f.path for f in self.diff.files]

    def file(self, path: str) -> ChangedFile | None:
        return self.diff.get(path)

    def read(self, path: str) -> str | None:
        """Read a file as it exists at head.

        Prefers the working tree (the CI checkout has it) and falls back to
        `git show`, which matters when the engine runs against a ref that is
        not checked out.
        """
        candidate = self.repo_root / path
        if candidate.is_file():
            try:
                return candidate.read_text(encoding="utf-8", errors="replace")
            except OSError:
                return None
        return read_file_at(self.repo_root, path, self.head_ref)

    def read_lines(self, path: str) -> list[str]:
        content = self.read(path)
        return content.splitlines() if content else []

    def excerpt(self, path: str, line: int, before: int = 4, after: int = 4) -> str:
        """Numbered source excerpt around a line. Used by the verification
        pass, which must re-read actual code rather than trust a claim."""
        lines = self.read_lines(path)
        if not lines:
            return ""
        start = max(1, line - before)
        end = min(len(lines), line + after)
        return "\n".join(f"{n:>5} | {lines[n - 1]}" for n in range(start, end + 1))

    def pack_named(self, name: str) -> Any | None:
        for pack in self.packs:
            if getattr(pack, "name", None) == name:
                return pack
        return None

    @property
    def pack_versions(self) -> dict[str, str]:
        return {p.name: str(p.version) for p in self.packs}
