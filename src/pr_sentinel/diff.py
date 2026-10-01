"""Unified-diff parsing and the notion of "what this PR actually changed".

Almost every rule in the engine wants the same thing: the set of files touched
and, within them, the *added* lines with their line numbers in the head
revision. Reporting a pre-existing problem on someone else's PR is the fastest
way to get a reviewer muted, so findings are filtered to changed lines unless
a rule explicitly opts out (whole-file rules like "this file must never be
committed" legitimately do).
"""

from __future__ import annotations

import fnmatch
import re
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_DIFF_HEADER_RE = re.compile(r'^diff --git "?a/(.+?)"? "?b/(.+?)"?$')


class DiffError(RuntimeError):
    """Raised when the PR's diff cannot be determined.

    Separate from a generic subprocess failure because the caller can give
    the user something actionable, and because "no diff" must never be
    mistaken for "no changes" - an empty review of an unreviewed PR is the
    worst possible output.
    """


class ChangeKind(Enum):
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    RENAMED = "renamed"


@dataclass
class Hunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    #: (line_number_in_head, text) for lines this PR introduced
    added_lines: list[tuple[int, str]] = field(default_factory=list)
    #: (line_number_in_base, text) for lines this PR removed
    removed_lines: list[tuple[int, str]] = field(default_factory=list)


@dataclass
class ChangedFile:
    path: str
    kind: ChangeKind
    hunks: list[Hunk] = field(default_factory=list)
    old_path: str | None = None
    is_binary: bool = False

    @property
    def added_lines(self) -> list[tuple[int, str]]:
        out: list[tuple[int, str]] = []
        for h in self.hunks:
            out.extend(h.added_lines)
        return out

    @property
    def removed_lines(self) -> list[tuple[int, str]]:
        out: list[tuple[int, str]] = []
        for h in self.hunks:
            out.extend(h.removed_lines)
        return out

    @property
    def added_line_numbers(self) -> set[int]:
        return {n for n, _ in self.added_lines}

    @property
    def added_text(self) -> str:
        return "\n".join(text for _, text in self.added_lines)

    @property
    def churn(self) -> int:
        return len(self.added_lines) + len(self.removed_lines)

    @property
    def suffix(self) -> str:
        return Path(self.path).suffix.lower()

    def touches_line(self, line: int | None, slack: int = 0) -> bool:
        """Did this PR change at or near `line`?

        `slack` exists because a semgrep match can start a few lines above the
        line that was actually edited (a function signature match on an edited
        body, say). Zero slack drops real findings; large slack reintroduces
        noise from untouched code. Three lines is the compromise.
        """
        if line is None:
            return True
        if not self.hunks:
            return True
        nums = self.added_line_numbers
        return any(abs(line - n) <= slack for n in nums)


@dataclass
class Diff:
    files: list[ChangedFile] = field(default_factory=list)

    def by_path(self) -> dict[str, ChangedFile]:
        return {f.path: f for f in self.files}

    def get(self, path: str) -> ChangedFile | None:
        for f in self.files:
            if f.path == path:
                return f
        return None

    @property
    def total_churn(self) -> int:
        return sum(f.churn for f in self.files)

    @property
    def live_files(self) -> list[ChangedFile]:
        """Files that still exist at head. Rules that read file content must
        use this; scanning a deleted path is a crash waiting to happen."""
        return [f for f in self.files if f.kind is not ChangeKind.DELETED]

    def filter_paths(self, ignore_globs: list[str]) -> Diff:
        return Diff([f for f in self.files if not path_ignored(f.path, ignore_globs)])


def path_ignored(path: str, patterns: list[str]) -> bool:
    """Match a path against ignore patterns.

    A pattern ending in `/` is a directory prefix; otherwise it is an fnmatch
    glob tried against both the full path and the basename, because people
    write `*.min.js` and mean it at any depth.
    """
    # NB: `lstrip("./")` would be wrong here - str.lstrip takes a character
    # SET, so it eats the leading dot of `.github/` and `.env`, silently
    # disabling every pattern anchored on a dotfile. Strip the prefix only.
    norm = path.replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    for pattern in patterns:
        p = str(pattern).replace("\\", "/").strip()
        if not p:
            continue
        if p.endswith("/"):
            if norm.startswith(p) or f"/{p}" in f"/{norm}":
                return True
            continue
        if fnmatch.fnmatch(norm, p) or fnmatch.fnmatch(Path(norm).name, p):
            return True
        if p in norm.split("/"):
            return True
    return False


def parse_unified_diff(text: str) -> Diff:
    """Parse `git diff` output.

    Written by hand rather than shelling out to a library because the parsing
    is small, the failure modes matter (a silently dropped file is a silently
    unreviewed file) and it keeps the dependency list at one entry.
    """
    files: list[ChangedFile] = []
    current: ChangedFile | None = None
    hunk: Hunk | None = None
    old_line = new_line = 0
    saw_deleted_file = False

    def flush() -> None:
        nonlocal current, hunk
        if current is not None:
            files.append(current)
        current, hunk = None, None

    for line in text.splitlines():
        header = _DIFF_HEADER_RE.match(line)
        if header:
            flush()
            b_path = header.group(2)
            current = ChangedFile(path=b_path, kind=ChangeKind.MODIFIED)
            saw_deleted_file = False
            continue

        if current is None:
            continue

        if line.startswith("new file mode"):
            current.kind = ChangeKind.ADDED
            continue
        if line.startswith("deleted file mode"):
            current.kind = ChangeKind.DELETED
            saw_deleted_file = True
            continue
        if line.startswith("rename from "):
            current.old_path = line[len("rename from "):].strip()
            continue
        if line.startswith("rename to "):
            current.path = line[len("rename to "):].strip()
            current.kind = ChangeKind.RENAMED
            continue
        if line.startswith("Binary files ") or line.startswith("GIT binary patch"):
            current.is_binary = True
            continue
        if line.startswith("--- "):
            continue
        if line.startswith("+++ "):
            target = line[4:].strip()
            if target != "/dev/null":
                current.path = target[2:] if target.startswith("b/") else target
            elif not saw_deleted_file:
                current.kind = ChangeKind.DELETED
            continue

        m = _HUNK_RE.match(line)
        if m:
            old_start = int(m.group(1))
            old_count = int(m.group(2) or 1)
            new_start = int(m.group(3))
            new_count = int(m.group(4) or 1)
            hunk = Hunk(old_start, old_count, new_start, new_count)
            current.hunks.append(hunk)
            old_line, new_line = old_start, new_start
            continue

        if hunk is None:
            continue

        if line.startswith("+"):
            hunk.added_lines.append((new_line, line[1:]))
            new_line += 1
        elif line.startswith("-"):
            hunk.removed_lines.append((old_line, line[1:]))
            old_line += 1
        elif line.startswith("\\"):
            # "\ No newline at end of file"
            continue
        else:
            old_line += 1
            new_line += 1

    flush()
    return Diff(files)


def git_diff(
    repo_root: Path | str,
    base: str,
    head: str = "HEAD",
    *,
    context: int = 3,
) -> Diff:
    """Produce the diff for a PR.

    Uses the merge base rather than a raw two-dot diff so that commits landing
    on the base branch after the PR opened are not attributed to the PR. That
    attribution bug is how a reviewer ends up commenting on a colleague's code
    inside your pull request.
    """
    root = Path(repo_root)
    merge_base = _merge_base(root, base, head) or base
    try:
        out = _run_git(
            root,
            [
                "diff",
                f"--unified={context}",
                "--no-color",
                "--no-ext-diff",
                "-M",  # detect renames; a moved file is not a rewritten file
                f"{merge_base}",
                head,
            ],
        )
    except subprocess.CalledProcessError as exc:
        # The overwhelmingly common cause is a base ref that does not exist
        # locally: a shallow `actions/checkout` clone has the head but not the
        # base branch. A traceback here sends people hunting through the
        # engine; the fix is almost always `fetch-depth: 0`.
        raise DiffError(
            f"could not diff `{merge_base}`..`{head}` in {root}.\n"
            f"  git said: {(exc.stderr or '').strip()[:300]}\n"
            f"  If this is CI, the base ref is probably not in the clone. Use "
            f"`actions/checkout` with `fetch-depth: 0`, or fetch the base branch "
            f"before running the review."
        ) from exc
    return parse_unified_diff(out)


def _merge_base(root: Path, base: str, head: str) -> str | None:
    try:
        return _run_git(root, ["merge-base", base, head]).strip() or None
    except subprocess.CalledProcessError:
        return None


def _run_git(root: Path, args: list[str]) -> str:
    result = subprocess.run(  # noqa: S603
        ["git", *args],
        cwd=str(root),
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def read_file_at(repo_root: Path | str, path: str, ref: str = "HEAD") -> str | None:
    """Read a file's content at a git ref, or None if it is absent there."""
    try:
        return _run_git(Path(repo_root), ["show", f"{ref}:{path}"])
    except subprocess.CalledProcessError:
        return None
