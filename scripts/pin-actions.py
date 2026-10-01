#!/usr/bin/env python3
"""Report GitHub Actions referenced by a mutable ref instead of a commit SHA.

DESIGN s12: `uses: actions/checkout@v4` is a pointer, not a version. Whoever
controls that tag controls what executes in CI, with every secret the job can
see. The rule is a full 40-character commit SHA with the version in a trailing
comment, so that the pin is immutable and Dependabot still knows what to bump.

Reports only. It never rewrites a workflow, for two reasons: resolving a tag to
a SHA requires trusting a network lookup at the exact moment you are trying to
establish trust, and a tool that silently edits the file it is auditing removes
the human review step that makes the pin meaningful. Look the SHA up yourself,
against the tag page, and paste it.

Usage:
    python scripts/pin-actions.py                 # report, always exit 0
    python scripts/pin-actions.py --check         # exit 1 if anything is unpinned
    python scripts/pin-actions.py path/to/repo    # audit another checkout

Standard library only, deliberately: this runs in CI before the project's own
dependencies are necessarily installed, and an auditor with a dependency tree
is an auditor with a supply-chain problem.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

#: A `uses:` line. The ref half is optional so that a `uses:` with no ref at
#: all is reported rather than skipped.
USES_RE = re.compile(
    r"""^\s*-?\s*uses\s*:\s*['"]?(?P<spec>[^'"\s#]+)['"]?\s*(?P<comment>\#.*)?$"""
)

#: Exactly 40 lowercase hex characters. A short SHA is not a pin: it is not
#: guaranteed unique forever and GitHub will happily resolve it.
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")

#: A reusable-workflow reference, e.g.
#: `owner/repo/.github/workflows/review.yml@v1`. Held to a different standard
#: on purpose - see `reusable_workflow_problem`.
REUSABLE_RE = re.compile(r"/\.github/workflows/[^@]+\.ya?ml@")

#: Refs that are branches by any other name. A reusable workflow pinned to one
#: of these adopts upstream rule changes the moment they merge.
MUTABLE_BRANCH_REFS = {"main", "master", "trunk", "develop", "head", "latest"}

#: A trailing comment naming the version, e.g. `# v4.3.0`. Not required for a
#: valid pin, but without it nobody - human or Dependabot - can tell what the
#: SHA is supposed to be.
VERSION_COMMENT_RE = re.compile(r"#\s*v?\d+(\.\d+)*")


class Problem:
    __slots__ = ("path", "line_no", "line", "kind", "detail")

    def __init__(self, path: Path, line_no: int, line: str, kind: str, detail: str) -> None:
        self.path = path
        self.line_no = line_no
        self.line = line.strip()
        self.kind = kind
        self.detail = detail

    def render(self, root: Path) -> str:
        try:
            where = self.path.relative_to(root)
        except ValueError:
            where = self.path
        return f"{where}:{self.line_no}: {self.kind}\n    {self.line}\n    {self.detail}"


def is_local_reference(spec: str) -> bool:
    """`./.github/actions/foo` and `docker://...` are not tag references.

    A local path is whatever this commit contains, which is already immutable
    with respect to the workflow using it. A docker reference should carry a
    digest, but that is a different check and this script does not pretend to
    make it.
    """
    return spec.startswith("./") or spec.startswith("../") or spec.startswith("docker://")


def reusable_workflow_problem(path: Path, line_no: int, line: str, ref: str) -> Problem | None:
    """Reusable workflows are pinned to a TAG, not a SHA (DESIGN s4).

    Different hazard, different rule. A third-party action is somebody else's
    code executing with your secrets, so nothing short of an immutable SHA is
    honest. A reusable workflow is a versioned release of a repository you have
    deliberately delegated to, and s4's requirement is that a rule added
    upstream must not silently change verdicts overnight - which a release tag
    satisfies while remaining reviewable and bumpable. A branch does not.
    """
    if FULL_SHA_RE.match(ref):
        return None
    if ref.lower() in MUTABLE_BRANCH_REFS or ref.startswith("refs/heads/"):
        return Problem(
            path,
            line_no,
            line,
            "reusable workflow on a branch",
            f"`@{ref}` adopts upstream rule changes the moment they merge. Pin to a "
            "release tag so verdicts change when you bump the tag, not overnight "
            "(DESIGN s4).",
        )
    return None


def scan_file(path: Path) -> list[Problem]:
    problems: list[Problem] = []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:  # pragma: no cover - IO edge
        return [Problem(path, 0, "", "unreadable", str(exc))]

    for line_no, line in enumerate(text.splitlines(), start=1):
        match = USES_RE.match(line)
        if not match:
            continue
        spec = match.group("spec")
        comment = match.group("comment") or ""

        if is_local_reference(spec):
            continue

        if "@" not in spec:
            problems.append(
                Problem(
                    path,
                    line_no,
                    line,
                    "no ref at all",
                    "resolves to the default branch, which anyone with write access "
                    "to that repo can move.",
                )
            )
            continue

        ref = spec.rsplit("@", 1)[1]

        if REUSABLE_RE.search(spec):
            problem = reusable_workflow_problem(path, line_no, line, ref)
            if problem is not None:
                problems.append(problem)
            continue

        if not FULL_SHA_RE.match(ref):
            kind = "mutable ref"
            if re.fullmatch(r"[0-9a-f]{7,39}", ref):
                kind = "abbreviated SHA"
            problems.append(
                Problem(
                    path,
                    line_no,
                    line,
                    kind,
                    f"`@{ref}` is a pointer, not a version. Pin to the full 40-character "
                    "commit SHA and put the version in a trailing comment.",
                )
            )
            continue

        if not VERSION_COMMENT_RE.search(comment):
            problems.append(
                Problem(
                    path,
                    line_no,
                    line,
                    "pinned but unlabelled",
                    "the SHA is immutable but nothing says which version it is, so "
                    "nobody can review the bump and Dependabot has nothing to write.",
                )
            )

    return problems


def workflow_files(root: Path) -> list[Path]:
    """Workflows, composite actions, and the templates we hand to other people.

    `action.yml` is included because a composite action carries exactly the
    same `uses:` hazard as a workflow and is reviewed far less often.
    `templates/` is included because shipping a template with a mutable ref
    would teach the exact habit this repo exists to discourage.
    """
    found: list[Path] = []
    workflows = root / ".github" / "workflows"
    if workflows.is_dir():
        found.extend(sorted(p for p in workflows.iterdir() if p.suffix in (".yml", ".yaml")))
    for pattern in ("**/action.yml", "**/action.yaml"):
        found.extend(sorted(p for p in root.glob(pattern) if ".git/" not in p.as_posix()))
    templates = root / "templates"
    if templates.is_dir():
        found.extend(sorted(p for p in templates.rglob("*.y*ml") if p.is_file()))
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pin-actions.py",
        description="Report GitHub Actions that are not pinned to a full commit SHA.",
    )
    parser.add_argument(
        "root",
        nargs="?",
        default=None,
        help="repository root to audit (default: the repo this script lives in)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit 1 if any unpinned reference is found (for CI)",
    )
    args = parser.parse_args(argv)

    root = Path(args.root).resolve() if args.root else Path(__file__).resolve().parent.parent

    files = workflow_files(root)
    if not files:
        print(f"no workflows or composite actions found under {root}")
        return 0

    problems: list[Problem] = []
    for path in files:
        problems.extend(scan_file(path))

    scanned = f"{len(files)} file(s)"
    if not problems:
        print(
            f"{scanned}: every action pinned to a full commit SHA, every reusable "
            "workflow pinned to a tag."
        )
        return 0

    for problem in problems:
        print(problem.render(root))
        print()
    print(f"{len(problems)} unpinned or unlabelled reference(s) in {scanned}.")
    print(
        "A mutable ref means a compromised upstream action executes in CI with every "
        "secret that job can see (DESIGN s12)."
    )
    return 1 if args.check else 0


if __name__ == "__main__":
    sys.exit(main())
