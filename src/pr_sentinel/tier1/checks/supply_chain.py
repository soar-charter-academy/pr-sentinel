"""`supply-chain` pack script checks: the one that is about the diff's shape.

This module used to hold four checks. Three of them — `install-scripts`,
`new-dependency` and `license-drift` — have been deleted, and the `socket`
adapter replaces them (DESIGN-V2 §3).

That is not a retreat from the position in DESIGN.md §12. It is the position
finally applied. Every one of those three wanted registry data and worked
around not having it: `new-dependency` guessed at typosquats with a bundled
list of popular package names because it could not ask npm which names are
popular, and skipped publish age and maintainer churn outright with a comment
saying so. Socket does not guess. It has the registry, it has behavioural
analysis of the package contents, and it is somebody's full-time job. A
hand-rolled Damerau-Levenshtein pass over 180 hardcoded names was the best
available answer offline; it was never the best available answer.

What survives is `lockfile-integrity`, and it survives because it is not a
question about a package at all. "A lockfile moved and its manifest did not"
is a fact about the *shape of this diff* — two files that must change
together, one of which did. Socket analyses packages; it has no view on which
files a pull request touched, and no package analyser can acquire one. The
same reasoning keeps the migration checks in `supabase_sql.py`: facts about
how this team's commits are arranged are ours to check, because they are not
facts about anyone's software.

The check remains a question rather than an accusation. A lockfile changing
alone is usually a merge artifact and occasionally dependency substitution,
the two produce an identical diff, and the only thing that separates them is
a human reading the resolved URLs.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import TYPE_CHECKING

from ...diff import ChangeKind, path_ignored
from ...models import Severity
from .base import CheckSpec, register

if TYPE_CHECKING:  # pragma: no cover
    from ...context import ReviewContext
    from ...models import Finding


MANIFEST = "package.json"

#: Lockfile -> the tool that writes it. Order matters only for the message.
LOCKFILES: dict[str, str] = {
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
}

#: `"name": "value"` inside a manifest. Used against added/removed diff lines,
#: which carry no section context — so the match is only ever trusted to
#: answer "did the dependency block move at all", never "which package".
_DEP_LINE_RE = re.compile(
    r'^\s*"(?P<name>@?[A-Za-z0-9._][A-Za-z0-9._~/-]*)"\s*:\s*"[^"]*"\s*,?\s*$'
)

#: Top-level manifest keys that look exactly like dependency entries on a
#: single diff line. Needed because there is no parsed map to intersect
#: against: a changed `"version": "1.2.0"` must not read as a dependency edit.
_MANIFEST_SCALAR_KEYS = frozenset(
    {
        "name", "version", "description", "main", "module", "browser", "types",
        "typings", "license", "homepage", "author", "type", "private", "bin",
        "man", "unpkg", "jsdelivr", "packageManager", "engines", "repository",
        "bugs", "funding", "sideEffects", "exports", "imports", "files",
    }
)


# --------------------------------------------------------------------------
# supply-chain.lockfile-integrity
# --------------------------------------------------------------------------


@register(
    "supply-chain.lockfile-integrity",
    default_severity=Severity.HIGH,
    title="Lockfile and manifest disagree about what changed",
    description="A lockfile moved without its package.json, or the reverse.",
    applies_to=["package.json", "package-lock.json", "npm-shrinkwrap.json",
                "yarn.lock", "pnpm-lock.yaml"],
)
def lockfile_integrity(ctx: ReviewContext, spec: CheckSpec) -> Iterable[Finding]:
    """The two halves of a dependency change must move together.

    Both directions are wrong, for different reasons, so they get different
    messages.

    A lockfile changing with no manifest change is both a common merge
    artifact and what dependency substitution looks like (DESIGN s12). That
    ambiguity is the entire point of the check: the benign explanation and
    the attack produce an identical diff, and the only way to tell them apart
    is for a human to read the resolved URLs and integrity hashes. Since the
    benign case is frequent, this must be phrased as a question.

    A manifest changing with no lockfile change is not an attack, it is a
    broken build waiting for CI on main: `npm ci` fails outright when the two
    disagree, and anyone running `npm install` locally gets a tree nobody
    reviewed.

    This is the only check left in this module, and the reason it is not an
    adapter's job is in the module docstring: it reads the diff, not the
    packages.
    """
    for directory, manifest_path in _manifest_dirs(ctx):
        lock_paths = [_join(directory, name) for name in LOCKFILES]

        # If the repo has configured lockfiles out of the diff (the sample
        # config in DESIGN s6 does exactly that), direction A can never fire
        # and direction B would fire on every dependency bump. Better to say
        # nothing than to be confidently wrong in one direction only.
        if any(path_ignored(p, ctx.config.ignore.paths) for p in lock_paths):
            continue

        changed_locks = [p for p in lock_paths if _changed(ctx, p)]
        manifest_changed = _changed(ctx, manifest_path)

        if changed_locks and not manifest_changed:
            names = ", ".join(f"`{p}`" for p in changed_locks)
            yield spec.finding(
                title="Lockfile changed without its `package.json`",
                message=(
                    f"{names} changed in this PR but `{manifest_path}` did not.\n\n"
                    "Usually this is a merge artifact or a `npm install` run that "
                    "re-resolved a floating range — harmless, and worth confirming "
                    "in a sentence. It is also, exactly, what dependency "
                    "substitution looks like: the declared dependencies are "
                    "unchanged while what actually gets installed is not.\n\n"
                    "Worth a look before this lands: which entries moved, and do "
                    "their `resolved` URLs and `integrity` hashes still point at "
                    "the registry you expect?"
                ),
                rationale=(
                    "The manifest is what humans review; the lockfile is what "
                    "actually gets installed. When only the second one moves, the "
                    "review and the install have diverged and nothing in the PR "
                    "description explains why. Dependabot cannot help here — no "
                    "advisory is involved and the substituted package may be "
                    "brand new. Neither can a package analyser like Socket: this "
                    "is a claim about which files the PR touched, not about any "
                    "package in the tree."
                ),
                path=changed_locks[0],
                direction="lock-without-manifest",
            )

        elif manifest_changed and not changed_locks:
            existing = [p for p in lock_paths if ctx.read(p) is not None]
            if not existing:
                # No lockfile in the repo at all. That is a different problem
                # and not this check's to raise.
                continue
            if not _manifest_deps_edited(ctx, manifest_path):
                # Scripts, metadata or engines changed. Not a dependency edit,
                # so the lockfile has no reason to move.
                continue
            names = ", ".join(f"`{p}`" for p in existing)
            yield spec.finding(
                title="`package.json` dependencies changed without the lockfile",
                message=(
                    f"`{manifest_path}` changed its dependencies but {names} did "
                    "not.\n\n"
                    "`npm ci` refuses to run when the two disagree, so this will "
                    "fail on main even though the PR may be green if CI uses "
                    "`npm install`. Re-run the install and commit the lockfile."
                ),
                rationale=(
                    "An un-updated lockfile means the reviewed dependency set and "
                    "the installed one are different, and which one you get "
                    "depends on whether the machine ran `npm ci` or `npm install`. "
                    "That is a reproducibility hole first and an unreviewed "
                    "dependency tree second."
                ),
                path=manifest_path,
                direction="manifest-without-lock",
            )


# --------------------------------------------------------------------------
# manifest plumbing
# --------------------------------------------------------------------------


def _manifest_dirs(ctx: ReviewContext) -> list[tuple[str, str]]:
    """Every directory in this PR that looks like an npm package root.

    Returns (directory, manifest_path) pairs. Workspaces and monorepos mean
    there can be several, and pairing a lockfile with the wrong manifest
    produces exactly the confident-but-wrong finding this engine is supposed
    not to emit.
    """
    dirs: dict[str, str] = {}
    for cf in ctx.diff.files:
        norm = cf.path.replace("\\", "/")
        base = norm.rsplit("/", 1)[-1]
        if base != MANIFEST and base not in LOCKFILES:
            continue
        directory = norm[: -(len(base) + 1)] if "/" in norm else ""
        dirs.setdefault(directory, _join(directory, MANIFEST))
    # Deterministic order so findings come out the same way run to run.
    return sorted(dirs.items())


def _join(directory: str, name: str) -> str:
    return f"{directory}/{name}" if directory else name


def _changed(ctx: ReviewContext, path: str) -> bool:
    cf = ctx.diff.get(path)
    return cf is not None and cf.kind is not ChangeKind.DELETED


def _manifest_deps_edited(ctx: ReviewContext, manifest_path: str) -> bool:
    """Did the change to this manifest touch dependencies at all?

    A scripts-only or metadata-only edit gives the lockfile no reason to move,
    and complaining about it is how a check earns a permanent entry in
    `ignore.rules`.
    """
    cf = ctx.diff.get(manifest_path)
    if cf is None:
        return False
    for _, text in list(cf.added_lines) + list(cf.removed_lines):
        m = _DEP_LINE_RE.match(text)
        if m and m.group("name") not in _MANIFEST_SCALAR_KEYS:
            return True
    return False
