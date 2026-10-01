"""Two helpers the surviving script checks share.

These lived in `core_hygiene.py` until DESIGN-V2 §3 deleted that module, and
the only thing holding them there was the accident of which check needed them
first. `privacy_edu` and `react_vite` both import them, neither is a hygiene
check, and a shared helper that lives inside a deletable module is a shared
helper that breaks when the module is deleted. So: here, with no checks in it.

### Why `glob_match` is a one-liner now

It did not used to be. `diff.path_ignored` once normalised paths with
`lstrip("./")`, and `str.lstrip` takes a character *set* — so it ate the
leading dot of `.github/` and `.env`, silently disabling every pattern
anchored on a dotfile. A check that needs `.env` to match `.env*` could not
use it, and `_glob_match` existed to be the version that worked.

`path_ignored` strips the prefix correctly now (see the comment in
`diff.py`), so the duplicate has no reason to exist. Keeping two glob
dialects for user-facing path options in one engine is its own bug: a repo
author writing `test/` in `ignore.paths` and `test/` in
`privacy-edu.test_path_globs` is entitled to have them mean the same thing.

The delegation was checked rather than assumed. Across a matrix of paths and
patterns the two agree everywhere except one case: a **wildcard-free pattern
naming a path component**, like `dist`. `path_ignored` treats that as a
directory prefix (`src/dist/app.js` matches); a strict reading of the three
documented rules below does not. That difference is additive — it broadens
wildcard-free patterns and changes none of the three rules — and it is the
reading a person who typed `dist` meant. No default pattern in the engine is
wildcard-free, so no existing behaviour moves. `test_checks_util.py` pins
both the agreement and that one documented divergence.

The three rules, which hold exactly:

1. a pattern ending in `/` is a directory prefix, matched at any depth;
2. any other pattern is an fnmatch glob tried against the full path *and*
   against the basename, because people write `*.min.js` and mean it anywhere;
3. dot-files match — `.env` against `.env*`, `.github/workflows/ci.yml`
   against `.github/`. This is the property the original existed for and the
   one most worth a test.
"""

from __future__ import annotations

from ...diff import path_ignored


def as_list(value: object) -> list[str]:
    """Coerce a pack option into a list of strings.

    Pack manifests are YAML written by humans, so a single-value option
    arrives as a bare string about as often as as a one-item list. Accepting
    both is the difference between `extra_pii_columns: dob` working and
    producing a check that silently scans for the letters `d`, `o` and `b`.

    Anything that is neither a string nor a sequence returns empty rather than
    raising: a malformed option should cost that option, not the review.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value]
    return []


def glob_match(path: str, patterns: list[str]) -> bool:
    """Does `path` match any of `patterns`? See the module docstring."""
    return path_ignored(path, patterns)
