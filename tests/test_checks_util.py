"""The two helpers the surviving script checks share.

`tier1/checks/util.py` exists because DESIGN-V2 §3 deleted `core_hygiene.py`,
which these had been living in by accident. `glob_match` now delegates to
`diff.path_ignored`, and that delegation is the thing worth testing rather
than asserting.

Three claims:

* the three documented rules hold — directory prefix at any depth, glob
  against the full path *and* the basename, and **dot-files match**. The last
  is why the duplicate existed in the first place: `path_ignored` used to
  normalise with `lstrip("./")`, which takes a character *set* and therefore
  ate the leading dot of `.env` and `.github/`. If that regression ever comes
  back, `.env` stops matching `.env*` and a committed service-role key stops
  being seen, so it is pinned here as well as in `test_diff.py`.
* the one place delegation diverges from a strict reading of those rules is
  documented rather than discovered. A wildcard-free pattern used as a
  directory name (`dist`) is treated as a directory prefix. It is additive,
  and it is the reading a person who typed `dist` meant — but it is a
  difference, so it has a test that names it, and a second test that proves
  it changes nothing for any pattern the engine actually ships.
* `as_list` accepts a bare string, because pack manifests are YAML written by
  humans and `extra_pii_columns: dob` must not become a search for `d`, `o`
  and `b`.
"""

from __future__ import annotations

import unittest

from pr_sentinel.diff import path_ignored
from pr_sentinel.tier1.checks.util import as_list, glob_match


class GlobMatchRuleTests(unittest.TestCase):
    """Rule 1 and 2: directory prefixes and globs."""

    def test_a_trailing_slash_is_a_directory_prefix(self):
        self.assertTrue(glob_match("tests/unit/test_a.py", ["tests/"]))

    def test_a_directory_prefix_matches_at_any_depth(self):
        # The whole reason the rule is a prefix rather than an anchor: a
        # fixture under `packages/app/tests/` is as much a test file as one
        # under `tests/`.
        self.assertTrue(glob_match("packages/app/tests/test_a.py", ["tests/"]))
        self.assertTrue(glob_match("a/b/c/fixtures/students.json", ["fixtures/"]))

    def test_a_directory_prefix_does_not_match_a_similarly_named_file(self):
        self.assertFalse(glob_match("tests.py", ["tests/"]))
        self.assertFalse(glob_match("src/contests/a.py", ["tests/"]))

    def test_a_glob_matches_against_the_full_path(self):
        self.assertTrue(glob_match("supabase/seed_data.sql", ["supabase/*.sql"]))

    def test_a_glob_matches_against_the_basename_at_any_depth(self):
        # People write `*.min.js` and mean it anywhere, which is the reason
        # both forms are tried rather than just the full path.
        self.assertTrue(glob_match("a/b/c/vendor.min.js", ["*.min.js"]))
        self.assertTrue(glob_match("packages/app/vite.config.mts", ["vite.config.*"]))

    def test_a_non_matching_pattern_is_false_rather_than_an_error(self):
        self.assertFalse(glob_match("src/app.ts", ["*.py", "docs/"]))

    def test_an_empty_pattern_list_matches_nothing(self):
        self.assertFalse(glob_match("src/app.ts", []))

    def test_a_blank_pattern_is_skipped_rather_than_matching_everything(self):
        self.assertFalse(glob_match("src/app.ts", ["", "   "]))

    def test_windows_separators_are_normalised(self):
        self.assertTrue(glob_match("src\\components\\Button.tsx", ["src/"]))

    def test_a_leading_dot_slash_is_stripped(self):
        self.assertTrue(glob_match("./src/app.ts", ["src/"]))


class DotfileTests(unittest.TestCase):
    """Rule 3, and the reason this helper ever existed.

    `str.lstrip` takes a character set. `lstrip("./")` on `.github/x` yields
    `github/x`, which silently disables every pattern anchored on a dotfile.
    These are the two paths where that bug costs the most.
    """

    def test_dotenv_matches_a_dotenv_glob(self):
        self.assertTrue(glob_match(".env", [".env"]))
        self.assertTrue(glob_match(".env", [".env*"]))
        self.assertTrue(glob_match(".env.production", [".env.*"]))

    def test_a_dotenv_file_in_a_subdirectory_matches_by_basename(self):
        self.assertTrue(glob_match("packages/app/.env.local", [".env.*"]))

    def test_a_dot_directory_prefix_matches(self):
        self.assertTrue(glob_match(".github/workflows/ci.yml", [".github/"]))

    def test_a_star_glob_does_not_lose_the_leading_dot(self):
        # `fnmatch` does not special-case dots the way `glob` does, and this
        # test is here so that a well-meaning switch to `glob` fails loudly.
        self.assertTrue(glob_match(".hidden", ["*"]))
        self.assertTrue(glob_match(".npmrc", ["*.npmrc", ".npmrc"]))


class DelegationTests(unittest.TestCase):
    """`glob_match` IS `path_ignored`. Pin both the agreement and the gap."""

    #: Every path/pattern shape the surviving checks actually pass in, plus
    #: the shapes a repo author is likely to write by hand.
    PATHS = [
        ".env", ".env.production", ".github/workflows/ci.yml", "src/a.ts",
        "src/test/a.ts", "tests/x.py", "a/b/tests/x.py", "src/a.test.ts",
        "supabase/seed.sql", "db/0001_seed_data.sql", "vite.config.ts",
        "packages/app/vite.config.mts", "dist/app.js", "src/dist/app.js",
        "node_modules/x/y.js", "./src/b.ts", "components/Button.tsx",
        "public/logo.svg", "cypress/e2e/a.cy.ts",
    ]
    PATTERNS = [
        ".env", ".env.*", ".github/", "*.ts", "test/", "tests/", "*.test.*",
        "*seed*.sql", "vite.config.*", "dist/", "src/", "*", "components/",
        "public/", "*.cy.*", "__tests__/", "*.stories.*",
    ]

    def test_it_agrees_with_path_ignored_on_every_pattern_shape_in_use(self):
        for path in self.PATHS:
            for pattern in self.PATTERNS:
                with self.subTest(path=path, pattern=pattern):
                    self.assertEqual(
                        glob_match(path, [pattern]),
                        path_ignored(path, [pattern]),
                    )

    def test_the_documented_divergence_is_a_wildcard_free_component_name(self):
        # `path_ignored` has a fourth clause the three documented rules do not
        # describe: a pattern equal to a path component matches. So `dist`
        # behaves like `dist/`. Additive, and intentional — but recorded here
        # so that anyone reading `util.py`'s claim can check it.
        self.assertTrue(glob_match("src/dist/app.js", ["dist"]))
        self.assertTrue(glob_match("node_modules/x/y.js", ["node_modules"]))
        self.assertTrue(glob_match("src/test/a.ts", ["test"]))

        # It is component equality, not a substring: `di` must not match
        # `dist`, or every short pattern would match half the repo.
        self.assertFalse(glob_match("src/dist/app.js", ["di"]))
        self.assertFalse(glob_match("src/distant/app.js", ["dist"]))

    def test_delegation_changes_nothing_for_any_default_pattern_we_ship(self):
        """The claim that made delegating safe, asserted directly.

        A strict implementation of just the three documented rules is built
        here and compared against `glob_match` over every default pattern the
        engine ships. They must agree everywhere: the extra clause in
        `path_ignored` only fires for a wildcard-free pattern used as a
        *directory* prefix, and no default is written that way. `.env` is
        wildcard-free but is a filename, so basename matching already decides
        it and the extra clause never gets a say.

        If a new default arrives that the two implementations disagree about,
        this fails and whoever added it chooses deliberately instead of
        finding out from a false negative six months later.
        """
        import fnmatch
        from pathlib import Path as _Path

        def strict(path: str, patterns: list[str]) -> bool:
            norm = path.replace("\\", "/")
            while norm.startswith("./"):
                norm = norm[2:]
            for raw in patterns:
                pattern = str(raw).replace("\\", "/").strip()
                if not pattern:
                    continue
                if pattern.endswith("/"):
                    if norm.startswith(pattern) or f"/{pattern}" in f"/{norm}":
                        return True
                    continue
                if fnmatch.fnmatch(norm, pattern) or fnmatch.fnmatch(
                    _Path(norm).name, pattern
                ):
                    return True
            return False

        from pr_sentinel.tier1.checks.privacy_edu import (
            DEFAULT_TEST_PATH_GLOBS,
            JS_GLOBS,
        )
        from pr_sentinel.tier1.checks.react_vite import (
            DEFAULT_CLIENT_ROOTS,
            ENV_GLOBS,
            VITE_CONFIG_GLOBS,
        )
        from pr_sentinel.tier1.checks.supabase_sql import SQL_GLOBS

        defaults = (
            DEFAULT_TEST_PATH_GLOBS
            + DEFAULT_CLIENT_ROOTS
            + list(ENV_GLOBS)
            + list(VITE_CONFIG_GLOBS)
            + list(JS_GLOBS)
            + list(SQL_GLOBS)
        )
        self.assertTrue(defaults)

        for pattern in defaults:
            for path in self.PATHS:
                with self.subTest(pattern=pattern, path=path):
                    self.assertEqual(
                        glob_match(path, [pattern]),
                        strict(path, [pattern]),
                        f"delegating to path_ignored changes the meaning of "
                        f"{pattern!r} for {path!r}",
                    )


class AsListTests(unittest.TestCase):
    def test_a_bare_string_becomes_a_one_item_list(self):
        # `extra_pii_columns: dob` in a pack manifest. Without this, the
        # option becomes a search for the letters `d`, `o` and `b`.
        self.assertEqual(as_list("dob"), ["dob"])

    def test_a_list_is_passed_through_as_strings(self):
        self.assertEqual(as_list(["dob", "ssn"]), ["dob", "ssn"])

    def test_tuples_and_sets_are_accepted(self):
        self.assertEqual(as_list(("a", "b")), ["a", "b"])
        self.assertEqual(sorted(as_list({"a", "b"})), ["a", "b"])

    def test_non_string_members_are_coerced(self):
        # YAML turns `2024` into an int, and a check comparing it to text
        # would silently never match.
        self.assertEqual(as_list([1, 2]), ["1", "2"])

    def test_none_and_junk_return_empty_rather_than_raising(self):
        # A malformed option should cost that option, not the review.
        self.assertEqual(as_list(None), [])
        self.assertEqual(as_list(42), [])
        self.assertEqual(as_list({"a": 1}), [])


if __name__ == "__main__":
    unittest.main()
