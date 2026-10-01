"""Unified-diff parsing and "what this PR actually changed".

Almost every rule wants the same two things: which files were touched, and
which lines were *added*, numbered in the head revision. Two failure modes
matter more than the rest:

* a silently dropped file is a silently unreviewed file;
* an added line reported at the wrong number is a finding nobody can find.

`path_ignored` gets its own section because of a real bug: `lstrip("./")`
takes a character *set*, so it ate the leading dot of `.github/` and `.env`
and silently disabled every pattern anchored on a dotfile. Dotfiles are
where the workflow definitions and the environment secrets live, so that is
the worst possible set of patterns to disable.
"""

from __future__ import annotations

import unittest

from pr_sentinel.diff import ChangeKind, path_ignored
from tests.helpers import diff_of

ADDED_FILE = """
diff --git a/src/new.ts b/src/new.ts
new file mode 100644
index 0000000..e69de29
--- /dev/null
+++ b/src/new.ts
@@ -0,0 +1,3 @@
+const a = 1;
+const b = 2;
+const c = 3;
"""

MODIFIED_TWO_HUNKS = """
diff --git a/src/app.ts b/src/app.ts
index 1111111..2222222 100644
--- a/src/app.ts
+++ b/src/app.ts
@@ -1,4 +1,5 @@
 import x from "x";
+import y from "y";

 export function a() {
   return 1;
@@ -20,6 +21,7 @@ export function a() {
 function b() {
   const q = 1;
-  return q;
+  return q + 1;
+  // trailing
 }
"""

DELETED_FILE = """
diff --git a/src/old.ts b/src/old.ts
deleted file mode 100644
index 1111111..0000000
--- a/src/old.ts
+++ /dev/null
@@ -1,2 +0,0 @@
-const a = 1;
-const b = 2;
"""

RENAMED_FILE = """
diff --git a/src/old-name.ts b/src/new-name.ts
similarity index 95%
rename from src/old-name.ts
rename to src/new-name.ts
index 1111111..2222222 100644
--- a/src/old-name.ts
+++ b/src/new-name.ts
@@ -1,2 +1,2 @@
-const a = 1;
+const a = 2;
 const b = 2;
"""

BINARY_FILE = """
diff --git a/assets/logo.png b/assets/logo.png
new file mode 100644
index 0000000..3333333
Binary files /dev/null and b/assets/logo.png differ
"""

NO_NEWLINE_AT_EOF = """
diff --git a/src/eof.ts b/src/eof.ts
index 1111111..2222222 100644
--- a/src/eof.ts
+++ b/src/eof.ts
@@ -1,2 +1,2 @@
 const a = 1;
-const b = 2;
\\ No newline at end of file
+const b = 3;
\\ No newline at end of file
"""


class ChangeKindTests(unittest.TestCase):
    def test_a_new_file_is_added_and_all_its_lines_are_added_lines(self):
        changed = diff_of(ADDED_FILE).files[0]
        self.assertEqual(changed.path, "src/new.ts")
        self.assertIs(changed.kind, ChangeKind.ADDED)
        self.assertEqual(changed.added_lines, [(1, "const a = 1;"), (2, "const b = 2;"), (3, "const c = 3;")])
        self.assertEqual(changed.removed_lines, [])

    def test_a_modified_file_is_modified(self):
        changed = diff_of(MODIFIED_TWO_HUNKS).files[0]
        self.assertEqual(changed.path, "src/app.ts")
        self.assertIs(changed.kind, ChangeKind.MODIFIED)

    def test_a_deleted_file_keeps_its_path_and_is_excluded_from_live_files(self):
        # Rules that read file content must use `live_files`; scanning a
        # deleted path is a crash waiting to happen.
        diff = diff_of(DELETED_FILE)
        changed = diff.files[0]
        self.assertEqual(changed.path, "src/old.ts")
        self.assertIs(changed.kind, ChangeKind.DELETED)
        self.assertEqual(diff.live_files, [])

    def test_a_rename_records_both_paths_and_is_not_reported_as_a_rewrite(self):
        changed = diff_of(RENAMED_FILE).files[0]
        self.assertIs(changed.kind, ChangeKind.RENAMED)
        self.assertEqual(changed.path, "src/new-name.ts")
        self.assertEqual(changed.old_path, "src/old-name.ts")

    def test_a_binary_file_is_flagged_and_has_no_line_content(self):
        changed = diff_of(BINARY_FILE).files[0]
        self.assertTrue(changed.is_binary)
        self.assertEqual(changed.added_lines, [])
        self.assertIs(changed.kind, ChangeKind.ADDED)

    def test_several_files_in_one_diff_are_all_kept(self):
        # A dropped file is an unreviewed file, so this is worth asserting
        # rather than assuming.
        diff = diff_of(ADDED_FILE + MODIFIED_TWO_HUNKS + DELETED_FILE + BINARY_FILE)
        self.assertEqual(
            [f.path for f in diff.files],
            ["src/new.ts", "src/app.ts", "src/old.ts", "assets/logo.png"],
        )


class LineNumberingTests(unittest.TestCase):
    def test_added_lines_carry_head_revision_numbers_across_multiple_hunks(self):
        changed = diff_of(MODIFIED_TWO_HUNKS).files[0]
        self.assertEqual(len(changed.hunks), 2)
        self.assertEqual(
            changed.added_lines,
            [(2, 'import y from "y";'), (23, "  return q + 1;"), (24, "  // trailing")],
        )

    def test_removed_lines_carry_base_revision_numbers(self):
        changed = diff_of(MODIFIED_TWO_HUNKS).files[0]
        self.assertEqual(changed.removed_lines, [(22, "  return q;")])

    def test_context_lines_advance_both_counters(self):
        # If context did not advance the head counter, every added line after
        # the first context line would be reported too low.
        changed = diff_of(MODIFIED_TWO_HUNKS).files[0]
        self.assertEqual(changed.hunks[1].new_start, 21)
        self.assertIn(23, changed.added_line_numbers)

    def test_a_no_newline_marker_does_not_consume_a_line_number(self):
        changed = diff_of(NO_NEWLINE_AT_EOF).files[0]
        self.assertEqual(changed.added_lines, [(2, "const b = 3;")])
        self.assertEqual(changed.removed_lines, [(2, "const b = 2;")])

    def test_churn_counts_both_directions(self):
        self.assertEqual(diff_of(MODIFIED_TWO_HUNKS).files[0].churn, 4)

    def test_total_churn_sums_across_files(self):
        diff = diff_of(ADDED_FILE + MODIFIED_TWO_HUNKS)
        self.assertEqual(diff.total_churn, 3 + 4)

    def test_touches_line_uses_slack_for_matches_just_above_the_edit(self):
        # A semgrep match can start a few lines above the edited line (a
        # function signature match on an edited body). Zero slack drops real
        # findings; too much reintroduces someone else's bug.
        changed = diff_of(MODIFIED_TWO_HUNKS).files[0]
        self.assertTrue(changed.touches_line(23))
        self.assertTrue(changed.touches_line(20, slack=3))
        self.assertFalse(changed.touches_line(20, slack=0))
        self.assertFalse(changed.touches_line(100, slack=3))

    def test_a_finding_with_no_line_is_treated_as_touching_the_file(self):
        # Whole-file rules ("this file must never be committed") legitimately
        # have no line to point at.
        self.assertTrue(diff_of(MODIFIED_TWO_HUNKS).files[0].touches_line(None))

    def test_added_text_joins_only_the_added_lines(self):
        self.assertEqual(
            diff_of(ADDED_FILE).files[0].added_text,
            "const a = 1;\nconst b = 2;\nconst c = 3;",
        )


class MalformedInputTests(unittest.TestCase):
    def test_an_empty_diff_parses_to_no_files_rather_than_raising(self):
        self.assertEqual(diff_of("").files, [])

    def test_content_before_any_file_header_is_ignored(self):
        diff = diff_of("warning: something\n" + ADDED_FILE.lstrip("\n"))
        self.assertEqual([f.path for f in diff.files], ["src/new.ts"])

    def test_lookup_by_path_finds_the_file_and_misses_cleanly(self):
        diff = diff_of(MODIFIED_TWO_HUNKS)
        self.assertIsNotNone(diff.get("src/app.ts"))
        self.assertIsNone(diff.get("src/nope.ts"))


class PathIgnoredDotfileTests(unittest.TestCase):
    """The regression. `.github/` and `.env` must match.

    A `lstrip("./")` here removed the leading dot from every dotfile path, so
    these patterns matched nothing — disabling ignore rules aimed at exactly
    the files that carry CI definitions and secrets.
    """

    def test_a_dot_directory_prefix_pattern_matches(self):
        self.assertTrue(path_ignored(".github/workflows/review.yml", [".github/"]))

    def test_a_dot_directory_prefix_pattern_matches_at_depth(self):
        self.assertTrue(path_ignored("packages/app/.github/x.yml", [".github/"]))

    def test_a_dotfile_pattern_matches_the_dotfile(self):
        self.assertTrue(path_ignored(".env", [".env"]))

    def test_a_dotfile_pattern_matches_the_dotfile_in_a_subdirectory(self):
        self.assertTrue(path_ignored("apps/web/.env", [".env"]))

    def test_a_dotfile_pattern_does_not_match_a_differently_named_sibling(self):
        # `.env` must not swallow `.env.example`, which is committed on
        # purpose in most repos.
        self.assertFalse(path_ignored(".env.example", [".env"]))

    def test_a_leading_dot_slash_is_stripped_without_eating_the_next_dot(self):
        self.assertTrue(path_ignored("./.env", [".env"]))
        self.assertTrue(path_ignored("./.github/workflows/x.yml", [".github/"]))

    def test_a_dot_directory_name_without_a_slash_matches_as_a_segment(self):
        self.assertTrue(path_ignored(".github/workflows/x.yml", [".github"]))


class PathIgnoredGeneralTests(unittest.TestCase):
    def test_a_trailing_slash_pattern_is_a_directory_prefix(self):
        self.assertTrue(path_ignored("dist/bundle.js", ["dist/"]))
        self.assertTrue(path_ignored("packages/app/dist/bundle.js", ["dist/"]))
        self.assertFalse(path_ignored("distribution/readme.md", ["dist/"]))

    def test_a_glob_matches_at_any_depth_via_the_basename(self):
        self.assertTrue(path_ignored("src/vendor/thing.min.js", ["*.min.js"]))

    def test_an_exact_filename_pattern_matches_anywhere(self):
        self.assertTrue(path_ignored("package-lock.json", ["package-lock.json"]))
        self.assertTrue(path_ignored("apps/web/package-lock.json", ["package-lock.json"]))

    def test_backslash_separated_paths_are_normalised(self):
        self.assertTrue(path_ignored("src\\vendor\\thing.min.js", ["*.min.js"]))

    def test_an_empty_pattern_is_skipped_rather_than_matching_everything(self):
        self.assertFalse(path_ignored("src/app.ts", ["", "   "]))

    def test_nothing_matches_an_empty_pattern_list(self):
        self.assertFalse(path_ignored("src/app.ts", []))

    def test_filter_paths_removes_ignored_files_from_the_diff(self):
        diff = diff_of(ADDED_FILE + BINARY_FILE)
        kept = diff.filter_paths(["assets/"])
        self.assertEqual([f.path for f in kept.files], ["src/new.ts"])


if __name__ == "__main__":
    unittest.main()
