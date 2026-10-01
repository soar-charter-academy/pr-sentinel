"""The version resolver behind independent pack pinning.

DESIGN s15 resolved pack versioning in favour of pinning each pack
separately. That only works if the engine can answer "does the pack I ship
satisfy the spec this repo wrote?" the same way node-semver would — a repo
author writing `^1.0` means the node-semver `^1.0`, and a resolver that
disagrees on the 0.x rule or on prerelease ordering silently runs a rule set
nobody asked for (DESIGN s4).
"""

from __future__ import annotations

import unittest

from pr_sentinel.semver import (
    InvalidSpec,
    InvalidVersion,
    Spec,
    Version,
    satisfies,
)


class CaretTests(unittest.TestCase):
    def test_caret_allows_minor_and_patch_but_not_major(self):
        self.assertTrue(satisfies("1.2.3", "^1.2.3"))
        self.assertTrue(satisfies("1.9.9", "^1.2.3"))
        self.assertFalse(satisfies("2.0.0", "^1.2.3"))

    def test_caret_does_not_allow_below_the_pinned_patch(self):
        self.assertFalse(satisfies("1.2.2", "^1.2.3"))

    def test_caret_on_zero_major_treats_minor_as_the_breaking_axis(self):
        # ^0.2.3 means >=0.2.3 <0.3.0. Getting this wrong is the classic
        # semver bug: 0.x packs would silently accept a breaking release.
        self.assertTrue(satisfies("0.2.3", "^0.2.3"))
        self.assertTrue(satisfies("0.2.99", "^0.2.3"))
        self.assertFalse(satisfies("0.3.0", "^0.2.3"))

    def test_caret_on_zero_zero_pins_the_patch_exactly(self):
        self.assertTrue(satisfies("0.0.3", "^0.0.3"))
        self.assertFalse(satisfies("0.0.4", "^0.0.3"))

    def test_caret_accepts_a_partial_version(self):
        self.assertTrue(satisfies("1.7.0", "^1.0"))
        self.assertFalse(satisfies("2.0.0", "^1.0"))

    def test_omitting_a_segment_widens_the_caret_rather_than_narrowing_it(self):
        # `^0` is bounded by the major, `^0.0` by the minor, `^0.0.0` by the
        # patch. Collapsing all three to `<0.0.1` refuses pins node-semver
        # accepts — and because an unsatisfiable pin is a hard error, that
        # turns a perfectly good pin into a failed review.
        self.assertTrue(satisfies("0.9.9", "^0"))
        self.assertFalse(satisfies("1.0.0", "^0"))

        self.assertTrue(satisfies("0.0.9", "^0.0"))
        self.assertFalse(satisfies("0.1.0", "^0.0"))

        self.assertTrue(satisfies("0.0.0", "^0.0.0"))
        self.assertFalse(satisfies("0.0.1", "^0.0.0"))


class TildeTests(unittest.TestCase):
    def test_tilde_allows_patch_but_not_minor(self):
        self.assertTrue(satisfies("1.2.3", "~1.2.3"))
        self.assertTrue(satisfies("1.2.99", "~1.2.3"))
        self.assertFalse(satisfies("1.3.0", "~1.2.3"))

    def test_tilde_with_only_a_major_allows_the_whole_major(self):
        self.assertTrue(satisfies("1.9.0", "~1"))
        self.assertFalse(satisfies("2.0.0", "~1"))


class WildcardTests(unittest.TestCase):
    def test_bare_star_and_empty_and_any_match_everything(self):
        for spec in ("*", "", "any", "latest"):
            with self.subTest(spec=spec):
                self.assertTrue(satisfies("0.0.1", spec))
                self.assertTrue(satisfies("99.4.2", spec))
                self.assertTrue(Spec(spec).is_any)

    def test_major_wildcard_bounds_the_major(self):
        self.assertTrue(satisfies("1.0.0", "1.x"))
        self.assertTrue(satisfies("1.99.4", "1.x"))
        self.assertFalse(satisfies("2.0.0", "1.x"))

    def test_minor_wildcard_bounds_the_minor(self):
        self.assertTrue(satisfies("1.2.99", "1.2.x"))
        self.assertFalse(satisfies("1.3.0", "1.2.x"))

    def test_a_partial_exact_spec_behaves_as_a_wildcard_range(self):
        # `=1.2` is not "version 1.2.0"; it is the 1.2.x range.
        self.assertTrue(satisfies("1.2.7", "=1.2"))
        self.assertFalse(satisfies("1.3.0", "=1.2"))


class RangeAndOrTests(unittest.TestCase):
    def test_space_separated_comparators_are_anded(self):
        self.assertTrue(satisfies("1.5.0", ">=1.2.3 <2.0.0"))
        self.assertFalse(satisfies("1.2.2", ">=1.2.3 <2.0.0"))
        self.assertFalse(satisfies("2.0.0", ">=1.2.3 <2.0.0"))

    def test_an_operator_separated_from_its_version_still_parses(self):
        self.assertTrue(satisfies("1.5.0", ">= 1.2.3 < 2.0.0"))

    def test_double_pipe_alternatives_are_ored(self):
        spec = "^1.0 || ^2.0"
        self.assertTrue(satisfies("1.4.0", spec))
        self.assertTrue(satisfies("2.9.0", spec))
        self.assertFalse(satisfies("3.0.0", spec))

    def test_exact_specs_match_only_that_version(self):
        self.assertTrue(satisfies("1.2.3", "1.2.3"))
        self.assertTrue(satisfies("1.2.3", "=1.2.3"))
        self.assertFalse(satisfies("1.2.4", "1.2.3"))

    def test_build_metadata_is_ignored_for_matching(self):
        self.assertTrue(satisfies("1.2.3+20260930", "1.2.3"))


class PrereleaseOrderingTests(unittest.TestCase):
    def test_a_prerelease_is_lower_than_its_release(self):
        self.assertLess(Version.parse("1.0.0-alpha"), Version.parse("1.0.0"))
        self.assertLess(Version.parse("1.0.0-rc.1"), Version.parse("1.0.0"))

    def test_fewer_prerelease_identifiers_sort_lower(self):
        self.assertLess(Version.parse("1.0.0-alpha"), Version.parse("1.0.0-alpha.1"))

    def test_numeric_prerelease_identifiers_sort_below_alphanumeric(self):
        self.assertLess(Version.parse("1.0.0-alpha.1"), Version.parse("1.0.0-alpha.beta"))

    def test_numeric_prerelease_identifiers_compare_numerically_not_as_strings(self):
        # "11" < "2" as strings; 2 < 11 as numbers. The spec says numbers.
        self.assertLess(Version.parse("1.0.0-beta.2"), Version.parse("1.0.0-beta.11"))

    def test_the_canonical_precedence_chain_sorts_correctly(self):
        chain = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
        ]
        parsed = [Version.parse(v) for v in chain]
        self.assertEqual(sorted(parsed), parsed)

    def test_build_metadata_does_not_affect_equality(self):
        self.assertEqual(Version.parse("1.2.3+a"), Version.parse("1.2.3+b"))

    def test_version_round_trips_through_str(self):
        for text in ("1.2.3", "1.2.3-rc.1", "1.2.3-rc.1+build.9"):
            with self.subTest(text=text):
                self.assertEqual(str(Version.parse(text)), text)


class InvalidInputTests(unittest.TestCase):
    """Invalid input raises. A resolver that shrugs at `1.2` and guesses
    `1.2.0` turns a typo in a pin into a different rule set."""

    def test_incomplete_or_junk_versions_raise(self):
        for bad in ("1.2", "v1", "not-a-version", "1.2.3.4", ""):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidVersion):
                    Version.parse(bad)

    def test_an_empty_alternative_raises(self):
        with self.assertRaises(InvalidSpec):
            Spec("1.2.3 || ")

    def test_a_wildcard_with_an_inequality_operator_raises(self):
        # ">1.x" has no defensible meaning; guessing one is worse than failing.
        for bad in (">1.x", ">=x.y", "<2.*"):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidSpec):
                    Spec(bad)

    def test_too_many_version_segments_raises(self):
        with self.assertRaises(InvalidSpec):
            Spec("1.2.3.4.5")

    def test_non_numeric_segments_raise(self):
        with self.assertRaises(InvalidSpec):
            Spec("^one.two.three")


if __name__ == "__main__":
    unittest.main()
