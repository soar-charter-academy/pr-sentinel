"""Resolving independent pack pins against the packs this engine ships.

DESIGN s15 resolved pack versioning in favour of independent pinning, and the
loader's docstring states the consequence: resolution is an *assertion*. If
the shipped pack does not satisfy the pin, that is a hard error telling the
user which engine tag they want. A warning would be exactly the silent
verdict change that `@main` pinning was rejected over (DESIGN s4).

These run against the real `packs/` directory rather than a synthetic
fixture, so a shipped `pack.yml` that stops parsing fails here.
"""

from __future__ import annotations

import unittest

from pr_sentinel.adapters import all_adapters
from pr_sentinel.models import Severity
from pr_sentinel.packs.loader import (
    Pack,
    PackError,
    PackVersionConflict,
    compose_briefing,
    discover_packs,
    load_lore,
    load_pack,
    resolve_packs,
)
from pr_sentinel.semver import Version
from tests.helpers import PACKS_DIR, TempDirTestCase, make_config, write_tree


class DiscoveryTests(unittest.TestCase):
    def test_the_six_designed_packs_are_all_shipped_and_parse(self):
        # DESIGN s5 names the initial packs. If one stops loading, every repo
        # pinning it gets a hard error, so this is worth asserting directly.
        found = discover_packs(PACKS_DIR)
        self.assertEqual(
            sorted(found),
            ["core", "github-actions", "privacy-edu", "react-vite", "supabase", "supply-chain"],
        )

    def test_every_shipped_pack_has_a_parseable_version_and_a_briefing(self):
        # A pack contributes *both* halves (DESIGN s5): rules and a briefing.
        # A pack with no briefing teaches the agent tier nothing.
        for name, pack in discover_packs(PACKS_DIR).items():
            with self.subTest(pack=name):
                self.assertIsInstance(pack.version, Version)
                self.assertTrue(pack.briefing.strip(), f"{name} ships no briefing")


class AdapterManifestTests(TempDirTestCase):
    """`adapters:` alongside `checks:` (DESIGN-V2 §3).

    Parsed the same way as a check entry on purpose. A pack author turning on
    `zizmor` should not have to learn a second syntax, and a consuming repo
    enabling the `github-actions` pack should not have to separately know that
    the pack needs an external tool — that is the pack's business, declared in
    the pack's manifest.
    """

    def _pack(self, body: str) -> Pack:
        root = self.tmp / "packs" / "fixture"
        root.mkdir(parents=True, exist_ok=True)
        (root / "pack.yml").write_text(
            "name: fixture\nversion: 1.0.0\n" + body, encoding="utf-8"
        )
        return load_pack(root)

    def test_a_bare_string_entry_enables_the_adapter(self):
        pack = self._pack("adapters:\n  - gitleaks\n")
        self.assertEqual([a.adapter_id for a in pack.adapters], ["gitleaks"])
        self.assertEqual(pack.adapters[0].pack, "fixture")
        self.assertTrue(pack.adapters[0].enabled)
        self.assertIsNone(pack.adapters[0].severity_floor)
        self.assertIsNone(pack.adapters[0].severity_ceiling)

    def test_a_mapping_entry_carries_severity_bounds_and_options(self):
        # The reason an adapter entry is not just a string. A tool calibrates
        # severity to its own audience; the pack narrows the range rather than
        # the engine second-guessing individual findings, which would break
        # the promise in adapters/base.py that we never rewrite their verdicts.
        pack = self._pack(
            "adapters:\n"
            "  - id: zizmor\n"
            "    severity_floor: low\n"
            "    severity_ceiling: medium\n"
            "    options:\n"
            "      persona: regular\n"
        )
        spec = pack.adapters[0]
        self.assertEqual(spec.adapter_id, "zizmor")
        self.assertIs(spec.severity_floor, Severity.LOW)
        self.assertIs(spec.severity_ceiling, Severity.MEDIUM)
        self.assertEqual(spec.option("persona"), "regular")

    def test_unknown_keys_fall_through_to_options(self):
        # Mirrors `_load_checks`. A pack can pass an adapter a flag this
        # engine has never heard of, which is what lets an adapter gain an
        # option without a loader change.
        pack = self._pack("adapters:\n  - id: socket\n    timeout: 90\n")
        self.assertEqual(pack.adapters[0].option("timeout"), 90)

    def test_enabled_false_is_preserved_rather_than_dropped(self):
        # It must survive parsing: `runner.run_adapters` reports a disabled
        # adapter as skipped-by-pack, and dropping the entry here would make
        # "switched off" indistinguishable from "never asked for".
        pack = self._pack("adapters:\n  - id: squawk\n    enabled: false\n")
        self.assertFalse(pack.adapters[0].enabled)

    def test_an_entry_with_no_id_is_a_hard_error(self):
        with self.assertRaises(PackError):
            self._pack("adapters:\n  - severity_floor: low\n")

    def test_a_non_mapping_non_string_entry_is_a_hard_error(self):
        with self.assertRaises(PackError):
            self._pack("adapters:\n  - [gitleaks]\n")

    def test_an_unparseable_severity_is_a_hard_error_not_a_warning(self):
        # A pack that meant to cap zizmor at `medium` and typo'd it would
        # otherwise ship blocking findings it intended to be advisory. Silence
        # there is the silent-verdict-change failure independent pinning
        # exists to prevent.
        with self.assertRaises(PackError):
            self._pack("adapters:\n  - id: zizmor\n    severity_ceiling: medum\n")

    def test_a_pack_with_no_adapters_key_gets_an_empty_list(self):
        self.assertEqual(self._pack("checks: []\n").adapters, [])


class ShippedAdapterEnablementTests(unittest.TestCase):
    """What the six shipped packs actually turn on, asserted against `packs/`.

    These are the rollout decisions from DESIGN-V2 §3 written down somewhere a
    test can check. A pack that silently stopped enabling `gitleaks` would be
    a repository with no secret scanning and no error.
    """

    def setUp(self) -> None:
        self.packs = discover_packs(PACKS_DIR)

    def test_each_pack_enables_the_adapters_the_rollout_assigned_it(self):
        expected = {
            "core": ["gitleaks"],
            "supply-chain": ["socket"],
            "github-actions": ["zizmor", "actionlint"],
            "supabase": ["supabase-advisors", "squawk"],
            "react-vite": [],
            "privacy-edu": [],
        }
        actual = {
            name: [a.adapter_id for a in pack.adapters]
            for name, pack in self.packs.items()
        }
        self.assertEqual(actual, expected)

    def test_every_adapter_a_shipped_pack_enables_is_implemented(self):
        # The `validate`-time guarantee, pinned at build time too: a pack
        # naming an adapter this engine does not have is a tool everyone
        # believes is running.
        known = set(all_adapters())
        for name, pack in self.packs.items():
            for spec in pack.adapters:
                with self.subTest(pack=name, adapter=spec.adapter_id):
                    self.assertIn(spec.adapter_id, known)

    def test_the_packs_that_now_own_no_rules_still_ship_a_briefing(self):
        # `core` and `github-actions` have no checks and no semgrep rules
        # left. The briefing is the whole reason they are still packs: an
        # adapter audits the workflow, it does not teach Tier 2 what this
        # repo's CI mistakes have been. A pack is both halves (DESIGN s5).
        for name in ("core", "github-actions"):
            with self.subTest(pack=name):
                pack = self.packs[name]
                self.assertEqual(pack.script_checks, [])
                self.assertEqual(pack.rule_files, [])
                self.assertTrue(pack.adapters)
                self.assertTrue(pack.briefing.strip())

    def test_the_packs_whose_rule_sets_changed_bumped_their_minor(self):
        # Independent pinning means a consumer must be able to *see* that the
        # rules moved. A changed rule set at the same version is the silent
        # verdict change the whole scheme exists to prevent.
        for name in ("core", "supply-chain", "supabase", "github-actions"):
            with self.subTest(pack=name):
                version = self.packs[name].version
                self.assertEqual((version.major, version.minor), (1, 1))

        for name in ("react-vite", "privacy-edu"):
            with self.subTest(pack=name):
                version = self.packs[name].version
                self.assertEqual((version.major, version.minor), (1, 0))

    def test_the_surviving_script_checks_are_exactly_the_ones_we_still_own(self):
        enabled = sorted(
            spec.check_id
            for pack in self.packs.values()
            for spec in pack.script_checks
        )
        self.assertEqual(
            enabled,
            [
                "privacy-edu.analytics-student-identifier",
                "privacy-edu.pii-in-url",
                "privacy-edu.pii-new-sink",
                "privacy-edu.test-data-bleed",
                "privacy-edu.widens-pii-read",
                "react-vite.browser-storage",
                "react-vite.client-env-secrets",
                "supabase.migration-immutability",
                "supabase.migration-numbering",
                "supabase.missing-grants",
                "supabase.permissive-policy",
                "supply-chain.lockfile-integrity",
            ],
        )


class ResolutionTests(unittest.TestCase):
    def test_a_satisfiable_pin_resolves_to_the_shipped_pack(self):
        core = discover_packs(PACKS_DIR)["core"]
        cfg = make_config(packs=[f"core@^{core.version.major}.{core.version.minor}"])
        packs, warnings = resolve_packs(cfg, PACKS_DIR)
        self.assertEqual([p.name for p in packs], ["core"])
        self.assertEqual(packs[0].version, core.version)
        self.assertEqual(warnings, [])

    def test_an_unsatisfiable_pin_is_a_hard_error_and_not_a_warning(self):
        # THE load-bearing behaviour of independent pinning. Running a rule
        # set the repo did not pin must be impossible, not merely noted.
        cfg = make_config(packs=["core@^99.0"])
        with self.assertRaises(PackVersionConflict) as caught:
            resolve_packs(cfg, PACKS_DIR)
        message = str(caught.exception)
        self.assertIn("core@^99.0", message)
        self.assertIn("engine ships", message)
        # The message has to tell the user what to do about it.
        self.assertIn("engine tag", message)

    def test_a_version_conflict_is_a_pack_error_so_callers_can_catch_either(self):
        self.assertTrue(issubclass(PackVersionConflict, PackError))

    def test_an_exact_pin_one_patch_off_still_fails(self):
        core = discover_packs(PACKS_DIR)["core"]
        bumped = f"{core.version.major}.{core.version.minor}.{core.version.patch + 1}"
        cfg = make_config(packs=[f"core@{bumped}"])
        with self.assertRaises(PackVersionConflict):
            resolve_packs(cfg, PACKS_DIR)

    def test_an_unknown_pack_raises_and_lists_what_is_available(self):
        cfg = make_config(packs=["kubernetes"])
        with self.assertRaises(PackError) as caught:
            resolve_packs(cfg, PACKS_DIR)
        message = str(caught.exception)
        self.assertIn("kubernetes", message)
        self.assertIn("core", message)

    def test_an_unknown_pack_is_not_reported_as_a_version_conflict(self):
        cfg = make_config(packs=["kubernetes"])
        with self.assertRaises(PackError) as caught:
            resolve_packs(cfg, PACKS_DIR)
        self.assertNotIsInstance(caught.exception, PackVersionConflict)

    def test_an_unpinned_pack_resolves_but_warns_with_a_suggested_pin(self):
        cfg = make_config(packs=["core"])
        packs, warnings = resolve_packs(cfg, PACKS_DIR)
        self.assertEqual([p.name for p in packs], ["core"])
        self.assertEqual(len(warnings), 1)
        self.assertIn("unpinned", warnings[0])
        self.assertIn(f"core@^{packs[0].version.major}.{packs[0].version.minor}", warnings[0])

    def test_a_malformed_pin_spec_is_a_pack_error(self):
        cfg = make_config(packs=["core@>=x.y"])
        with self.assertRaises(PackError):
            resolve_packs(cfg, PACKS_DIR)

    def test_pins_are_independent_so_one_conflict_names_only_that_pack(self):
        # The point of independent pinning: the fix is local to one pin.
        cfg = make_config(packs=["core@^1.0", "supabase@^99.0"])
        with self.assertRaises(PackVersionConflict) as caught:
            resolve_packs(cfg, PACKS_DIR)
        message = str(caught.exception)
        self.assertIn("supabase@^99.0", message)
        self.assertIn("does not affect", message)

    def test_the_resolved_pack_records_what_it_was_pinned_as(self):
        cfg = make_config(packs=["core@^1.0"])
        packs, _ = resolve_packs(cfg, PACKS_DIR)
        self.assertEqual(packs[0].pinned_as, "^1.0")

    def test_an_engine_too_old_for_a_pack_is_a_version_conflict(self):
        cfg = make_config(packs=["core@^1.0"])
        with self.assertRaises(PackVersionConflict):
            resolve_packs(cfg, PACKS_DIR, engine_version="0.0.1")

    def test_resolution_preserves_the_configured_order(self):
        cfg = make_config(packs=["supabase@^1.0", "core@^1.0"])
        packs, _ = resolve_packs(cfg, PACKS_DIR)
        self.assertEqual([p.name for p in packs], ["supabase", "core"])


def _pack(name: str, briefing: str, passes: list[str]) -> Pack:
    return Pack(
        name=name,
        version=Version.parse("1.0.0"),
        description="",
        path=PACKS_DIR / name,
        briefing=briefing,
        briefing_passes=passes,
    )


class ComposeBriefingTests(unittest.TestCase):
    """DESIGN s5 pairs rules with a briefing; s8 makes lore the local fact
    that wins where the two conflict."""

    def setUp(self) -> None:
        self.security_only = _pack("core", "CORE-BRIEFING", ["security"])
        self.privacy_too = _pack("supabase", "SUPABASE-BRIEFING", ["security", "privacy"])
        self.always = _pack("everything", "ALWAYS-BRIEFING", [])
        self.packs = [self.security_only, self.privacy_too, self.always]

    def test_a_pass_only_sees_briefings_declared_for_it(self):
        # Keeping a supabase briefing out of the `parity` prompt is a real
        # token saving on every single review.
        text = compose_briefing(self.packs, "privacy")
        self.assertNotIn("CORE-BRIEFING", text)
        self.assertIn("SUPABASE-BRIEFING", text)

    def test_a_pack_with_no_declared_passes_is_included_everywhere(self):
        for pass_name in ("security", "privacy", "parity"):
            with self.subTest(pass_name=pass_name):
                self.assertIn("ALWAYS-BRIEFING", compose_briefing(self.packs, pass_name))

    def test_a_pass_no_pack_briefs_gets_only_the_always_on_briefing(self):
        text = compose_briefing(self.packs, "parity")
        self.assertNotIn("CORE-BRIEFING", text)
        self.assertNotIn("SUPABASE-BRIEFING", text)

    def test_lore_goes_last_because_the_local_fact_wins(self):
        text = compose_briefing(self.packs, "security", lore="LORE-BODY")
        self.assertIn("LORE-BODY", text)
        self.assertGreater(text.index("LORE-BODY"), text.index("CORE-BRIEFING"))
        self.assertGreater(text.index("LORE-BODY"), text.index("ALWAYS-BRIEFING"))

    def test_the_lore_section_states_that_it_overrides_the_pack_guidance(self):
        text = compose_briefing(self.packs, "security", lore="LORE-BODY")
        self.assertIn("these win", text)

    def test_blank_lore_adds_no_section(self):
        self.assertNotIn("Repository lore", compose_briefing(self.packs, "security", lore="  \n"))

    def test_a_pack_with_an_empty_briefing_contributes_nothing(self):
        empty = _pack("hollow", "", [])
        self.assertEqual(compose_briefing([empty], "security"), "")


class LoreLoadingTests(TempDirTestCase):
    def test_lore_is_read_from_the_consuming_repo(self):
        # DESIGN s8: lore stays in the consuming repo, which is what makes a
        # public engine safe.
        root = self.make_repo()
        write_tree(root, {".pr-sentinel/lore.md": "service_role needs its own GRANT.\n"})
        cfg = make_config(lore_path=".pr-sentinel/lore.md")
        self.assertIn("service_role", load_lore(root, cfg) or "")

    def test_a_configured_but_missing_lore_file_returns_none_rather_than_raising(self):
        cfg = make_config(lore_path=".pr-sentinel/lore.md")
        self.assertIsNone(load_lore(self.make_repo(), cfg))

    def test_no_configured_lore_returns_none(self):
        self.assertIsNone(load_lore(self.make_repo(), make_config()))


if __name__ == "__main__":
    unittest.main()
