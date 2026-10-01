"""`.pr-sentinel.yml` parsing.

Two claims in DESIGN s6 and s15 are load-bearing and are what this module
defends:

* **Mode is a preset over the severity map, not a separate code path.** If
  `gated` expanded into anything other than what an explicit `authority:`
  block produces, there would be two enforcement paths and one of them would
  eventually be wrong.
* **Pack pins are independent and parsed from either form.** Repos write
  both `core@^1.0` and `{core: "^1.0"}`; a parser that understands one and
  silently mis-reads the other pins nothing.

Everything the engine refuses to run with is fatal, never a warning. A
reviewer that quietly runs something other than what was configured is worse
than one that does not run at all.
"""

from __future__ import annotations

import unittest

from pr_sentinel.config import (
    DEFAULT_AGENT_PASSES,
    MODE_PRESETS,
    ConfigError,
    PackPin,
    default_config,
    load_config,
    parse_config,
)
from pr_sentinel.models import Authority, Severity
from tests.helpers import TempDirTestCase, write_tree


class ModePresetTests(unittest.TestCase):
    def test_each_mode_expands_to_the_map_an_explicit_authority_block_would_give(self):
        # DESIGN s6: "Mode is a convenience layer over the per-severity map,
        # not a separate code path."
        for mode, preset in MODE_PRESETS.items():
            with self.subTest(mode=mode):
                from_mode = parse_config({"version": 1, "mode": mode})
                explicit = parse_config(
                    {
                        "version": 1,
                        "mode": "advisory",
                        "authority": {s.value: a.value for s, a in preset.items()},
                    }
                )
                self.assertEqual(from_mode.authority, explicit.authority)

    def test_gated_blocks_critical_only(self):
        cfg = parse_config({"version": 1, "mode": "gated"})
        self.assertIs(cfg.authority_for(Severity.CRITICAL), Authority.BLOCKING)
        self.assertIs(cfg.authority_for(Severity.HIGH), Authority.COMMENT)

    def test_advisory_blocks_nothing_at_any_severity(self):
        cfg = parse_config({"version": 1, "mode": "advisory"})
        self.assertNotIn(Authority.BLOCKING, cfg.authority.values())

    def test_blocking_mode_blocks_high_as_well_as_critical(self):
        cfg = parse_config({"version": 1, "mode": "blocking"})
        self.assertIs(cfg.authority_for(Severity.CRITICAL), Authority.BLOCKING)
        self.assertIs(cfg.authority_for(Severity.HIGH), Authority.BLOCKING)
        self.assertIs(cfg.authority_for(Severity.MEDIUM), Authority.COMMENT)

    def test_an_explicit_authority_entry_overrides_the_preset_for_that_severity_only(self):
        cfg = parse_config(
            {"version": 1, "mode": "gated", "authority": {"high": "blocking"}}
        )
        self.assertIs(cfg.authority_for(Severity.HIGH), Authority.BLOCKING)
        # The rest of the preset survives untouched.
        self.assertIs(cfg.authority_for(Severity.CRITICAL), Authority.BLOCKING)
        self.assertIs(cfg.authority_for(Severity.MEDIUM), Authority.COMMENT)
        self.assertIs(cfg.authority_for(Severity.LOW), Authority.SUMMARY_ONLY)

    def test_authority_can_downgrade_as_well_as_upgrade(self):
        cfg = parse_config(
            {"version": 1, "mode": "gated", "authority": {"critical": "comment"}}
        )
        self.assertIs(cfg.authority_for(Severity.CRITICAL), Authority.COMMENT)

    def test_the_mode_string_is_recorded_for_the_comment(self):
        self.assertEqual(parse_config({"version": 1, "mode": "blocking"}).mode, "blocking")


class PackPinTests(unittest.TestCase):
    def test_pins_parse_from_the_list_form(self):
        cfg = parse_config(
            {"version": 1, "packs": ["core@^1.0", "supabase@1.2.3", "react-vite"]}
        )
        self.assertEqual(
            cfg.packs,
            [
                PackPin("core", "^1.0"),
                PackPin("supabase", "1.2.3"),
                PackPin("react-vite", "*"),
            ],
        )

    def test_pins_parse_from_the_mapping_form(self):
        cfg = parse_config({"version": 1, "packs": {"core": "^1.0", "supabase": "1.2.3"}})
        self.assertEqual(cfg.packs, [PackPin("core", "^1.0"), PackPin("supabase", "1.2.3")])

    def test_both_forms_produce_identical_pins(self):
        listed = parse_config({"version": 1, "packs": ["core@^1.0", "supabase@~2.1"]})
        mapped = parse_config({"version": 1, "packs": {"core": "^1.0", "supabase": "~2.1"}})
        self.assertEqual(listed.packs, mapped.packs)

    def test_whitespace_around_a_pin_is_tolerated(self):
        cfg = parse_config({"version": 1, "packs": ["  core @ ^1.0  "]})
        self.assertEqual(cfg.packs, [PackPin("core", "^1.0")])

    def test_a_range_pin_containing_spaces_survives_intact(self):
        cfg = parse_config({"version": 1, "packs": ["core@>=1.0.0 <2.0.0"]})
        self.assertEqual(cfg.packs, [PackPin("core", ">=1.0.0 <2.0.0")])

    def test_an_unpinned_pack_records_the_any_spec_rather_than_a_version(self):
        cfg = parse_config({"version": 1, "packs": ["core"]})
        self.assertEqual(cfg.packs[0].spec, "*")

    def test_a_duplicate_pack_is_rejected(self):
        # Two pins for one pack means one of them is not being honoured, and
        # which one depends on dict ordering. Refuse rather than pick.
        with self.assertRaises(ConfigError) as caught:
            parse_config({"version": 1, "packs": ["core@^1.0", "core@^2.0"]})
        self.assertIn("more than once", str(caught.exception))

    def test_pack_names_are_exposed_for_resolution(self):
        cfg = parse_config({"version": 1, "packs": ["core@^1.0", "supabase"]})
        self.assertEqual(cfg.pack_names, ["core", "supabase"])

    def test_packs_as_a_scalar_is_rejected(self):
        with self.assertRaises(ConfigError):
            parse_config({"version": 1, "packs": "core"})


class RejectionTests(unittest.TestCase):
    def test_an_unknown_mode_is_rejected_and_the_message_lists_the_real_ones(self):
        with self.assertRaises(ConfigError) as caught:
            parse_config({"version": 1, "mode": "strict"})
        message = str(caught.exception)
        self.assertIn("unknown mode", message)
        for mode in MODE_PRESETS:
            self.assertIn(mode, message)

    def test_an_unknown_severity_in_the_authority_block_is_rejected(self):
        with self.assertRaises(ConfigError) as caught:
            parse_config({"version": 1, "authority": {"catastrophic": "blocking"}})
        self.assertIn("unknown severity", str(caught.exception))

    def test_an_unknown_authority_value_is_rejected(self):
        with self.assertRaises(ConfigError) as caught:
            parse_config({"version": 1, "authority": {"high": "explode"}})
        self.assertIn("unknown authority", str(caught.exception))

    def test_an_unknown_agent_pass_is_rejected_rather_than_skipped(self):
        # A typo'd pass name that is merely skipped is a review everyone
        # believes ran. DESIGN s9 names exactly five passes.
        with self.assertRaises(ConfigError) as caught:
            parse_config({"version": 1, "agent": {"passes": ["security", "vibes"]}})
        message = str(caught.exception)
        self.assertIn("vibes", message)
        self.assertIn("security", message)

    def test_the_five_designed_passes_are_all_accepted(self):
        cfg = parse_config({"version": 1, "agent": {"passes": list(DEFAULT_AGENT_PASSES)}})
        self.assertEqual(cfg.agent.passes, list(DEFAULT_AGENT_PASSES))

    def test_an_unsupported_config_version_is_rejected(self):
        with self.assertRaises(ConfigError):
            parse_config({"version": 99})

    def test_a_non_positive_numeric_setting_is_rejected(self):
        with self.assertRaises(ConfigError):
            parse_config({"version": 1, "agent": {"max_findings": 0}})

    def test_a_non_integer_numeric_setting_is_rejected(self):
        with self.assertRaises(ConfigError):
            parse_config({"version": 1, "agent": {"max_findings": "lots"}})

    def test_a_non_mapping_agent_block_is_rejected(self):
        with self.assertRaises(ConfigError):
            parse_config({"version": 1, "agent": ["security"]})

    def test_an_unknown_top_level_key_warns_rather_than_fails(self):
        # An unknown key cannot make the engine run the wrong rules, so it
        # earns a warning and not a refusal.
        cfg = parse_config({"version": 1, "rulez": []})
        self.assertTrue(any("rulez" in w for w in cfg.warnings))


class AgentAndIgnoreTests(unittest.TestCase):
    def test_disabling_verification_warns_loudly(self):
        cfg = parse_config({"version": 1, "agent": {"verification": False}})
        self.assertFalse(cfg.agent.verification)
        self.assertTrue(any("verification" in w for w in cfg.warnings))

    def test_ignore_paths_and_rules_are_read(self):
        cfg = parse_config(
            {"version": 1, "ignore": {"paths": ["dist/"], "rules": ["core.huge-diff"]}}
        )
        self.assertEqual(cfg.ignore.paths, ["dist/"])
        self.assertEqual(cfg.ignore.rules, ["core.huge-diff"])

    def test_lore_and_local_rules_paths_are_read(self):
        cfg = parse_config(
            {"version": 1, "lore": ".pr-sentinel/lore.md", "local_rules": "rules/"}
        )
        self.assertEqual(cfg.lore_path, ".pr-sentinel/lore.md")
        self.assertEqual(cfg.local_rules_path, "rules/")


class DefaultConfigTests(TempDirTestCase):
    def test_a_repo_with_no_config_file_gets_core_only_in_advisory_mode(self):
        # DESIGN: "A tool that shows up uninvited with opinions about your
        # database schema does not get adopted."
        root = self.make_repo({"README.md": "hi\n"})
        cfg = load_config(root)
        self.assertEqual(cfg.pack_names, ["core"])
        self.assertEqual(cfg.mode, "advisory")
        self.assertNotIn(Authority.BLOCKING, cfg.authority.values())

    def test_the_default_config_says_out_loud_that_it_is_a_default(self):
        cfg = default_config()
        self.assertTrue(any("No .pr-sentinel.yml" in w for w in cfg.warnings))

    def test_a_config_file_is_found_and_parsed_from_the_repo_root(self):
        root = self.make_repo()
        write_tree(
            root,
            {
                ".pr-sentinel.yml": (
                    "version: 1\n"
                    "packs: [core@^1.0, supabase@^1.0]\n"
                    "mode: blocking\n"
                )
            },
        )
        cfg = load_config(root)
        self.assertEqual(cfg.mode, "blocking")
        self.assertEqual(cfg.pack_names, ["core", "supabase"])
        self.assertEqual(cfg.source_path, root / ".pr-sentinel.yml")

    def test_the_yaml_alternative_extension_is_also_found(self):
        root = self.make_repo()
        write_tree(root, {".pr-sentinel.yaml": "version: 1\nmode: advisory\n"})
        self.assertEqual(load_config(root).mode, "advisory")

    def test_invalid_yaml_is_a_hard_error_not_a_fallback_to_defaults(self):
        root = self.make_repo()
        write_tree(root, {".pr-sentinel.yml": "version: 1\npacks: [core\n"})
        with self.assertRaises(ConfigError):
            load_config(root)

    def test_a_top_level_list_is_rejected(self):
        root = self.make_repo()
        write_tree(root, {".pr-sentinel.yml": "- core\n- supabase\n"})
        with self.assertRaises(ConfigError):
            load_config(root)

    def test_an_explicitly_named_missing_config_is_an_error_not_a_default(self):
        root = self.make_repo()
        with self.assertRaises(ConfigError):
            load_config(root, root / "nope.yml")


if __name__ == "__main__":
    unittest.main()
