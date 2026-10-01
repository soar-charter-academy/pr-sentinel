"""The §7 guardrails on rules authored in a consuming repo.

DESIGN s7 sets two tiers of authorship with deliberately different bars.
Local rules live in the consuming repo, anyone may add one, and there is no
review gate beyond that repo's own PR process — so the engine has to supply
the guardrails the process does not:

* declarative only, never executable code;
* severity capped at `high`, because `critical` is curated-only and a local
  rule must never be able to block a merge on its own;
* `id`, `message` and `rationale` all mandatory.

The last is explicitly not bureaucracy: "a finding without a stated reason
gets suppressed, and a rule that is always suppressed trains everyone to
ignore the tool."

The staged YAML is asserted on disk as well as in the report, because the
report is what a human reads and the staging file is what semgrep actually
runs. A cap that is reported but not applied is worse than no cap.
"""

from __future__ import annotations

import unittest

import yaml

from pr_sentinel.tier1.local_rules import LOCAL_ID_PREFIX, load_local_rules
from tests.helpers import TempDirTestCase, write_tree

RULES_DIR = ".pr-sentinel/rules/"


def rule_yaml(**fields) -> str:
    return yaml.safe_dump({"rules": [fields]}, sort_keys=False)


VALID = {
    "id": "no-console-log",
    "message": "console.log left in shipped code",
    "languages": ["typescript"],
    "severity": "WARNING",
    "patterns": [{"pattern": "console.log(...)"}],
    "metadata": {
        "rationale": "Console output in the client bundle leaks internals to anyone with devtools.",
        "sentinel-severity": "medium",
    },
}


class LocalRuleTestCase(TempDirTestCase):
    def load(self, files: dict[str, str]):
        root = self.make_repo()
        write_tree(root, {f"{RULES_DIR}{name}": body for name, body in files.items()})
        staging = self.tmp / "staging"
        return load_local_rules(root, RULES_DIR, staging_dir=staging)

    def staged_rules(self, report) -> list[dict]:
        out: list[dict] = []
        for path in report.accepted_files:
            out.extend(yaml.safe_load(path.read_text(encoding="utf-8"))["rules"])
        return out


class AcceptanceTests(LocalRuleTestCase):
    def test_a_valid_rule_is_accepted_and_written_to_staging(self):
        report = self.load({"rules.yml": rule_yaml(**VALID)})
        self.assertEqual(report.rejections, [])
        self.assertTrue(report.ok)
        self.assertEqual(len(report.accepted_files), 1)
        staged = self.staged_rules(report)
        self.assertEqual(len(staged), 1)
        self.assertEqual(staged[0]["message"], VALID["message"])

    def test_the_staged_copy_is_what_runs_not_the_original(self):
        # Rules are rewritten into staging so that a normalised severity or
        # an enforced namespace is what actually runs, not just what was
        # reported.
        report = self.load({"rules.yml": rule_yaml(**VALID)})
        self.assertNotIn(
            ".pr-sentinel", str(report.accepted_files[0].parent),
        )

    def test_a_rule_with_no_declared_severity_defaults_to_medium(self):
        fields = dict(VALID)
        fields["metadata"] = {"rationale": "Because."}
        report = self.load({"rules.yml": rule_yaml(**fields)})
        self.assertEqual(self.staged_rules(report)[0]["metadata"]["sentinel-severity"], "medium")

    def test_every_staged_rule_is_stamped_as_belonging_to_the_local_pack(self):
        report = self.load({"rules.yml": rule_yaml(**VALID)})
        self.assertEqual(self.staged_rules(report)[0]["metadata"]["pack"], "local")

    def test_no_rules_directory_is_not_an_error(self):
        root = self.make_repo()
        report = load_local_rules(root, RULES_DIR, staging_dir=self.tmp / "staging")
        self.assertEqual(report.rejections, [])
        self.assertEqual(report.accepted_files, [])

    def test_rationale_may_also_be_spelled_why(self):
        fields = dict(VALID)
        fields["metadata"] = {"why": "Short but stated."}
        report = self.load({"rules.yml": rule_yaml(**fields)})
        self.assertEqual(report.rejections, [])
        self.assertEqual(self.staged_rules(report)[0]["metadata"]["rationale"], "Short but stated.")


class MandatoryRationaleTests(LocalRuleTestCase):
    def test_a_rule_missing_a_rationale_is_rejected(self):
        # DESIGN s7. Not bureaucracy: a finding without a stated reason gets
        # suppressed, and a rule that is always suppressed trains everyone to
        # ignore the tool.
        fields = dict(VALID)
        fields["metadata"] = {"sentinel-severity": "medium"}
        report = self.load({"rules.yml": rule_yaml(**fields)})
        self.assertFalse(report.ok)
        self.assertEqual(self.staged_rules(report), [])
        self.assertTrue(any("rationale" in r for r in report.rejections))

    def test_a_rule_with_no_metadata_at_all_is_rejected_for_the_rationale(self):
        fields = {k: v for k, v in VALID.items() if k != "metadata"}
        report = self.load({"rules.yml": rule_yaml(**fields)})
        self.assertTrue(any("rationale" in r for r in report.rejections))

    def test_a_blank_rationale_does_not_count_as_a_rationale(self):
        fields = dict(VALID)
        fields["metadata"] = {"rationale": "   "}
        report = self.load({"rules.yml": rule_yaml(**fields)})
        self.assertTrue(any("rationale" in r for r in report.rejections))

    def test_the_rejection_explains_why_rather_than_just_refusing(self):
        fields = dict(VALID)
        fields["metadata"] = {}
        report = self.load({"rules.yml": rule_yaml(**fields)})
        self.assertTrue(any("suppressed" in r for r in report.rejections))

    def test_a_rule_missing_id_or_message_is_rejected(self):
        no_id = {k: v for k, v in VALID.items() if k != "id"}
        no_message = {k: v for k, v in VALID.items() if k != "message"}
        for name, fields in (("id", no_id), ("message", no_message)):
            with self.subTest(missing=name):
                report = self.load({"rules.yml": rule_yaml(**fields)})
                self.assertTrue(any(name in r for r in report.rejections))
                self.assertEqual(self.staged_rules(report), [])


class ExecutableCodeTests(LocalRuleTestCase):
    def test_pattern_where_python_is_rejected(self):
        # It executes arbitrary Python inside the scan, and local rules run
        # in CI with no review gate beyond the consuming repo.
        fields = dict(VALID)
        fields["patterns"] = [
            {"pattern": "f(...)"},
            {"pattern-where-python": "__import__('os').system('id')"},
        ]
        report = self.load({"rules.yml": rule_yaml(**fields)})
        self.assertEqual(self.staged_rules(report), [])
        self.assertTrue(any("pattern-where-python" in r for r in report.rejections))

    def test_a_fix_key_is_rejected_because_the_engine_never_edits_a_pr(self):
        # DESIGN s2: never auto-merges, never pushes code, never edits a PR.
        fields = dict(VALID)
        fields["fix"] = "logger.debug(...)"
        report = self.load({"rules.yml": rule_yaml(**fields)})
        self.assertEqual(self.staged_rules(report), [])
        self.assertTrue(any("fix" in r for r in report.rejections))

    def test_fix_regex_is_rejected_too(self):
        fields = dict(VALID)
        fields["fix-regex"] = {"regex": "a", "replacement": "b"}
        report = self.load({"rules.yml": rule_yaml(**fields)})
        self.assertEqual(self.staged_rules(report), [])

    def test_a_forbidden_key_nested_deep_inside_the_rule_is_still_found(self):
        fields = dict(VALID)
        fields["patterns"] = [{"patterns": [{"pattern-where-python": "True"}]}]
        report = self.load({"rules.yml": rule_yaml(**fields)})
        self.assertEqual(self.staged_rules(report), [])

    def test_the_rejection_says_local_rules_are_data_not_code(self):
        fields = dict(VALID)
        fields["fix"] = "x"
        report = self.load({"rules.yml": rule_yaml(**fields)})
        self.assertTrue(any("declarative" in r for r in report.rejections))


class SeverityCapTests(LocalRuleTestCase):
    def test_critical_is_lowered_to_high_and_the_adjustment_is_reported(self):
        # DESIGN s7: `critical` is curated-only, so a local rule can never
        # block a merge on its own.
        fields = dict(VALID)
        fields["metadata"] = {"rationale": "Stated.", "sentinel-severity": "critical"}
        report = self.load({"rules.yml": rule_yaml(**fields)})
        self.assertEqual(report.rejections, [])
        self.assertTrue(any("lowered to" in a for a in report.adjustments))
        self.assertTrue(any("critical" in a for a in report.adjustments))

    def test_the_staged_yaml_on_disk_carries_the_lowered_severity(self):
        # The report is what a human reads; the staged file is what runs. A
        # cap that is reported but not applied is worse than no cap.
        fields = dict(VALID)
        fields["metadata"] = {"rationale": "Stated.", "sentinel-severity": "critical"}
        report = self.load({"rules.yml": rule_yaml(**fields)})
        staged = self.staged_rules(report)
        self.assertEqual(staged[0]["metadata"]["sentinel-severity"], "high")
        raw = report.accepted_files[0].read_text(encoding="utf-8")
        self.assertNotIn("critical", raw)

    def test_high_and_below_pass_through_unchanged(self):
        for severity in ("high", "medium", "low", "info"):
            with self.subTest(severity=severity):
                fields = dict(VALID)
                fields["metadata"] = {"rationale": "Stated.", "sentinel-severity": severity}
                report = self.load({"rules.yml": rule_yaml(**fields)})
                self.assertEqual([a for a in report.adjustments if "lowered" in a], [])
                self.assertEqual(
                    self.staged_rules(report)[0]["metadata"]["sentinel-severity"], severity
                )

    def test_an_unknown_severity_is_rejected_rather_than_guessed(self):
        fields = dict(VALID)
        fields["metadata"] = {"rationale": "Stated.", "sentinel-severity": "apocalyptic"}
        report = self.load({"rules.yml": rule_yaml(**fields)})
        self.assertEqual(self.staged_rules(report), [])
        self.assertTrue(any("apocalyptic" in r for r in report.rejections))


class NamespaceTests(LocalRuleTestCase):
    def test_an_unnamespaced_id_is_prefixed_with_local(self):
        report = self.load({"rules.yml": rule_yaml(**VALID)})
        self.assertEqual(self.staged_rules(report)[0]["id"], LOCAL_ID_PREFIX + VALID["id"])
        self.assertIn(LOCAL_ID_PREFIX + VALID["id"], report.rule_ids)

    def test_the_namespacing_is_reported_as_an_adjustment(self):
        report = self.load({"rules.yml": rule_yaml(**VALID)})
        self.assertTrue(any("namespaced" in a for a in report.adjustments))

    def test_a_local_rule_cannot_impersonate_a_curated_pack_rule(self):
        # An id of `supabase.permissive-policy` must not end up looking like
        # the curated critical rule of the same name.
        fields = dict(VALID)
        fields["id"] = "supabase.permissive-policy"
        report = self.load({"rules.yml": rule_yaml(**fields)})
        staged_id = self.staged_rules(report)[0]["id"]
        self.assertTrue(staged_id.startswith(LOCAL_ID_PREFIX))
        self.assertNotEqual(staged_id, "supabase.permissive-policy")

    def test_an_already_namespaced_id_is_left_alone(self):
        fields = dict(VALID)
        fields["id"] = "local.no-console-log"
        report = self.load({"rules.yml": rule_yaml(**fields)})
        self.assertEqual(self.staged_rules(report)[0]["id"], "local.no-console-log")
        self.assertEqual(report.adjustments, [])

    def test_an_id_with_illegal_characters_is_rejected(self):
        fields = dict(VALID)
        fields["id"] = "No Console Log!"
        report = self.load({"rules.yml": rule_yaml(**fields)})
        self.assertEqual(self.staged_rules(report), [])

    def test_an_uppercase_id_is_rejected_because_the_message_says_lowercase(self):
        # The check used to lower-case the id before matching, so it accepted
        # exactly what its own rejection message claims to refuse — and the
        # id that then reached semgrep kept the original casing, so the
        # thing validated was not the thing that ran.
        fields = dict(VALID)
        fields["id"] = "NoConsoleLog"
        report = self.load({"rules.yml": rule_yaml(**fields)})
        self.assertEqual(self.staged_rules(report), [])
        self.assertTrue(any("lowercase" in r for r in report.rejections))


class FileLevelTests(LocalRuleTestCase):
    def test_invalid_yaml_is_reported_rather_than_silently_skipped(self):
        # A local rule that stopped running without anyone noticing is a rule
        # everyone believes is protecting them.
        report = self.load({"broken.yml": "rules: [\n"})
        self.assertFalse(report.ok)
        self.assertTrue(any("not valid YAML" in r for r in report.rejections))

    def test_a_file_without_a_top_level_rules_list_is_rejected(self):
        report = self.load({"odd.yml": yaml.safe_dump({"patterns": []})})
        self.assertTrue(any("rules" in r for r in report.rejections))

    def test_one_bad_rule_does_not_take_its_good_siblings_down(self):
        bad = {k: v for k, v in VALID.items() if k != "message"}
        body = yaml.safe_dump({"rules": [VALID, bad]}, sort_keys=False)
        report = self.load({"rules.yml": body})
        self.assertEqual(len(self.staged_rules(report)), 1)
        self.assertEqual(len(report.rejections), 1)

    def test_rules_in_nested_directories_are_found(self):
        report = self.load({"team/rules.yml": rule_yaml(**VALID)})
        self.assertEqual(len(report.accepted_files), 1)

    def test_without_a_staging_directory_rules_are_refused_not_run_raw(self):
        root = self.make_repo()
        write_tree(root, {f"{RULES_DIR}rules.yml": rule_yaml(**VALID)})
        report = load_local_rules(root, RULES_DIR, staging_dir=None)
        self.assertEqual(report.accepted_files, [])
        self.assertTrue(any("staging" in r for r in report.rejections))


if __name__ == "__main__":
    unittest.main()
