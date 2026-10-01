"""Parsing semgrep's output, without semgrep.

DESIGN s5 makes semgrep the deterministic backend, and the runner's own
docstring says the engine "must import and run its tests without semgrep
installed". So the tests here feed a recorded `semgrep scan --json` payload
to `parse_semgrep_results`, which is everything interesting that happens
after the subprocess exits:

* which severity wins — the pack's `sentinel-severity` metadata, not
  semgrep's own coarse ERROR/WARNING/INFO;
* whether the match lands on a line this pull request actually touched. "A
  rule firing on code the PR did not touch is someone else's bug appearing
  in your review";
* whether a rule shipped without a rationale degrades or takes the run down.
"""

from __future__ import annotations

import unittest

from pr_sentinel.diff import Diff
from pr_sentinel.models import Engine, Severity, Tier
from pr_sentinel.tier1.semgrep_runner import parse_semgrep_results
from tests.helpers import synthetic_diff


def result(
    check_id: str,
    path: str,
    line: int,
    *,
    severity: str = "WARNING",
    metadata: dict | None = None,
    message: str = "Row level security policy uses `using (true)`.",
    lines: str = "create policy p on students for select using (true);",
) -> dict:
    """One entry shaped exactly as semgrep emits it."""
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": line, "col": 1, "offset": 0},
        "end": {"line": line, "col": 52, "offset": 51},
        "extra": {
            "message": message,
            "severity": severity,
            "lines": lines,
            "fingerprint": "abc123",
            "metavars": {},
            "metadata": metadata if metadata is not None else {},
            "is_ignored": False,
        },
    }


RATIONALE = (
    "A policy predicate of `true` authorises every authenticated caller, which in "
    "a repo where student accounts share the staff domain means every student."
)

PAYLOAD = {
    "version": "1.96.0",
    "results": [
        result(
            "supabase.permissive-policy",
            "supabase/migrations/002_guardians.sql",
            3,
            severity="WARNING",
            metadata={
                "sentinel-severity": "critical",
                "rationale": RATIONALE,
                "pack": "supabase",
                "title": "Row level security policy is permissive",
            },
        ),
    ],
    "errors": [],
    "paths": {"scanned": ["supabase/migrations/002_guardians.sql"]},
}


TOUCHED = synthetic_diff(
    {
        "supabase/migrations/002_guardians.sql": [
            (3, "create policy p_guardians on guardians for select using (true);")
        ]
    }
)


class SeverityResolutionTests(unittest.TestCase):
    def test_sentinel_severity_metadata_beats_semgreps_own_severity(self):
        # semgrep's severities are coarse; the pack's judgement is the one
        # that decides whether something blocks.
        findings, _ = parse_semgrep_results(PAYLOAD, TOUCHED)
        self.assertEqual(len(findings), 1)
        self.assertIs(findings[0].severity, Severity.CRITICAL)

    def test_the_underscore_spelling_of_the_metadata_key_also_works(self):
        payload = {
            "results": [
                result(
                    "core.secret",
                    "src/config.ts",
                    1,
                    severity="INFO",
                    metadata={"sentinel_severity": "high", "rationale": RATIONALE},
                )
            ]
        }
        findings, _ = parse_semgrep_results(
            payload, synthetic_diff({"src/config.ts": [(1, "const k = '...'")]})
        )
        self.assertIs(findings[0].severity, Severity.HIGH)

    def test_semgreps_severity_is_the_fallback_when_metadata_is_silent(self):
        for raw, expected in (
            ("ERROR", Severity.HIGH),
            ("WARNING", Severity.MEDIUM),
            ("INFO", Severity.LOW),
        ):
            with self.subTest(raw=raw):
                payload = {
                    "results": [
                        result("core.x", "src/a.ts", 1, severity=raw,
                               metadata={"rationale": RATIONALE})
                    ]
                }
                findings, _ = parse_semgrep_results(
                    payload, synthetic_diff({"src/a.ts": [(1, "x")]})
                )
                self.assertIs(findings[0].severity, expected)

    def test_an_unparseable_sentinel_severity_falls_back_rather_than_crashing(self):
        payload = {
            "results": [
                result("core.x", "src/a.ts", 1, severity="ERROR",
                       metadata={"sentinel-severity": "apocalyptic", "rationale": RATIONALE})
            ]
        }
        findings, _ = parse_semgrep_results(payload, synthetic_diff({"src/a.ts": [(1, "x")]}))
        self.assertIs(findings[0].severity, Severity.HIGH)

    def test_an_unknown_semgrep_severity_falls_back_to_medium(self):
        payload = {
            "results": [
                result("core.x", "src/a.ts", 1, severity="EXPERIMENT",
                       metadata={"rationale": RATIONALE})
            ]
        }
        findings, _ = parse_semgrep_results(payload, synthetic_diff({"src/a.ts": [(1, "x")]}))
        self.assertIs(findings[0].severity, Severity.MEDIUM)


class ChangedLineFilterTests(unittest.TestCase):
    def test_a_match_on_a_line_the_pr_did_not_touch_is_filtered_out(self):
        # Reporting a pre-existing problem on someone else's PR is the
        # fastest way to get a reviewer muted.
        payload = {
            "results": [
                result("supabase.permissive-policy", "supabase/migrations/002_guardians.sql", 200,
                       metadata={"rationale": RATIONALE})
            ]
        }
        findings, _ = parse_semgrep_results(payload, TOUCHED)
        self.assertEqual(findings, [])

    def test_a_match_on_a_touched_line_survives(self):
        findings, _ = parse_semgrep_results(PAYLOAD, TOUCHED)
        self.assertEqual(len(findings), 1)

    def test_a_match_within_the_slack_window_survives(self):
        # A semgrep match can start a few lines above the edited line.
        payload = {
            "results": [
                result("supabase.permissive-policy", "supabase/migrations/002_guardians.sql", 1,
                       metadata={"rationale": RATIONALE})
            ]
        }
        findings, _ = parse_semgrep_results(payload, TOUCHED, line_slack=3)
        self.assertEqual(len(findings), 1)
        findings, _ = parse_semgrep_results(payload, TOUCHED, line_slack=0)
        self.assertEqual(findings, [])

    def test_a_whole_file_rule_is_not_filtered_by_line(self):
        # "This file must never be committed" legitimately points at a line
        # nobody edited.
        payload = {
            "results": [
                result("core.forbidden-files", "supabase/migrations/002_guardians.sql", 500,
                       metadata={"rationale": RATIONALE, "whole-file": True})
            ]
        }
        findings, _ = parse_semgrep_results(payload, TOUCHED)
        self.assertEqual(len(findings), 1)

    def test_a_match_in_a_file_not_in_the_diff_is_kept(self):
        # The filter narrows within changed files; it does not decide which
        # files were scanned, and dropping an unknown path silently would
        # hide a real result.
        payload = {
            "results": [
                result("core.x", "src/untouched.ts", 9, metadata={"rationale": RATIONALE})
            ]
        }
        findings, _ = parse_semgrep_results(payload, TOUCHED)
        self.assertEqual(len(findings), 1)

    def test_filtering_can_be_switched_off_wholesale(self):
        payload = {
            "results": [
                result("supabase.permissive-policy", "supabase/migrations/002_guardians.sql", 200,
                       metadata={"rationale": RATIONALE})
            ]
        }
        findings, _ = parse_semgrep_results(payload, TOUCHED, only_changed_files=False)
        self.assertEqual(len(findings), 1)


class MissingRationaleTests(unittest.TestCase):
    def test_a_rule_with_no_rationale_degrades_rather_than_crashing_the_run(self):
        # `rationale` is mandatory on `Finding`, so a curated rule that slips
        # through without one would otherwise take down a whole review.
        payload = {
            "results": [
                result("supabase.permissive-policy", "supabase/migrations/002_guardians.sql", 3)
            ]
        }
        findings, errors = parse_semgrep_results(payload, TOUCHED)
        self.assertEqual(len(findings), 1)
        self.assertEqual(errors, [])

    def test_the_placeholder_rationale_blames_the_rule_and_not_the_code(self):
        payload = {
            "results": [
                result("supabase.permissive-policy", "supabase/migrations/002_guardians.sql", 3)
            ]
        }
        findings, _ = parse_semgrep_results(payload, TOUCHED)
        self.assertIn("bug in the rule, not in", findings[0].rationale)

    def test_rationale_may_be_spelled_why(self):
        payload = {
            "results": [
                result("core.x", "src/a.ts", 1, metadata={"why": "Because it leaks."})
            ]
        }
        findings, _ = parse_semgrep_results(payload, synthetic_diff({"src/a.ts": [(1, "x")]}))
        self.assertEqual(findings[0].rationale, "Because it leaks.")


class FindingShapeTests(unittest.TestCase):
    def test_a_parsed_finding_is_stamped_as_deterministic_and_semgrep(self):
        finding = parse_semgrep_results(PAYLOAD, TOUCHED)[0][0]
        self.assertIs(finding.tier, Tier.DETERMINISTIC)
        self.assertIs(finding.engine, Engine.SEMGREP)

    def test_the_pack_comes_from_metadata_first(self):
        finding = parse_semgrep_results(PAYLOAD, TOUCHED)[0][0]
        self.assertEqual(finding.pack, "supabase")

    def test_the_pack_falls_back_to_the_rule_file_mapping(self):
        payload = {
            "results": [result("client", "src/a.ts", 1, metadata={"rationale": RATIONALE})]
        }
        findings, _ = parse_semgrep_results(
            payload, synthetic_diff({"src/a.ts": [(1, "x")]}), pack_of_rule={"client": "supabase"}
        )
        self.assertEqual(findings[0].pack, "supabase")

    def test_the_pack_falls_back_to_the_leading_segment_of_the_rule_id(self):
        payload = {
            "results": [
                result("react-vite.browser-storage", "src/a.ts", 1,
                       metadata={"rationale": RATIONALE})
            ]
        }
        findings, _ = parse_semgrep_results(payload, synthetic_diff({"src/a.ts": [(1, "x")]}))
        self.assertEqual(findings[0].pack, "react-vite")

    def test_the_location_carries_the_path_and_both_line_bounds(self):
        finding = parse_semgrep_results(PAYLOAD, TOUCHED)[0][0]
        self.assertEqual(finding.location.path, "supabase/migrations/002_guardians.sql")
        self.assertEqual(finding.location.line, 3)
        self.assertEqual(finding.location.end_line, 3)
        self.assertIn("using (true)", finding.location.snippet)

    def test_nonbinding_metadata_and_frameworks_survive_the_round_trip(self):
        # DESIGN s11: a privacy-edu rule must arrive still labelled
        # nonbinding, or the comment renders it as a legal conclusion.
        payload = {
            "results": [
                result(
                    "privacy-edu.pii-in-url",
                    "src/report.ts",
                    2,
                    metadata={
                        "rationale": RATIONALE,
                        "nonbinding": True,
                        "frameworks": ["FERPA", "COPPA"],
                        "verify": "Check whether the CDN logs query strings.",
                    },
                )
            ]
        }
        findings, _ = parse_semgrep_results(
            payload, synthetic_diff({"src/report.ts": [(2, "url")]})
        )
        finding = findings[0]
        self.assertTrue(finding.nonbinding)
        self.assertEqual(finding.frameworks, ["FERPA", "COPPA"])
        self.assertIn("CDN", finding.verify_hint)

    def test_the_title_falls_back_to_the_first_line_of_the_message(self):
        payload = {
            "results": [
                result("core.x", "src/a.ts", 1, metadata={"rationale": RATIONALE},
                       message="Hardcoded credential.\nSecond line of detail.")
            ]
        }
        findings, _ = parse_semgrep_results(payload, synthetic_diff({"src/a.ts": [(1, "x")]}))
        self.assertEqual(findings[0].title, "Hardcoded credential")

    def test_an_entry_with_no_check_id_is_skipped(self):
        payload = {"results": [{"path": "src/a.ts", "start": {"line": 1}, "extra": {}}]}
        findings, _ = parse_semgrep_results(payload, synthetic_diff({"src/a.ts": [(1, "x")]}))
        self.assertEqual(findings, [])


class ErrorReportingTests(unittest.TestCase):
    def test_semgrep_errors_are_surfaced_so_a_partial_scan_is_visible(self):
        # A deterministic tier that ran at 70% and said nothing about it is
        # the failure mode this design exists to avoid.
        payload = {
            "results": [],
            "errors": [
                {"long_msg": "Syntax error in rule file rules/jsx.yml", "level": "error"},
                {"message": "timeout scanning src/huge.ts"},
            ],
        }
        findings, errors = parse_semgrep_results(payload, Diff())
        self.assertEqual(findings, [])
        self.assertEqual(len(errors), 2)
        self.assertIn("Syntax error", errors[0])
        self.assertIn("timeout", errors[1])

    def test_an_empty_payload_yields_nothing_and_no_errors(self):
        findings, errors = parse_semgrep_results({}, Diff())
        self.assertEqual((findings, errors), ([], []))


if __name__ == "__main__":
    unittest.main()
