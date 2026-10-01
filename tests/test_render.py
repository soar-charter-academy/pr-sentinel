"""The single PR comment.

One comment, updated in place. The ordering is the argument: what blocks,
then what is worth reading, then what is merely recorded. Findings a human
must act on appear above the fold; everything else is behind a `<details>`.

Two things get asserted here that are not cosmetic:

* a `nonbinding` privacy finding renders the not-legal-advice caveat *and*
  names its frameworks. DESIGN s11: the pack flags surfaces and names the
  framework plausibly engaged; it never rules on compliance, and a finding
  that lost its caveat would read like a legal conclusion.
* provenance says "semgrep **not run**" when semgrep did not run, and says
  so about the adapters too. A comment that looks identical whether or not
  the deterministic tier executed is the failure mode this whole design
  exists to avoid — and since DESIGN-V2 §3 most of that tier is other
  people's tools, whose *versions* belong in the same line for the same
  reason: their rule sets move without our engine changing.
"""

from __future__ import annotations

import unittest

from pr_sentinel.models import Authority, Engine, Severity, Verdict
from pr_sentinel.policy import auto_merge_recommendation, compute_verdict
from pr_sentinel.render.comment import MARKER, render_comment
from tests.helpers import make_config, make_finding, make_provenance


def build(findings, *, mode="gated", tier0_failed=False, notes=None, **prov) -> Verdict:
    return compute_verdict(
        make_config(mode=mode),
        list(findings),
        make_provenance(**prov),
        tier0_failed=tier0_failed,
        notes=list(notes or []),
    )


def privacy_finding(**kwargs):
    return make_finding(
        "privacy-edu.pii-in-url",
        Severity.HIGH,
        pack="privacy-edu",
        title="Student email placed in a URL query string",
        nonbinding=True,
        frameworks=["FERPA", "COPPA", "state student-privacy statutes"],
        verify_hint="Confirm whether this URL is logged by the CDN or the proxy.",
        **kwargs,
    )


class StructureTests(unittest.TestCase):
    def test_the_comment_carries_the_marker_so_it_can_be_updated_in_place(self):
        # A reviewer that adds a new comment per push buries the
        # conversation the humans are having.
        body = render_comment(build([]))
        self.assertIn(MARKER, body)
        self.assertTrue(body.startswith(MARKER))

    def test_a_clean_review_says_nothing_to_report_rather_than_going_silent(self):
        self.assertIn("Nothing to report", render_comment(build([])))

    def test_blocking_findings_appear_above_advisory_ones(self):
        blocking = make_finding(
            "supabase.permissive-policy", Severity.CRITICAL, title="Policy uses using (true)"
        )
        advisory = make_finding(
            "supply-chain.new-dependency", Severity.MEDIUM, title="New direct dependency"
        )
        body = render_comment(build([blocking, advisory]))
        self.assertLess(body.index("Blocking (1)"), body.index("Worth a look (1)"))
        self.assertLess(
            body.index("Policy uses using (true)"), body.index("New direct dependency")
        )

    def test_summary_only_findings_are_folded_into_a_details_block(self):
        low = make_finding("core.huge-diff", Severity.LOW, title="Very large diff")
        body = render_comment(build([low]))
        self.assertIn("<details>", body)
        self.assertIn("Also noted (1)", body)

    def test_a_failed_tier_zero_headline_says_nothing_else_was_weighed(self):
        body = render_comment(build([], tier0_failed=True))
        self.assertIn("project's own checks did not pass", body)

    def test_the_headline_names_the_mode_the_verdict_was_reached_under(self):
        body = render_comment(build([make_finding("a.b", Severity.HIGH)], mode="gated"))
        self.assertIn("`gated`", body)

    def test_degraded_notes_render_as_a_warning_above_the_findings(self):
        body = render_comment(
            build([]), degraded_notes=["semgrep is not installed, so the rule tier did NOT run"]
        )
        self.assertIn("[!WARNING]", body)
        self.assertIn("does not", body)
        self.assertLess(body.index("[!WARNING]"), body.index("engine `0.1.0`"))

    def test_run_notes_are_rendered_but_kept_out_of_the_way(self):
        body = render_comment(build([], notes=["Tier 0 project checks were not run."]))
        self.assertIn("Run notes", body)
        self.assertIn("Tier 0 project checks were not run.", body)

    def test_every_finding_shows_its_rule_id_location_and_rationale(self):
        finding = make_finding("core.forbidden-files", Severity.CRITICAL, path=".env", line=None)
        body = render_comment(build([finding]))
        self.assertIn("core.forbidden-files", body)
        self.assertIn(".env", body)
        self.assertIn(finding.rationale, body)


class NonbindingTests(unittest.TestCase):
    def test_a_nonbinding_finding_renders_the_not_legal_advice_caveat(self):
        body = render_comment(build([privacy_finding()]))
        self.assertIn("not legal advice", body)
        self.assertIn("nonbinding", body)
        self.assertIn("counsel", body)

    def test_it_states_that_it_is_not_a_ruling_in_either_direction(self):
        body = render_comment(build([privacy_finding()]))
        self.assertIn("does or does not comply", body)

    def test_it_names_the_frameworks_plausibly_engaged(self):
        body = render_comment(build([privacy_finding()]))
        for framework in ("FERPA", "COPPA", "state student-privacy statutes"):
            with self.subTest(framework=framework):
                self.assertIn(framework, body)

    def test_it_says_what_a_human_should_verify(self):
        body = render_comment(build([privacy_finding()]))
        self.assertIn("What to verify", body)
        self.assertIn("logged by the CDN", body)

    def test_an_ordinary_finding_gets_no_legal_caveat(self):
        body = render_comment(build([make_finding("core.conflict-markers", Severity.HIGH)]))
        self.assertNotIn("not legal advice", body)


class AgentFindingRenderTests(unittest.TestCase):
    def test_a_verified_agent_finding_shows_the_verification_note(self):
        finding = make_finding(
            "agent.security", Severity.HIGH, engine=Engine.AGENT, pack="agent:security"
        )
        finding.verified = True
        finding.verification_note = "the role check runs after the fetch on line 40"
        body = render_comment(build([finding]))
        self.assertIn("**Verified.**", body)
        self.assertIn("after the fetch on line 40", body)

    def test_an_unverified_agent_finding_says_it_was_not_checked(self):
        finding = make_finding("agent.security", Severity.HIGH, engine=Engine.AGENT)
        finding.verified = False
        body = render_comment(build([finding]))
        self.assertIn("Not verified", body)

    def test_a_severity_lowered_by_verification_is_disclosed(self):
        finding = make_finding("agent.security", Severity.MEDIUM, engine=Engine.AGENT)
        finding.verified = True
        finding.metadata["severity_lowered_by_verification"] = "high -> medium"
        body = render_comment(build([finding]))
        self.assertIn("Severity lowered by verification", body)


class DroppedFindingTests(unittest.TestCase):
    def test_the_dropped_finding_count_is_mentioned(self):
        # Saying how many were dropped is what makes "dropped, not softened"
        # legible rather than just quiet.
        body = render_comment(build([]), dropped_count=3)
        self.assertIn("3 further finding(s)", body)
        self.assertIn("dropped rather than reported with a hedge", body)

    def test_nothing_is_said_when_nothing_was_dropped(self):
        self.assertNotIn("further finding(s)", render_comment(build([]), dropped_count=0))


class MergeStatusTests(unittest.TestCase):
    def test_a_clear_deterministic_status_says_no_model_contributed_to_it(self):
        rec = auto_merge_recommendation(make_config(), [], tier0_failed=False, degraded=False)
        body = render_comment(build([]), rec)
        self.assertIn("Deterministic status: clear", body)
        self.assertIn("No model contributed", body)

    def test_a_withheld_deterministic_status_lists_its_reasons(self):
        finding = make_finding("supabase.permissive-policy", Severity.CRITICAL)
        rec = auto_merge_recommendation(
            make_config(), [finding], tier0_failed=False, degraded=False
        )
        body = render_comment(build([finding]), rec)
        self.assertIn("Deterministic status: withheld", body)
        self.assertIn("critical", body)


class ProvenanceTests(unittest.TestCase):
    def test_semgrep_is_reported_as_not_run_when_it_was_not(self):
        body = render_comment(build([]))
        self.assertIn("semgrep **not run**", body)

    def test_a_semgrep_version_is_reported_when_it_did_run(self):
        body = render_comment(build([], semgrep_version="1.96.0"))
        self.assertIn("semgrep `1.96.0`", body)
        self.assertNotIn("semgrep **not run**", body)

    def test_adapter_tool_versions_are_recorded(self):
        # DESIGN-V2 §3: an adapter's premise is that somebody else maintains
        # the rules, which means the rule set can change under us between two
        # runs of the same engine on the same commit. "zizmor found nothing"
        # is not reproducible; "zizmor 1.5.2 found nothing" is.
        body = render_comment(
            build([], tool_versions={"zizmor": "1.5.2", "gitleaks": "8.21.1"})
        )
        self.assertIn("adapters `", body)
        self.assertIn("gitleaks 8.21.1", body)
        self.assertIn("zizmor 1.5.2", body)

    def test_the_absence_of_any_adapter_version_is_stated_rather_than_omitted(self):
        # Same reasoning as "semgrep **not run**". A provenance line that
        # looks identical whether or not six external tools ran is the exact
        # failure this design exists to avoid.
        self.assertIn("no adapter reported a version", render_comment(build([])))

    def test_semgrep_is_not_duplicated_into_the_adapter_list(self):
        # `Tier1Result.tool_versions` folds semgrep in so that one dict holds
        # every external version. The renderer already has a dedicated
        # semgrep row, so it must not also appear under `adapters`.
        body = render_comment(
            build([], semgrep_version="1.96.0", tool_versions={"semgrep": "1.96.0"})
        )
        self.assertIn("semgrep `1.96.0`", body)
        self.assertIn("no adapter reported a version", body)

    def test_the_agent_tier_is_reported_as_not_run_when_no_model_answered(self):
        self.assertIn("agent tier not run", render_comment(build([])))

    def test_models_pack_versions_and_commit_are_recorded_for_reproducibility(self):
        # DESIGN s10: a verdict must be reproducible and a regression in the
        # reviewer diagnosable.
        body = render_comment(
            build(
                [],
                pack_versions={"core": "1.0.0", "supabase": "1.0.0"},
                models={"review": "claude-sonnet-5-5"},
                commit_sha="abcdef1234567890",
            )
        )
        self.assertIn("engine `0.1.0`", body)
        self.assertIn("core@1.0.0", body)
        self.assertIn("supabase@1.0.0", body)
        self.assertIn("claude-sonnet-5-5", body)
        self.assertIn("abcdef12", body)

    def test_the_footer_says_it_is_a_recommendation_and_not_an_authority(self):
        # DESIGN s2: not a merge gate by default.
        body = render_comment(build([]))
        self.assertIn("recommendation, not an authority", body)
        self.assertIn("never merges, pushes, or edits code", body)


class EveryFindingShapeRendersTests(unittest.TestCase):
    def test_a_finding_at_every_severity_renders_without_a_key_error(self):
        findings = [make_finding(f"a.{s.value}", s) for s in Severity]
        body = render_comment(build(findings))
        for s in Severity:
            with self.subTest(severity=s):
                self.assertIn(s.value, body)

    def test_a_finding_with_no_location_renders_an_em_dash_rather_than_crashing(self):
        body = render_comment(build([make_finding("a.b", Severity.HIGH, path=None)]))
        self.assertIn("—", body)

    def test_a_snippet_is_rendered_in_a_code_fence(self):
        finding = make_finding("a.b", Severity.HIGH)
        finding.location = type(finding.location)(
            path="src/app.ts", line=3, snippet="using (true)"
        )
        self.assertIn("using (true)", render_comment(build([finding])))

    def test_the_comment_always_ends_with_exactly_one_trailing_newline(self):
        body = render_comment(build([make_finding("a.b", Severity.HIGH)]))
        self.assertTrue(body.endswith("\n"))
        self.assertFalse(body.endswith("\n\n"))


if __name__ == "__main__":
    unittest.main()
