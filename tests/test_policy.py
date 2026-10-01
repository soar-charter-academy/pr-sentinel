"""The hard boundary between guarantees and judgment.

This is the module the whole design turns on. DESIGN s1 separates facts about
text (a script decides them correctly 100% of the time) from judgment calls
(a model decides them correctly most of the time), and s3 says the boundary
is only real if something downstream can act on one without the other.

Four claims are defended here, and every one of them is a security property
rather than a nicety:

* an agent finding can never be `critical` — capped in `Finding.__post_init__`
  so the cap cannot be forgotten at a call site;
* an agent finding can never *block*, in any mode, because PR text is one of
  its inputs;
* `auto_merge_recommendation` does not consult agent findings, the configured
  mode, or anything derived from PR text;
* a `degraded` deterministic tier is not clear to merge even with zero
  findings. A clean result from a tier that half-ran is not a clean result.
"""

from __future__ import annotations

import unittest

from pr_sentinel.models import Authority, Engine, Severity, Tier, Verdict
from pr_sentinel.policy import (
    CHECK_NAME_COMBINED,
    CHECK_NAME_DETERMINISTIC,
    auto_merge_recommendation,
    check_run_output,
    compute_verdict,
    deterministic_only,
)
from tests.helpers import make_config, make_finding, make_provenance


def verdict_for(config, findings, **kwargs) -> Verdict:
    return compute_verdict(config, findings, make_provenance(), **kwargs)


class AgentSeverityCapTests(unittest.TestCase):
    def test_an_agent_finding_requesting_critical_is_capped_to_high(self):
        # DESIGN s1/s7: only the deterministic tier may emit `critical`.
        finding = make_finding(
            "agent.security", Severity.CRITICAL, engine=Engine.AGENT, pack="agent:security"
        )
        self.assertIs(finding.severity, Severity.HIGH)

    def test_the_cap_records_why_the_severity_moved(self):
        finding = make_finding("agent.security", Severity.CRITICAL, engine=Engine.AGENT)
        self.assertIn("severity_capped", finding.metadata)

    def test_the_cap_is_applied_at_construction_so_no_call_site_can_skip_it(self):
        finding = make_finding("agent.security", "critical", engine=Engine.AGENT)
        self.assertIs(finding.severity, Severity.HIGH)

    def test_a_deterministic_finding_may_be_critical(self):
        for engine in (Engine.SCRIPT, Engine.SEMGREP, Engine.PROJECT_CHECK):
            with self.subTest(engine=engine):
                self.assertIs(
                    make_finding("x.y", Severity.CRITICAL, engine=engine).severity,
                    Severity.CRITICAL,
                )

    def test_an_agent_finding_below_critical_is_left_alone(self):
        finding = make_finding("agent.privacy", Severity.HIGH, engine=Engine.AGENT)
        self.assertIs(finding.severity, Severity.HIGH)
        self.assertNotIn("severity_capped", finding.metadata)

    def test_a_finding_without_a_rationale_cannot_be_constructed(self):
        # DESIGN s7, enforced in the type rather than in each producer.
        with self.assertRaises(ValueError):
            make_finding(rationale="   ")


class AgentNeverBlocksTests(unittest.TestCase):
    def test_an_agent_finding_does_not_block_even_in_blocking_mode(self):
        # `blocking` mode maps high -> BLOCKING. An agent finding at high
        # still must not land in verdict.blocking: it cannot be guaranteed,
        # and PR text is one of its inputs.
        config = make_config(mode="blocking")
        agent = make_finding("agent.security", Severity.HIGH, engine=Engine.AGENT)
        verdict = verdict_for(config, [agent])
        self.assertEqual(verdict.blocking, [])
        self.assertIn(agent, verdict.findings)

    def test_the_downgrade_is_recorded_on_the_finding(self):
        config = make_config(mode="blocking")
        agent = make_finding("agent.security", Severity.HIGH, engine=Engine.AGENT)
        verdict_for(config, [agent])
        self.assertIn("authority_downgraded", agent.metadata)
        self.assertIn("never block", agent.metadata["authority_downgraded"])

    def test_an_explicit_authority_block_cannot_make_agent_findings_blocking_either(self):
        # A repo cannot opt into letting judgment block. The boundary is not
        # configurable.
        config = make_config(
            mode="advisory",
            authority={s: Authority.BLOCKING for s in Severity},
        )
        agent = make_finding("agent.privacy", Severity.HIGH, engine=Engine.AGENT)
        self.assertEqual(verdict_for(config, [agent]).blocking, [])

    def test_a_deterministic_critical_does_block_in_gated_mode(self):
        config = make_config(mode="gated")
        det = make_finding("supabase.permissive-policy", Severity.CRITICAL)
        verdict = verdict_for(config, [det])
        self.assertEqual(verdict.blocking, [det])
        self.assertTrue(verdict.should_fail_check)

    def test_gated_leaves_deterministic_high_advisory(self):
        # "Guarantees block, judgment advises" is the recommended default.
        config = make_config(mode="gated")
        det = make_finding("supabase.missing-grants", Severity.HIGH)
        verdict = verdict_for(config, [det])
        self.assertEqual(verdict.blocking, [])
        self.assertIn(det, verdict.findings)

    def test_advisory_mode_blocks_nothing_at_all(self):
        config = make_config(mode="advisory")
        findings = [make_finding("a.b", s) for s in (Severity.CRITICAL, Severity.HIGH)]
        self.assertEqual(verdict_for(config, findings).blocking, [])

    def test_summary_only_findings_are_recorded_but_not_surfaced_as_advisory(self):
        config = make_config(mode="gated")
        low = make_finding("core.huge-diff", Severity.LOW)
        verdict = verdict_for(config, [low])
        self.assertEqual(verdict.summary_only, [low])
        self.assertEqual(verdict.blocking, [])

    def test_an_ignored_severity_drops_the_finding_entirely(self):
        config = make_config(mode="gated", authority={Severity.LOW: Authority.IGNORE})
        verdict = verdict_for(config, [make_finding("core.huge-diff", Severity.LOW)])
        self.assertEqual(verdict.findings, [])


class AutoMergeRecommendationTests(unittest.TestCase):
    def test_agent_findings_are_ignored_entirely_however_severe(self):
        # The deterministic status must be reproducible from the code alone,
        # so nothing a model said may move it.
        agent = make_finding("agent.security", Severity.HIGH, engine=Engine.AGENT)
        rec = auto_merge_recommendation(
            make_config(), [agent], tier0_failed=False, degraded=False
        )
        self.assertTrue(rec.safe)
        self.assertEqual(rec.blockers, [])
        self.assertEqual(rec.reasons, [])

    def test_the_configured_mode_does_not_change_the_recommendation(self):
        det = make_finding("supabase.missing-grants", Severity.HIGH)
        results = {
            mode: auto_merge_recommendation(
                make_config(mode=mode), [det], tier0_failed=False, degraded=False
            ).safe
            for mode in ("advisory", "gated", "blocking")
        }
        self.assertEqual(set(results.values()), {False})

    def test_a_deterministic_high_withholds_the_status_by_default(self):
        # The threshold is `high`, not `critical`, on purpose: a repo that
        # auto-merges everything short of critical auto-merges a lot.
        det = make_finding("supabase.missing-grants", Severity.HIGH)
        rec = auto_merge_recommendation(
            make_config(), [det], tier0_failed=False, degraded=False
        )
        self.assertFalse(rec.safe)
        self.assertEqual(rec.blockers, [det])

    def test_a_deterministic_medium_does_not_withhold_it(self):
        det = make_finding("supply-chain.new-dependency", Severity.MEDIUM)
        rec = auto_merge_recommendation(
            make_config(), [det], tier0_failed=False, degraded=False
        )
        self.assertTrue(rec.safe)

    def test_the_threshold_is_adjustable(self):
        det = make_finding("supply-chain.new-dependency", Severity.MEDIUM)
        rec = auto_merge_recommendation(
            make_config(), [det], tier0_failed=False, degraded=False,
            threshold=Severity.MEDIUM,
        )
        self.assertFalse(rec.safe)

    def test_a_failed_tier_zero_withholds_the_status(self):
        rec = auto_merge_recommendation(make_config(), [], tier0_failed=True, degraded=False)
        self.assertFalse(rec.safe)
        self.assertTrue(any("Tier 0" in r for r in rec.reasons))

    def test_a_degraded_tier_is_unsafe_even_with_zero_findings(self):
        # THE claim. A clean result from a tier that half-ran is not a clean
        # result; semgrep missing means the critical guarantees did not run.
        rec = auto_merge_recommendation(make_config(), [], tier0_failed=False, degraded=True)
        self.assertFalse(rec.safe)
        self.assertEqual(rec.blockers, [])
        self.assertTrue(any("did not run" in r for r in rec.reasons))

    def test_a_degraded_tier_concludes_failure_even_if_safe_were_somehow_true(self):
        rec = auto_merge_recommendation(make_config(), [], tier0_failed=False, degraded=True)
        self.assertEqual(rec.conclusion, "failure")
        self.assertTrue(rec.degraded)

    def test_a_clean_undegraded_run_is_safe(self):
        rec = auto_merge_recommendation(make_config(), [], tier0_failed=False, degraded=False)
        self.assertTrue(rec.safe)
        self.assertEqual(rec.conclusion, "success")

    def test_the_reason_explains_the_severity_mix_rather_than_just_a_count(self):
        findings = [
            make_finding("a.b", Severity.CRITICAL),
            make_finding("c.d", Severity.HIGH),
        ]
        rec = auto_merge_recommendation(
            make_config(), findings, tier0_failed=False, degraded=False
        )
        joined = " ".join(rec.reasons)
        self.assertIn("critical", joined)
        self.assertIn("high", joined)

    def test_deterministic_only_keeps_project_and_rule_tiers_and_drops_the_agent(self):
        findings = [
            make_finding("tier0.npm-test", Severity.HIGH, engine=Engine.PROJECT_CHECK),
            make_finding("core.secret", Severity.HIGH, engine=Engine.SEMGREP),
            make_finding("agent.security", Severity.HIGH, engine=Engine.AGENT),
        ]
        kept = deterministic_only(findings)
        self.assertEqual([f.tier for f in kept], [Tier.PROJECT, Tier.DETERMINISTIC])


class CheckRunTests(unittest.TestCase):
    """Two statuses, because the boundary is only real if something
    downstream can require one without the other (DESIGN s3)."""

    def test_the_two_check_runs_are_named_as_designed(self):
        self.assertEqual(CHECK_NAME_COMBINED, "pr-sentinel")
        self.assertEqual(CHECK_NAME_DETERMINISTIC, "pr-sentinel/deterministic")

    def test_both_check_runs_are_always_produced(self):
        verdict = verdict_for(make_config(), [])
        rec = auto_merge_recommendation(make_config(), [], tier0_failed=False, degraded=False)
        out = check_run_output(verdict, rec)
        self.assertEqual(set(out), {CHECK_NAME_COMBINED, CHECK_NAME_DETERMINISTIC})

    def test_a_clean_run_concludes_success(self):
        self.assertEqual(verdict_for(make_config(), []).conclusion, "success")

    def test_findings_that_do_not_block_conclude_neutral_not_failure(self):
        # Recommendation, not authority (DESIGN s2).
        verdict = verdict_for(make_config(mode="gated"), [make_finding("a.b", Severity.HIGH)])
        self.assertEqual(verdict.conclusion, "neutral")
        self.assertFalse(verdict.should_fail_check)

    def test_a_blocking_finding_concludes_failure(self):
        verdict = verdict_for(
            make_config(mode="gated"), [make_finding("a.b", Severity.CRITICAL)]
        )
        self.assertEqual(verdict.conclusion, "failure")

    def test_a_failed_tier_zero_concludes_failure_with_no_findings_at_all(self):
        self.assertEqual(verdict_for(make_config(), [], tier0_failed=True).conclusion, "failure")

    def test_the_deterministic_summary_states_that_no_model_contributed(self):
        # A reader must be able to tell at a glance whether the thing gating
        # their merge is a guarantee or an opinion.
        verdict = verdict_for(make_config(), [])
        rec = auto_merge_recommendation(make_config(), [], tier0_failed=False, degraded=False)
        summary = check_run_output(verdict, rec)[CHECK_NAME_DETERMINISTIC]["summary"]
        self.assertIn("no model contributed", summary.lower())

    def test_a_withheld_deterministic_status_lists_its_reasons(self):
        det = make_finding("supabase.permissive-policy", Severity.CRITICAL)
        verdict = verdict_for(make_config(), [det])
        rec = auto_merge_recommendation(
            make_config(), [det], tier0_failed=False, degraded=False
        )
        block = check_run_output(verdict, rec)[CHECK_NAME_DETERMINISTIC]
        self.assertIn("withheld", block["title"].lower())
        self.assertIn("critical", block["summary"])

    def test_the_combined_status_reports_the_mode_it_judged_under(self):
        verdict = verdict_for(make_config(mode="blocking"), [make_finding("a.b", Severity.HIGH)])
        rec = auto_merge_recommendation(
            make_config(mode="blocking"), [], tier0_failed=False, degraded=False
        )
        self.assertIn("blocking", check_run_output(verdict, rec)[CHECK_NAME_COMBINED]["summary"])

    def test_an_agent_high_leaves_the_deterministic_status_clear_while_the_combined_one_speaks(self):
        # The two statuses disagreeing is the design working, not a bug.
        config = make_config(mode="blocking")
        agent = make_finding("agent.security", Severity.HIGH, engine=Engine.AGENT)
        verdict = verdict_for(config, [agent])
        rec = auto_merge_recommendation(config, [agent], tier0_failed=False, degraded=False)
        self.assertEqual(verdict.conclusion, "neutral")
        self.assertEqual(rec.conclusion, "success")


class VerdictSerialisationTests(unittest.TestCase):
    def test_counts_are_reported_per_severity(self):
        findings = [
            make_finding("a.b", Severity.CRITICAL),
            make_finding("c.d", Severity.HIGH),
            make_finding("e.f", Severity.HIGH),
        ]
        counts = verdict_for(make_config(), findings).counts()
        self.assertEqual(counts["critical"], 1)
        self.assertEqual(counts["high"], 2)
        self.assertEqual(counts["low"], 0)

    def test_the_serialised_verdict_carries_provenance_and_blocking_fingerprints(self):
        det = make_finding("a.b", Severity.CRITICAL)
        data = verdict_for(make_config(mode="gated"), [det]).to_dict()
        self.assertEqual(data["blocking"], [det.fingerprint])
        self.assertEqual(data["provenance"]["engine_version"], "0.1.0")
        self.assertEqual(data["mode"], "gated")

    def test_a_fingerprint_ignores_line_drift(self):
        # The same problem two lines lower because someone added an import is
        # the same problem.
        a = make_finding("a.b", line=10)
        b = make_finding("a.b", line=12)
        self.assertEqual(a.fingerprint, b.fingerprint)

    def test_a_fingerprint_distinguishes_different_files(self):
        a = make_finding("a.b", path="src/one.ts")
        b = make_finding("a.b", path="src/two.ts")
        self.assertNotEqual(a.fingerprint, b.fingerprint)


if __name__ == "__main__":
    unittest.main()
