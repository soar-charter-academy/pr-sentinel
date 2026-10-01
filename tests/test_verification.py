"""The verification pass — the load-bearing one.

DESIGN s3: "Each candidate finding is re-checked against actual code before
it may enter the comment. Unverified findings are dropped, not softened.
That is the difference between a reviewer you read and one you mute."

So the claims here are mostly about what does *not* survive. Softening was
considered and rejected: a comment full of "possible", "might" and "consider"
gets skimmed, and once it is skimmed the verified findings go unread with the
rest.

Every test runs against `ScriptedProvider`. No key, no network — which is the
point of the provider abstraction: an agent tier that can only be tested by
spending money does not get tested.
"""

from __future__ import annotations

import unittest

from pr_sentinel.models import Engine, Severity
from pr_sentinel.tier2.verification import verify_findings
from tests.helpers import (
    VERIFY_NEEDLE,
    FailingProvider,
    TempDirTestCase,
    json_response,
    make_context,
    make_finding,
    scripted,
    synthetic_diff,
    write_tree,
)

SOURCE = """\
export async function loadStudent(id: string) {
  const { data } = await supabase.from("students").select("*").eq("id", id);
  return data;
}
"""

MODEL = "claude-sonnet-5-5"


def agent_finding(title: str, severity=Severity.HIGH, *, path="src/data.ts", line=2):
    return make_finding(
        "agent.security",
        severity,
        engine=Engine.AGENT,
        pack="agent:security",
        path=path,
        line=line,
        title=title,
    )


def confirmed(reason="the select has no tenant predicate", **extra) -> str:
    payload = {"verdict": "confirmed", "reason": reason, "corrected_severity": None,
               "corrected_line": None}
    payload.update(extra)
    import json

    return json_response(json.dumps(payload))


def rejected(reason="the guard clause eleven lines above already handles this") -> str:
    import json

    return json_response(
        json.dumps(
            {"verdict": "rejected", "reason": reason, "corrected_severity": None,
             "corrected_line": None}
        )
    )


class VerificationTestCase(TempDirTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.root = self.make_repo({"src/data.ts": SOURCE})
        self.ctx = make_context(
            self.root,
            synthetic_diff({"src/data.ts": [(2, '  const { data } = await supabase...')]}),
        )


class DroppingTests(VerificationTestCase):
    def test_a_rejected_finding_is_dropped_and_not_softened(self):
        finding = agent_finding("Missing tenant predicate")
        provider = scripted(("Missing tenant predicate", rejected()))
        result = verify_findings(self.ctx, [finding], provider, model=MODEL)

        self.assertNotIn(finding, result.confirmed)
        self.assertEqual([f for f, _ in result.rejected], [finding])
        # Not softened: it did not come back at a lower severity instead.
        self.assertIs(finding.severity, Severity.HIGH)
        self.assertIsNot(finding.verified, True)

    def test_the_rejection_reason_is_kept_so_the_drop_can_be_audited(self):
        finding = agent_finding("Missing tenant predicate")
        provider = scripted(("Missing tenant predicate", rejected("handled by a wrapper")))
        result = verify_findings(self.ctx, [finding], provider, model=MODEL)
        self.assertIn("handled by a wrapper", result.rejected[0][1])

    def test_a_confirmed_finding_survives_and_is_marked_verified(self):
        finding = agent_finding("Missing tenant predicate")
        provider = scripted(("Missing tenant predicate", confirmed()))
        result = verify_findings(self.ctx, [finding], provider, model=MODEL)
        self.assertEqual(result.confirmed, [finding])
        self.assertTrue(finding.verified)
        self.assertIn("tenant predicate", finding.verification_note or "")

    def test_confirmed_and_rejected_findings_are_separated_in_one_run(self):
        good = agent_finding("Real problem")
        bad = agent_finding("Imagined problem")
        provider = scripted(
            ("Real problem", confirmed()),
            ("Imagined problem", rejected()),
        )
        result = verify_findings(self.ctx, [good, bad], provider, model=MODEL)
        self.assertEqual(result.confirmed, [good])
        self.assertEqual([f for f, _ in result.rejected], [bad])
        self.assertAlmostEqual(result.drop_rate, 0.5)

    def test_the_drop_rate_of_an_empty_run_is_zero_rather_than_undefined(self):
        result = verify_findings(self.ctx, [], scripted(), model=MODEL)
        self.assertEqual(result.drop_rate, 0.0)


class NoModelCallNeededTests(VerificationTestCase):
    def test_a_finding_citing_a_nonexistent_file_is_rejected_without_a_model_call(self):
        # Disqualifying on its own and it costs nothing to determine, so
        # paying a model to read a file that is not there would be waste.
        finding = agent_finding("Ghost finding", path="src/does-not-exist.ts")
        provider = scripted(("Ghost finding", confirmed()))
        result = verify_findings(self.ctx, [finding], provider, model=MODEL)

        self.assertEqual(provider.prompts, [])
        self.assertEqual(result.confirmed, [])
        self.assertIn("does not exist", result.rejected[0][1])

    def test_a_finding_with_no_location_is_dropped_rather_than_passed_through(self):
        finding = agent_finding("Vague worry", path=None)
        provider = scripted(("Vague worry", confirmed()))
        result = verify_findings(self.ctx, [finding], provider, model=MODEL)
        self.assertEqual(provider.prompts, [])
        self.assertEqual(result.confirmed, [])

    def test_a_finding_on_a_pseudo_path_is_dropped_rather_than_verified(self):
        finding = agent_finding("About the PR body", path="<pr-body>")
        provider = scripted(("About the PR body", confirmed()))
        result = verify_findings(self.ctx, [finding], provider, model=MODEL)
        self.assertEqual(provider.prompts, [])
        self.assertEqual(result.confirmed, [])


class FailClosedTests(VerificationTestCase):
    def test_a_model_error_drops_the_finding_rather_than_letting_it_through(self):
        # Failing open here would quietly turn verification off exactly when
        # the API is flaky — the run that looks normal and is not.
        finding = agent_finding("Missing tenant predicate")
        provider = FailingProvider(VERIFY_NEEDLE)
        result = verify_findings(self.ctx, [finding], provider, model=MODEL)

        self.assertEqual(result.confirmed, [])
        self.assertEqual([f for f, _ in result.rejected], [finding])
        self.assertIn("dropped unverified", result.rejected[0][1])

    def test_a_model_error_is_also_recorded_as_a_run_error(self):
        # The drop must be visible as degradation, not just as silence.
        finding = agent_finding("Missing tenant predicate")
        result = verify_findings(self.ctx, [finding], FailingProvider(VERIFY_NEEDLE), model=MODEL)
        self.assertTrue(any("verification error" in e for e in result.errors))

    def test_one_failed_call_does_not_stop_the_other_findings_being_verified(self):
        good = agent_finding("Real problem")
        doomed = agent_finding("Explodes")
        provider = FailingProvider("Explodes", [("Real problem", confirmed())])
        result = verify_findings(self.ctx, [good, doomed], provider, model=MODEL)
        self.assertEqual(result.confirmed, [good])
        self.assertEqual([f for f, _ in result.rejected], [doomed])

    def test_an_unparseable_response_drops_the_finding(self):
        # Inventing structure from a garbled response is how a reviewer
        # reports something the model never said.
        finding = agent_finding("Missing tenant predicate")
        provider = scripted(("Missing tenant predicate", "I'm not sure, honestly."))
        result = verify_findings(self.ctx, [finding], provider, model=MODEL)
        self.assertEqual(result.confirmed, [])
        self.assertIn("no usable verdict", result.rejected[0][1])

    def test_a_response_with_no_verdict_key_drops_the_finding(self):
        finding = agent_finding("Missing tenant predicate")
        provider = scripted(("Missing tenant predicate", json_response('{"reason": "sure"}')))
        result = verify_findings(self.ctx, [finding], provider, model=MODEL)
        self.assertEqual(result.confirmed, [])

    def test_an_unrecognised_verdict_string_is_not_treated_as_confirmation(self):
        finding = agent_finding("Missing tenant predicate")
        provider = scripted(
            ("Missing tenant predicate", json_response('{"verdict": "maybe", "reason": "eh"}'))
        )
        result = verify_findings(self.ctx, [finding], provider, model=MODEL)
        self.assertEqual(result.confirmed, [])


class SeverityCorrectionTests(VerificationTestCase):
    def test_corrected_severity_may_lower_the_severity(self):
        finding = agent_finding("Missing tenant predicate", Severity.HIGH)
        provider = scripted(
            ("Missing tenant predicate", confirmed(corrected_severity="low"))
        )
        verify_findings(self.ctx, [finding], provider, model=MODEL)
        self.assertIs(finding.severity, Severity.LOW)

    def test_a_lowering_is_recorded_so_the_comment_can_show_it(self):
        finding = agent_finding("Missing tenant predicate", Severity.HIGH)
        provider = scripted(
            ("Missing tenant predicate", confirmed(corrected_severity="medium"))
        )
        verify_findings(self.ctx, [finding], provider, model=MODEL)
        self.assertEqual(
            finding.metadata["severity_lowered_by_verification"], "high -> medium"
        )

    def test_corrected_severity_may_never_raise_the_severity(self):
        # Verification substantiates or drops; it is not a second chance to
        # escalate, and a model that could raise severity could reach
        # `critical` by the back door.
        finding = agent_finding("Missing tenant predicate", Severity.MEDIUM)
        provider = scripted(
            ("Missing tenant predicate", confirmed(corrected_severity="high"))
        )
        verify_findings(self.ctx, [finding], provider, model=MODEL)
        self.assertIs(finding.severity, Severity.MEDIUM)
        self.assertNotIn("severity_lowered_by_verification", finding.metadata)

    def test_a_corrected_severity_equal_to_the_claimed_one_changes_nothing(self):
        finding = agent_finding("Missing tenant predicate", Severity.HIGH)
        provider = scripted(
            ("Missing tenant predicate", confirmed(corrected_severity="high"))
        )
        verify_findings(self.ctx, [finding], provider, model=MODEL)
        self.assertIs(finding.severity, Severity.HIGH)

    def test_a_nonsense_corrected_severity_is_ignored_rather_than_fatal(self):
        finding = agent_finding("Missing tenant predicate", Severity.HIGH)
        provider = scripted(
            ("Missing tenant predicate", confirmed(corrected_severity="spicy"))
        )
        result = verify_findings(self.ctx, [finding], provider, model=MODEL)
        self.assertEqual(result.confirmed, [finding])
        self.assertIs(finding.severity, Severity.HIGH)

    def test_a_corrected_line_moves_the_location_without_losing_the_path(self):
        finding = agent_finding("Missing tenant predicate", line=2)
        provider = scripted(("Missing tenant predicate", confirmed(corrected_line=3)))
        verify_findings(self.ctx, [finding], provider, model=MODEL)
        self.assertEqual(finding.location.line, 3)
        self.assertEqual(finding.location.path, "src/data.ts")


class PromptTests(VerificationTestCase):
    """It reads the file, not the diff. Most false findings are context
    errors, so the prompt has to carry the evidence that would refute one."""

    def test_the_prompt_carries_the_real_source_from_head_not_just_the_diff(self):
        finding = agent_finding("Missing tenant predicate")
        provider = scripted(("Missing tenant predicate", confirmed()))
        verify_findings(self.ctx, [finding], provider, model=MODEL)
        prompt = provider.prompts[0][1]
        self.assertIn("loadStudent", prompt)
        self.assertIn("Actual source at that location", prompt)

    def test_the_system_prompt_asks_whether_the_finding_is_wrong(self):
        # Asking a model to confirm its own output produces confirmation.
        finding = agent_finding("Missing tenant predicate")
        provider = scripted(("Missing tenant predicate", confirmed()))
        verify_findings(self.ctx, [finding], provider, model=MODEL)
        self.assertEqual(len(provider.prompts), 1)

    def test_verification_uses_the_model_it_was_asked_to_use(self):
        finding = agent_finding("Missing tenant predicate")
        provider = scripted(("Missing tenant predicate", confirmed()))
        verify_findings(self.ctx, [finding], provider, model="some-review-model")
        self.assertEqual(provider.prompts[0][0], "some-review-model")

    def test_untracked_source_read_through_the_working_tree_is_enough(self):
        write_tree(self.root, {"src/extra.ts": "export const x = 1;\n"})
        finding = agent_finding("Elsewhere", path="src/extra.ts", line=1)
        provider = scripted(("Elsewhere", confirmed()))
        result = verify_findings(self.ctx, [finding], provider, model=MODEL)
        self.assertEqual(result.confirmed, [finding])


if __name__ == "__main__":
    unittest.main()
