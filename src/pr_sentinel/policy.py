"""Turning findings into a verdict.

Two things are decided here and nowhere else: what blocks, and what the
check-runs conclude.

## Why there are two check-runs

DESIGN s3 draws a hard boundary between guarantees (deterministic, correct
100% of the time) and judgment (agent, correct most of the time). That
boundary is only real if something downstream can act on one without the
other. So the engine publishes two statuses:

    pr-sentinel                  the whole review, per the configured mode
    pr-sentinel/deterministic    Tier 0 + Tier 1 only, never model-influenced

The second exists so that branch protection has something safe to require.
Its conclusion is a function of scripts and semgrep alone: no prompt
contributed to it, so no PR text can argue with it, and it does not move when
a model is swapped or a temperature drifts. That is the status you gate a
merge on. The combined status is for humans to read.

This is also the answer to "can this ever auto-merge?" — see
`Verdict.auto_merge_recommendation` and docs/AUTO-MERGE.md. The engine itself
never merges anything and holds no write permission. It publishes a status;
GitHub's own auto-merge decides what to do with it.
"""

from __future__ import annotations

from dataclasses import dataclass

from .config import Config
from .models import Authority, Engine, Finding, Provenance, Severity, Tier, Verdict

CHECK_NAME_COMBINED = "pr-sentinel"
CHECK_NAME_DETERMINISTIC = "pr-sentinel/deterministic"


@dataclass
class AutoMergeRecommendation:
    """Whether the deterministic tiers found a reason to stop.

    Deliberately named a *recommendation*. The engine has `contents: read`
    and could not merge anything if it wanted to (DESIGN s10), and s2 says it
    never auto-merges, never pushes code, never edits a PR. What it can do is
    publish a status honest enough that GitHub's native auto-merge can be
    keyed to it.
    """

    safe: bool
    reasons: list[str]
    #: Findings that would have to be resolved or dismissed first.
    blockers: list[Finding]
    #: True when some part of the deterministic tier did not run. A clean
    #: result from a tier that half-ran is not a clean result.
    degraded: bool = False

    @property
    def conclusion(self) -> str:
        if self.degraded:
            return "failure"
        return "success" if self.safe else "failure"


def compute_verdict(
    config: Config,
    findings: list[Finding],
    provenance: Provenance,
    *,
    tier0_failed: bool = False,
    degraded: bool = False,
    notes: list[str] | None = None,
) -> Verdict:
    blocking: list[Finding] = []
    summary_only: list[Finding] = []
    visible: list[Finding] = []

    for finding in findings:
        authority = config.authority_for(finding.severity)

        # The hard boundary, enforced at the point it matters. An agent
        # finding may be reported, may be severe, and may be right - but it
        # cannot by itself stop a merge, because it cannot be guaranteed and
        # because PR text is one of its inputs.
        if authority is Authority.BLOCKING and finding.engine is Engine.AGENT:
            authority = Authority.COMMENT
            finding.metadata.setdefault(
                "authority_downgraded",
                "agent findings are advisory by design; they never block",
            )

        if authority is Authority.IGNORE:
            continue
        if authority is Authority.BLOCKING:
            blocking.append(finding)
            visible.append(finding)
        elif authority is Authority.COMMENT:
            visible.append(finding)
        else:
            summary_only.append(finding)
            visible.append(finding)

    return Verdict(
        findings=visible,
        blocking=blocking,
        summary_only=summary_only,
        tier0_failed=tier0_failed,
        provenance=provenance,
        mode=config.mode,
        notes=list(notes or []),
    )


def deterministic_only(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.tier in (Tier.PROJECT, Tier.DETERMINISTIC)]


def auto_merge_recommendation(
    config: Config,
    findings: list[Finding],
    *,
    tier0_failed: bool,
    degraded: bool,
    threshold: Severity = Severity.HIGH,
) -> AutoMergeRecommendation:
    """The deterministic-only verdict, suitable for branch protection.

    `threshold` is the lowest severity that withholds the status. It defaults
    to `high` rather than `critical` deliberately: `critical` is a small,
    curated set, and a repo that auto-merges everything short of it is
    auto-merging a lot.

    Note what is *not* consulted: agent findings, the configured mode, and
    anything derived from PR text. This result must be reproducible from the
    code alone.
    """
    reasons: list[str] = []
    blockers: list[Finding] = []

    if tier0_failed:
        reasons.append("the project's own checks (Tier 0) did not pass")

    if degraded:
        reasons.append(
            "part of the deterministic tier did not run, so a clean result here "
            "would not mean the guarantees were checked"
        )

    for finding in deterministic_only(findings):
        if finding.severity.rank >= threshold.rank:
            blockers.append(finding)

    if blockers:
        by_severity: dict[str, int] = {}
        for f in blockers:
            by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
        summary = ", ".join(f"{count} {sev}" for sev, count in by_severity.items())
        reasons.append(f"deterministic findings at or above `{threshold.value}`: {summary}")

    return AutoMergeRecommendation(
        safe=not reasons,
        reasons=reasons,
        blockers=blockers,
        degraded=degraded,
    )


def check_run_output(
    verdict: Verdict, recommendation: AutoMergeRecommendation
) -> dict[str, dict[str, str]]:
    """Titles and summaries for the two check-runs."""
    counts = verdict.counts()
    headline = ", ".join(
        f"{counts[s.value]} {s.value}" for s in Severity if counts.get(s.value)
    ) or "no findings"

    if verdict.tier0_failed:
        combined_title = "Project checks failed"
    elif verdict.blocking:
        combined_title = f"{len(verdict.blocking)} blocking finding(s)"
    elif verdict.findings:
        combined_title = f"Review complete: {headline}"
    else:
        combined_title = "Review complete: nothing to report"

    if recommendation.safe:
        det_title = "No deterministic blockers"
        det_summary = (
            "Tier 0 and the deterministic rule packs found nothing at or above the "
            "configured threshold. This status is computed from scripts and semgrep "
            "only - no model contributed to it, and nothing written in this pull "
            "request could influence it."
        )
    else:
        det_title = "Deterministic checks withheld"
        det_summary = "Not clear to merge on the deterministic tier:\n\n" + "\n".join(
            f"- {reason}" for reason in recommendation.reasons
        )

    return {
        CHECK_NAME_COMBINED: {
            "title": combined_title,
            "summary": f"{headline}. Mode: `{verdict.mode}`.",
        },
        CHECK_NAME_DETERMINISTIC: {"title": det_title, "summary": det_summary},
    }
