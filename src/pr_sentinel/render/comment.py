"""Rendering the single PR comment.

One comment, updated in place, never a thread of them. A reviewer that adds a
new comment per push buries the conversation the humans are having, and the
fastest way to get a bot muted is to make it noisy in the place people talk.

The ordering is deliberate: what blocks, then what is worth reading, then what
is merely recorded. Findings a human must act on appear above the fold;
everything else is behind a `<details>`. Provenance goes last, because it is
for the day something is wrong with the reviewer rather than with the code.
"""

from __future__ import annotations

from ..models import Engine, Finding, Severity, Tier, Verdict
from ..policy import AutoMergeRecommendation

#: Lets the engine find and update its own previous comment.
MARKER = "<!-- pr-sentinel:comment:v1 -->"

SEVERITY_BADGE = {
    Severity.CRITICAL: "🔴 critical",
    Severity.HIGH: "🟠 high",
    Severity.MEDIUM: "🟡 medium",
    Severity.LOW: "⚪ low",
    Severity.INFO: "⚪ info",
}

TIER_LABEL = {
    Tier.PROJECT: "project check",
    Tier.DETERMINISTIC: "deterministic rule",
    Tier.AGENT: "agent review",
}

NOT_LEGAL_ADVICE = (
    "This is a nonbinding, legal-adjacent observation. It flags a surface and "
    "names a framework that may be engaged; it is **not** a ruling that this "
    "change does or does not comply with anything, and it is not legal advice. "
    "Anything consequential should be confirmed with counsel."
)


def render_comment(
    verdict: Verdict,
    recommendation: AutoMergeRecommendation | None = None,
    *,
    degraded_notes: list[str] | None = None,
    dropped_count: int = 0,
) -> str:
    out: list[str] = [MARKER, "## pr-sentinel review", ""]

    out.append(_headline(verdict))
    out.append("")

    if degraded_notes:
        out.append("> [!WARNING]")
        out.append(
            "> **Part of this review did not run.** A clean result below does not "
            "mean the missing checks passed."
        )
        for note in degraded_notes[:6]:
            out.append(f"> - {note}")
        out.append("")

    blocking = verdict.blocking
    if blocking:
        out.append(f"### Blocking ({len(blocking)})")
        out.append("")
        for finding in blocking:
            out.extend(_render_finding(finding))
        out.append("")

    advisory = [
        f
        for f in verdict.findings
        if f not in blocking and f not in verdict.summary_only
    ]
    if advisory:
        out.append(f"### Worth a look ({len(advisory)})")
        out.append("")
        for finding in advisory:
            out.extend(_render_finding(finding))
        out.append("")

    if verdict.summary_only:
        out.append("<details>")
        out.append(f"<summary>Also noted ({len(verdict.summary_only)})</summary>")
        out.append("")
        for finding in verdict.summary_only:
            location = finding.location.render() if finding.location else "—"
            out.append(
                f"- {SEVERITY_BADGE[finding.severity]} `{finding.rule_id}` — "
                f"{finding.title} (`{location}`)"
            )
        out.append("")
        out.append("</details>")
        out.append("")

    if recommendation is not None:
        out.extend(_render_merge_status(recommendation))

    if dropped_count:
        out.append(
            f"<sub>The agent tier proposed {dropped_count} further finding(s) that "
            f"verification could not substantiate against the source. They were "
            f"dropped rather than reported with a hedge.</sub>"
        )
        out.append("")

    if verdict.notes:
        out.append("<details>")
        out.append("<summary>Run notes</summary>")
        out.append("")
        for note in verdict.notes:
            out.append(f"- {note}")
        out.append("")
        out.append("</details>")
        out.append("")

    out.extend(_render_provenance(verdict))
    return "\n".join(out).rstrip() + "\n"


def _headline(verdict: Verdict) -> str:
    if verdict.tier0_failed:
        return (
            "**The project's own checks did not pass.** Nothing further was reviewed "
            "in depth — there is no point weighing a design question while the build "
            "is red."
        )
    counts = verdict.counts()
    if not verdict.findings:
        return "**Nothing to report.** No rule fired and no review pass substantiated a finding."
    parts = [
        f"{counts[s.value]} {s.value}" for s in Severity if counts.get(s.value)
    ]
    summary = ", ".join(parts)
    if verdict.blocking:
        return (
            f"**{summary}.** {len(verdict.blocking)} finding(s) block under mode "
            f"`{verdict.mode}`."
        )
    return f"**{summary}.** Nothing blocks under mode `{verdict.mode}`."


def _render_finding(finding: Finding) -> list[str]:
    location = finding.location.render() if finding.location else "—"
    badge = SEVERITY_BADGE[finding.severity]
    tier = TIER_LABEL.get(finding.tier, "")

    lines = [
        f"#### {badge} — {finding.title}",
        "",
        f"`{finding.rule_id}` · {tier} · `{location}`",
        "",
        finding.message.strip(),
        "",
    ]

    if finding.nonbinding:
        lines.append(f"> {NOT_LEGAL_ADVICE}")
        if finding.frameworks:
            lines.append(">")
            lines.append(
                "> Frameworks plausibly engaged: "
                + ", ".join(f"**{f}**" for f in finding.frameworks)
            )
        lines.append("")

    if finding.verify_hint:
        lines.append(f"**What to verify:** {finding.verify_hint}")
        lines.append("")

    details: list[str] = [f"**Why this rule exists.** {finding.rationale.strip()}"]

    if finding.location and finding.location.snippet:
        details.append("")
        details.append("```")
        details.append(finding.location.snippet)
        details.append("```")

    if finding.engine is Engine.AGENT:
        details.append("")
        if finding.verified:
            note = finding.verification_note or "confirmed against the source"
            details.append(f"**Verified.** {note}")
        else:
            details.append(
                "**Not verified.** Verification was disabled for this run, so this "
                "finding has not been checked against the source."
            )
        if finding.confidence is not None:
            details.append(f" (model confidence {finding.confidence:.0%})")

    if finding.metadata.get("severity_lowered_by_verification"):
        details.append("")
        details.append(
            f"Severity lowered by verification: "
            f"{finding.metadata['severity_lowered_by_verification']}."
        )

    lines.append("<details><summary>Why, and what to do</summary>")
    lines.append("")
    lines.extend(details)
    lines.append("")
    lines.append("</details>")
    lines.append("")
    return lines


def _render_merge_status(recommendation: AutoMergeRecommendation) -> list[str]:
    """The deterministic-only status, stated plainly.

    Separated out because it is the status a branch protection rule should
    require, and a reader needs to be able to tell at a glance whether the
    thing gating their merge is a guarantee or an opinion.
    """
    if recommendation.safe:
        return [
            "### Deterministic status: clear",
            "",
            "Tier 0 and the deterministic rule packs found nothing at or above the "
            "configured threshold. No model contributed to this line, and nothing "
            "written in this pull request could have changed it.",
            "",
        ]
    lines = ["### Deterministic status: withheld", ""]
    for reason in recommendation.reasons:
        lines.append(f"- {reason}")
    lines.append("")
    return lines


def _render_provenance(verdict: Verdict) -> list[str]:
    p = verdict.provenance
    packs = ", ".join(f"{name}@{version}" for name, version in sorted(p.pack_versions.items()))
    models = ", ".join(f"{role}: {model}" for role, model in sorted(p.models.items()))

    rows = [f"engine `{p.engine_version}`"]
    if packs:
        rows.append(f"packs `{packs}`")
    if p.semgrep_version:
        rows.append(f"semgrep `{p.semgrep_version}`")
    else:
        rows.append("semgrep **not run**")
    adapter_versions = {
        name: version
        for name, version in sorted(p.tool_versions.items())
        if name != "semgrep"
    }
    if adapter_versions:
        # The adapters' own versions, not ours. DESIGN-V2 s3: somebody else
        # maintains these rule sets, so a verdict is only reproducible if the
        # comment records which version of their rules produced it.
        tools = ", ".join(f"{name} {version}" for name, version in adapter_versions.items())
        rows.append(f"adapters `{tools}`")
    else:
        rows.append("no adapter reported a version")
    if models:
        rows.append(f"models `{models}`")
    else:
        rows.append("agent tier not run")
    if p.tool_calls:
        # What the agent tier actually looked at, not just which model it
        # asked. A pass that read the repository and one that guessed produce
        # the same-looking finding; this is the only place they differ.
        tools = ", ".join(f"{name}×{n}" for name, n in sorted(p.tool_calls.items()))
        rows.append(f"tools `{tools}`")
    if p.commit_sha:
        rows.append(f"commit `{p.commit_sha[:8]}`")
    if p.duration_seconds:
        rows.append(f"{p.duration_seconds:.0f}s")

    return [
        "---",
        "",
        "<sub>" + " · ".join(rows) + "</sub>",
        "",
        "<sub>This is a recommendation, not an authority. It never merges, pushes, "
        "or edits code. Findings you disagree with should be argued with in review — "
        "and if a rule is wrong, that is a bug worth reporting against the engine.</sub>",
    ]
