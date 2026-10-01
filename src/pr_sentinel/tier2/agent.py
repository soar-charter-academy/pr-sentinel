"""Tier 2 orchestration: triage, run the passes, then verify.

The shape is from DESIGN s9: triage cheap, escalate expensive. A fast model
picks which files warrant close reading; a strong model does the reading;
then everything it produced goes through verification before it can reach a
human.

Cost control is structural rather than advisory. The engine caps files read,
bytes per file, and findings emitted, and it skips the tier entirely for
draft PRs when configured to. A reviewer whose bill scales with a bad day in
the monorepo gets switched off, and a switched-off reviewer catches nothing.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from ..context import ReviewContext
from ..models import Engine, Finding, Location, Severity, Tier
from ..packs.loader import compose_briefing
from .passes import ALL_PASSES, TRIAGE_SYSTEM, AgentPass
from .provider import ModelError, ModelProvider, Usage, parse_json_response
from .sanitize import (
    InjectionSignal,
    fence_untrusted,
    injection_findings,
    scan_for_injection,
)
from .tools import LOCAL_TOOLS, ToolSession
from .verification import VerificationResult, verify_findings

#: Never worth a strong model's attention, whatever triage says.
ALWAYS_SKIP_SUFFIXES = {
    ".lock", ".snap", ".map", ".min.js", ".png", ".jpg", ".jpeg", ".gif",
    ".svg", ".ico", ".woff", ".woff2", ".ttf", ".pdf", ".zip",
}
ALWAYS_SKIP_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Cargo.lock", "go.sum", "composer.lock",
}


@dataclass
class AgentResult:
    findings: list[Finding] = field(default_factory=list)
    dropped: list[tuple[Finding, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    ran: bool = False
    usage: Usage = field(default_factory=Usage)
    models: dict[str, str] = field(default_factory=dict)
    triaged_files: list[str] = field(default_factory=list)
    duration: float = 0.0
    verification: VerificationResult | None = None
    #: pass name -> {tool name: call count}. Lands in provenance, so a reader
    #: of the comment can see that the `parity` pass grepped twice and read
    #: three files before it claimed a call site was stale. A finding whose
    #: investigation is visible is a finding a human can argue with.
    tool_usage: dict[str, dict[str, int]] = field(default_factory=dict)
    #: Every call, in order, with its arguments. Verbose on purpose: this is
    #: the audit trail for a tier that reads the repository.
    tool_log: list[dict[str, Any]] = field(default_factory=list)

    @property
    def tool_totals(self) -> dict[str, int]:
        totals: dict[str, int] = {}
        for counts in self.tool_usage.values():
            for tool, n in counts.items():
                totals[tool] = totals.get(tool, 0) + n
        return totals


@dataclass
class _PassOutcome:
    """What one pass produced, including how it went about it."""

    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    tool_counts: dict[str, int] = field(default_factory=dict)
    tool_log: list[dict[str, Any]] = field(default_factory=list)


def run_tier2(
    ctx: ReviewContext,
    provider: ModelProvider | None,
    *,
    deterministic_findings: list[Finding] | None = None,
) -> AgentResult:
    started = time.monotonic()
    result = AgentResult()
    cfg = ctx.config.agent

    if not cfg.enabled:
        result.notes.append("Agent tier disabled by config.")
        return result
    if provider is None:
        result.notes.append(
            "Agent tier skipped: no model provider configured. The deterministic "
            "tiers ran; judgment-level review did not."
        )
        return result
    if ctx.pr.is_draft and cfg.skip_draft_prs:
        result.notes.append("Agent tier skipped: pull request is a draft.")
        return result

    # An injection attempt is reported whether or not the agent tier runs,
    # because it is evidence about the change rather than about the tool.
    signals = scan_for_injection(ctx.pr.title.raw, "pull request title")
    signals += scan_for_injection(ctx.pr.body.raw, "pull request description")
    result.findings.extend(injection_findings(signals))

    candidate_files = _triage(ctx, provider, result)
    result.triaged_files = candidate_files
    if not candidate_files:
        result.notes.append("Agent tier: triage selected no files worth close review.")
        result.ran = True
        result.duration = time.monotonic() - started
        return result

    lore = ctx.lore
    candidates: list[Finding] = []

    for pass_name in cfg.passes:
        agent_pass = ALL_PASSES.get(pass_name)
        if agent_pass is None:
            result.errors.append(f"unknown agent pass `{pass_name}`; skipped")
            continue
        if pass_name == "lore" and not (lore and lore.strip()):
            result.notes.append(
                "Agent tier: `lore` pass skipped, this repo has no "
                "`.pr-sentinel/lore.md`. Same engine plus different lore is a "
                "different reviewer; without lore it is the generic one."
            )
            continue
        try:
            outcome = _run_pass(
                ctx, agent_pass, provider, candidate_files, lore, deterministic_findings or []
            )
        except ModelError as exc:
            result.errors.append(f"agent pass `{pass_name}` failed: {exc}")
            continue
        candidates.extend(outcome.findings)
        result.notes.extend(outcome.notes)
        if outcome.tool_counts:
            result.tool_usage[pass_name] = outcome.tool_counts
        result.tool_log.extend(outcome.tool_log)

    # Verification. Load-bearing: unverified findings are dropped, not
    # softened (DESIGN s3).
    if cfg.verification:
        verification = verify_findings(ctx, candidates, provider, model=cfg.review_model)
        result.verification = verification
        if verification.tool_counts:
            result.tool_usage["verification"] = verification.tool_counts
        result.tool_log.extend(verification.tool_log)
        result.notes.extend(verification.notes)
        result.findings.extend(verification.confirmed)
        result.dropped.extend(verification.rejected)
        if verification.rejected:
            result.notes.append(
                f"Verification dropped {len(verification.rejected)} of "
                f"{len(candidates)} candidate findings that the source did not "
                f"substantiate."
            )
        result.errors.extend(verification.errors)
    else:
        for finding in candidates:
            finding.verified = False
            finding.verification_note = "verification disabled by config"
        result.findings.extend(candidates)
        result.notes.append(
            "Verification was disabled for this run. Agent findings below are "
            "UNVERIFIED and should be read with that in mind."
        )

    # Cap after verification, so the cap discards the weakest surviving
    # findings rather than throwing away strong ones before they are checked.
    agent_only = [f for f in result.findings if f.engine is Engine.AGENT]
    if len(agent_only) > cfg.max_findings:
        agent_only.sort(key=lambda f: (-f.severity.rank, -(f.confidence or 0.0)))
        keep = set(id(f) for f in agent_only[: cfg.max_findings])
        trimmed = [f for f in result.findings if f.engine is not Engine.AGENT or id(f) in keep]
        result.notes.append(
            f"Agent tier produced {len(agent_only)} verified findings; showing the "
            f"{cfg.max_findings} most severe (agent.max_findings)."
        )
        result.findings = trimmed

    result.ran = True
    result.usage = provider.usage
    result.models = provider.models_used
    result.duration = time.monotonic() - started
    return result


# ---------------------------------------------------------------------------
# triage
# ---------------------------------------------------------------------------


def _triage(ctx: ReviewContext, provider: ModelProvider, result: AgentResult) -> list[str]:
    cfg = ctx.config.agent
    reviewable = [
        f
        for f in ctx.diff.live_files
        if not f.is_binary
        and f.suffix not in ALWAYS_SKIP_SUFFIXES
        and f.path.rsplit("/", 1)[-1] not in ALWAYS_SKIP_NAMES
        and f.added_lines
    ]
    if not reviewable:
        return []

    # Below the threshold, triage costs more than it saves.
    if len(reviewable) <= 4:
        return [f.path for f in reviewable][: cfg.max_files_reviewed]

    manifest = "\n".join(
        f"- {f.path} ({f.kind.value}, +{len(f.added_lines)}/-{len(f.removed_lines)})"
        for f in reviewable[:200]
    )
    prompt = (
        "## Changed files\n\n"
        + fence_untrusted(manifest, label="changed-file list", max_chars=8000)
        + f"\n\nReturn at most {cfg.max_files_reviewed} files."
    )

    try:
        completion = provider.complete(
            system=TRIAGE_SYSTEM,
            prompt=prompt,
            model=cfg.triage_model,
            max_tokens=1500,
            temperature=0.0,
        )
    except ModelError as exc:
        # Triage failing should degrade to "review the plausible files",
        # not to "review nothing".
        result.notes.append(f"Triage failed ({exc}); falling back to heuristic selection.")
        return [f.path for f in reviewable][: cfg.max_files_reviewed]

    data = parse_json_response(completion.text, expect="object")
    paths: list[str] = []
    known = {f.path for f in reviewable}
    for entry in (data or {}).get("files", []) if isinstance(data, dict) else []:
        path = str((entry or {}).get("path", "")).strip() if isinstance(entry, dict) else str(entry)
        # Only paths that are actually in the diff. A triage step that can
        # name arbitrary files is a file-read primitive driven by model output.
        if path in known and path not in paths:
            paths.append(path)

    if not paths:
        result.notes.append("Triage returned nothing usable; falling back to heuristic selection.")
        return [f.path for f in reviewable][: cfg.max_files_reviewed]
    return paths[: cfg.max_files_reviewed]


# ---------------------------------------------------------------------------
# a single pass
# ---------------------------------------------------------------------------


def _run_pass(
    ctx: ReviewContext,
    agent_pass: AgentPass,
    provider: ModelProvider,
    candidate_files: list[str],
    lore: str | None,
    deterministic: list[Finding],
) -> _PassOutcome:
    """Run one pass, with tools if it has them.

    The diff still goes in the prompt rather than being left for the pass to
    fetch: the diff is the subject of the review and the thing we want read
    first. Tools are for the questions the diff raises and cannot answer.
    """
    cfg = ctx.config.agent
    briefing = compose_briefing(ctx.packs, agent_pass.name, lore)

    session: ToolSession | None = None
    if cfg.tools_enabled and hasattr(provider, "complete_with_tools"):
        session = ToolSession(
            ctx,
            names=LOCAL_TOOLS
            + (("fetch_advisory",) if cfg.allow_network_tools else ()),
            budget=cfg.tool_budget,
            timeout_seconds=cfg.tool_timeout_seconds,
            allow_network=cfg.allow_network_tools,
            label=agent_pass.name,
        )
    system = agent_pass.system_prompt(
        briefing, tools=session.available if session else None
    )

    sections: list[str] = [
        "## Pull request\n\n"
        f"title:\n{ctx.pr.title.render_as_data(500)}\n\n"
        f"description:\n{ctx.pr.body.render_as_data(2000)}"
    ]

    if deterministic:
        already = "\n".join(
            f"- {f.rule_id} ({f.severity.value}) at "
            f"{f.location.render() if f.location else 'n/a'}: {f.title}"
            for f in deterministic[:30]
        )
        sections.append(
            "## Already reported by deterministic rules — do not repeat these\n\n" + already
        )

    budget = cfg.max_file_bytes
    for path in candidate_files:
        changed = ctx.file(path)
        if changed is None:
            continue
        body = _render_change(ctx, changed, budget)
        if not body:
            continue
        sections.append(
            f"## Change: {path} ({changed.kind.value})\n\n"
            + fence_untrusted(body, label=f"diff of {path}", max_chars=budget)
        )

    prompt = "\n\n".join(sections) + (
        "\n\nReturn JSON as specified. An empty `findings` list is the correct "
        "answer when this change raises nothing within your concern."
    )

    outcome = _PassOutcome()

    if session is not None:
        completion = provider.complete_with_tools(
            system=system,
            prompt=prompt,
            model=cfg.review_model,
            runner=session,
            max_tokens=4096,
            temperature=0.0,
            max_rounds=cfg.tool_budget + 4,
        )
        outcome.tool_counts = session.usage()
        outcome.tool_log = [
            dict(inv.to_dict(), pass_name=agent_pass.name) for inv in session.invocations
        ]
        # A budget note has to reach the comment. A pass that stopped looking
        # halfway through and said nothing is indistinguishable from a pass
        # that looked and found nothing, and those are not the same answer.
        outcome.notes.extend(
            f"Agent tier: {note}" for note in (session.notes + list(completion.notes))
        )
    else:
        completion = provider.complete(
            system=system,
            prompt=prompt,
            model=cfg.review_model,
            max_tokens=4096,
            temperature=0.0,
        )

    data = parse_json_response(completion.text, expect="object")
    if not isinstance(data, dict):
        return outcome

    findings: list[Finding] = []
    # A file the pass READ is a file the pass was shown. That is the whole
    # point of giving it tools: the stale call site is in a file the diff
    # never mentioned. What stays forbidden is a location the pass neither
    # saw in the diff nor read — which is a hallucination, not a finding.
    valid_paths = set(candidate_files) | (session.paths_read if session else set())

    for raw in data.get("findings") or []:
        if not isinstance(raw, dict):
            continue
        finding = _to_finding(raw, agent_pass, valid_paths)
        if finding is not None:
            findings.append(finding)

    # The pass noticed something the regex scan may have missed. Report it,
    # but from the pass's observation rather than its wording: the point is
    # that a human looks, not that the model narrates what it was told.
    if data.get("injection_observed"):
        observed = scan_for_injection(ctx.pr.body.raw, "pull request description") or [
            InjectionSignal(
                kind="reported-by-review-pass",
                source="pull request content",
                excerpt=f"the `{agent_pass.name}` pass reported text addressed to it",
            )
        ]
        findings.extend(injection_findings(observed))

    outcome.findings = findings
    return outcome


def _to_finding(raw: dict, agent_pass: AgentPass, valid_paths: set[str]) -> Finding | None:
    path = str(raw.get("path", "")).strip()
    # A finding about a file the pass was not shown is not a finding, it is a
    # hallucinated location. Dropping it here costs one verification call.
    if path not in valid_paths:
        return None

    title = str(raw.get("title", "")).strip()
    message = str(raw.get("message", "")).strip()
    rationale = str(raw.get("rationale", "")).strip()
    if not title or not message or not rationale:
        return None

    try:
        severity = Severity.parse(str(raw.get("severity", "medium")))
    except ValueError:
        severity = Severity.MEDIUM
    if severity.rank > agent_pass.max_severity.rank:
        severity = agent_pass.max_severity

    line = raw.get("line")
    line = int(line) if isinstance(line, int) and line > 0 else None

    confidence = raw.get("confidence")
    confidence = float(confidence) if isinstance(confidence, (int, float)) else None

    return Finding(
        rule_id=f"agent.{agent_pass.name}",
        severity=severity,
        title=title[:120],
        message=message,
        rationale=rationale,
        pack=f"agent:{agent_pass.name}",
        tier=Tier.AGENT,
        engine=Engine.AGENT,
        location=Location(path=path, line=line),
        confidence=confidence,
        nonbinding=agent_pass.nonbinding,
        frameworks=list(agent_pass.frameworks) if agent_pass.nonbinding else [],
        metadata={"evidence": str(raw.get("evidence", ""))[:600]},
    )


def _render_change(ctx: ReviewContext, changed, budget: int) -> str:
    """Render one file's change as a compact, line-numbered diff.

    Line numbers are the head-revision numbers, because every downstream step
    — verification, the comment, the human clicking through — works in head
    coordinates. A finding reported at a diff-relative offset is a finding
    nobody can find.
    """
    rows: list[str] = []
    size = 0
    for hunk in changed.hunks:
        rows.append(f"@@ around line {hunk.new_start} @@")
        for number, text in hunk.removed_lines:
            row = f"      - {text}"
            rows.append(row)
            size += len(row)
        for number, text in hunk.added_lines:
            row = f"{number:>5} + {text}"
            rows.append(row)
            size += len(row)
        if size > budget:
            rows.append(f"[... {changed.churn} changed lines total, truncated ...]")
            break
    return "\n".join(rows)
