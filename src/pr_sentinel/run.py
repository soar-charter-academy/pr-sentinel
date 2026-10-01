"""Top-level orchestration: one function that performs a whole review.

The ordering here is the architecture from DESIGN s3, and each step's
placement is an argument rather than a convenience:

    Tier 0  project checks        cheap, certain, and if it fails nothing
                                  below is worth paying for
    Tier 1  deterministic packs   the guarantees; no model, unarguable
    Tier 2  agent passes          the judgment, then verification
    Verdict one comment, two statuses

`review()` returns a structured result and writes nothing. Publishing is a
separate step, so the CLI can dry-run a review against any checkout without
credentials and without touching a pull request.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .config import Config, load_config
from .context import PullRequest, ReviewContext
from .diff import Diff, git_diff
from .models import Finding, Provenance, Verdict
from .packs.loader import load_lore, resolve_packs
from .policy import AutoMergeRecommendation, auto_merge_recommendation, compute_verdict
from .tier0.project_checks import Tier0Result, run_tier0
from .tier1.engine import Tier1Result, run_tier1
from .tier1.semgrep_runner import semgrep_version
from .tier2.agent import AgentResult, run_tier2
from .tier2.provider import ModelProvider


@dataclass
class ReviewResult:
    verdict: Verdict
    recommendation: AutoMergeRecommendation
    context: ReviewContext
    tier0: Tier0Result | None = None
    tier1: Tier1Result | None = None
    tier2: AgentResult | None = None
    degraded_notes: list[str] = field(default_factory=list)

    @property
    def dropped_count(self) -> int:
        return len(self.tier2.dropped) if self.tier2 else 0


def review(
    repo_root: Path | str,
    *,
    base: str = "main",
    head: str = "HEAD",
    config: Config | None = None,
    config_path: Path | str | None = None,
    packs_dir: Path | str | None = None,
    pr: PullRequest | None = None,
    provider: ModelProvider | None = None,
    diff: Diff | None = None,
    run_tier0_checks: bool = True,
    run_agent: bool = True,
) -> ReviewResult:
    started = time.monotonic()
    root = Path(repo_root)

    cfg = config or load_config(root, config_path)
    notes: list[str] = list(cfg.warnings)
    degraded: list[str] = []

    packs, pack_warnings = resolve_packs(cfg, packs_dir, engine_version=__version__)
    notes.extend(pack_warnings)

    if diff is None:
        diff = git_diff(root, base, head)
    diff = diff.filter_paths(cfg.ignore.paths)

    pull_request = pr or PullRequest.from_env() or PullRequest(base_ref=base, head_ref=head)

    ctx = ReviewContext(
        repo_root=root,
        config=cfg,
        diff=diff,
        pr=pull_request,
        packs=packs,
        lore=load_lore(root, cfg),
        head_ref=head,
    )

    if cfg.lore_path and ctx.lore is None:
        notes.append(
            f"`lore: {cfg.lore_path}` is configured but the file was not found. "
            "The `lore` pass has nothing to check against."
        )

    findings: list[Finding] = []

    # -- Tier 0 -----------------------------------------------------------
    tier0: Tier0Result | None = None
    tier0_failed = False
    if run_tier0_checks and cfg.tier0.enabled:
        tier0 = run_tier0(
            root,
            commands=cfg.tier0.commands,
            fail_fast=cfg.tier0.fail_fast,
            timeout_seconds=cfg.tier0.timeout_seconds,
            audit_level=cfg.tier0.audit_level,
            enabled=cfg.tier0.enabled,
        )
        findings.extend(tier0.findings)
        notes.extend(tier0.notes)
        tier0_failed = tier0.failed
    else:
        notes.append("Tier 0 project checks were not run for this review.")

    # -- Tier 1 -----------------------------------------------------------
    tier1 = run_tier1(ctx)
    findings.extend(tier1.findings)
    notes.extend(tier1.notes)
    # One source for "what did not run". Script-check errors, a missing
    # semgrep and a missing *required* adapter are the same fact as far as
    # this list is concerned — the deterministic tier cannot claim its
    # guarantees were checked — and `Tier1Result.degradation_notes` is where
    # that judgement is made, so the comment's warning block and the withheld
    # check-run cannot drift apart.
    degraded.extend(tier1.degradation_notes)

    # -- Tier 2 -----------------------------------------------------------
    tier2: AgentResult | None = None
    if run_agent and cfg.agent.enabled:
        if tier0_failed:
            # DESIGN s3: if the build is broken, spending model tokens on
            # nuanced review is waste.
            notes.append(
                "Agent tier skipped: the project's own checks failed, so a design "
                "review would be premature."
            )
        else:
            tier2 = run_tier2(ctx, provider, deterministic_findings=tier1.findings)
            findings.extend(tier2.findings)
            notes.extend(tier2.notes)
            degraded.extend(tier2.errors)

    # -- verdict ----------------------------------------------------------
    provenance = Provenance(
        engine_version=__version__,
        pack_versions=ctx.pack_versions,
        semgrep_version=(tier1.semgrep.version if tier1.semgrep else None) or semgrep_version(),
        tool_versions=tier1.tool_versions,
        models=(tier2.models if tier2 else {}),
        tool_calls=(tier2.tool_totals if tier2 else {}),
        commit_sha=pull_request.head_sha,
        run_url=_run_url(),
        started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )

    verdict = compute_verdict(
        cfg,
        findings,
        provenance,
        tier0_failed=tier0_failed,
        degraded=bool(degraded),
        notes=notes,
    )
    recommendation = auto_merge_recommendation(
        cfg,
        findings,
        tier0_failed=tier0_failed,
        degraded=bool(degraded),
    )

    provenance.duration_seconds = time.monotonic() - started

    return ReviewResult(
        verdict=verdict,
        recommendation=recommendation,
        context=ctx,
        tier0=tier0,
        tier1=tier1,
        tier2=tier2,
        degraded_notes=degraded,
    )


def _run_url() -> str | None:
    import os

    server = os.environ.get("GITHUB_SERVER_URL")
    repo = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID")
    if server and repo and run_id:
        return 