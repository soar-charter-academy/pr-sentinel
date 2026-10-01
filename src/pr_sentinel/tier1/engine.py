"""Tier 1: run the deterministic rules and return severity-tagged findings.

This tier is the one that holds the guarantees. DESIGN s1: "No policy in this
repo may ever say `using (true)`" is a fact about text. A script decides it
correctly 100% of the time; a model decides it correctly ~95% of the time,
which for a security rule is worse than having no rule, because you will
trust it.

Everything here follows from that. The tier does not consult a model, cannot
be argued with by PR content, and is the only tier permitted to emit
`critical`. When part of it fails to run, that is reported loudly rather than
absorbed, because a run that quietly skipped its guarantees still prints "no
critical findings".

Since DESIGN-V2 s3 the tier has three sources rather than two, and they are
peers:

    script checks   our own code, for facts nobody else checks
    adapters        zizmor, gitleaks, socket, squawk, supabase-advisors,
                    actionlint — run the real tool, normalise its output
    semgrep         declarative pattern rules from packs and from the repo

They are peers in the sense that matters here: all three produce `Finding`
values that one severity policy and one verdict govern, and for all three a
part that did not run withholds the deterministic check-run rather than
passing quietly. The distinction the adapter layer adds is `required` versus
optional — a missing `socket` costs breadth, a missing `gitleaks` costs a
guarantee — and that distinction lives in `adapters/runner.py`, not here.
"""

from __future__ import annotations

import os
import tempfile
import traceback
from dataclasses import dataclass, field
from pathlib import Path

from ..adapters import AdapterContext, AdapterRunReport, AdapterSpec, run_adapters
from ..context import ReviewContext
from ..diff import path_ignored
from ..models import Finding, Severity
from ..packs.loader import Pack
from .checks import base as checks_base
from .local_rules import LocalRuleReport, load_local_rules
from .semgrep_runner import SemgrepResult, run_semgrep

# Importing the check modules is what populates the registry. Explicit rather
# than a directory scan: a check that silently fails to register is a rule
# everyone believes is running.
#
# `core_hygiene` and `github_actions` are absent because they were deleted:
# gitleaks and zizmor do their jobs, with a far larger corpus, and the
# adapter package's own import list is now what populates the other half of
# the registry (DESIGN-V2 s3).
from .checks import (  # noqa: F401  (imported for side effects)
    privacy_edu,
    react_vite,
    supabase_sql,
    supply_chain,
)


@dataclass
class Tier1Result:
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    semgrep: SemgrepResult | None = None
    local_rules: LocalRuleReport | None = None
    #: What the adapter layer did. `None` means adapters were not run at all
    #: (a test, or `run_adapter_tools=False`), which is different from "ran
    #: and found nothing" and is kept distinguishable on purpose.
    adapters: AdapterRunReport | None = None
    checks_run: list[str] = field(default_factory=list)
    checks_skipped: list[str] = field(default_factory=list)

    @property
    def degraded(self) -> bool:
        """True when some part of the tier did not run.

        Surfaced in the comment. A deterministic tier that ran at 70% and said
        nothing about it is the failure mode this whole design exists to
        avoid.

        A *required* adapter counts here and an optional one does not, which
        is the only asymmetry in the tier. The reasoning is in
        `adapters/runner.py`: `socket` needs an API key and `supabase-advisors`
        needs a reachable database, so treating their absence as degradation
        would paint the status red on every fork and every laptop, and a
        warning that is always on is a warning nobody reads.
        """
        return (
            bool(self.errors)
            or (self.semgrep is not None and not self.semgrep.ran)
            or (self.adapters is not None and self.adapters.withholds_deterministic_status)
        )

    @property
    def degradation_notes(self) -> list[str]:
        """Why the deterministic status should be withheld, in English.

        `run.py` concatenates this into its `degraded` list, so the comment's
        "part of this review did not run" block and the withheld check-run are
        driven by one source rather than two that can disagree.
        """
        notes = list(self.errors)
        if self.semgrep is not None and not self.semgrep.ran:
            notes.extend(self.semgrep.notes)
        if self.adapters is not None:
            notes.extend(self.adapters.degradation_notes())
        return notes

    @property
    def tool_versions(self) -> dict[str, str]:
        """adapter id -> tool version, for `Provenance`.

        A verdict has to be reproducible, and "zizmor ran" is not reproducible
        without "which zizmor".
        """
        versions = dict(self.adapters.versions) if self.adapters else {}
        if self.semgrep is not None and self.semgrep.version:
            versions.setdefault("semgrep", self.semgrep.version)
        return versions


def run_tier1(
    ctx: ReviewContext,
    *,
    run_semgrep_rules: bool = True,
    run_adapter_tools: bool = True,
) -> Tier1Result:
    result = Tier1Result()
    result.findings.extend(_run_script_checks(ctx, result))

    if run_adapter_tools:
        _run_adapter_tools(ctx, result)

    if run_semgrep_rules:
        _run_semgrep_rules(ctx, result)

    # After all three sources, so that `ignore.paths`, `ignore.rules` and
    # dedup apply identically to an adapter finding and to one of ours. An
    # adapter that bypassed the repo's ignore lists would be an adapter the
    # repo had no way to quiet.
    result.findings = _postprocess(ctx, result.findings)
    return result


# ---------------------------------------------------------------------------
# script checks
# ---------------------------------------------------------------------------


def _run_script_checks(ctx: ReviewContext, result: Tier1Result) -> list[Finding]:
    findings: list[Finding] = []
    changed = ctx.changed_paths

    for pack in ctx.packs:
        for spec in pack.script_checks:
            if not spec.enabled:
                result.checks_skipped.append(f"{spec.check_id} (disabled by pack)")
                continue

            registered = checks_base.get(spec.check_id)
            if registered is None:
                # A pack referencing a check this engine does not have is a
                # version mismatch, and it is worth saying out loud: the pack
                # was pinned expecting a guarantee that is not being enforced.
                result.errors.append(
                    f"pack {pack.name}@{pack.version} enables unknown check "
                    f"`{spec.check_id}`. This engine does not implement it, so that "
                    f"check is NOT running. Check your pack pin."
                )
                continue

            if registered.applies_to and not registered.reads_whole_repo:
                if not any(path_ignored(p, registered.applies_to) for p in changed):
                    result.checks_skipped.append(f"{spec.check_id} (no matching files)")
                    continue

            severity = (
                Severity.parse(spec.severity) if spec.severity else registered.default_severity
            )
            check_spec = checks_base.CheckSpec(
                check_id=spec.check_id,
                pack=pack.name,
                severity=severity,
                options=dict(spec.options),
                default_title=registered.title,
            )

            try:
                produced = list(registered.fn(ctx, check_spec) or [])
            except Exception as exc:  # noqa: BLE001
                # One broken check must not take down the review. It must also
                # not be invisible: a crashed critical check is a missing
                # guarantee, and the comment says so.
                result.errors.append(
                    f"check `{spec.check_id}` raised {type(exc).__name__}: {exc}. "
                    f"That check did not run. "
                    + ("A CRITICAL check failed to run. " if severity is Severity.CRITICAL else "")
                    + "Please report this against the engine."
                )
                result.notes.append(
                    "traceback (" + spec.check_id + "): "
                    + "".join(traceback.format_exception_only(type(exc), exc)).strip()
                )
                continue

            result.checks_run.append(spec.check_id)
            findings.extend(produced)

    return findings


# ---------------------------------------------------------------------------
# adapters
# ---------------------------------------------------------------------------


def adapter_specs(packs: list[Pack]) -> list[AdapterSpec]:
    """Every adapter the resolved packs enable, in pack order.

    Duplicates are left in deliberately. `runner.run_adapters` is the one
    place that decides what happens when two packs want the same tool, and it
    says so in a note rather than silently collapsing it here — the user
    benefits from knowing that `gitleaks` arrived twice.
    """
    specs: list[AdapterSpec] = []
    for pack in packs:
        specs.extend(pack.adapters)
    return specs


def _run_adapter_tools(ctx: ReviewContext, result: Tier1Result) -> None:
    specs = adapter_specs(ctx.packs)
    if not specs:
        return

    # A thin slice of the review, not the review itself: an adapter gets the
    # checkout, the diff and the ignore list, and no access to the PR text.
    # Nothing an adapter does should be influenceable by the pull request's
    # description (DESIGN s10), and the cheapest way to guarantee that is to
    # not hand it over.
    report = run_adapters(
        AdapterContext(
            repo_root=ctx.repo_root,
            diff=ctx.diff,
            ignore_paths=list(ctx.config.ignore.paths),
            env=dict(os.environ),
        ),
        specs,
    )

    result.adapters = report
    result.findings.extend(report.findings)
    result.notes.extend(report.notes)
    # An adapter error is an engine-level problem (an unknown adapter id, or
    # one that raised) and belongs with the script-check errors, which already
    # withhold the status. A *missing tool* is not an error and is not here —
    # it arrives as a note, and `degraded` consults `required` for it.
    result.errors.extend(report.errors)


# ---------------------------------------------------------------------------
# semgrep
# ---------------------------------------------------------------------------


def _run_semgrep_rules(ctx: ReviewContext, result: Tier1Result) -> None:
    rule_files: list[Path] = []
    pack_of_rule: dict[str, str] = {}
    for pack in ctx.packs:
        for rf in pack.rule_files:
            rule_files.append(rf)
            pack_of_rule[rf.stem] = pack.name

    with tempfile.TemporaryDirectory(prefix="pr-sentinel-local-rules-") as staging:
        local = load_local_rules(
            ctx.repo_root, ctx.config.local_rules_path, staging_dir=Path(staging)
        )
        result.local_rules = local
        rule_files.extend(local.accepted_files)

        for rejection in local.rejections:
            result.errors.append(f"local rule rejected: {rejection}")
        for adjustment in local.adjustments:
            result.notes.append(f"local rule adjusted: {adjustment}")

        semgrep_result = run_semgrep(
            ctx.repo_root,
            rule_files,
            ctx.diff,
            pack_of_rule=pack_of_rule,
        )

    result.semgrep = semgrep_result
    result.findings.extend(semgrep_result.findings)
    result.notes.extend(semgrep_result.notes)
    result.errors.extend(semgrep_result.errors)


# ---------------------------------------------------------------------------
# post-processing
# ---------------------------------------------------------------------------


def _postprocess(ctx: ReviewContext, findings: list[Finding]) -> list[Finding]:
    """Apply the repo's ignore lists, deduplicate, and sort.

    Ignores are applied here rather than inside each check so that a rule
    author cannot forget to honour them, and so that `ignore.rules` works
    uniformly across semgrep rules and script checks.
    """
    ignore_paths = ctx.config.ignore.paths
    ignore_rules = set(ctx.config.ignore.rules)

    kept: dict[str, Finding] = {}
    for finding in findings:
        if _rule_ignored(finding.rule_id, ignore_rules):
            continue
        if finding.location and finding.location.path:
            path = finding.location.path
            # Pseudo-paths like "<pr-body>" are not repo files and are never
            # path-ignored; ignoring them would be ignoring the PR itself.
            if not path.startswith("<") and path_ignored(path, ignore_paths):
                continue
        existing = kept.get(finding.fingerprint)
        if existing is None or finding.severity.rank > existing.severity.rank:
            kept[finding.fingerprint] = finding

    ordered = sorted(
        kept.values(),
        key=lambda f: (
            -f.severity.rank,
            f.pack,
            f.rule_id,
            f.location.path if f.location else "",
            f.location.line or 0 if f.location else 0,
        ),
    )
    return ordered


def _rule_ignored(rule_id: str, ignore_rules: set[str]) -> bool:
    """Exact id, or a prefix ending in `.*`.

    Deliberately not full glob matching: `ignore: rules: ["*"]` should look
    like what it is, and a typo in an ignore pattern should fail closed
    (the rule keeps running) rather than open.
    """
    if rule_id in ignore_rules:
        return True
    for pattern in ignore_rules:
        if pattern.endswith(".*") and rule_id.startswith(pattern[:-1]):
            return True
        if pattern.endswith("*") and rule_id.startswith(pattern[:-1]):
            return True
    return False


def available_checks() -> dict[str, checks_base.RegisteredCheck]:
    return checks_base.all_checks()


def packs_missing_checks(packs: list[Pack]) -> list[str]:
    """Which enabled checks this engine cannot provide. Used by `sentinel validate`."""
    missing: list[str] = []
    for pack in packs:
        for spec in pack.script_checks:
            if checks_base.get(spec.check_id) is None:
                missing.append(f"{pack.name}: {spec.check_id}")
    return missing
