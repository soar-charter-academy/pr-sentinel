"""Run the adapters a pack asked for, and be honest about the ones that did not.

This is `tier1/engine.py::_run_script_checks` for external tools, and it
copies that function's behaviour on purpose: a pack names adapters, an
unknown name is a version mismatch worth saying out loud, an adapter that
raises is contained rather than fatal, and nothing that failed to run is
allowed to look like something that ran and found nothing.

The one thing this adds over the script-check loop is the required/optional
distinction. A script check that crashes is always a bug. An adapter that
does not run is often just a tool that is not installed, which is normal for
`socket` and routine for `supabase-advisors`, and treating that as an engine
error would bury the case that actually matters. So failures are sorted:

- **optional adapter absent** — a note. Breadth lost, no guarantee lost.
- **required adapter absent or broken** — `withholds_deterministic_status`
  goes true. `zizmor` and `gitleaks` are the only two, and for both the
  absence means a class of problem was not looked for at all. On a private
  repo with no GitHub secret scanning, a missing `gitleaks` means nothing in
  the run read the diff for credentials.
- **adapter raised** — an error, a one-line traceback in the notes, and the
  review continues. One broken adapter must not cost the other five.

An adapter also runs at most once per review even if two packs enable it.
Running `gitleaks` twice produces duplicate findings that dedupe would mostly
hide and a doubled runtime that nothing would explain.
"""

from __future__ import annotations

import traceback
from dataclasses import dataclass, field

from ..diff import path_ignored
from ..models import Finding
from .base import (
    AdapterContext,
    AdapterResult,
    AdapterSpec,
    RegisteredAdapter,
    get,
)


@dataclass
class AdapterRunReport:
    """What the adapter layer did, in a shape the comment renderer can use."""

    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    #: Per-adapter raw results, for provenance and for tests.
    results: dict[str, AdapterResult] = field(default_factory=dict)

    ran: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    #: Adapters that were asked for but did not deliver their checks.
    degraded: list[str] = field(default_factory=list)
    #: The subset of `degraded` whose absence withholds the deterministic status.
    degraded_required: list[str] = field(default_factory=list)
    #: adapter id -> tool version, recorded for reproducibility.
    versions: dict[str, str] = field(default_factory=dict)

    @property
    def withholds_deterministic_status(self) -> bool:
        """True when a required adapter's guarantees were not enforced.

        The engine must not publish a passing deterministic check-run while
        this is true. That is the entire point of the `required` flag.
        """
        return bool(self.degraded_required)

    def degradation_notes(self) -> list[str]:
        """One line per required adapter whose checks did not run.

        This is what `run.py` puts into its `degraded` list, which is what
        withholds `pr-sentinel/deterministic` — so a missing `gitleaks` costs
        the status exactly as a missing semgrep does. Optional adapters are
        deliberately excluded: their absence is breadth lost, reported as a
        note in the comment, and withholding the status for it would make the
        status permanently red on every machine without a Socket API key.

        The adapter's own note is preferred where it has one, because
        `missing_tool_result` already states the install hint and names what
        was not enforced. The fallback covers the adapter that *raised*, where
        there is no tool-level note to quote.
        """
        notes: list[str] = []
        for adapter_id in self.degraded_required:
            result = self.results.get(adapter_id)
            own = [n for n in (result.notes if result else []) if n.strip()]
            if own:
                notes.extend(own)
            else:
                notes.append(
                    f"required adapter `{adapter_id}` did not run, so the checks it "
                    f"provides were not performed in this review."
                )
        return notes

    def summary(self) -> str:
        """One line for the comment's provenance block."""
        parts = [f"{len(self.ran)} adapter(s) ran"]
        if self.skipped:
            parts.append(f"{len(self.skipped)} not applicable")
        if self.degraded:
            parts.append(f"{len(self.degraded)} degraded")
        if self.degraded_required:
            parts.append(
                f"{len(self.degraded_required)} REQUIRED adapter(s) did not run: "
                + ", ".join(self.degraded_required)
            )
        return "; ".join(parts)


def run_adapters(
    ctx: AdapterContext,
    specs: list[AdapterSpec],
) -> AdapterRunReport:
    report = AdapterRunReport()
    changed = [f.path for f in ctx.diff.files]
    seen: dict[str, str] = {}

    for spec in specs:
        if not spec.enabled:
            report.skipped.append(f"{spec.adapter_id} (disabled by pack {spec.pack})")
            continue

        if spec.adapter_id in seen:
            report.notes.append(
                f"adapter `{spec.adapter_id}` is enabled by both "
                f"`{seen[spec.adapter_id]}` and `{spec.pack}`; it was run once, "
                f"under `{seen[spec.adapter_id]}`."
            )
            continue

        registered = get(spec.adapter_id)
        if registered is None:
            # Identical reasoning to the script-check loop: a pack pinned
            # expecting a guarantee this engine cannot provide, and the user
            # needs to know the guarantee is absent, not just that a name was
            # unrecognised.
            report.errors.append(
                f"pack {spec.pack} enables unknown adapter `{spec.adapter_id}`. "
                f"This engine does not implement it, so that tool is NOT "
                f"running. Check your pack pin."
            )
            continue

        if registered.applies_to and not any(
            path_ignored(p, registered.applies_to) for p in changed
        ):
            report.skipped.append(f"{spec.adapter_id} (no matching files)")
            continue

        seen[spec.adapter_id] = spec.pack

        try:
            result = registered.fn(ctx, spec) or AdapterResult()
        except Exception as exc:  # noqa: BLE001
            # Contained, but never silent. An adapter that raises is an engine
            # bug; the checks it owns still did not run, and if it was a
            # required adapter that is a withheld status, not a footnote.
            report.errors.append(
                f"adapter `{spec.adapter_id}` raised {type(exc).__name__}: {exc}. "
                f"`{registered.tool}` did not run and its checks were not "
                f"performed. "
                + (
                    "A REQUIRED adapter failed, so the deterministic status is "
                    "being withheld. "
                    if registered.required
                    else ""
                )
                + "Please report this against the engine."
            )
            report.notes.append(
                f"traceback ({spec.adapter_id}): "
                + "".join(traceback.format_exception_only(type(exc), exc)).strip()
            )
            _mark_degraded(report, registered)
            continue

        _absorb(report, registered, spec, result)

    return report


def _absorb(
    report: AdapterRunReport,
    registered: RegisteredAdapter,
    spec: AdapterSpec,
    result: AdapterResult,
) -> None:
    report.results[spec.adapter_id] = result
    report.findings.extend(result.findings)
    report.notes.extend(result.notes)
    report.errors.extend(result.errors)
    if result.version:
        report.versions[spec.adapter_id] = result.version

    if result.ran and not result.degraded:
        report.ran.append(spec.adapter_id)
        return

    # `ran=False` and `degraded=True` both mean the tool's checks were not
    # performed. They are kept as separate fields upstream because the first
    # is "it was never invoked" and the second is "it was and it failed", but
    # for the purpose of deciding what we are allowed to claim they are the
    # same fact.
    _mark_degraded(report, registered)


def _mark_degraded(report: AdapterRunReport, registered: RegisteredAdapter) -> None:
    if registered.adapter_id not in report.degraded:
        report.degraded.append(registered.adapter_id)
    if registered.required and registered.adapter_id not in report.degraded_required:
        report.degraded_required.append(registered.adapter_id)


def missing_required_adapters(specs: list[AdapterSpec]) -> list[str]:
    """Required adapters a pack enables that this engine does not implement.

    Used by `sentinel validate`, so a pack pin that promises `zizmor` from a
    newer engine fails at configuration time rather than at review time.
    """
    missing: list[str] = []
    for spec in specs:
        if spec.enabled and get(spec.adapter_id) is None:
            missing.append(f"{spec.pack}: {spec.adapter_id}")
    return missing
