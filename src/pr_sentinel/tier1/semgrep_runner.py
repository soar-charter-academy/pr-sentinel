"""The deterministic backend: semgrep, shelled out.

Why semgrep rather than regex (DESIGN s5): real AST matching, a rule format
that is already data, an existing public rule corpus to inherit, and
multi-language support for whatever repo this gets pointed at next.

Two operational decisions worth stating:

**semgrep is optional at import time and required at verdict time.** The
engine must import and run its tests without semgrep installed, but a run
that silently skips the deterministic tier is a run that reports "no critical
findings" without having looked. So a missing binary produces a loud note and,
in `--strict` mode, a non-zero exit.

**Findings are filtered to changed lines.** A rule firing on code the PR did
not touch is someone else's bug appearing in your review.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..diff import Diff
from ..models import Engine, Finding, Location, Severity, Tier

#: semgrep's own severities are coarse; the pack's `sentinel-severity`
#: metadata wins when present. This is the fallback.
_SEMGREP_SEVERITY = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

DEFAULT_TIMEOUT = 300


class SemgrepUnavailable(RuntimeError):
    pass


@dataclass
class SemgrepResult:
    findings: list[Finding] = field(default_factory=list)
    ran: bool = False
    version: str | None = None
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    rules_run: int = 0


def semgrep_path() -> str | None:
    return os.environ.get("PR_SENTINEL_SEMGREP_BIN") or shutil.which("semgrep")


def semgrep_version() -> str | None:
    binary = semgrep_path()
    if not binary:
        return None
    try:
        proc = subprocess.run(  # noqa: S603
            [binary, "--version"], capture_output=True, text=True, timeout=30, check=False
        )
        return (proc.stdout or proc.stderr).strip().splitlines()[0] if proc.stdout or proc.stderr else None
    except (OSError, subprocess.SubprocessError):
        return None


def run_semgrep(
    repo_root: Path | str,
    rule_files: list[Path],
    diff: Diff,
    *,
    pack_of_rule: dict[str, str] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    only_changed_files: bool = True,
    line_slack: int = 3,
) -> SemgrepResult:
    root = Path(repo_root)
    result = SemgrepResult()

    if not rule_files:
        result.notes.append("No semgrep rules enabled by the selected packs.")
        return result

    binary = semgrep_path()
    if not binary:
        result.notes.append(
            "semgrep is not installed, so the deterministic rule tier did NOT run. "
            "Install it (`pip install semgrep`) or use the engine's reusable workflow, "
            "which installs it. Critical guarantees are not being enforced in this run."
        )
        return result

    targets: list[str] = []
    if only_changed_files:
        targets = [f.path for f in diff.live_files if (root / f.path).is_file()]
        if not targets:
            result.notes.append("No changed files to scan.")
            result.ran = True
            return result

    result.version = semgrep_version()

    with tempfile.TemporaryDirectory(prefix="pr-sentinel-semgrep-") as tmp:
        output_path = Path(tmp) / "results.json"
        cmd = [
            binary,
            "scan",
            "--json",
            "--quiet",
            "--no-git-ignore",
            "--disable-version-check",
            "--metrics=off",
            f"--timeout={max(10, timeout // 5)}",
            "--output",
            str(output_path),
        ]
        for rf in rule_files:
            cmd.extend(["--config", str(rf)])
        cmd.extend(targets or ["."])

        try:
            proc = subprocess.run(  # noqa: S603
                cmd,
                cwd=str(root),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            result.notes.append(f"semgrep timed out after {timeout}s; rule tier incomplete.")
            return result
        except OSError as exc:
            result.notes.append(f"semgrep could not be executed: {exc}")
            return result

        result.ran = True

        if not output_path.is_file():
            result.errors.append(
                f"semgrep exited {proc.returncode} without writing results: "
                f"{(proc.stderr or '').strip()[:500]}"
            )
            return result

        try:
            data = json.loads(output_path.read_text(encoding="utf-8"))
        except ValueError as exc:
            result.errors.append(f"semgrep output was not valid JSON: {exc}")
            return result

    result.rules_run = len(rule_files)
    findings, errors = parse_semgrep_results(
        data,
        diff,
        pack_of_rule=pack_of_rule,
        only_changed_files=only_changed_files,
        line_slack=line_slack,
    )
    result.findings.extend(findings)
    result.errors.extend(errors)
    return result


def parse_semgrep_results(
    data: dict[str, Any],
    diff: Diff,
    *,
    pack_of_rule: dict[str, str] | None = None,
    only_changed_files: bool = True,
    line_slack: int = 3,
) -> tuple[list[Finding], list[str]]:
    """Turn semgrep's JSON payload into findings, filtered to changed lines.

    Split out from `run_semgrep` because everything interesting about the
    deterministic tier's semgrep half happens *after* the subprocess: which
    severity wins, which pack a rule belongs to, and whether the match lands
    on a line this pull request actually touched. Keeping it pure means those
    decisions can be exercised against a recorded payload, on a machine with
    no semgrep installed — which is most machines, and all of CI's early
    minutes.
    """
    findings: list[Finding] = []
    errors: list[str] = []

    for err in data.get("errors") or []:
        message = err.get("long_msg") or err.get("message") or str(err)
        errors.append(str(message)[:400])

    by_path = diff.by_path()

    for raw in data.get("results") or []:
        finding = _to_finding(raw, pack_of_rule or {})
        if finding is None:
            continue
        if only_changed_files and finding.location and finding.location.line:
            changed = by_path.get(finding.location.path)
            whole_file = bool(raw.get("extra", {}).get("metadata", {}).get("whole-file"))
            if changed and not whole_file and not changed.touches_line(
                finding.location.line, slack=line_slack
            ):
                continue
        findings.append(finding)

    return findings, errors


def _to_finding(raw: dict[str, Any], pack_of_rule: dict[str, str]) -> Finding | None:
    rule_id = raw.get("check_id")
    if not rule_id:
        return None
    extra = raw.get("extra") or {}
    metadata = extra.get("metadata") or {}

    severity = _resolve_severity(metadata, extra)
    pack = str(metadata.get("pack") or pack_of_rule.get(rule_id) or _pack_from_id(rule_id))

    rationale = str(
        metadata.get("rationale")
        or metadata.get("why")
        or ""
    ).strip()
    if not rationale:
        # Enforced at validation time for local rules, but a curated rule that
        # slips through should degrade rather than crash a review run.
        rationale = (
            "No rationale recorded for this rule. That is a bug in the rule, not in "
            "your code - please report it against the engine."
        )

    start = raw.get("start") or {}
    end = raw.get("end") or {}
    location = Location(
        path=str(raw.get("path", "")),
        line=start.get("line"),
        end_line=end.get("line"),
        snippet=_trim(extra.get("lines")),
    )

    message = str(extra.get("message") or metadata.get("message") or rule_id).strip()

    return Finding(
        rule_id=str(rule_id),
        severity=severity,
        title=str(metadata.get("title") or _title_from(message, rule_id)),
        message=message,
        rationale=rationale,
        pack=pack,
        tier=Tier.DETERMINISTIC,
        engine=Engine.SEMGREP,
        location=location,
        nonbinding=bool(metadata.get("nonbinding")),
        frameworks=[str(f) for f in (metadata.get("frameworks") or [])],
        verify_hint=(str(metadata["verify"]) if metadata.get("verify") else None),
        metadata={
            k: v
            for k, v in metadata.items()
            if k not in {"pack", "rationale", "verify", "frameworks", "nonbinding", "title"}
        },
    )


def _resolve_severity(metadata: dict[str, Any], extra: dict[str, Any]) -> Severity:
    explicit = metadata.get("sentinel-severity") or metadata.get("sentinel_severity")
    if explicit:
        try:
            return Severity.parse(str(explicit))
        except ValueError:
            pass
    return _SEMGREP_SEVERITY.get(str(extra.get("severity", "")).upper(), Severity.MEDIUM)


def _pack_from_id(rule_id: str) -> str:
    # Rule ids are namespaced `pack.area.rule`; the leading segment is the pack.
    head = str(rule_id).split(".")[0]
    return head or "unknown"


def _title_from(message: str, rule_id: str) -> str:
    first = message.strip().splitlines()[0] if message.strip() else rule_id
    return first[:120].rstrip(". ")


def _trim(value: Any, limit: int = 400) -> str | None:
    if not value:
        return None
    text = str(value).strip("\n")
    return text[:limit] + (" ..." if len(text) > limit else "")
