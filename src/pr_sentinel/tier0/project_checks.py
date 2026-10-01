"""Tier 0: the project's own checks. No model, no cleverness, runs first.

The ordering argument from DESIGN s3: if the build is broken, spending model
tokens on nuanced review is waste. A reviewer that writes three paragraphs
about your RLS policy while `npm test` is red has misread the room.

Commands are auto-detected from `package.json` rather than assumed, because
half of "add CI to this repo" failures are a workflow confidently running a
script that does not exist.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Engine, Finding, Location, Severity, Tier

PACK = "tier0"

#: script name -> (label, severity when it fails, whether a miss is worth a note)
CANDIDATE_SCRIPTS: list[tuple[str, str, Severity]] = [
    ("lint", "lint", Severity.MEDIUM),
    ("typecheck", "typecheck", Severity.HIGH),
    ("test", "tests", Severity.HIGH),
    ("build", "build", Severity.HIGH),
]


@dataclass
class CommandResult:
    label: str
    command: str
    exit_code: int
    duration: float
    stdout: str = ""
    stderr: str = ""
    skipped_reason: str | None = None

    @property
    def ok(self) -> bool:
        return self.skipped_reason is not None or self.exit_code == 0

    @property
    def tail(self) -> str:
        """The last useful chunk of output.

        Test runners put the summary at the end, so the tail is where the
        answer is. Capped because a PR comment is not a log viewer.
        """
        combined = (self.stdout or "") + ("\n" + self.stderr if self.stderr else "")
        lines = [ln for ln in combined.splitlines() if ln.strip()]
        return "\n".join(lines[-40:])


@dataclass
class Tier0Result:
    results: list[CommandResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    ran: bool = True
    notes: list[str] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        return any(not r.ok for r in self.results)


def detect_commands(repo_root: Path) -> tuple[list[tuple[str, str]], list[str]]:
    """Work out what this project can actually run.

    Returns (commands, notes). A missing script is a note, not a finding: not
    every repo has a typecheck script and nagging about it is how a tool
    becomes background noise.
    """
    pkg_path = repo_root / "package.json"
    if not pkg_path.is_file():
        return [], ["No package.json found; Tier 0 has nothing to run."]

    try:
        pkg = json.loads(pkg_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [], [f"package.json could not be parsed ({exc}); skipping Tier 0 scripts."]

    scripts = pkg.get("scripts") or {}
    commands: list[tuple[str, str]] = []
    notes: list[str] = []

    has_lockfile = (repo_root / "package-lock.json").is_file()
    if has_lockfile:
        # --ignore-scripts because postinstall is arbitrary code execution at
        # resolution time, and CI is where the secrets are (DESIGN s12).
        commands.append(("install", "npm ci --ignore-scripts"))
    else:
        notes.append(
            "No package-lock.json; using `npm install`, which does not give a "
            "reproducible dependency tree in CI."
        )
        commands.append(("install", "npm install --ignore-scripts --no-audit --no-fund"))

    for script, label, _sev in CANDIDATE_SCRIPTS:
        if script in scripts:
            commands.append((label, f"npm run {script} --if-present"))
        else:
            notes.append(f"No `{script}` script in package.json; skipped.")

    return commands, notes


def run_tier0(
    repo_root: Path | str,
    *,
    commands: list[str] | None = None,
    fail_fast: bool = True,
    timeout_seconds: int = 900,
    audit_level: str = "high",
    enabled: bool = True,
    run_audit: bool = True,
) -> Tier0Result:
    root = Path(repo_root)
    if not enabled:
        return Tier0Result(ran=False, notes=["Tier 0 disabled by config."])

    result = Tier0Result()

    if commands:
        plan = [(f"custom:{i + 1}", cmd) for i, cmd in enumerate(commands)]
    else:
        plan, notes = detect_commands(root)
        result.notes.extend(notes)

    severity_by_label = {label: sev for _s, label, sev in CANDIDATE_SCRIPTS}

    for label, command in plan:
        run = _run(command, root, timeout_seconds)
        result.results.append(run)
        if not run.ok:
            severity = severity_by_label.get(label, Severity.HIGH)
            if label == "install":
                severity = Severity.HIGH
            result.findings.append(
                Finding(
                    rule_id=f"tier0.{label}",
                    severity=severity,
                    title=f"Tier 0: `{command}` failed",
                    message=(
                        f"`{command}` exited {run.exit_code}.\n\n"
                        "```\n" + (run.tail or "(no output captured)") + "\n```"
                    ),
                    rationale=(
                        "The project's own checks are the cheapest and most reliable signal "
                        "available. Nothing further is worth reviewing until they pass."
                    ),
                    pack=PACK,
                    tier=Tier.PROJECT,
                    engine=Engine.PROJECT_CHECK,
                    metadata={"command": command, "exit_code": run.exit_code},
                )
            )
            if fail_fast:
                result.notes.append(
                    f"Stopped after `{command}` failed (tier0.fail_fast). "
                    "Later checks were not run."
                )
                break

    if run_audit and (root / "package.json").is_file() and not result.failed:
        audit = _run_audit(root, audit_level, timeout_seconds)
        if audit is not None:
            result.results.append(audit.result)
            result.findings.extend(audit.findings)

    return result


@dataclass
class _AuditOutcome:
    result: CommandResult
    findings: list[Finding]


def _run_audit(root: Path, audit_level: str, timeout_seconds: int) -> _AuditOutcome | None:
    """`npm audit`, parsed rather than pasted.

    Dependabot answers "does my tree contain a package with a published CVE"
    already (DESIGN s12), so this is not the interesting part of supply-chain
    review. It is here because it is free, and because a PR that *introduces*
    a known-vulnerable package is worth catching at the review moment rather
    than in a bot PR three days later.
    """
    command = "npm audit --json --audit-level=" + shlex.quote(audit_level)
    run = _run(command, root, timeout_seconds)

    try:
        data = json.loads(run.stdout or "{}")
    except ValueError:
        run.skipped_reason = "npm audit produced no parseable JSON"
        return _AuditOutcome(run, [])

    meta = ((data.get("metadata") or {}).get("vulnerabilities")) or {}
    counts = {k: int(v) for k, v in meta.items() if isinstance(v, int)}
    ranked = ["critical", "high", "moderate", "low", "info"]
    summary = ", ".join(f"{counts.get(k, 0)} {k}" for k in ranked if counts.get(k))

    findings: list[Finding] = []
    threshold = {"critical": 1, "high": 2, "moderate": 3, "low": 4}.get(audit_level, 2)
    breaching = [
        k for k in ranked
        if counts.get(k) and {"critical": 1, "high": 2, "moderate": 3, "low": 4}.get(k, 9)
        <= threshold
    ]
    if breaching:
        advisories = _top_advisories(data)
        findings.append(
            Finding(
                rule_id="tier0.audit",
                severity=Severity.HIGH if "critical" in breaching else Severity.MEDIUM,
                title=f"`npm audit` reports vulnerabilities at or above `{audit_level}`",
                message=(
                    f"{summary or 'vulnerabilities reported'}.\n\n" + advisories
                ),
                rationale=(
                    "A known-vulnerable dependency reaching main is cheaper to stop here "
                    "than to chase later. This overlaps with Dependabot by design; it "
                    "catches the introduction rather than the aftermath."
                ),
                pack=PACK,
                tier=Tier.PROJECT,
                engine=Engine.PROJECT_CHECK,
                metadata={"counts": counts},
            )
        )
    # A non-zero exit from `npm audit` means "found vulnerabilities", which is
    # reported as a finding above, not as a broken command.
    run.exit_code = 0
    return _AuditOutcome(run, findings)


def _top_advisories(data: dict, limit: int = 6) -> str:
    vulns = data.get("vulnerabilities") or {}
    rows: list[str] = []
    for name, entry in list(vulns.items())[: limit * 3]:
        if not isinstance(entry, dict):
            continue
        sev = entry.get("severity", "?")
        if sev in ("info", "low"):
            continue
        via = entry.get("via") or []
        title = ""
        for v in via:
            if isinstance(v, dict) and v.get("title"):
                title = v["title"]
                break
        fix = entry.get("fixAvailable")
        fixable = "yes" if fix else "no"
        rows.append(f"| `{name}` | {sev} | {title or '—'} | {fixable} |")
        if len(rows) >= limit:
            break
    if not rows:
        return ""
    return (
        "| Package | Severity | Advisory | Fix available |\n"
        "|---|---|---|---|\n" + "\n".join(rows)
    )


def _run(command: str, cwd: Path, timeout_seconds: int) -> CommandResult:
    start = time.monotonic()
    env = dict(os.environ)
    env.setdefault("CI", "true")
    env.setdefault("NPM_CONFIG_FUND", "false")
    env.setdefault("NPM_CONFIG_AUDIT", "false")
    try:
        proc = subprocess.run(  # noqa: S602
            command,
            cwd=str(cwd),
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=env,
        )
        return CommandResult(
            label=command,
            command=command,
            exit_code=proc.returncode,
            duration=time.monotonic() - start,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
        )
    except subprocess.TimeoutExpired:
        return CommandResult(
            label=command,
            command=command,
            exit_code=124,
            duration=time.monotonic() - start,
            stderr=f"timed out after {timeout_seconds}s",
        )
    except OSError as exc:
        return CommandResult(
            label=command,
            command=command,
            exit_code=127,
            duration=time.monotonic() - start,
            stderr=str(exc),
            skipped_reason=f"could not execute: {exc}",
        )


def tier0_location(path: str) -> Location:
    return Location(path=path)
