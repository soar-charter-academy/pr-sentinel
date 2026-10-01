"""`gitleaks` — the only secret scanning this repo gets.

DESIGN-V2 §3 deletes `core/rules/secrets.yml`: a few dozen hand-written
regexes against `gitleaks`' corpus of several hundred rules, tuned with
entropy thresholds and allowlists we were never going to maintain. Theirs
wins on every axis.

`required=True`, and the reason is specific rather than general. DESIGN.md
§12: **soar-app is a private repository on the free tier, so GitHub secret
scanning and push protection are not available to it.** There is no safety
net underneath this adapter. If `gitleaks` is absent, the number of
mechanisms examining that PR for a committed credential is zero, and the
deterministic check-run must not go green on that basis.

Two implementation notes.

**Exit codes are disambiguated deliberately.** `gitleaks` returns 1 both for
"I found leaks" and, historically, for "I failed", which is the one
distinction this adapter cannot afford to get wrong — treating a crash as
"found nothing" is precisely the silent pass the design forbids. So we pass
`--exit-code 11` and give leaks their own code: 0 means clean, 11 means
findings, and anything else means `gitleaks` itself failed.

**Findings outside the diff are counted, not reported.** A whole-tree scan
surfaces secrets that predate the PR. Commenting on them derails someone
else's review, so they are summarised in a note with a count instead of
dropped in silence — a pre-existing committed secret is still worth knowing
about, just not as a line comment on an unrelated change.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from ..models import Severity
from .base import (
    AdapterContext,
    AdapterResult,
    AdapterSpec,
    findings_from_sarif,
    get,
    missing_tool_result,
    register,
    run_tool,
    tool_version,
    which,
)

ADAPTER_ID = "gitleaks"

#: Our own exit code for "leaks found", so it cannot be confused with the
#: exit code `gitleaks` uses for its own failures.
LEAKS_EXIT_CODE = 11


@register(
    ADAPTER_ID,
    tool="gitleaks",
    description=(
        "Secret scanning over the working tree or the PR's commit range, "
        "using gitleaks' rule corpus and entropy heuristics."
    ),
    required=True,
    applies_to=[],  # a secret can be committed into any file
    install_hint=(
        "Install with `brew install gitleaks`, `go install "
        "github.com/gitleaks/gitleaks/v8@latest`, or the release binary. "
        "This repo is PRIVATE on the free tier, so GitHub secret scanning and "
        "push protection are NOT available to it: gitleaks is the only secret "
        "scanning this repository has. Without it, nothing in this run looked "
        "for committed credentials."
    ),
    homepage="https://github.com/gitleaks/gitleaks",
)
def run_gitleaks(ctx: AdapterContext, spec: AdapterSpec) -> AdapterResult:
    registered = get(ADAPTER_ID)
    assert registered is not None

    binary = which("gitleaks")
    if not binary:
        return missing_tool_result(registered)

    result = AdapterResult(version=tool_version(binary))

    changed = set(ctx.changed())
    if not changed and spec.option("mode", "dir") == "dir":
        result.notes.append("gitleaks: no files live at head to scan.")
        result.ran = True
        return result

    with tempfile.TemporaryDirectory(prefix="pr-sentinel-gitleaks-") as staging:
        report = Path(staging) / "gitleaks.sarif"
        args = _build_args(spec, report)
        outcome = run_tool(
            binary, args, ctx.repo_root, timeout=int(spec.option("timeout", 300))
        )
        if outcome is None:
            result.degraded = True
            result.errors.append(
                "gitleaks is installed but could not be executed (timeout or "
                "killed). NO secret scanning ran, and this repo has no other "
                "secret scanning."
            )
            return result

        code, stdout, stderr = outcome

        if code not in (0, LEAKS_EXIT_CODE):
            result.degraded = True
            result.errors.append(
                f"gitleaks exited {code}, which is a gitleaks failure rather "
                f"than a finding (findings use exit code {LEAKS_EXIT_CODE}). "
                f"NO secret scanning ran. stderr: {_trim(stderr)}"
            )
            return result

        payload = _read_report(report, stdout)

    if payload is None:
        result.degraded = True
        result.errors.append(
            "gitleaks exited cleanly but produced no readable SARIF report, so "
            "its scan cannot be trusted to have covered this PR. "
            f"stderr: {_trim(stderr)}"
        )
        return result

    findings, errors = findings_from_sarif(
        payload,
        spec,
        diff=None,  # we filter by path ourselves, below
        only_changed_files=False,
        # gitleaks grades everything `error` in SARIF, which is correct: a
        # committed credential is not a style question. We keep that, and
        # raise it one notch because for us a live secret is the one finding
        # class that justifies blocking a merge outright.
        severity_map={
            "error": Severity.CRITICAL,
            "warning": Severity.HIGH,
            "note": Severity.MEDIUM,
            "none": Severity.LOW,
        },
    )
    result.errors.extend(errors)

    in_diff, pre_existing = _split_by_diff(findings, changed)
    result.findings = in_diff
    result.ran = True

    if pre_existing:
        result.notes.append(
            f"gitleaks also matched {len(pre_existing)} secret(s) in files this "
            f"PR does not touch: "
            + ", ".join(sorted({f.location.path for f in pre_existing if f.location})[:10])
            + ". Those are not reported as findings on this PR, but they are "
            "committed secrets and need rotating."
        )
    return result


def _build_args(spec: AdapterSpec, report: Path) -> list[str]:
    """Assemble the gitleaks invocation.

    `detect` is used rather than the newer `dir`/`git` subcommands because it
    is still accepted by every 8.x release, and an adapter that only works
    against the latest point release is a support burden. `log_opts` switches
    from a working-tree scan to a scan of exactly the PR's commit range, which
    is cheaper and strictly scoped — use it when the caller knows the range.
    """
    args = [
        "detect",
        "--report-format=sarif",
        f"--report-path={report}",
        f"--exit-code={LEAKS_EXIT_CODE}",
        "--redact",  # never print the secret itself into CI logs
        "--no-banner",
    ]
    log_opts = spec.option("log_opts")
    if log_opts:
        # git mode: scan the commits in the PR range only.
        args.append(f"--log-opts={log_opts}")
    else:
        args.append("--no-git")
    config = spec.option("config")
    if config:
        args.append(f"--config={config}")
    baseline = spec.option("baseline_path")
    if baseline:
        args.append(f"--baseline-path={baseline}")
    return args


def _read_report(report: Path, stdout: str) -> dict[str, Any] | None:
    for text in (_read(report), stdout):
        if not text or not text.strip():
            continue
        try:
            payload = json.loads(text)
        except ValueError:
            continue
        if isinstance(payload, dict) and "runs" in payload:
            return payload
    return None


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _split_by_diff(findings: list[Any], changed: set[str]) -> tuple[list[Any], list[Any]]:
    in_diff, other = [], []
    for finding in findings:
        path = finding.location.path if finding.location else None
        (in_diff if (path and path in changed) else other).append(finding)
    return in_diff, other


def _trim(text: str, limit: int = 400) -> str:
    collapsed = " ".join((text or "").split())
    return collapsed[:limit] or "(empty)"
