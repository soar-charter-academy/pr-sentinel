"""`zizmor` — GitHub Actions auditing, in place of our own rules.

DESIGN-V2 §3. v1 shipped a `github-actions` pack with five hand-written
checks. `zizmor` ships roughly thirty-eight, maintained by people who track
new Actions attack classes for a living: `template-injection`,
`excessive-permissions`, `unpinned-uses`, `artipacked`, `impostor-commit`,
`cache-poisoning`, `dangerous-triggers`, `secrets-inherit`, and the rest. Our
five were a subset of theirs with worse messages. That pack is deleted and
this adapter is what replaced it.

`required=True`. Workflow compromise is how a CI secret leaves the building,
and it is the attack our own lore has the least defence against. A run
without `zizmor` has not audited the workflows at all, and must not print a
deterministic pass as if it had.

Two deliberate choices worth stating.

**We hand `zizmor` only the changed workflow files, and we do not then
filter its findings by changed line.** A workflow is a single unit of trust:
an `excessive-permissions` finding sits at the top of the file while the
dangerous step someone just added sits sixty lines below it, and line
filtering would drop exactly the finding that explains the risk.

**Online audits are opt-in by token, not by default.** `impostor-commit`,
`known-vulnerable-actions` and `stale-action-refs` need the GitHub API.
Adapter code makes no network calls; `zizmor` may. When no token is in the
environment we pass `--offline` and say in the notes which audits therefore
did not run, rather than letting the tool half-run them and reporting the
result as complete.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

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

ADAPTER_ID = "zizmor"

#: Workflow definitions. `zizmor` audits these as workflows.
WORKFLOW_GLOBS = [
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
]

#: Composite/JS action definitions, anywhere in the tree. `zizmor` audits
#: these as action definitions, which is a different (smaller) rule set.
ACTION_GLOBS = ["action.yml", "action.yaml"]

#: The audits `zizmor` can only perform with GitHub API access. Named here so
#: that a degraded offline run can say precisely what it did not check,
#: instead of the useless "some audits were skipped".
ONLINE_AUDITS = ("impostor-commit", "known-vulnerable-actions", "stale-action-refs")

_TOKEN_VARS = ("GH_TOKEN", "GITHUB_TOKEN", "ZIZMOR_GH_TOKEN")


@register(
    ADAPTER_ID,
    tool="zizmor",
    description=(
        "Static auditing of GitHub Actions workflows and composite actions "
        "(~38 audits: template injection, excessive permissions, unpinned "
        "uses, artipacked, cache poisoning, dangerous triggers)."
    ),
    required=True,
    applies_to=[*WORKFLOW_GLOBS, *ACTION_GLOBS],
    install_hint=(
        "Install with `pipx install zizmor`, `cargo install zizmor`, or "
        "`uv tool install zizmor`. Without it NO GitHub Actions security "
        "auditing happens in this run."
    ),
    homepage="https://docs.zizmor.sh/",
)
def run_zizmor(ctx: AdapterContext, spec: AdapterSpec) -> AdapterResult:
    registered = get(ADAPTER_ID)
    assert registered is not None  # registered immediately above

    binary = which("zizmor")
    if not binary:
        return missing_tool_result(registered)

    result = AdapterResult(version=tool_version(binary))

    targets = _targets(ctx)
    if not targets:
        result.notes.append(
            "zizmor: no changed workflow or action definition in this PR, so it "
            "had nothing to audit."
        )
        result.ran = True
        return result

    args: list[str] = ["--format=sarif"]

    persona = spec.option("persona")
    if persona:
        args.append(f"--persona={persona}")
    min_severity = spec.option("min_severity")
    if min_severity:
        args.append(f"--min-severity={min_severity}")
    min_confidence = spec.option("min_confidence")
    if min_confidence:
        args.append(f"--min-confidence={min_confidence}")
    for audit in spec.option("disable_audits") or []:
        args.append(f"--no-audit={audit}")

    offline = bool(spec.option("offline", False)) or not _has_token(ctx)
    if offline:
        args.append("--offline")
        result.notes.append(
            "zizmor ran offline"
            + (
                " (configured)"
                if spec.option("offline", False)
                else " because no GitHub token was present in the environment"
            )
            + ", so its API-backed audits did NOT run: "
            + ", ".join(ONLINE_AUDITS)
            + ". Set GH_TOKEN to enable them."
        )

    args.extend(sorted(targets))

    outcome = run_tool(binary, args, ctx.repo_root, timeout=int(spec.option("timeout", 300)))
    if outcome is None:
        result.degraded = True
        result.errors.append(
            "zizmor is installed but could not be executed (it may have timed "
            "out or been killed). Its audits did not run."
        )
        return result

    code, stdout, stderr = outcome

    # zizmor's exit codes: 0 = ran, nothing found; 1 = ran, findings at or
    # above the configured thresholds; anything else = zizmor itself failed
    # (bad flag, unparseable workflow, internal error). We do not trust the
    # code alone, because "found things" and "broke" are both non-zero in
    # some versions: the authority is whether SARIF with a `runs` key came
    # back on stdout. A code of 2+ *with* valid SARIF is still a real audit.
    payload = _parse_sarif(stdout)
    if payload is None:
        result.degraded = True
        result.errors.append(
            f"zizmor exited {code} without emitting parseable SARIF, so its "
            f"audits did not run. stderr: {_trim(stderr)}"
        )
        return result

    if code not in (0, 1):
        # SARIF arrived anyway, so something partial happened. Keep the
        # findings, but do not let the anomaly pass unmentioned.
        result.notes.append(
            f"zizmor exited {code} (expected 0 or 1) but produced parseable "
            f"SARIF; findings below are from that output. stderr: {_trim(stderr)}"
        )

    findings, errors = findings_from_sarif(
        payload,
        spec,
        diff=ctx.diff,
        # See the module docstring: we already restricted the inputs to
        # changed files, and a workflow's security posture is not line-local.
        only_changed_files=bool(spec.option("only_changed_lines", False)),
    )
    _attach_zizmor_metadata(payload, findings)

    result.findings = findings
    result.errors.extend(errors)
    result.ran = True
    result.notes.append(
        f"zizmor audited {len(targets)} changed workflow/action file(s)."
    )
    return result


# ---------------------------------------------------------------------------
# target selection
# ---------------------------------------------------------------------------


def _targets(ctx: AdapterContext) -> list[str]:
    """Changed files `zizmor` can actually audit.

    Two filters that are not fussiness. The file must exist at head — handing
    `zizmor` a deleted path makes it exit non-zero, which we would then have
    to distinguish from a real failure. And an `action.yml` is only an action
    definition if it has a top-level `runs:` key; plenty of repos have an
    `action.yml` that is configuration for something else, and `zizmor`
    rejects those rather than skipping them.
    """
    out: list[str] = []
    for path in ctx.changed(*WORKFLOW_GLOBS):
        if (ctx.repo_root / path).is_file():
            out.append(path)
    for path in ctx.changed(*ACTION_GLOBS):
        full = ctx.repo_root / path
        if full.is_file() and _is_action_definition(full):
            out.append(path)
    return sorted(set(out))


def _is_action_definition(path: Path) -> bool:
    try:
        parsed = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, yaml.YAMLError):
        # Unparseable YAML is actionlint's and zizmor's problem to report, but
        # we cannot assert it is an action definition, so we leave it out.
        return False
    return isinstance(parsed, dict) and "runs" in parsed


def _has_token(ctx: AdapterContext) -> bool:
    import os

    return any(ctx.env.get(v) or os.environ.get(v) for v in _TOKEN_VARS)


# ---------------------------------------------------------------------------
# output
# ---------------------------------------------------------------------------


def _parse_sarif(stdout: str) -> dict[str, Any] | None:
    text = (stdout or "").strip()
    if not text:
        return None
    try:
        payload = json.loads(text)
    except ValueError:
        return None
    if not isinstance(payload, dict) or "runs" not in payload:
        return None
    return payload


def _attach_zizmor_metadata(payload: dict[str, Any], findings: list[Any]) -> None:
    """Carry `zizmor`'s persona and confidence through into our metadata.

    `zizmor` grades each finding by audit confidence and by the persona that
    would care about it (`regular`, `pedantic`, `auditor`). That is genuinely
    useful triage information and it is in the SARIF `properties` bag, which
    the generic parser does not look at. We copy whatever is there and invent
    nothing: a `zizmor` build that does not emit these keys simply yields
    findings without them.
    """
    index: dict[tuple[str, str, int], dict[str, Any]] = {}
    for run in payload.get("runs") or []:
        for res in run.get("results") or []:
            props = res.get("properties")
            extracted: dict[str, Any] = {}
            if isinstance(props, dict):
                for key, value in props.items():
                    lowered = str(key).lower()
                    if "persona" in lowered or "confidence" in lowered:
                        extracted[f"zizmor_{lowered}"] = value
            rank = res.get("rank")
            if rank is not None:
                extracted["zizmor_rank"] = rank
            if not extracted:
                continue
            index[_result_key(res)] = extracted

    if not index:
        return
    for finding in findings:
        upstream = str(finding.metadata.get("upstream_rule") or "")
        path = finding.location.path if finding.location else ""
        line = (finding.location.line if finding.location else None) or 0
        extra = index.get((upstream, path, line))
        if extra:
            finding.metadata.update(extra)


def _result_key(res: dict[str, Any]) -> tuple[str, str, int]:
    rule_id = str(res.get("ruleId") or "")
    for location in res.get("locations") or []:
        physical = location.get("physicalLocation") or {}
        uri = (physical.get("artifactLocation") or {}).get("uri")
        if not uri:
            continue
        path = str(uri).removeprefix("file://").lstrip("/")
        start = (physical.get("region") or {}).get("startLine") or 0
        return rule_id, path, int(start)
    return rule_id, "", 0


def _trim(text: str, limit: int = 400) -> str:
    collapsed = " ".join((text or "").split())
    return collapsed[:limit] or "(empty)"
