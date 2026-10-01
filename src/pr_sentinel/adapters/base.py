"""The adapter contract: run someone else's tool, speak our `Finding`.

DESIGN-V2 §3. v1 reimplemented rules that `zizmor`, Socket, gitleaks and
Supabase's own advisors already maintain better, which DESIGN.md §2 had
explicitly ruled out. An adapter is the apology: invoke the real tool, parse
its native output, and normalise into the one model that severity policy,
dedup, rendering and the verdict already understand.

Three properties every adapter must have:

**Absence is loud.** A missing tool means its guarantees are not being
enforced. `required` adapters withhold the deterministic check-run when
absent, exactly as a missing semgrep does. Silence here would let the engine
report "no critical findings" without having looked.

**Version in provenance.** A verdict has to be reproducible, which means
recording not just that zizmor ran but which zizmor.

**Theirs is theirs.** An adapter does not second-guess the tool's own
severity beyond mapping it onto our scale, and never rewrites its message.
If the tool is wrong, that is a bug to report upstream, not to patch here.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..diff import Diff, path_ignored
from ..models import Engine, Finding, Location, Severity, Tier

DEFAULT_TIMEOUT = 300


@dataclass
class AdapterResult:
    findings: list[Finding] = field(default_factory=list)
    ran: bool = False
    version: str | None = None
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    #: True when the tool is absent or failed and its checks did not run.
    degraded: bool = False


@dataclass
class AdapterSpec:
    """How a pack configured this adapter."""

    adapter_id: str
    pack: str
    severity_floor: Severity | None = None
    severity_ceiling: Severity | None = None
    options: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True

    def option(self, key: str, default: Any = None) -> Any:
        return self.options.get(key, default)


@dataclass
class RegisteredAdapter:
    adapter_id: str
    fn: Callable[["AdapterContext", AdapterSpec], AdapterResult]
    tool: str
    description: str
    #: When True, absence withholds the deterministic check-run.
    required: bool = True
    #: Globs that make this adapter relevant; empty means always.
    applies_to: list[str] = field(default_factory=list)
    install_hint: str = ""
    homepage: str = ""


REGISTRY: dict[str, RegisteredAdapter] = {}


def register(
    adapter_id: str,
    *,
    tool: str,
    description: str,
    required: bool = True,
    applies_to: list[str] | None = None,
    install_hint: str = "",
    homepage: str = "",
) -> Callable[[Callable], Callable]:
    def decorator(fn: Callable) -> Callable:
        if adapter_id in REGISTRY:
            raise RuntimeError(f"duplicate adapter id: {adapter_id}")
        REGISTRY[adapter_id] = RegisteredAdapter(
            adapter_id=adapter_id,
            fn=fn,
            tool=tool,
            description=description,
            required=required,
            applies_to=applies_to or [],
            install_hint=install_hint,
            homepage=homepage,
        )
        return fn

    return decorator


def get(adapter_id: str) -> RegisteredAdapter | None:
    return REGISTRY.get(adapter_id)


def all_adapters() -> dict[str, RegisteredAdapter]:
    return dict(REGISTRY)


@dataclass
class AdapterContext:
    """What an adapter is given. A thin slice of ReviewContext, so adapters
    stay testable without constructing a whole review."""

    repo_root: Path
    diff: Diff
    ignore_paths: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)

    def changed(self, *globs: str) -> list[str]:
        patterns = list(globs)
        return [
            f.path
            for f in self.diff.live_files
            if not patterns or path_ignored(f.path, patterns)
        ]


# ---------------------------------------------------------------------------
# running tools
# ---------------------------------------------------------------------------


def which(tool: str) -> str | None:
    """Locate a tool, honouring a per-tool env override.

    The override exists so CI can pin an exact binary and so tests can point
    at a stub. `PR_SENTINEL_ZIZMOR_BIN`, etc.
    """
    override = os.environ.get(f"PR_SENTINEL_{tool.upper().replace('-', '_')}_BIN")
    return override or shutil.which(tool)


def tool_version(binary: str, args: list[str] | None = None) -> str | None:
    try:
        proc = subprocess.run(  # noqa: S603
            [binary, *(args or ["--version"])],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    out = (proc.stdout or proc.stderr or "").strip()
    return out.splitlines()[0] if out else None


def run_tool(
    binary: str,
    args: list[str],
    cwd: Path,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    env: dict[str, str] | None = None,
) -> tuple[int, str, str] | None:
    """Run a tool. Returns (exit_code, stdout, stderr), or None if it could
    not be executed at all — which the caller must treat as degraded."""
    merged = dict(os.environ)
    merged.update(env or {})
    try:
        proc = subprocess.run(  # noqa: S603
            [binary, *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=merged,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def missing_tool_result(
    registered: RegisteredAdapter, extra: str = ""
) -> AdapterResult:
    """The uniform "this tool is not installed" outcome."""
    note = (
        f"`{registered.tool}` is not installed, so the checks it provides did NOT run. "
        f"{registered.install_hint or ''} "
        + (
            "Critical guarantees from this adapter are not being enforced in this run."
            if registered.required
            else "This adapter is optional."
        )
    ).strip()
    if extra:
        note += f" {extra}"
    return AdapterResult(ran=False, degraded=registered.required, notes=[note])


# ---------------------------------------------------------------------------
# SARIF, the common case
# ---------------------------------------------------------------------------

_SARIF_SEVERITY = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}


def findings_from_sarif(
    payload: dict[str, Any] | str,
    spec: AdapterSpec,
    *,
    diff: Diff | None = None,
    only_changed_files: bool = True,
    line_slack: int = 3,
    severity_map: dict[str, Severity] | None = None,
    rule_prefix: str | None = None,
) -> tuple[list[Finding], list[str]]:
    """Parse SARIF 2.1.0 into findings.

    Most modern analysers emit SARIF, so this is written once rather than per
    adapter. Rule metadata (`help`, `fullDescription`) supplies the rationale
    that our model requires, with an honest fallback when the tool does not
    provide one — a rule whose reason we cannot state is still worth
    reporting, but the comment says the reason is missing rather than
    inventing one.
    """
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except ValueError as exc:
            return [], [f"{spec.adapter_id}: output was not valid SARIF JSON: {exc}"]
    if not isinstance(payload, dict):
        return [], [f"{spec.adapter_id}: SARIF payload was not an object"]

    findings: list[Finding] = []
    errors: list[str] = []
    mapping = severity_map or _SARIF_SEVERITY
    by_path = diff.by_path() if diff else {}

    for run in payload.get("runs") or []:
        tool_rules = _index_rules(run)
        for result in run.get("results") or []:
            rule_id = str(result.get("ruleId") or "")
            if not rule_id:
                continue
            rule = tool_rules.get(rule_id, {})

            level = str(result.get("level") or rule.get("_level") or "warning").lower()
            severity = mapping.get(level, Severity.MEDIUM)
            severity = _clamp(severity, spec)

            path, line, end_line = _sarif_location(result)
            if only_changed_files and diff is not None and path and line:
                changed = by_path.get(path)
                if changed and not changed.touches_line(line, slack=line_slack):
                    continue

            message = _sarif_text(result.get("message")) or rule_id
            rationale = (
                _sarif_text(rule.get("fullDescription"))
                or _sarif_text(rule.get("help"))
                or _sarif_text(rule.get("shortDescription"))
                or (
                    f"Reported by `{spec.adapter_id}`, which did not supply a rationale "
                    f"for this rule. See the tool's documentation for rule `{rule_id}`."
                )
            )

            findings.append(
                Finding(
                    rule_id=f"{rule_prefix or spec.adapter_id}.{rule_id}",
                    severity=severity,
                    title=(_sarif_text(rule.get("shortDescription")) or message)[:120],
                    message=message,
                    rationale=rationale,
                    pack=spec.pack,
                    tier=Tier.DETERMINISTIC,
                    engine=Engine.SCRIPT,
                    location=Location(path, line, end_line) if path else None,
                    metadata={
                        "adapter": spec.adapter_id,
                        "upstream_rule": rule_id,
                        "help_uri": rule.get("helpUri", ""),
                    },
                )
            )

    return findings, errors


def _index_rules(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    driver = ((run.get("tool") or {}).get("driver")) or {}
    for extension in [driver, *((run.get("tool") or {}).get("extensions") or [])]:
        for rule in extension.get("rules") or []:
            rule_id = str(rule.get("id") or "")
            if not rule_id:
                continue
            entry = dict(rule)
            default_level = (
                (rule.get("defaultConfiguration") or {}).get("level")
            )
            if default_level:
                entry["_level"] = default_level
            rules[rule_id] = entry
    return rules


def _sarif_location(result: dict[str, Any]) -> tuple[str | None, int | None, int | None]:
    for location in result.get("locations") or []:
        physical = location.get("physicalLocation") or {}
        artifact = physical.get("artifactLocation") or {}
        uri = artifact.get("uri")
        if not uri:
            continue
        path = str(uri).removeprefix("file://").lstrip("/")
        region = physical.get("region") or {}
        return path, region.get("startLine"), region.get("endLine")
    return None, None, None


def _sarif_text(node: Any) -> str:
    if node is None:
        return ""
    if isinstance(node, str):
        return node.strip()
    if isinstance(node, dict):
        return str(node.get("text") or node.get("markdown") or "").strip()
    return ""


def _clamp(severity: Severity, spec: AdapterSpec) -> Severity:
    """Let a pack narrow an adapter's severity range.

    Needed because a tool's notion of `error` is calibrated to its own
    audience. `zizmor`'s informational findings should not arrive as `high`
    in a repo that has not adopted its whole philosophy yet.
    """
    if spec.severity_ceiling and severity.rank > spec.severity_ceiling.rank:
        return spec.severity_ceiling
    if spec.severity_floor and severity.rank < spec.severity_floor.rank:
        return spec.severity_floor
    return severity
