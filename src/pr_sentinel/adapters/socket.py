"""Socket — supply-chain analysis we provably cannot do offline.

DESIGN-V2 §3. v1's `supply-chain.new-dependency` and
`supply-chain.install-scripts` tried to answer "is this package safe to add"
from the lockfile alone. DESIGN.md §12 lists what that question actually
needs: how long ago the version was published, whether the maintainer set
changed, whether the tarball contains install scripts or obfuscated code,
whether the package reaches the network at import time. Every one of those is
registry data or package-content analysis, and no amount of local cleverness
produces it. Socket has it. Those two checks are deleted.

`required=False`, for a reason that is about incentives rather than about
value. Socket is a keyed, largely paid service. If its absence withheld the
deterministic check-run, then every contributor without a key — a fork, a
new clone, someone running `sentinel review` locally — would see a red
status they cannot clear, and the first fix anyone reaches for is to turn
the whole thing off. An optional adapter that is loudly absent is worth more
than a required one that gets disabled. The checks it replaced were
heuristics, not guarantees, so no guarantee is being silently dropped.

**The key, and the alternative.** Socket needs an API token. When there is
none, this adapter returns a degraded result that names the other way to get
the same analysis: Socket's GitHub App, which comments on the PR directly
and needs no CI secret at all. "Install the app instead" is a real answer, so
the degraded message gives it rather than just reporting a missing variable.

**Invocation is pack-configurable, and the parser is shape-tolerant.**
Socket's CLI has moved its surface between majors (`socket report create` →
`socket scan create`), and its JSON alert payloads are an API shape rather
than a published CLI schema. Rather than pretend to a precision we do not
have, the subcommand is an option with a sensible default, the adapter
retries the older subcommand when the newer one is rejected as unknown, and
the parser accepts the several envelope shapes Socket has emitted. Where a
field is absent we omit it instead of guessing.
"""

from __future__ import annotations

import json
import os
from typing import Any

from ..models import Engine, Finding, Location, Severity, Tier
from .base import (
    AdapterContext,
    AdapterResult,
    AdapterSpec,
    _clamp,
    get,
    missing_tool_result,
    register,
    run_tool,
    tool_version,
    which,
)

ADAPTER_ID = "socket"

#: Manifests and lockfiles. Socket analyses dependencies, so there is nothing
#: for it to do unless the dependency set or its resolution changed.
MANIFEST_GLOBS = [
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lockb",
    "requirements.txt",
    "requirements-*.txt",
    "pyproject.toml",
    "poetry.lock",
    "Pipfile",
    "Pipfile.lock",
    "uv.lock",
    "go.mod",
    "go.sum",
    "Gemfile",
    "Gemfile.lock",
    "Cargo.toml",
    "Cargo.lock",
    "composer.json",
    "composer.lock",
]

#: Every name Socket's tooling has used for its credential. Checked in order;
#: the CLI itself reads several of these, and a run that fails for want of a
#: token the user did set would be an infuriating way to lose trust.
API_KEY_VARS = (
    "SOCKET_SECURITY_API_KEY",
    "SOCKET_SECURITY_API_TOKEN",
    "SOCKET_CLI_API_TOKEN",
    "SOCKET_CLI_API_KEY",
)

DEFAULT_ARGS = ["scan", "create", "--json"]
LEGACY_ARGS = ["report", "create", "--json"]

DOCS = "https://docs.socket.dev/"

#: Socket's severity vocabulary. `middle` is theirs, not a typo of ours.
_SEVERITIES = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "middle": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


@register(
    ADAPTER_ID,
    tool="socket",
    description=(
        "Socket supply-chain analysis: install scripts, obfuscated code, "
        "network and filesystem access in dependencies, publish age, "
        "maintainer churn, typosquats — registry data that cannot be derived "
        "from a lockfile."
    ),
    required=False,
    applies_to=MANIFEST_GLOBS,
    install_hint=(
        "Install with `npm i -g @socketsecurity/cli` and set "
        "SOCKET_SECURITY_API_KEY. Or skip CI entirely and install Socket's "
        "GitHub App, which analyses dependency changes and comments on the PR "
        "without a CI secret. Optional: Socket is a keyed service and the "
        "checks it replaced were heuristics, so its absence loses breadth "
        "rather than a guarantee."
    ),
    homepage=DOCS,
)
def run_socket(ctx: AdapterContext, spec: AdapterSpec) -> AdapterResult:
    registered = get(ADAPTER_ID)
    assert registered is not None

    globs = spec.option("manifest_globs") or MANIFEST_GLOBS
    manifests = sorted(ctx.changed(*globs))
    if not manifests:
        # Checked before the tool so a PR with no dependency change does not
        # produce a "Socket is not installed" note about work there was none
        # of. Noise about an irrelevant tool is how notes get skimmed.
        return AdapterResult(
            ran=True,
            notes=[
                "socket: no manifest or lockfile changed in this PR, so there "
                "was no dependency change to analyse."
            ],
        )

    binary = which("socket")
    if not binary:
        return missing_tool_result(
            registered,
            extra=(
                f"This PR changes {len(manifests)} manifest/lockfile "
                f"({', '.join(manifests[:5])}), so dependency supply-chain "
                f"analysis was the relevant check and it did not happen."
            ),
        )

    result = AdapterResult(version=tool_version(binary))

    key = _api_key(ctx)
    if not key:
        result.notes.append(
            "socket is installed but no API token is set, so supply-chain "
            "analysis did NOT run for the dependency changes in this PR. "
            "Either set SOCKET_SECURITY_API_KEY in CI, or install Socket's "
            "GitHub App on this repository — the app performs the same "
            "analysis and comments on the pull request without needing a CI "
            "secret. Until one of those is done, nobody has looked at these "
            "dependencies for install scripts, obfuscation or maintainer "
            "churn."
        )
        return result

    args = list(spec.option("args") or DEFAULT_ARGS)
    if spec.option("pass_manifests", True):
        args.extend(manifests)

    timeout = int(spec.option("timeout", 300))
    outcome = run_tool(binary, args, ctx.repo_root, timeout=timeout)
    if outcome is None:
        result.errors.append(
            "socket is installed but could not be executed (timeout or "
            "killed); dependency supply-chain analysis did not run."
        )
        return result

    code, stdout, stderr = outcome

    if _looks_like_unknown_subcommand(code, stderr) and not spec.option("args"):
        # Older CLI majors call it `report create`. Retry once rather than
        # telling the user their working Socket install is broken.
        retry_args = list(LEGACY_ARGS)
        if spec.option("pass_manifests", True):
            retry_args.extend(manifests)
        retry = run_tool(binary, retry_args, ctx.repo_root, timeout=timeout)
        if retry is not None:
            code, stdout, stderr = retry
            result.notes.append(
                "socket rejected `scan create`; fell back to the older "
                "`report create` subcommand."
            )

    # Socket's CLI exits 0 on a clean scan, non-zero when its security policy
    # fails the scan (which is a successful run with something to say), and
    # non-zero again on usage or authentication errors. The exit code alone
    # therefore cannot tell those apart, so the deciding test is whether JSON
    # we recognise came back: an analysed scan always prints one.
    payload, parse_error = _parse(stdout)
    if parse_error is not None:
        if code == 0:
            result.ran = True
            result.notes.append(
                "socket completed and reported no supply-chain alerts for the "
                "changed dependencies."
            )
            return result
        result.errors.append(
            f"socket exited {code} and produced no readable JSON "
            f"({parse_error}), so dependency supply-chain analysis did not "
            f"run. stderr: {_trim(stderr)}"
        )
        return result

    alerts = _alerts(payload)
    for alert in alerts:
        finding = _to_finding(alert, spec)
        if finding is not None:
            result.findings.append(finding)

    result.ran = True
    result.notes.append(
        f"socket analysed {len(manifests)} changed manifest/lockfile(s) and "
        f"returned {len(result.findings)} alert(s)."
    )
    return result


# ---------------------------------------------------------------------------
# environment
# ---------------------------------------------------------------------------


def _api_key(ctx: AdapterContext) -> str | None:
    for var in API_KEY_VARS:
        value = ctx.env.get(var) or os.environ.get(var)
        if value and value.strip():
            return value.strip()
    return None


def _looks_like_unknown_subcommand(code: int, stderr: str) -> bool:
    lowered = (stderr or "").lower()
    return code != 0 and any(
        marker in lowered
        for marker in ("unknown command", "command not found", "is not a socket command")
    )


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------


def _parse(stdout: str) -> tuple[Any, str | None]:
    text = (stdout or "").strip()
    if not text:
        return None, "empty output"
    try:
        return json.loads(text), None
    except ValueError:
        pass
    # Some Socket subcommands emit NDJSON, one object per package.
    objects: list[Any] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] not in "{[":
            continue
        try:
            objects.append(json.loads(line))
        except ValueError:
            continue
    if objects:
        return objects, None
    return None, "output was neither JSON nor NDJSON"


def _alerts(payload: Any) -> list[dict[str, Any]]:
    """Pull the alert list out of whichever envelope Socket used.

    Shapes accepted: a bare list of alerts; `{"issues": [...]}`;
    `{"alerts": [...]}`; `{"results": [...]}`; and a list of per-package
    objects each carrying their own `alerts`/`issues`, in which case the
    package name is pushed down into the alert so the finding can name it.
    """
    if payload is None:
        return []
    if isinstance(payload, dict):
        for key in ("issues", "alerts", "results", "violations", "data"):
            node = payload.get(key)
            if isinstance(node, list):
                payload = node
                break
        else:
            payload = [payload]
    if not isinstance(payload, list):
        return []

    out: list[dict[str, Any]] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        nested = None
        for key in ("alerts", "issues"):
            if isinstance(item.get(key), list):
                nested = item[key]
                break
        if nested is None:
            out.append(item)
            continue
        carried = {
            k: item[k]
            for k in ("name", "package", "version", "type", "ecosystem")
            if k in item
        }
        for alert in nested:
            if isinstance(alert, dict):
                merged = {**carried, **alert}
                # The outer `type` is the package type; the alert's own type
                # is the rule. Do not let the former shadow the latter.
                if "type" in alert:
                    merged["type"] = alert["type"]
                out.append(merged)
    return out


def _to_finding(alert: dict[str, Any], spec: AdapterSpec) -> Finding | None:
    rule = str(alert.get("type") or alert.get("key") or alert.get("rule") or "").strip()
    if not rule:
        return None

    props = alert.get("props") if isinstance(alert.get("props"), dict) else {}
    value = alert.get("value") if isinstance(alert.get("value"), dict) else {}

    level = str(
        alert.get("severity")
        or value.get("severity")
        or alert.get("level")
        or "medium"
    ).strip().lower()
    severity = _clamp(_SEVERITIES.get(level, Severity.MEDIUM), spec)

    package = str(alert.get("package") or alert.get("name") or "").strip()
    version = str(alert.get("version") or "").strip()
    subject = f"{package}@{version}" if package and version else package

    title = str(alert.get("title") or props.get("title") or rule).strip()
    description = str(
        alert.get("description") or props.get("description") or value.get("description") or ""
    ).strip()

    message = description or (
        f"Socket alert `{rule}`" + (f" on {subject}" if subject else "")
    )

    # Socket's alert description is the upstream rationale. When an alert
    # arrives without one we say so rather than writing a plausible-sounding
    # explanation of a rule we did not author.
    rationale = description or (
        f"Socket raised its `{rule}` alert"
        + (f" against {subject}" if subject else "")
        + ". Socket did not include a description for this alert in its "
        f"output; see {DOCS} for what `{rule}` means. Socket's analysis uses "
        "registry metadata and package contents that cannot be derived from "
        "the lockfile in this repository."
    )

    path = str(alert.get("file") or alert.get("manifest") or props.get("file") or "").strip()
    line = _int(alert.get("start") or alert.get("line") or props.get("line"))

    return Finding(
        rule_id=f"{ADAPTER_ID}.{rule}",
        severity=severity,
        title=(f"{title} ({subject})" if subject else title)[:120],
        message=message,
        rationale=rationale,
        pack=spec.pack,
        tier=Tier.DETERMINISTIC,
        engine=Engine.SCRIPT,
        location=Location(path.replace("\\", "/"), line) if path else None,
        metadata={
            "adapter": ADAPTER_ID,
            "upstream_rule": rule,
            "upstream_severity": level,
            "package": package,
            "version": version,
            "category": str(alert.get("category") or "").strip(),
            "help_uri": str(alert.get("url") or alert.get("helpUri") or DOCS),
        },
    )


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _trim(text: str, limit: int = 400) -> str:
    collapsed = " ".join((text or "").split())
    return collapsed[:limit] or "(empty)"
