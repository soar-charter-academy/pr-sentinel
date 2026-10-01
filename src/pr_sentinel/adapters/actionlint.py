"""`actionlint` — is the workflow *correct*, which `zizmor` does not ask.

DESIGN-V2 §3. `zizmor` audits workflows for security; it does not tell you
that `runs-on: ubunut-latest` is a typo, that a `needs:` names a job that
does not exist, or that the inline `run:` block has a shell quoting bug.
Those are the failures that waste an afternoon of push-and-watch-CI, and
`actionlint` finds them statically, including by handing embedded scripts to
shellcheck and pyflakes when those are installed.

`required=False`. A workflow correctness bug announces itself the first time
the workflow runs — it is expensive, not silent. Withholding the
deterministic status because `actionlint` is missing would be claiming a
guarantee this adapter does not actually provide, and that devalues the
times we withhold it for `zizmor` or `gitleaks`.

On rationale: `actionlint` emits no per-rule description, only a `kind`,
which is its own name for the class of check that fired. We say that
plainly in the rationale and point at its documentation rather than writing
an explanation `actionlint` never made.
"""

from __future__ import annotations

import json
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

ADAPTER_ID = "actionlint"

WORKFLOW_GLOBS = [".github/workflows/*.yml", ".github/workflows/*.yaml"]

#: `actionlint -format '{{json .}}'` is a Go text/template over its error
#: list. This is the documented way to get machine-readable output; there is
#: no SARIF mode, hence the bespoke parser below.
JSON_FORMAT = "{{json .}}"

DOCS = "https://github.com/rhysd/actionlint/blob/main/docs/checks.md"

#: `kind`s that come from a delegated linter rather than from actionlint's own
#: workflow model. They are real, but they are style-and-shell advice about an
#: embedded script, so they sit a notch below "this workflow is wrong".
_DELEGATED_KINDS = {"shellcheck", "pyflakes"}


@register(
    ADAPTER_ID,
    tool="actionlint",
    description=(
        "Static correctness checking for GitHub Actions workflows: expression "
        "typing, job graph validity, runner labels, action input schemas, and "
        "shellcheck/pyflakes over embedded scripts."
    ),
    required=False,
    applies_to=WORKFLOW_GLOBS,
    install_hint=(
        "Install with `brew install actionlint`, `go install "
        "github.com/rhysd/actionlint/cmd/actionlint@latest`, or the release "
        "binary. Optional: workflow correctness bugs surface on the next "
        "workflow run, so its absence is a slower feedback loop rather than a "
        "missing guarantee."
    ),
    homepage="https://github.com/rhysd/actionlint",
)
def run_actionlint(ctx: AdapterContext, spec: AdapterSpec) -> AdapterResult:
    registered = get(ADAPTER_ID)
    assert registered is not None

    binary = which("actionlint")
    if not binary:
        return missing_tool_result(registered)

    result = AdapterResult(version=tool_version(binary))

    targets = sorted(
        p for p in ctx.changed(*WORKFLOW_GLOBS) if (ctx.repo_root / p).is_file()
    )
    if not targets:
        result.notes.append("actionlint: no changed workflow files to check.")
        result.ran = True
        return result

    args = ["-format", JSON_FORMAT, "-no-color"]
    if spec.option("shellcheck") is False:
        args += ["-shellcheck", ""]
    if spec.option("pyflakes") is False:
        args += ["-pyflakes", ""]
    config = spec.option("config")
    if config:
        args += ["-config-file", str(config)]
    for ignore in spec.option("ignore") or []:
        args += ["-ignore", str(ignore)]
    args.extend(targets)

    outcome = run_tool(
        binary, args, ctx.repo_root, timeout=int(spec.option("timeout", 180))
    )
    if outcome is None:
        result.errors.append(
            "actionlint is installed but could not be executed (timeout or "
            "killed); workflow correctness was not checked."
        )
        return result

    code, stdout, stderr = outcome

    # actionlint's documented exit statuses: 0 = no problems found, 1 =
    # problems found, 2 = actionlint could not run (bad flag, unreadable
    # file). 1 is a successful run that has something to say.
    if code >= 2:
        result.errors.append(
            f"actionlint exited {code}, which means it failed to run rather "
            f"than that it found problems. stderr: {_trim(stderr)}"
        )
        return result

    parsed, parse_error = _parse(stdout)
    if parse_error:
        result.errors.append(parse_error)
        return result

    changed = set(targets)
    for entry in parsed:
        finding = _to_finding(entry, spec)
        if finding is None:
            continue
        # actionlint only inspects the files we hand it, but it can report a
        # problem in a reusable workflow it followed. Keep it scoped.
        if finding.location and finding.location.path not in changed:
            continue
        result.findings.append(finding)

    result.ran = True
    result.notes.append(f"actionlint checked {len(targets)} changed workflow file(s).")
    return result


def _parse(stdout: str) -> tuple[list[dict[str, Any]], str | None]:
    text = (stdout or "").strip()
    if not text:
        return [], None
    try:
        payload = json.loads(text)
    except ValueError as exc:
        return [], (
            f"actionlint output was not valid JSON ({exc}); no workflow "
            f"correctness findings could be read from this run."
        )
    if isinstance(payload, dict):
        payload = [payload]
    if not isinstance(payload, list):
        return [], "actionlint JSON output was neither an object nor an array."
    return [e for e in payload if isinstance(e, dict)], None


def _to_finding(entry: dict[str, Any], spec: AdapterSpec) -> Finding | None:
    message = str(entry.get("message") or "").strip()
    if not message:
        return None
    kind = str(entry.get("kind") or "unknown").strip() or "unknown"
    path = str(entry.get("filepath") or "").replace("\\", "/") or None
    line = _int(entry.get("line"))
    column = _int(entry.get("column"))

    severity = _clamp(
        Severity.LOW if kind in _DELEGATED_KINDS else Severity.MEDIUM, spec
    )

    return Finding(
        rule_id=f"{ADAPTER_ID}.{kind}",
        severity=severity,
        title=f"actionlint: {kind}"[:120],
        message=message,
        # actionlint ships no machine-readable per-rule description, so the
        # honest rationale names the check that fired and sends the reader to
        # the upstream catalogue. We do not write an explanation on its behalf.
        rationale=(
            f"actionlint's `{kind}` check reported this. actionlint does not "
            f"emit a per-rule rationale in its machine-readable output; the "
            f"reasoning for `{kind}` is documented upstream at {DOCS}. "
            f"A workflow that fails this check will usually fail or misbehave "
            f"when GitHub next runs it."
        ),
        pack=spec.pack,
        tier=Tier.DETERMINISTIC,
        engine=Engine.SCRIPT,
        location=Location(path, line, line) if path else None,
        metadata={
            "adapter": ADAPTER_ID,
            "upstream_rule": kind,
            "column": column,
            "snippet": str(entry.get("snippet") or "").strip(),
            "help_uri": DOCS,
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
