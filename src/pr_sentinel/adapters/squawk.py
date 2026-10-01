"""`squawk` — Postgres migration safety, by a tool that parses SQL.

DESIGN-V2 §3. v1 asked the Tier 2 `data-model` pass to judge whether a
migration was safe to apply to a live table. That is the wrong mechanism for
the question: "does `ALTER TABLE ... ADD COLUMN ... NOT NULL DEFAULT` take an
`ACCESS EXCLUSIVE` lock on this server version" is a fact about Postgres, and
a model answering it from memory is guessing at something `squawk` decides by
parsing the statement.

So this adapter owns the mechanical half — unsafe column additions, adding an
index without `CONCURRENTLY`, renames and type changes that break deployed
clients, missing `lock_timeout`, transactional DDL hazards — and the agent
tier keeps the half that needs context about *this* table's size and traffic.

`required=False`. `squawk` covers general Postgres migration hazards, and the
specific migration facts this project cannot get elsewhere —
`supabase.migration-numbering`, `migration-immutability`, `missing-grants` —
remain our own checks and still run. Its absence loses breadth, not a
guarantee.

Output format caveat, stated because it affected the code: `squawk
--reporter json` emits an array of violation objects whose `messages` field
is a list of tagged variants (`{"Note": {"content": ...}}`). That shape is
not covered by a published schema, so the parser below accepts the tagged
form, a flat `{"type": ..., "content": ...}` form, and bare strings, and
degrades to a note rather than a crash if a future release changes it again.
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

ADAPTER_ID = "squawk"

MIGRATION_GLOBS = [
    "supabase/migrations/*.sql",
    "migrations/*.sql",
    "db/migrate/*.sql",
    "*.sql",
]

DOCS = "https://squawkhq.com/docs/rules"

#: squawk's own levels. `Warning` is its default for a rule violation and
#: means "this will take a lock or break a deployed client", which is a real
#: production hazard rather than a style note, hence HIGH.
_LEVELS = {
    "error": Severity.HIGH,
    "warning": Severity.HIGH,
    "info": Severity.LOW,
    "note": Severity.LOW,
}


@register(
    ADAPTER_ID,
    tool="squawk",
    description=(
        "Postgres migration linter: unsafe column additions, locking DDL, "
        "non-concurrent index creation, renames and type changes that break "
        "deployed clients."
    ),
    required=False,
    applies_to=MIGRATION_GLOBS,
    install_hint=(
        "Install with `npm i -g squawk-cli`, `cargo install squawk`, or the "
        "release binary. Optional: our own supabase migration checks "
        "(numbering, immutability, grants) still run without it, but general "
        "Postgres locking and backwards-compatibility hazards go unchecked."
    ),
    homepage="https://squawkhq.com/",
)
def run_squawk(ctx: AdapterContext, spec: AdapterSpec) -> AdapterResult:
    registered = get(ADAPTER_ID)
    assert registered is not None

    binary = which("squawk")
    if not binary:
        return missing_tool_result(registered)

    result = AdapterResult(version=tool_version(binary))

    globs = spec.option("migration_globs") or MIGRATION_GLOBS
    targets = sorted(p for p in ctx.changed(*globs) if (ctx.repo_root / p).is_file())
    if not targets:
        result.notes.append("squawk: no changed SQL migration files in this PR.")
        result.ran = True
        return result

    args = ["--reporter", "json"]
    pg_version = spec.option("pg_version")
    if pg_version:
        args += ["--pg-version", str(pg_version)]
    excluded = spec.option("exclude") or []
    for rule in excluded:
        args += ["--exclude", str(rule)]
    if spec.option("assume_in_transaction"):
        args.append("--assume-in-transaction")
    args.extend(targets)

    outcome = run_tool(
        binary, args, ctx.repo_root, timeout=int(spec.option("timeout", 180))
    )
    if outcome is None:
        result.errors.append(
            "squawk is installed but could not be executed (timeout or "
            "killed); migration safety was not linted."
        )
        return result

    code, stdout, stderr = outcome

    # squawk exits 0 when it found nothing and 1 when it found violations;
    # usage errors and unparseable SQL produce a higher code with nothing on
    # stdout. Because 1 is ambiguous across versions, the test that actually
    # decides "ran" vs "crashed" is whether stdout is a JSON array — a
    # violation run always emits one, a failed run never does.
    parsed, parse_error = _parse(stdout)
    if parse_error is not None:
        if code == 0:
            # Clean run, no JSON because there was nothing to report.
            result.ran = True
            result.notes.append(f"squawk linted {len(targets)} migration file(s); no violations.")
            return result
        result.errors.append(
            f"squawk exited {code} and its output could not be read as JSON "
            f"({parse_error}); migration safety was not linted. "
            f"stderr: {_trim(stderr)}"
        )
        return result

    if code not in (0, 1):
        result.notes.append(
            f"squawk exited {code} (expected 0 or 1) but produced readable "
            f"JSON; findings below come from that output. stderr: {_trim(stderr)}"
        )

    changed = set(targets)
    for entry in parsed:
        finding = _to_finding(entry, spec)
        if finding is None:
            continue
        if finding.location and finding.location.path not in changed:
            continue
        result.findings.append(finding)

    result.ran = True
    result.notes.append(f"squawk linted {len(targets)} changed migration file(s).")
    return result


def _parse(stdout: str) -> tuple[list[dict[str, Any]], str | None]:
    text = (stdout or "").strip()
    if not text:
        return [], "empty output"
    try:
        payload = json.loads(text)
    except ValueError as exc:
        return [], str(exc)
    if isinstance(payload, dict):
        # Tolerated shape: a wrapper object around the violation list.
        for key in ("violations", "results", "findings"):
            if isinstance(payload.get(key), list):
                payload = payload[key]
                break
        else:
            payload = [payload]
    if not isinstance(payload, list):
        return [], "output was not a JSON array of violations"
    return [e for e in payload if isinstance(e, dict)], None


def _to_finding(entry: dict[str, Any], spec: AdapterSpec) -> Finding | None:
    rule = str(entry.get("rule_name") or entry.get("rule") or "").strip()
    if not rule:
        return None

    messages = _messages(entry.get("messages"))
    level = str(entry.get("level") or "warning").strip().lower()
    severity = _clamp(_LEVELS.get(level, Severity.MEDIUM), spec)

    path = str(entry.get("file") or "").replace("\\", "/") or None
    line = _int(entry.get("line"))

    # squawk's first message is the violation; the remainder are its own
    # explanation and suggested alternative. That is the upstream rationale,
    # so it is used verbatim rather than paraphrased.
    message = messages[0] if messages else rule
    detail = " ".join(messages[1:]).strip()
    rationale = detail or (
        f"squawk's `{rule}` rule reported this and supplied no further "
        f"explanation in its JSON output; the reasoning is documented at "
        f"{DOCS}#{rule}."
    )

    return Finding(
        rule_id=f"{ADAPTER_ID}.{rule}",
        severity=severity,
        title=f"squawk: {rule}"[:120],
        message=message,
        rationale=rationale,
        pack=spec.pack,
        tier=Tier.DETERMINISTIC,
        engine=Engine.SCRIPT,
        location=Location(path, line, line) if path else None,
        metadata={
            "adapter": ADAPTER_ID,
            "upstream_rule": rule,
            "upstream_level": level,
            "column": _int(entry.get("column")),
            "help_uri": f"{DOCS}#{rule}",
        },
    )


def _messages(node: Any) -> list[str]:
    """Flatten squawk's message list.

    Three shapes handled: the tagged-enum form squawk currently emits
    (`{"Note": {"content": "..."}}`), a flattened `{"type": ..., "content":
    ...}`, and a bare string. Anything else is skipped rather than
    stringified, because a Rust debug repr leaking into a PR comment is worse
    than a shorter message.
    """
    if node is None:
        return []
    if isinstance(node, str):
        return [node.strip()]
    if not isinstance(node, list):
        node = [node]
    out: list[str] = []
    for item in node:
        if isinstance(item, str):
            text = item.strip()
        elif isinstance(item, dict):
            if "content" in item:
                text = str(item.get("content") or "").strip()
            else:
                inner = next(
                    (v for v in item.values() if isinstance(v, (dict, str))), None
                )
                if isinstance(inner, dict):
                    text = str(inner.get("content") or "").strip()
                elif isinstance(inner, str):
                    text = inner.strip()
                else:
                    text = ""
        else:
            text = ""
        if text:
            out.append(text)
    return out


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _trim(text: str, limit: int = 400) -> str:
    collapsed = " ".join((text or "").split())
    return collapsed[:limit] or "(empty)"
