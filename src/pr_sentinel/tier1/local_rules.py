"""Validation for rules authored in the consuming repo.

DESIGN s7 sets two tiers of authorship with deliberately different bars.
Curated pack rules go through review in the engine repo. Local rules in
`.pr-sentinel/rules/` can be added by anyone in their own repo, with no gate
beyond that repo's own PR process — which means the engine has to supply the
guardrails the review process doesn't:

- **declarative only** — a rule is data, never executable code
- **severity capped at `high`** — `critical` is curated-only, so a local rule
  can never block a merge on its own
- **`id`, `message` and `rationale` are mandatory** — not bureaucracy: a
  finding without a stated reason gets suppressed, and a rule that is always
  suppressed trains everyone to ignore the tool

A rule that fails validation is dropped and reported, never silently skipped.
A local rule that stopped running without anyone noticing is a rule everyone
believes is protecting them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..models import Severity

#: `pattern-where-python` executes arbitrary Python inside the scan. `fix`
#: and `fix-regex` describe code edits, and this engine never edits a PR
#: (DESIGN s2). All are refused in repo-authored rules.
FORBIDDEN_KEYS = {
    "pattern-where-python",
    "pattern-where",
    "fix",
    "fix-regex",
    "fix-regex-count",
}

MAX_LOCAL_SEVERITY = Severity.HIGH

LOCAL_ID_PREFIX = "local."

_ID_RE = re.compile(r"^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$")


@dataclass
class LocalRuleReport:
    accepted_files: list[Path] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)
    rejections: list[str] = field(default_factory=list)
    adjustments: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.rejections


def load_local_rules(
    repo_root: Path | str,
    rules_dir: str | None,
    staging_dir: Path | str | None = None,
) -> LocalRuleReport:
    """Validate repo-authored rules and stage the clean ones for semgrep.

    Rules are rewritten into `staging_dir` rather than passed through
    untouched, so that a normalised severity or an enforced namespace is
    what actually runs, not just what was reported.
    """
    report = LocalRuleReport()
    if not rules_dir:
        return report

    root = Path(repo_root)
    source = root / rules_dir
    if not source.is_dir():
        return report

    files = sorted(p for p in source.rglob("*.y*ml") if p.is_file())
    if not files:
        return report

    if staging_dir is None:
        report.rejections.append(
            "internal: no staging directory supplied for local rules; they were not run."
        )
        return report
    staging = Path(staging_dir)
    staging.mkdir(parents=True, exist_ok=True)

    for path in files:
        rel = path.relative_to(root)
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            report.rejections.append(f"{rel}: not valid YAML ({exc}); file skipped.")
            continue

        if not isinstance(raw, dict) or not isinstance(raw.get("rules"), list):
            report.rejections.append(
                f"{rel}: expected a mapping with a top-level `rules:` list; file skipped."
            )
            continue

        kept: list[dict[str, Any]] = []
        for index, rule in enumerate(raw["rules"]):
            cleaned = _validate_rule(rule, rel, index, report)
            if cleaned is not None:
                kept.append(cleaned)
                report.rule_ids.append(cleaned["id"])

        if not kept:
            continue

        out_path = staging / f"{rel.as_posix().replace('/', '__')}"
        out_path.write_text(
            yaml.safe_dump({"rules": kept}, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
        report.accepted_files.append(out_path)

    return report


def _validate_rule(
    rule: Any, rel: Path, index: int, report: LocalRuleReport
) -> dict[str, Any] | None:
    where = f"{rel} rule #{index + 1}"

    if not isinstance(rule, dict):
        report.rejections.append(f"{where}: each rule must be a mapping; rule dropped.")
        return None

    rule_id = str(rule.get("id") or "").strip()
    if not rule_id:
        report.rejections.append(f"{where}: missing `id`; rule dropped.")
        return None
    # Matched against the id as written, not a lower-cased copy: lower-casing
    # first made the check accept exactly what its own message says it
    # refuses, and the id that reaches semgrep and the suppression list is
    # the original casing, not the copy that was validated.
    if not _ID_RE.match(rule_id):
        report.rejections.append(
            f"{where}: id {rule_id!r} must be lowercase alphanumeric with . _ or -; rule dropped."
        )
        return None

    message = str(rule.get("message") or "").strip()
    if not message:
        report.rejections.append(f"{where} ({rule_id}): missing `message`; rule dropped.")
        return None

    metadata = rule.get("metadata")
    if metadata is not None and not isinstance(metadata, dict):
        report.rejections.append(f"{where} ({rule_id}): `metadata` must be a mapping; rule dropped.")
        return None
    metadata = dict(metadata or {})

    rationale = str(metadata.get("rationale") or metadata.get("why") or "").strip()
    if not rationale:
        report.rejections.append(
            f"{where} ({rule_id}): missing `metadata.rationale`. Every rule must say why it "
            "exists - a finding without a stated reason gets suppressed, and a rule that is "
            "always suppressed trains everyone to ignore the tool. Rule dropped."
        )
        return None

    forbidden = _find_forbidden(rule)
    if forbidden:
        report.rejections.append(
            f"{where} ({rule_id}): uses {', '.join(sorted(forbidden))}, which is not allowed in "
            "repo-authored rules. Local rules are declarative data, never executable code, "
            "because they run in CI with no review gate beyond this repo. Rule dropped."
        )
        return None

    cleaned = dict(rule)

    # Namespace enforcement: a local rule may not impersonate a curated one.
    if not rule_id.startswith(LOCAL_ID_PREFIX):
        new_id = LOCAL_ID_PREFIX + rule_id
        report.adjustments.append(
            f"{where}: id {rule_id!r} namespaced to {new_id!r} so it cannot collide with a "
            "curated pack rule."
        )
        cleaned["id"] = new_id
        rule_id = new_id

    # Severity cap. `critical` is curated-only so that a local rule can never
    # block a merge on its own (DESIGN s7).
    requested = metadata.get("sentinel-severity") or metadata.get("sentinel_severity")
    if requested:
        try:
            severity = Severity.parse(str(requested))
        except ValueError as exc:
            report.rejections.append(f"{where} ({rule_id}): {exc}; rule dropped.")
            return None
        if severity.rank > MAX_LOCAL_SEVERITY.rank:
            report.adjustments.append(
                f"{where} ({rule_id}): severity `{severity.value}` lowered to "
                f"`{MAX_LOCAL_SEVERITY.value}`. `critical` is reserved for curated packs so a "
                "repo-local rule can never block a merge by itself."
            )
            severity = MAX_LOCAL_SEVERITY
        metadata["sentinel-severity"] = severity.value
    else:
        metadata["sentinel-severity"] = Severity.MEDIUM.value

    metadata["pack"] = "local"
    metadata["rationale"] = rationale
    cleaned["metadata"] = metadata

    if "severity" not in cleaned:
        cleaned["severity"] = "WARNING"

    return cleaned


def _find_forbidden(node: Any, found: set[str] | None = None) -> set[str]:
    found = found if found is not None else set()
    if isinstance(node, dict):
        for key, value in node.items():
            if str(key) in FORBIDDEN_KEYS:
                found.add(str(key))
            _find_forbidden(value, found)
    elif isinstance(node, list):
        for item in node:
            _find_forbidden(item, found)
    return found
