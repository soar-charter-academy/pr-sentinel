"""The script-check contract.

semgrep is for code patterns, not for counting files (DESIGN s5). Rules that
need graph or cross-file reasoning — migration numbering, dependency-tree
shape, "this lockfile changed but its manifest didn't" — are small
purpose-built scripts instead.

Script checks are *engine* code, deliberately. A pack chooses which checks run
and at what severity; it cannot supply the code, because pack data is also the
extension point offered to consuming repos, and repo-authored logic executing
in CI is the thing s7 rules out.

Before writing one, check whether a maintained tool already does it. Since
DESIGN-V2 s3 that is the first question: if `zizmor`, `gitleaks`, Socket,
`squawk` or Supabase's own advisors cover the ground, the answer is an
adapter in `adapters/`, not a check here. Twelve checks survived that
question; roughly fifteen did not.

Writing a check:

    @register(
        "supply-chain.lockfile-integrity",
        default_severity=Severity.HIGH,
        title="Lockfile and manifest disagree about what changed",
    )
    def lockfile_integrity(ctx: ReviewContext, spec: CheckSpec) -> Iterable[Finding]:
        ...
        yield spec.finding(title=..., message=..., rationale=..., path=...)

`spec.finding()` is the only sanctioned way to build one: it stamps the pack,
tier, engine and the pack-overridden severity so a check cannot accidentally
mislabel its own output.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ...models import Engine, Finding, Location, Severity, Tier

if TYPE_CHECKING:  # pragma: no cover
    from ...context import ReviewContext


CheckFn = Callable[["ReviewContext", "CheckSpec"], Iterable[Finding]]


@dataclass
class CheckSpec:
    """A check as configured by the pack that enabled it."""

    check_id: str
    pack: str
    severity: Severity
    options: dict[str, Any] = field(default_factory=dict)
    default_title: str = ""

    def option(self, key: str, default: Any = None) -> Any:
        return self.options.get(key, default)

    def finding(
        self,
        *,
        message: str,
        rationale: str,
        title: str | None = None,
        path: str | None = None,
        line: int | None = None,
        end_line: int | None = None,
        snippet: str | None = None,
        severity: Severity | str | None = None,
        nonbinding: bool = False,
        frameworks: list[str] | None = None,
        verify_hint: str | None = None,
        rule_suffix: str | None = None,
        **metadata: Any,
    ) -> Finding:
        location = Location(path, line, end_line, snippet) if path else None
        return Finding(
            rule_id=f"{self.check_id}.{rule_suffix}" if rule_suffix else self.check_id,
            severity=Severity.parse(severity) if severity else self.severity,
            title=title or self.default_title or self.check_id,
            message=message,
            rationale=rationale,
            pack=self.pack,
            tier=Tier.DETERMINISTIC,
            engine=Engine.SCRIPT,
            location=location,
            nonbinding=nonbinding,
            frameworks=frameworks or [],
            verify_hint=verify_hint,
            metadata=metadata,
        )


@dataclass
class RegisteredCheck:
    check_id: str
    fn: CheckFn
    default_severity: Severity
    title: str
    description: str
    #: Cheap gate so a check that cannot possibly apply never runs. Globs are
    #: matched against changed paths.
    applies_to: list[str] = field(default_factory=list)
    #: Whether the check needs files the PR did not touch (e.g. the full
    #: migrations directory). Purely informational, but it documents intent.
    reads_whole_repo: bool = False


REGISTRY: dict[str, RegisteredCheck] = {}


def register(
    check_id: str,
    *,
    default_severity: Severity = Severity.MEDIUM,
    title: str = "",
    description: str = "",
    applies_to: list[str] | None = None,
    reads_whole_repo: bool = False,
) -> Callable[[CheckFn], CheckFn]:
    def decorator(fn: CheckFn) -> CheckFn:
        if check_id in REGISTRY:
            raise RuntimeError(f"duplicate script check id: {check_id}")
        REGISTRY[check_id] = RegisteredCheck(
            check_id=check_id,
            fn=fn,
            default_severity=default_severity,
            title=title or check_id,
            description=description or (fn.__doc__ or "").strip().splitlines()[0]
            if (fn.__doc__ or "").strip()
            else check_id,
            applies_to=applies_to or [],
            reads_whole_repo=reads_whole_repo,
        )
        return fn

    return decorator


def get(check_id: str) -> RegisteredCheck | None:
    return REGISTRY.get(check_id)


def all_checks() -> dict[str, RegisteredCheck]:
    return dict(REGISTRY)
