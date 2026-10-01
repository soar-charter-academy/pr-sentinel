"""Core data types.

Everything the engine produces is a `Finding`. Tier 0 project checks, Tier 1
semgrep matches, Tier 1 script checks and Tier 2 agent passes all normalise
into the same shape so that severity policy, deduplication, rendering and the
verdict calculation have exactly one type to reason about.
"""

from __future__ import annotations

import enum
import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any


class Severity(enum.Enum):
    """Ordered severity. Comparison is meaningful and used by policy."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    @classmethod
    def parse(cls, value: str | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        try:
            return cls(str(value).strip().lower())
        except ValueError as exc:
            raise ValueError(
                f"unknown severity {value!r}; expected one of "
                + ", ".join(s.value for s in cls)
            ) from exc


# INFO is lowest, CRITICAL highest.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Authority(enum.Enum):
    """What a finding at a given severity is allowed to do.

    This is the only place the engine decides between "recommendation" and
    "authority" (DESIGN s6). `mode` is a convenience preset over a map of
    severity -> Authority, never a separate code path.
    """

    BLOCKING = "blocking"
    COMMENT = "comment"
    SUMMARY_ONLY = "summary-only"
    IGNORE = "ignore"


class Tier(enum.IntEnum):
    PROJECT = 0
    DETERMINISTIC = 1
    AGENT = 2


class Engine(enum.Enum):
    """Which mechanism produced a finding. Recorded for provenance, and used
    to enforce the hard boundary: agent findings can never be `critical`."""

    PROJECT_CHECK = "project-check"
    SEMGREP = "semgrep"
    SCRIPT = "script"
    AGENT = "agent"


@dataclass(frozen=True)
class Location:
    path: str
    line: int | None = None
    end_line: int | None = None
    snippet: str | None = None

    def render(self) -> str:
        if self.line is None:
            return self.path
        if self.end_line and self.end_line != self.line:
            return f"{self.path}:{self.line}-{self.end_line}"
        return f"{self.path}:{self.line}"


@dataclass
class Finding:
    """A single thing a human might need to look at.

    `rationale` is mandatory by design (DESIGN s7): a finding without a stated
    reason gets suppressed, and a rule that is always suppressed trains
    everyone to ignore the tool.
    """

    rule_id: str
    severity: Severity
    title: str
    message: str
    rationale: str
    pack: str
    tier: Tier
    engine: Engine
    location: Location | None = None

    # Agent-tier bookkeeping. `verified` is None for deterministic findings,
    # which do not pass through verification because they do not need to.
    verified: bool | None = None
    verification_note: str | None = None
    confidence: float | None = None

    # privacy-edu (DESIGN s11): a nonbinding finding names frameworks and
    # states what a human should check. It never rules on compliance.
    nonbinding: bool = False
    frameworks: list[str] = field(default_factory=list)
    verify_hint: str | None = None

    # Free-form, rendered in the details block.
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.severity = Severity.parse(self.severity)
        if not self.rationale or not self.rationale.strip():
            raise ValueError(
                f"rule {self.rule_id!r}: rationale is required "
                "(see DESIGN s7 - a finding without a reason gets suppressed)"
            )
        # The hard boundary. Judgment may not block a merge; only the
        # deterministic tier can produce `critical`.
        if self.engine is Engine.AGENT and self.severity is Severity.CRITICAL:
            self.severity = Severity.HIGH
            self.metadata.setdefault("severity_capped", "agent findings cap at high")

    @property
    def fingerprint(self) -> str:
        """Stable identity across runs, for dedupe and for suppression.

        Deliberately excludes line numbers: the same problem shifting down two
        lines because someone added an import is the same problem.
        """
        basis = json.dumps(
            {
                "rule_id": self.rule_id,
                "path": self.location.path if self.location else None,
                "title": self.title,
            },
            sort_keys=True,
        )
        return hashlib.sha256(basis.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["tier"] = int(self.tier)
        data["engine"] = self.engine.value
        data["fingerprint"] = self.fingerprint
        return data


@dataclass
class Provenance:
    """Recorded on every comment so a verdict is reproducible and a regression
    in the reviewer is diagnosable (DESIGN s10)."""

    engine_version: str
    pack_versions: dict[str, str] = field(default_factory=dict)
    semgrep_version: str | None = None
    #: adapter id -> the external tool's own version string.
    #:
    #: Required by DESIGN-V2 s3: an adapter's whole premise is that somebody
    #: else maintains the rules, which means the rule set can change under us
    #: between two runs of the same engine on the same commit. "zizmor found
    #: nothing" is not reproducible; "zizmor 1.5.2 found nothing" is. This is
    #: also the first thing to look at when a finding appears or disappears
    #: with no change to this repository.
    tool_versions: dict[str, str] = field(default_factory=dict)
    models: dict[str, str] = field(default_factory=dict)
    #: Tool name -> call count, across the whole agent tier. Recorded because
    #: a finding produced by a pass that read four files and grepped twice is
    #: a different claim from one produced by a pass that only saw the diff,
    #: and a reader of the comment cannot tell them apart otherwise.
    tool_calls: dict[str, int] = field(default_factory=dict)
    commit_sha: str | None = None
    run_url: str | None = None
    started_at: str | None = None
    duration_seconds: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Verdict:
    """The engine's recommendation. Note `blocking` is separate from
    `findings`: something can be worth saying without being worth stopping."""

    findings: list[Finding]
    blocking: list[Finding]
    summary_only: list[Finding]
    tier0_failed: bool
    provenance: Provenance
    mode: str
    notes: list[str] = field(default_factory=list)

    @property
    def should_fail_check(self) -> bool:
        return self.tier0_failed or bool(self.blocking)

    @property
    def conclusion(self) -> str:
        """GitHub check-run conclusion."""
        if self.should_fail_check:
            return "failure"
        if self.findings:
            return "neutral"
        return "success"

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "conclusion": self.conclusion,
            "should_fail_check": self.should_fail_check,
            "tier0_failed": self.tier0_failed,
            "counts": self.counts(),
            "findings": [f.to_dict() for f in self.findings],
            "blocking": [f.fingerprint for f in self.blocking],
            "provenance": self.provenance.to_dict(),
            "notes": self.notes,
        }
