"""Tier 3 data types: personas, sessions, inventories, evidence, manifests.

DESIGN-V2 §5. The tier that boots the software and signs in.

The central type is `Persona = (Role, Archetype, Session)`. Roles are
domain-specific and synthesised per target application; archetypes are
behavioural, shipped with the engine, and deliberately domain-free so they
transfer to anything. Keeping the two axes separate is what makes the matrix
prunable by judgement (§5.1a) rather than by arithmetic.
"""

from __future__ import annotations

import enum
import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


class Capability(enum.Enum):
    """What a persona is *expected* to be able to do.

    Expectations exist so that a difference is reportable in both directions:
    a persona that gains access it should not have, and one that loses access
    it should have. A reviewer that only notices widening misses the outage.
    """

    READ_OWN = "read-own"
    READ_ASSIGNED = "read-assigned"
    READ_ALL = "read-all"
    WRITE_OWN = "write-own"
    WRITE_ASSIGNED = "write-assigned"
    ADMINISTER = "administer"


@dataclass(frozen=True)
class Role:
    """A domain role, synthesised from the target's own auth model."""

    name: str
    description: str
    expected: tuple[Capability, ...] = ()
    #: Free-text note on how this role is represented in the target
    #: (a column, a JWT claim, an email pattern). Recorded so a human can
    #: check the synthesis was right.
    derived_from: str = ""
    #: Data this role must never be able to reach, in plain language.
    must_not_reach: tuple[str, ...] = ()


@dataclass(frozen=True)
class Archetype:
    """A behavioural pattern. Shipped with the engine; never domain-specific."""

    name: str
    description: str
    #: Instruction fragment handed to the explorer for this behaviour.
    charter: str
    #: Browser/environment adjustments this archetype implies.
    viewport: tuple[int, int] | None = None
    network: str | None = None  # "slow-3g" | "offline-flap" | None
    keyboard_only: bool = False
    mutates: bool = False
    #: True for archetypes allowed to probe below the UI (DESIGN-V2 §11).
    probes_api: bool = False
    locale: str | None = None


@dataclass
class Persona:
    role: Role
    archetype: Archetype
    #: Why this combination describes a real person (§5.1a). Written by the
    #: pruning pass and kept so a human can disagree with it.
    plausibility: str = ""
    session_ref: str | None = None

    @property
    def name(self) -> str:
        return f"{self.role.name}/{self.archetype.name}"

    def charter(self) -> str:
        return (
            f"You are a {self.role.name}. {self.role.description}\n\n"
            f"Behave as this kind of user: {self.archetype.description}\n\n"
            f"{self.archetype.charter}"
        )


# ---------------------------------------------------------------------------
# sessions
# ---------------------------------------------------------------------------


class SessionStatus(enum.Enum):
    OK = "ok"
    EXPIRED = "expired"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"


@dataclass
class Session:
    """An authenticated browser state for one persona."""

    persona: str
    status: SessionStatus
    provider: str
    #: Cookies / localStorage to inject before navigating.
    storage_state: dict[str, Any] = field(default_factory=dict)
    #: Bearer token, when the API probe needs one directly.
    access_token: str | None = None
    identity: str | None = None
    expires_at: str | None = None
    error: str | None = None

    @property
    def usable(self) -> bool:
        return self.status is SessionStatus.OK

    def __repr__(self) -> str:
        """Hand-written, because the generated one would print the token.

        `access_token` and `storage_state` are a live credential for a real
        account. A dataclass repr puts both into any log line, traceback,
        assertion failure or debugger frame that touches a `Session` — which
        is how a token ends up in CI output readable by anyone with the
        repository. Presence is all a reader ever needs.
        """
        return (
            f"Session(persona={self.persona!r}, status={self.status.value}, "
            f"provider={self.provider!r}, identity={self.identity!r}, "
            f"expires_at={self.expires_at!r}, "
            f"token={'present' if self.access_token else 'none'}, "
            f"storage_state={'present' if self.storage_state else 'empty'}, "
            f"error={self.error!r})"
        )

    __str__ = __repr__


# ---------------------------------------------------------------------------
# capability inventory
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Affordance:
    """One thing a persona can see or do on one screen.

    Identified by a stable key rather than a DOM path, because DOM paths
    change when anyone touches the markup and a diff full of "the button
    moved" is a diff nobody reads.
    """

    screen: str
    kind: str  # nav | button | link | field | region | row-set
    label: str
    enabled: bool = True
    visible: bool = True
    #: Fingerprint of the data rendered here, when this is a data region.
    #: Content itself is never stored - it may be personal data.
    content_fingerprint: str | None = None
    row_count: int | None = None

    @property
    def key(self) -> str:
        return f"{self.screen}::{self.kind}::{self.label}"


@dataclass
class Inventory:
    """What one persona could reach at one revision."""

    persona: str
    revision: str
    affordances: dict[str, Affordance] = field(default_factory=dict)
    api_results: dict[str, int] = field(default_factory=dict)  # endpoint -> status
    errors: list[str] = field(default_factory=list)
    screens_visited: list[str] = field(default_factory=list)
    complete: bool = True

    def add(self, affordance: Affordance) -> None:
        self.affordances[affordance.key] = affordance

    @property
    def reachable(self) -> set[str]:
        return {
            key for key, a in self.affordances.items() if a.visible and a.enabled
        }


@dataclass
class InventoryDiff:
    """Base vs head, for one persona. The heart of §5.4."""

    persona: str
    gained: list[Affordance] = field(default_factory=list)
    lost: list[Affordance] = field(default_factory=list)
    row_count_changed: list[tuple[Affordance, int, int]] = field(default_factory=list)
    api_status_changed: list[tuple[str, int, int]] = field(default_factory=list)
    #: True when either side's crawl was incomplete, in which case a "no
    #: change" result is not trustworthy and must not be reported as clean.
    degraded: bool = False

    @property
    def empty(self) -> bool:
        return not (
            self.gained or self.lost or self.row_count_changed or self.api_status_changed
        )


# ---------------------------------------------------------------------------
# evidence
# ---------------------------------------------------------------------------


@dataclass
class Evidence:
    """What makes a runtime finding checkable.

    Runtime verification is stronger than code-reading verification because
    the claim can be re-executed: replay `steps` and see whether the same
    thing happens. A runtime finding that does not reproduce is dropped.
    """

    steps: list[str] = field(default_factory=list)
    screenshots: list[str] = field(default_factory=list)
    console: list[str] = field(default_factory=list)
    network: list[dict[str, Any]] = field(default_factory=list)
    reproduced: bool | None = None
    run_id: str | None = None

    def redacted(self) -> Evidence:
        """Evidence is attached to a PR comment, so it must never carry the
        personal data it was collected to detect. Bodies are replaced by
        shapes; only the fact and the field name survive."""
        return Evidence(
            steps=list(self.steps),
            screenshots=list(self.screenshots),
            console=[c[:200] for c in self.console],
            network=[
                {
                    "method": n.get("method"),
                    "url": _strip_query(str(n.get("url", ""))),
                    "status": n.get("status"),
                    "fields": sorted(n.get("fields", []))[:20],
                }
                for n in self.network
            ],
            reproduced=self.reproduced,
            run_id=self.run_id,
        )


def _strip_query(url: str) -> str:
    return url.split("?", 1)[0]


# ---------------------------------------------------------------------------
# run manifest - being obviously announced (DESIGN-V2 §6a)
# ---------------------------------------------------------------------------


@dataclass
class RunManifest:
    """Written before probing and closed after.

    An authorization probe and an attack do the same things; the difference
    has to be legible to whoever reads the logs tomorrow. This is the record
    they will want, published before the traffic rather than explained after
    it.
    """

    run_id: str = field(default_factory=lambda: f"sentinel-{uuid.uuid4().hex[:12]}")
    pr_url: str | None = None
    repo: str | None = None
    target: str | None = None
    personas: list[str] = field(default_factory=list)
    request_budget: int = 500
    requests_made: int = 0
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )
    finished_at: str | None = None
    aborted_reason: str | None = None

    def headers(self) -> dict[str, str]:
        """Self-identifying headers on every request the tier makes."""
        out = {
            "X-PR-Sentinel": "probe",
            "X-PR-Sentinel-Run": self.run_id,
            "User-Agent": f"pr-sentinel/runtime ({self.run_id}; automated PR review probe)",
        }
        if self.pr_url:
            out["X-PR-Sentinel-PR"] = self.pr_url
        return out

    def close(self, reason: str | None = None) -> None:
        self.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.aborted_reason = reason

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# safety
# ---------------------------------------------------------------------------


@dataclass
class PreflightResult:
    """The §6 test-data invariant.

    Passing is the licence to explore. Failing is itself the most valuable
    finding the tier can produce: it means the RLS policies that are supposed
    to confine a reviewer account to synthetic data are not doing so.
    """

    passed: bool
    tables_checked: list[str] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)
    error: str | None = None
    #: Count only. The offending rows are never recorded or rendered - that
    #: would mean writing real student data into a PR comment.
    violating_row_count: int = 0


def fingerprint(value: Any) -> str:
    """Stable fingerprint of rendered content.

    Used instead of storing the content, so an inventory can be diffed
    without ever persisting personal data.
    """
    blob = json.dumps(value, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]
