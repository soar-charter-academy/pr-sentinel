"""Loading and validating `.pr-sentinel.yml` from the consuming repo.

Two things here are load-bearing rather than incidental:

1. **Mode is a preset, not a code path** (DESIGN s6). `advisory`, `gated` and
   `blocking` each expand into the same severity -> Authority map that an
   explicit `authority:` block would produce. There is one enforcement path.

2. **Pack pins are independent** (DESIGN s15). Each pack carries its own
   version and the repo pins each one separately. A pin that the shipped pack
   does not satisfy is a hard error, not a warning: quietly running a
   different rule set than the repo asked for is the failure `@main` pinning
   was rejected to avoid.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .models import Authority, Severity

CONFIG_FILENAMES = (".pr-sentinel.yml", ".pr-sentinel.yaml")

SUPPORTED_CONFIG_VERSIONS = (1,)

# `gated` is the recommended default: guarantees block, judgment advises.
DEFAULT_MODE = "gated"

MODE_PRESETS: dict[str, dict[Severity, Authority]] = {
    "advisory": {
        Severity.CRITICAL: Authority.COMMENT,
        Severity.HIGH: Authority.COMMENT,
        Severity.MEDIUM: Authority.COMMENT,
        Severity.LOW: Authority.SUMMARY_ONLY,
        Severity.INFO: Authority.SUMMARY_ONLY,
    },
    "gated": {
        Severity.CRITICAL: Authority.BLOCKING,
        Severity.HIGH: Authority.COMMENT,
        Severity.MEDIUM: Authority.COMMENT,
        Severity.LOW: Authority.SUMMARY_ONLY,
        Severity.INFO: Authority.SUMMARY_ONLY,
    },
    "blocking": {
        Severity.CRITICAL: Authority.BLOCKING,
        Severity.HIGH: Authority.BLOCKING,
        Severity.MEDIUM: Authority.COMMENT,
        Severity.LOW: Authority.SUMMARY_ONLY,
        Severity.INFO: Authority.SUMMARY_ONLY,
    },
}

DEFAULT_AGENT_PASSES = ["security", "privacy", "data-model", "lore", "parity"]

DEFAULT_IGNORE_PATHS = [
    "dist/",
    "build/",
    "node_modules/",
    ".venv/",
    "vendor/",
    "*.min.js",
    "*.map",
]

# `pack@spec` - the spec half is optional and means "any version".
_PACK_PIN_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:@\s*(.+?))?\s*$")


class ConfigError(ValueError):
    """Raised for a config the engine refuses to run with.

    Deliberately fatal. A reviewer that silently runs something other than
    what was configured is worse than one that does not run.
    """


@dataclass(frozen=True)
class PackPin:
    name: str
    spec: str = "*"

    @classmethod
    def parse(cls, raw: Any) -> PackPin:
        if isinstance(raw, dict):
            if len(raw) != 1:
                raise ConfigError(
                    f"pack entry must be a single name: version mapping, got {raw!r}"
                )
            name, spec = next(iter(raw.items()))
            return cls(str(name).strip(), str(spec).strip() or "*")
        m = _PACK_PIN_RE.match(str(raw))
        if not m:
            raise ConfigError(f"cannot parse pack entry {raw!r}")
        return cls(m.group(1), (m.group(2) or "*").strip())

    def __str__(self) -> str:
        return self.name if self.spec == "*" else f"{self.name}@{self.spec}"


@dataclass
class AgentConfig:
    enabled: bool = True
    passes: list[str] = field(default_factory=lambda: list(DEFAULT_AGENT_PASSES))
    max_findings: int = 8
    skip_draft_prs: bool = True
    # Triage cheap, escalate expensive (DESIGN s9). Reviewing a lockfile with
    # a frontier model is how this gets abandoned on cost.
    triage_model: str = "claude-haiku-4-5-20251001"
    review_model: str = "claude-sonnet-5-5"
    max_files_reviewed: int = 25
    max_file_bytes: int = 60_000
    # The verification pass is not optional in spirit; the flag exists so a
    # repo can prove to itself what verification is filtering out.
    verification: bool = True
    # Tools (DESIGN-V2 s4). On by default: a pass that can only see the diff
    # cannot check whether the guard clause is just above the hunk, which is
    # the commonest reason a finding is wrong.
    tools_enabled: bool = True
    tool_budget: int = 20
    tool_timeout_seconds: int = 120
    # Off by default, and opt-in rather than opt-out. Every other tool reads
    # the checkout; this one reaches the internet from a job holding
    # credentials, driven by a model whose context contains the pull request.
    # That is a decision a repository owner should make deliberately.
    allow_network_tools: bool = False


@dataclass
class IgnoreConfig:
    paths: list[str] = field(default_factory=lambda: list(DEFAULT_IGNORE_PATHS))
    rules: list[str] = field(default_factory=list)


@dataclass
class Tier0Config:
    enabled: bool = True
    # Empty means "auto-detect from package.json scripts".
    commands: list[str] = field(default_factory=list)
    fail_fast: bool = True
    timeout_seconds: int = 900
    audit_level: str = "high"


# ---------------------------------------------------------------------------
# Tier 3 - the runtime tier (DESIGN-V2 s7)
# ---------------------------------------------------------------------------

#: `mutations:` values. `off` is not a lesser setting - most archetypes have
#: no reason to write anything, and a probe that writes nothing needs no
#: teardown and cannot leave churn behind.
MUTATION_MODES = ("tagged-and-torn-down", "off")

#: What the invariant predicate is allowed to look like. Deliberately narrow:
#: `is_test_data = true` is a column, an equality and a literal, and anything
#: richer than that is SQL this engine would have to interpret correctly to
#: stay safe. Refusing to parse it is safer than half-parsing it.
_PREDICATE_RE = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|==|\bis\b)\s*([A-Za-z0-9_'\"-]+)\s*$",
    re.IGNORECASE,
)


@dataclass
class ReadyConfig:
    """The readiness probe. A boot is not "started", it is "answering"."""

    path: str = "/"
    #: Optional DOM substring that must be present before the app counts as
    #: ready. A dev server answers 200 with an empty shell long before the
    #: application has mounted, and crawling that shell produces an inventory
    #: of nothing that diffs cleanly against an inventory of nothing.
    selector: str | None = None
    timeout: int = 90


@dataclass
class BootConfig:
    command: str = ""
    port: int | None = None
    #: Explicit target. Takes precedence over `port`; if neither is set the
    #: tier refuses to boot, because s6 says it never guesses a target.
    base_url: str | None = None
    ready: ReadyConfig = field(default_factory=ReadyConfig)
    #: `secret` (the only supported value) means the environment comes from
    #: the platform's secret store. The repo's committed `.env` points at
    #: production and is never read - see `tier3/boot.py`.
    env_from: str = "secret"
    cwd: str | None = None

    @property
    def target(self) -> str | None:
        if self.base_url:
            return self.base_url.rstrip("/")
        if self.port:
            return f"http://127.0.0.1:{int(self.port)}"
        return None


@dataclass
class TestDataInvariantConfig:
    """The s6 pre-flight invariant: tables, and what marks a row synthetic."""

    tables: list[str] = field(default_factory=list)
    predicate: str = "is_test_data = true"
    #: Rows to ask for per table. Small on purpose - the answer is a count, and
    #: one row that should not exist is already the whole finding.
    limit: int = 50

    @property
    def column(self) -> str:
        match = _PREDICATE_RE.match(self.predicate)
        return match.group(1) if match else ""

    @property
    def value(self) -> str:
        match = _PREDICATE_RE.match(self.predicate)
        return match.group(2).strip("'\"") if match else ""


@dataclass
class SafetyConfig:
    #: Targets the tier must never point at, as substrings or globs. Env
    #: references (`${PROD_SUPABASE_URL}`) are expanded at boot time, not here,
    #: so a config can be validated on a machine that holds none of them.
    forbid_target_matching: list[str] = field(default_factory=list)
    test_data_invariant: TestDataInvariantConfig = field(
        default_factory=TestDataInvariantConfig
    )


@dataclass
class PersonaPin:
    """One committed (role, archetype) pair, with the reason it survived.

    The justification is stored rather than regenerated because it is the only
    part of the list a human can argue with (s5.1a), and arguing with it is the
    point.
    """

    role: str
    archetype: str
    plausibility: str = ""


@dataclass
class RuntimeConfig:
    """DESIGN-V2 s7, as a type.

    `enabled` is not the gate. s11 is explicit: this tier boots the PR's code
    with a live session against a shared database, so it runs on a
    maintainer-applied label and nothing else until `auto` is set. A config
    that enables the tier has made it *available*, not automatic.
    """

    enabled: bool = False
    #: s11. Flipping this to true removes the human consent step, and is
    #: meant to happen after the tier has earned trust rather than before.
    auto: bool = False
    label: str = "runtime-review"
    boot: BootConfig = field(default_factory=BootConfig)
    #: Free-form: every provider in `tier3/sessions.py` takes different keys,
    #: and the provider is the thing that knows which. Validated there.
    session: dict[str, Any] = field(default_factory=dict)
    safety: SafetyConfig = field(default_factory=SafetyConfig)
    roles: list[str] = field(default_factory=list)
    #: `all`, or a list of archetype names. Resolved against the shipped
    #: twelve at parse time so an unknown name fails here, where the file name
    #: is known, rather than silently reducing coverage at run time.
    archetypes: list[str] = field(default_factory=list)
    mutations: str = "off"
    #: The committed pruned matrix (s5.1a).
    personas: list[PersonaPin] = field(default_factory=list)
    #: Fingerprint of the auth model the roles were derived from (s11). When it
    #: moves, role synthesis re-runs and the difference is a finding.
    auth_fingerprint: str | None = None
    #: s6a: a hard request budget, published in the manifest. Exceeding it
    #: aborts the run rather than continuing quietly.
    request_budget: int = 500
    #: Per-persona exploration steps (s9).
    step_budget: int = 40
    #: Wall clock for one persona's exploration, seconds.
    explore_timeout_seconds: int = 300

    @property
    def mutates(self) -> bool:
        return self.mutations == "tagged-and-torn-down"


@dataclass
class Config:
    version: int = 1
    packs: list[PackPin] = field(default_factory=list)
    lore_path: str | None = None
    local_rules_path: str | None = ".pr-sentinel/rules/"
    mode: str = DEFAULT_MODE
    authority: dict[Severity, Authority] = field(default_factory=dict)
    agent: AgentConfig = field(default_factory=AgentConfig)
    ignore: IgnoreConfig = field(default_factory=IgnoreConfig)
    tier0: Tier0Config = field(default_factory=Tier0Config)
    runtime: RuntimeConfig = field(default_factory=RuntimeConfig)
    source_path: Path | None = None
    warnings: list[str] = field(default_factory=list)

    def authority_for(self, severity: Severity) -> Authority:
        return self.authority.get(severity, Authority.COMMENT)

    @property
    def pack_names(self) -> list[str]:
        return [p.name for p in self.packs]


def default_config() -> Config:
    """What a repo gets with no config file at all.

    Deliberately conservative: `core` only, advisory. A tool that shows up
    uninvited with opinions about your database schema does not get adopted.
    """
    cfg = Config(
        packs=[PackPin("core")],
        mode="advisory",
        authority=dict(MODE_PRESETS["advisory"]),
    )
    cfg.warnings.append(
        "No .pr-sentinel.yml found; running the `core` pack in advisory mode."
    )
    return cfg


def find_config(repo_root: Path) -> Path | None:
    for name in CONFIG_FILENAMES:
        candidate = repo_root / name
        if candidate.is_file():
            return candidate
    return None


def load_config(repo_root: Path | str, explicit_path: Path | str | None = None) -> Config:
    root = Path(repo_root)
    path = Path(explicit_path) if explicit_path else find_config(root)
    if path is None:
        return default_config()
    if not path.is_file():
        raise ConfigError(f"config file not found: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    cfg = parse_config(raw, source_path=path)
    return cfg


# Parsing lives in `_config_parse`, imported here at the bottom so that the
# dataclasses above already exist when it binds them. Re-exported so that
# `from pr_sentinel.config import parse_config` keeps working.
from ._config_parse import _positive_int, parse_config  # noqa: E402,F401

__all__ = [
    "Authority",
    "Config",
    "ConfigError",
    "AgentConfig",
    "BootConfig",
    "IgnoreConfig",
    "PackPin",
    "PersonaPin",
    "ReadyConfig",
    "RuntimeConfig",
    "SafetyConfig",
    "Severity",
    "TestDataInvariantConfig",
    "Tier0Config",
    "MODE_PRESETS",
    "MUTATION_MODES",
    "default_config",
    "find_config",
    "load_config",
    "parse_config",
]
ed)")

    # -- packs, each pinned independently ---------------------------------
    packs_raw = raw.get("packs", ["core"])
    packs: list[PackPin] = []
    if isinstance(packs_raw, dict):
        packs = [PackPin(str(n).strip(), str(s).strip() or "*") for n, s in packs_raw.items()]
    elif isinstance(packs_raw, list):
        packs = [PackPin.parse(entry) for entry in packs_raw]
    else:
        raise ConfigError(f"{where}: `packs` must be a list or a mapping")

    seen: set[str] = set()
    for pin in packs:
        if pin.name in seen:
            raise ConfigError(f"{where}: pack {pin.name!r} listed more than once")
        seen.add(pin.name)

    # -- mode and authority ------------------------------------------------
    mode = str(raw.get("mode", DEFAULT_MODE)).strip().lower()
    if mode not in MODE_PRESETS:
        raise ConfigError(
            f"{where}: unknown mode {mode!r}; expected one of {', '.join(MODE_PRESETS)}"
        )
    authority = dict(MODE_PRESETS[mode])

    authority_raw = raw.get("authority") or {}
    if not isinstance(authority_raw, dict):
        raise ConfigError(f"{where}: `authority` must be a mapping of severity to authority")
    for sev_raw, auth_raw in authority_raw.items():
        try:
            sev = Severity.parse(sev_raw)
        except ValueError as exc:
            raise ConfigError(f"{where}: {exc}") from exc
        try:
            auth = Authority(str(auth_raw).strip().lower())
        except ValueError as exc:
            raise ConfigError(
                f"{where}: unknown authority {auth_raw!r} for severity {sev.value}; "
                f"expected one of {', '.join(a.value for a in Authority)}"
            ) from exc
        authority[sev] = auth

    # -- agent -------------------------------------------------------------
    agent_raw = raw.get("agent") or {}
    if not isinstance(agent_raw, dict):
        raise ConfigError(f"{where}: `agent` must be a mapping")
    agent = AgentConfig()
    agent.enabled = bool(agent_raw.get("enabled", True))
    if "passes" in agent_raw:
        passes = agent_raw["passes"]
        if not isinstance(passes, list):
            raise ConfigError(f"{where}: `agent.passes` must be a list")
        unknown = [p for p in passes if p not in DEFAULT_AGENT_PASSES]
        if unknown:
            raise ConfigError(
                f"{where}: unknown agent pass(es) {unknown}; "
                f"available: {', '.join(DEFAULT_AGENT_PASSES)}"
            )
        agent.passes = [str(p) for p in passes]
    agent.max_findings = _positive_int(agent_raw, "max_findings", agent.max_findings, where)
    agent.skip_draft_prs = bool(agent_raw.get("skip_draft_prs", agent.skip_draft_prs))
    agent.triage_model = str(agent_raw.get("triage_model", agent.triage_model))
    agent.review_model = str(agent_raw.get("review_model", agent.review_model))
    agent.max_files_reviewed = _positive_int(
        agent_raw, "max_files_reviewed", agent.max_files_reviewed, where
    )
    agent.max_file_bytes = _positive_int(
        agent_raw, "max_file_bytes", agent.max_file_bytes, where
    )
    agent.verification = bool(agent_raw.get("verification", True))
    if not agent.verification:
        warnings.append(
            f"{where}: agent.verification is disabled. Unverified findings will be "
            "emitted as-is; expect noise (DESIGN s3)."
        )

    # Tools (DESIGN-V2 s4).
    agent.tools_enabled = bool(agent_raw.get("tools_enabled", agent.tools_enabled))
    agent.tool_budget = _positive_int(agent_raw, "tool_budget", agent.tool_budget, where)
    agent.tool_timeout_seconds = _positive_int(
        agent_raw, "tool_timeout_seconds", agent.tool_timeout_seconds, where
    )
    agent.allow_network_tools = bool(
        agent_raw.get("allow_network_tools", agent.allow_network_tools)
    )
    if not agent.tools_enabled:
        warnings.append(
            f"{where}: agent.tools_enabled is false. Passes see only the diff, so a "
            "guard clause just outside a hunk is invisible to them - the commonest "
            "reason a finding is wrong (DESIGN-V2 s4)."
        )
    if agent.allow_network_tools:
        warnings.append(
            f"{where}: agent.allow_network_tools is on. A job holding credentials may "
            "now make outbound requests under model direction; the allowlist confines "
            "it to advisory endpoints."
        )

    # -- ignore ------------------------------------------------------------
    ignore_raw = raw.get("ignore") or {}
    if not isinstance(ignore_raw, dict):
        raise ConfigError(f"{where}: `ignore` must be a mapping")
    ignore = IgnoreConfig(
        paths=[str(p) for p in (ignore_raw.get("paths") or DEFAULT_IGNORE_PATHS)],
        rules=[str(r) for r in (ignore_raw.get("rules") or [])],
    )

    # -- tier0 -------------------------------------------------------------
    tier0_raw = raw.get("tier0") or {}
    if not isinstance(tier0_raw, dict):
        raise ConfigError(f"{where}: `tier0` must be a mapping")
    tier0 = Tier0Config(
        enabled=bool(tier0_raw.get("enabled", True)),
        commands=[str(c) for c in (tier0_raw.get("commands") or [])],
        fail_fast=bool(tier0_raw.get("fail_fast", True)),
        timeout_seconds=_positive_int(tier0_raw, "timeout_seconds", 900, where),
        audit_level=str(tier0_raw.get("audit_level", "high")),
    )

    runtime = _parse_runtime(raw.get("runtime") or {}, where, warnings)

    lore = raw.get("lore")
    local_rules = raw.get("local_rules", ".pr-sentinel/rules/")

    return Config(
        version=int(version),
        packs=packs,
        lore_path=str(lore) if lore else None,
        local_rules_path=str(local_rules) if local_rules else None,
        mode=mode,
        authority=authority,
        agent=agent,
        ignore=ignore,
        tier0=tier0,
        runtime=runtime,
        source_path=source_path,
        warnings=warnings,
    )


def _parse_runtime(
    raw: dict[str, Any], where: str, warnings: list[str]
) -> RuntimeConfig:
    """Parse the Tier 3 block (DESIGN-V2 §7).

    Strict on purpose, and strict in one particular direction: every mistake
    that would cause the tier to run with *less* protection than the author
    intended is a hard error, not a warning. An unknown archetype name would
    silently reduce coverage; an unparseable invariant predicate would silently
    disarm the §6 pre-flight. Both fail here, where the file name is known.
    """
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: `runtime` must be a mapping")

    cfg = RuntimeConfig()
    cfg.enabled = bool(raw.get("enabled", False))
    cfg.auto = bool(raw.get("auto", False))
    cfg.label = str(raw.get("label", cfg.label)).strip() or "runtime-review"

    # -- boot --------------------------------------------------------------
    boot_raw = raw.get("boot") or {}
    if not isinstance(boot_raw, dict):
        raise ConfigError(f"{where}: `runtime.boot` must be a mapping")
    ready_raw = boot_raw.get("ready") or {}
    if not isinstance(ready_raw, dict):
        raise ConfigError(f"{where}: `runtime.boot.ready` must be a mapping")
    ready = ReadyConfig(
        path=str(ready_raw.get("path", "/")),
        selector=(str(ready_raw["selector"]) if ready_raw.get("selector") else None),
        timeout=_positive_int(ready_raw, "timeout", 90, where),
    )
    env_from = str(boot_raw.get("env_from", "secret")).strip().lower()
    if env_from != "secret":
        raise ConfigError(
            f"{where}: `runtime.boot.env_from` must be `secret`. The repo's committed "
            f"`.env` is never read: on this project it points at production, and a "
            f"browsing agent pointed at production is the harm this tier exists to "
            f"avoid (DESIGN-V2 §6)."
        )
    cfg.boot = BootConfig(
        command=str(boot_raw.get("command", "")).strip(),
        port=(int(boot_raw["port"]) if boot_raw.get("port") else None),
        base_url=(str(boot_raw["base_url"]) if boot_raw.get("base_url") else None),
        ready=ready,
        env_from=env_from,
        cwd=(str(boot_raw["cwd"]) if boot_raw.get("cwd") else None),
    )
    if cfg.enabled and not cfg.boot.command:
        raise ConfigError(f"{where}: `runtime.boot.command` is required when runtime is enabled")
    if cfg.enabled and not cfg.boot.target:
        raise ConfigError(
            f"{where}: `runtime` needs `boot.base_url` or `boot.port`. The tier does "
            f"not guess a target (DESIGN-V2 §6)."
        )

    # -- session -----------------------------------------------------------
    session_raw = raw.get("session") or {}
    if not isinstance(session_raw, dict):
        raise ConfigError(f"{where}: `runtime.session` must be a mapping")
    cfg.session = dict(session_raw)
    if cfg.enabled and not cfg.session.get("provider"):
        raise ConfigError(
            f"{where}: `runtime.session.provider` is required when runtime is enabled. "
            f"Run `sentinel runtime recon` to have one drafted for this project."
        )

    # -- safety ------------------------------------------------------------
    safety_raw = raw.get("safety") or {}
    if not isinstance(safety_raw, dict):
        raise ConfigError(f"{where}: `runtime.safety` must be a mapping")
    invariant_raw = safety_raw.get("test_data_invariant") or {}
    if not isinstance(invariant_raw, dict):
        raise ConfigError(f"{where}: `runtime.safety.test_data_invariant` must be a mapping")
    invariant = TestDataInvariantConfig(
        tables=[str(t) for t in (invariant_raw.get("tables") or [])],
        predicate=str(invariant_raw.get("predicate", "is_test_data = true")),
        limit=_positive_int(invariant_raw, "limit", 50, where),
    )
    if invariant.tables and not invariant.column:
        raise ConfigError(
            f"{where}: could not parse `test_data_invariant.predicate` "
            f"{invariant.predicate!r}. It must be `column = value` - the pre-flight "
            f"check is what keeps this tier away from real records, and a predicate "
            f"this engine cannot read is one it cannot enforce (DESIGN-V2 §6)."
        )
    cfg.safety = SafetyConfig(
        forbid_target_matching=[str(p) for p in (safety_raw.get("forbid_target_matching") or [])],
        test_data_invariant=invariant,
    )
    if cfg.enabled and not invariant.tables:
        warnings.append(
            f"{where}: `runtime.safety.test_data_invariant.tables` is empty, so the "
            f"pre-flight has nothing to verify. The tier will refuse to explore - "
            f"that guard is also the most valuable check it performs."
        )

    # -- personas ----------------------------------------------------------
    cfg.roles = [str(r) for r in (raw.get("roles") or [])]

    archetypes_raw = raw.get("archetypes", "all")
    from .tier3.archetypes import ARCHETYPE_NAMES  # local: avoids an import cycle

    if archetypes_raw in ("all", None, "", []):
        cfg.archetypes = list(ARCHETYPE_NAMES)
    elif isinstance(archetypes_raw, list):
        unknown = [a for a in archetypes_raw if str(a) not in ARCHETYPE_NAMES]
        if unknown:
            raise ConfigError(
                f"{where}: unknown archetype(s) {unknown}; available: "
                f"{', '.join(sorted(ARCHETYPE_NAMES))}"
            )
        cfg.archetypes = [str(a) for a in archetypes_raw]
    else:
        raise ConfigError(f"{where}: `runtime.archetypes` must be `all` or a list")

    personas_raw = raw.get("personas") or []
    if not isinstance(personas_raw, list):
        raise ConfigError(f"{where}: `runtime.personas` must be a list")
    pins: list[PersonaPin] = []
    for entry in personas_raw:
        if not isinstance(entry, dict) or not entry.get("role") or not entry.get("archetype"):
            raise ConfigError(
                f"{where}: each `runtime.personas` entry needs `role` and `archetype`, "
                f"got {entry!r}"
            )
        pins.append(
            PersonaPin(
                role=str(entry["role"]),
                archetype=str(entry["archetype"]),
                plausibility=str(entry.get("plausibility", "")),
            )
        )
    cfg.personas = pins
    cfg.auth_fingerprint = (
        str(raw["auth_fingerprint"]) if raw.get("auth_fingerprint") else None
    )

    # -- mutations and budgets --------------------------------------------
    mutations = str(raw.get("mutations", "off")).strip().lower()
    if mutations not in MUTATION_MODES:
        raise ConfigError(
            f"{where}: `runtime.mutations` must be one of {', '.join(MUTATION_MODES)}"
        )
    cfg.mutations = mutations

    cfg.request_budget = _positive_int(raw, "request_budget", cfg.request_budget, where)
    cfg.step_budget = _positive_int(raw, "step_budget", cfg.step_budget, where)
    cfg.explore_timeout_seconds = _positive_int(
        raw, "explore_timeout_seconds", cfg.explore_timeout_seconds, where
    )

    if cfg.auto:
        warnings.append(
            f"{where}: `runtime.auto` is on, so runtime review runs without the "
            f"`{cfg.label}` label. PR code will execute with a live session and no "
            f"per-PR human consent step (DESIGN-V2 §11)."
        )

    return cfg


def _positive_int(raw: dict[str, Any], key: str, default: int, where: str) -> int:
    if key not in raw:
        return default
    try:
        value = int(raw[key])
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{where}: `{key}` must be an integer") from exc
    if value <= 0:
        raise ConfigError(f"{where}: `{key}` must be positive, got {value}")
    return value
