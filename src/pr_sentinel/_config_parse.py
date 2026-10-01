"""Config parsing, split out from `config.py`.

The dataclasses live in `config.py`; the parsing lives here. The split is not
aesthetic — `config.py` had grown to hold both the Tier 0/2/3 schema *and*
several hundred lines of validation, and the validation is the part that
changes every time a tier gains an option.

`config.py` re-exports `parse_config` from here at the bottom of the module,
after its dataclasses exist, so `from pr_sentinel.config import parse_config`
keeps working.

The validation is strict in one particular direction: every mistake that
would cause a tier to run with *less* protection than the author intended is
a hard error rather than a warning. An unknown archetype silently reduces
coverage; an unparseable invariant predicate silently disarms the §6
pre-flight. Both fail at parse time, where the file name is still known.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import (
    DEFAULT_AGENT_PASSES,
    DEFAULT_IGNORE_PATHS,
    DEFAULT_MODE,
    MODE_PRESETS,
    MUTATION_MODES,
    SUPPORTED_CONFIG_VERSIONS,
    AgentConfig,
    BootConfig,
    Config,
    ConfigError,
    IgnoreConfig,
    PackPin,
    PersonaPin,
    ReadyConfig,
    RuntimeConfig,
    SafetyConfig,
    TestDataInvariantConfig,
    Tier0Config,
)
from .models import Authority, Severity


def parse_config(raw: dict[str, Any], source_path: Path | None = None) -> Config:
    where = str(source_path) if source_path else "<config>"
    warnings: list[str] = []

    version = raw.get("version", 1)
    if version not in SUPPORTED_CONFIG_VERSIONS:
        raise ConfigError(
            f"{where}: unsupported config version {version!r}; "
            f"this engine understands {SUPPORTED_CONFIG_VERSIONS}"
        )

    known = {
        "version", "packs", "lore", "local_rules", "mode", "authority",
        "agent", "ignore", "tier0", "runtime",
    }
    for key in raw:
        if key not in known:
            warnings.append(f"{where}: unknown top-level key {key!r} (ignored)")

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

    agent = _parse_agent(raw.get("agent") or {}, where, warnings)

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


def _parse_agent(raw: dict[str, Any], where: str, warnings: list[str]) -> AgentConfig:
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: `agent` must be a mapping")
    agent = AgentConfig()
    agent.enabled = bool(raw.get("enabled", True))

    if "passes" in raw:
        passes = raw["passes"]
        if not isinstance(passes, list):
            raise ConfigError(f"{where}: `agent.passes` must be a list")
        unknown = [p for p in passes if p not in DEFAULT_AGENT_PASSES]
        if unknown:
            raise ConfigError(
                f"{where}: unknown agent pass(es) {unknown}; "
                f"available: {', '.join(DEFAULT_AGENT_PASSES)}"
            )
        agent.passes = [str(p) for p in passes]

    agent.max_findings = _positive_int(raw, "max_findings", agent.max_findings, where)
    agent.skip_draft_prs = bool(raw.get("skip_draft_prs", agent.skip_draft_prs))
    agent.triage_model = str(raw.get("triage_model", agent.triage_model))
    agent.review_model = str(raw.get("review_model", agent.review_model))
    agent.max_files_reviewed = _positive_int(
        raw, "max_files_reviewed", agent.max_files_reviewed, where
    )
    agent.max_file_bytes = _positive_int(raw, "max_file_bytes", agent.max_file_bytes, where)
    agent.verification = bool(raw.get("verification", True))
    if not agent.verification:
        warnings.append(
            f"{where}: agent.verification is disabled. Unverified findings will be "
            "emitted as-is; expect noise (DESIGN s3)."
        )

    # Tools (DESIGN-V2 §4).
    agent.tools_enabled = bool(raw.get("tools_enabled", agent.tools_enabled))
    agent.tool_budget = _positive_int(raw, "tool_budget", agent.tool_budget, where)
    agent.tool_timeout_seconds = _positive_int(
        raw, "tool_timeout_seconds", agent.tool_timeout_seconds, where
    )
    agent.allow_network_tools = bool(
        raw.get("allow_network_tools", agent.allow_network_tools)
    )
    if not agent.tools_enabled:
        warnings.append(
            f"{where}: agent.tools_enabled is false. Passes see only the diff, so a "
            "guard clause just outside a hunk is invisible to them - the commonest "
            "reason a finding is wrong (DESIGN-V2 §4)."
        )
    if agent.allow_network_tools:
        warnings.append(
            f"{where}: agent.allow_network_tools is on. A job holding credentials may "
            "now make outbound requests under model direction; the allowlist confines "
            "it to advisory endpoints."
        )
    return agent


def _parse_runtime(raw: dict[str, Any], where: str, warnings: list[str]) -> RuntimeConfig:
    """Parse the Tier 3 block (DESIGN-V2 §7)."""
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
            f"`.env` is never read - on this project it points at production, and a "
            f"browsing agent pointed at production is the harm this tier exists to "
            f"prevent (DESIGN-V2 §6)."
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
        raise ConfigError(
            f"{where}: `runtime.boot.command` is required when runtime is enabled"
        )
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
        raise ConfigError(
            f"{where}: `runtime.safety.test_data_invariant` must be a mapping"
        )
    invariant = TestDataInvariantConfig(
        tables=[str(t) for t in (invariant_raw.get("tables") or [])],
        predicate=str(invariant_raw.get("predicate", "is_test_data = true")),
        limit=_positive_int(invariant_raw, "limit", 50, where),
    )
    if invariant.tables and not invariant.column:
        raise ConfigError(
            f"{where}: could not parse `test_data_invariant.predicate` "
            f"{invariant.predicate!r}. It must be `column = value` - the pre-flight is "
            f"what keeps this tier away from real records, and a predicate the engine "
            f"cannot read is one it cannot enforce (DESIGN-V2 §6)."
        )
    cfg.safety = SafetyConfig(
        forbid_target_matching=[
            str(p) for p in (safety_raw.get("forbid_target_matching") or [])
        ],
        test_data_invariant=invariant,
    )
    if cfg.enabled and not invariant.tables:
        warnings.append(
            f"{where}: `runtime.safety.test_data_invariant.tables` is empty, so the "
            f"pre-flight has nothing to verify and the tier will refuse to explore. "
            f"That guard is also the most valuable check it performs (DESIGN-V2 §6)."
        )

    # -- personas ----------------------------------------------------------
    cfg.roles = [str(r) for r in (raw.get("roles") or [])]

    from .tier3.archetypes import ARCHETYPE_NAMES

    archetypes_raw = raw.get("archetypes", "all")
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
