"""Pack discovery, version resolution and applicability.

A pack contributes *both* halves (DESIGN s5): semgrep rules for the
deterministic tier and a briefing for the agent tier. Enabling the supabase
pack should give you the `using (true)` matcher *and* teach the agent what
Supabase RLS failure looks like. Loading them together, from one directory,
is what keeps that pairing from drifting apart.

Since DESIGN-V2 s3 a pack contributes a *third* thing: the list of external
tools it wants run. `adapters:` sits alongside `checks:` and is parsed the
same way, because it is the same kind of statement — "this pack asserts these
guarantees" — and whether the guarantee is enforced by engine code or by
`zizmor` is an implementation detail of the pack, not of the pin. It matters
that they share a manifest: a repo enabling the `github-actions` pack should
not have to also know, separately, that it needs to turn `zizmor` on.

Independent pack pinning (DESIGN s15 resolved) means the consuming repo pins
each pack separately. The engine ships one version of each pack per tag, so
resolution is an *assertion*: if the shipped pack does not satisfy the pin,
that is a hard error telling the user which engine tag they want. A warning
would be wrong here — running a rule set the repo did not pin is precisely
the silent-verdict-change problem that `@main` pinning was rejected over.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..adapters.base import AdapterSpec
from ..config import Config, PackPin
from ..models import Severity
from ..semver import InvalidSpec, InvalidVersion, Spec, Version

PACK_MANIFEST = "pack.yml"
BRIEFING_FILE = "briefing.md"
RULES_DIR = "rules"
CHECKS_FILE = "checks.yml"


class PackError(ValueError):
    pass


class PackVersionConflict(PackError):
    """The shipped pack does not satisfy the pin in `.pr-sentinel.yml`."""


@dataclass
class ScriptCheckSpec:
    """A pack enabling one of the engine's built-in graph/counting checks.

    Script checks are engine code, not pack data, because they need to count
    files and walk dependency trees (DESIGN s5: "semgrep is for code patterns,
    not for counting files"). The pack chooses which run and with what
    severity; it cannot supply the code.
    """

    check_id: str
    severity: str | None = None
    enabled: bool = True
    options: dict[str, Any] = field(default_factory=dict)


@dataclass
class Pack:
    name: str
    version: Version
    description: str
    path: Path
    briefing: str = ""
    rule_files: list[Path] = field(default_factory=list)
    script_checks: list[ScriptCheckSpec] = field(default_factory=list)
    #: External tools this pack wants run, normalised into our `Finding`
    #: model by `adapters/`. Parsed from `adapters:` in the manifest.
    adapters: list[AdapterSpec] = field(default_factory=list)
    #: Filename globs that make this pack relevant. Empty means "always".
    applies_to: list[str] = field(default_factory=list)
    requires_engine: str = "*"
    tags: list[str] = field(default_factory=list)
    #: Which agent passes this pack's briefing is relevant to. Keeping a
    #: supabase briefing out of the `parity` prompt is a real token saving.
    briefing_passes: list[str] = field(default_factory=list)
    pinned_as: str = "*"

    def applicable_to(self, paths: list[str]) -> bool:
        if not self.applies_to:
            return True
        from ..diff import path_ignored

        return any(path_ignored(p, self.applies_to) for p in paths)

    def __str__(self) -> str:
        return f"{self.name}@{self.version}"


def default_packs_dir() -> Path:
    """Where the engine's curated packs live.

    Resolved relative to the installed package so the engine works both from
    a git checkout and from a wheel, and overridable for tests.
    """
    override = os.environ.get("PR_SENTINEL_PACKS_DIR")
    if override:
        return Path(override)
    here = Path(__file__).resolve()
    # src/pr_sentinel/packs/loader.py -> repo root/packs
    for parent in here.parents:
        candidate = parent / "packs"
        if candidate.is_dir() and (candidate != here.parent):
            if any(child.joinpath(PACK_MANIFEST).is_file() for child in candidate.iterdir()
                   if child.is_dir()):
                return candidate
    return here.parent.parent.parent.parent / "packs"


def discover_packs(packs_dir: Path | str | None = None) -> dict[str, Pack]:
    root = Path(packs_dir) if packs_dir else default_packs_dir()
    found: dict[str, Pack] = {}
    if not root.is_dir():
        return found
    for child in sorted(root.iterdir()):
        if not child.is_dir() or not (child / PACK_MANIFEST).is_file():
            continue
        pack = load_pack(child)
        found[pack.name] = pack
    return found


def load_pack(path: Path | str) -> Pack:
    path = Path(path)
    manifest_path = path / PACK_MANIFEST
    try:
        raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise PackError(f"{manifest_path}: cannot read pack manifest: {exc}") from exc
    if not isinstance(raw, dict):
        raise PackError(f"{manifest_path}: pack manifest must be a mapping")

    name = str(raw.get("name") or path.name).strip()
    try:
        version = Version.parse(str(raw.get("version", "0.0.0")))
    except InvalidVersion as exc:
        raise PackError(f"{manifest_path}: {exc}") from exc

    briefing = ""
    briefing_path = path / BRIEFING_FILE
    if briefing_path.is_file():
        briefing = briefing_path.read_text(encoding="utf-8").strip()

    rules_dir = path / RULES_DIR
    rule_files = (
        sorted(p for p in rules_dir.rglob("*.y*ml") if p.is_file()) if rules_dir.is_dir() else []
    )

    script_checks: list[ScriptCheckSpec] = []
    for entry in _load_checks(path, raw):
        script_checks.append(entry)

    adapters = _load_adapters(path, name, raw)

    return Pack(
        name=name,
        version=version,
        description=str(raw.get("description", "")).strip(),
        path=path,
        briefing=briefing,
        rule_files=rule_files,
        script_checks=script_checks,
        adapters=adapters,
        applies_to=[str(x) for x in (raw.get("applies_to") or [])],
        requires_engine=str(raw.get("requires_engine", "*")),
        tags=[str(t) for t in (raw.get("tags") or [])],
        briefing_passes=[str(p) for p in (raw.get("briefing_passes") or [])],
    )


def _load_checks(path: Path, manifest: dict[str, Any]) -> list[ScriptCheckSpec]:
    entries: list[Any] = list(manifest.get("checks") or [])
    checks_path = path / CHECKS_FILE
    if checks_path.is_file():
        try:
            extra = yaml.safe_load(checks_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise PackError(f"{checks_path}: invalid YAML: {exc}") from exc
        if isinstance(extra, dict):
            entries.extend(extra.get("checks") or [])
        elif isinstance(extra, list):
            entries.extend(extra)

    specs: list[ScriptCheckSpec] = []
    for entry in entries:
        if isinstance(entry, str):
            specs.append(ScriptCheckSpec(check_id=entry))
            continue
        if not isinstance(entry, dict):
            raise PackError(f"{path}: check entry must be a string or mapping, got {entry!r}")
        check_id = entry.get("id") or entry.get("check")
        if not check_id:
            raise PackError(f"{path}: check entry missing `id`: {entry!r}")
        known = {"id", "check", "severity", "enabled", "options"}
        options = dict(entry.get("options") or {})
        for key, value in entry.items():
            if key not in known:
                options[key] = value
        specs.append(
            ScriptCheckSpec(
                check_id=str(check_id),
                severity=(str(entry["severity"]) if entry.get("severity") else None),
                enabled=bool(entry.get("enabled", True)),
                options=options,
            )
        )
    return specs


def _load_adapters(
    path: Path, pack_name: str, manifest: dict[str, Any]
) -> list[AdapterSpec]:
    """Parse `adapters:` into `AdapterSpec`, mirroring `_load_checks`.

    Deliberately the same shape as a check entry — a bare string for the
    common case, a mapping when the pack needs to say more — because a pack
    author should not have to learn a second syntax to turn on a tool.

    `severity_floor` / `severity_ceiling` are the one addition, and they are
    the reason an adapter entry is not just a string. A tool calibrates
    severity to its own audience: `zizmor` grades informational audits as
    `error`, which is right for a repo that has adopted its whole philosophy
    and wrong for one that has not. The pack narrows the range rather than
    the engine second-guessing the tool finding by finding, which would break
    the promise in `adapters/base.py` that we never rewrite their verdicts.

    An unparseable severity is a hard error rather than a warning. A pack that
    meant to cap `zizmor` at `medium` and typo'd it would otherwise ship
    blocking findings it intended to be advisory, and silence there is the
    silent-verdict-change failure this module exists to prevent.
    """
    entries: list[Any] = list(manifest.get("adapters") or [])
    specs: list[AdapterSpec] = []

    for entry in entries:
        if isinstance(entry, str):
            specs.append(AdapterSpec(adapter_id=entry, pack=pack_name))
            continue
        if not isinstance(entry, dict):
            raise PackError(
                f"{path}: adapter entry must be a string or mapping, got {entry!r}"
            )
        adapter_id = entry.get("id") or entry.get("adapter")
        if not adapter_id:
            raise PackError(f"{path}: adapter entry missing `id`: {entry!r}")

        known = {"id", "adapter", "severity_floor", "severity_ceiling", "enabled", "options"}
        options = dict(entry.get("options") or {})
        for key, value in entry.items():
            if key not in known:
                options[key] = value

        specs.append(
            AdapterSpec(
                adapter_id=str(adapter_id),
                pack=pack_name,
                severity_floor=_severity(path, adapter_id, entry, "severity_floor"),
                severity_ceiling=_severity(path, adapter_id, entry, "severity_ceiling"),
                options=options,
                enabled=bool(entry.get("enabled", True)),
            )
        )
    return specs


def _severity(
    path: Path, adapter_id: Any, entry: dict[str, Any], key: str
) -> Severity | None:
    raw = entry.get(key)
    if raw in (None, ""):
        return None
    try:
        return Severity.parse(str(raw))
    except ValueError as exc:
        raise PackError(f"{path}: adapter `{adapter_id}`: {key}: {exc}") from exc


def resolve_packs(
    config: Config,
    packs_dir: Path | str | None = None,
    engine_version: str | None = None,
) -> tuple[list[Pack], list[str]]:
    """Resolve the config's independent pins against the shipped packs.

    Returns (packs, warnings). Raises PackVersionConflict on a pin the engine
    cannot satisfy, and PackError on a pack that does not exist.
    """
    available = discover_packs(packs_dir)
    warnings: list[str] = []
    resolved: list[Pack] = []

    for pin in config.packs:
        pack = available.get(pin.name)
        if pack is None:
            known = ", ".join(sorted(available)) or "(none found)"
            raise PackError(
                f"unknown pack {pin.name!r}. Packs shipped by this engine version: {known}"
            )
        try:
            spec = Spec(pin.spec)
        except InvalidSpec as exc:
            raise PackError(f"pack {pin.name!r}: {exc}") from exc

        if not spec.matches(pack.version):
            raise PackVersionConflict(
                f"pack pin not satisfiable: {pin.name}@{pin.spec} was requested, but this "
                f"engine ships {pin.name}@{pack.version}.\n"
                f"  Pin an engine tag that ships a matching {pin.name}, or relax the pin in "
                f".pr-sentinel.yml.\n"
                f"  Packs are pinned independently, so changing this pin does not affect "
                f"your other packs."
            )
        if spec.is_any:
            warnings.append(
                f"pack {pin.name!r} is unpinned; it will follow whatever the engine tag "
                f"ships (currently {pack.version}). Pin it as "
                f"`{pin.name}@^{pack.version.major}.{pack.version.minor}` for reproducible "
                f"verdicts."
            )

        if engine_version and pack.requires_engine not in ("", "*"):
            try:
                if not Spec(pack.requires_engine).matches(Version.parse(engine_version)):
                    raise PackVersionConflict(
                        f"pack {pack} requires engine {pack.requires_engine}, "
                        f"but this engine is {engine_version}"
                    )
            except (InvalidSpec, InvalidVersion) as exc:
                warnings.append(f"pack {pack.name}: could not check requires_engine: {exc}")

        pack.pinned_as = pin.spec
        resolved.append(pack)

    return resolved, warnings


def compose_briefing(packs: list[Pack], pass_name: str, lore: str | None = None) -> str:
    """Assemble the knowledge context for one agent pass.

    Pack briefings are general ("this is what Supabase RLS failure looks
    like"); lore is repo-specific ("in *this* repo student accounts share the
    staff domain, so bare `authenticated` authorises every student"). Lore
    goes last because when the two conflict, the local fact wins.
    """
    sections: list[str] = []
    for pack in packs:
        if not pack.briefing:
            continue
        if pack.briefing_passes and pass_name not in pack.briefing_passes:
            continue
        sections.append(f"### Pack: {pack.name} (v{pack.version})\n\n{pack.briefing}")
    if lore and lore.strip():
        sections.append(
            "### Repository lore\n\n"
            "Expensive mistakes this specific codebase has already made. These are "
            "facts about this repo, and where they conflict with the general pack "
            "guidance above, these win.\n\n" + lore.strip()
        )
    return "\n\n---\n\n".join(sections)


def load_lore(repo_root: Path, config: Config) -> str | None:
    if not config.lore_path:
        return None
    path = repo_root / config.lore_path
    if not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None
