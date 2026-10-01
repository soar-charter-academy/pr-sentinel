"""Shared fixture helpers for the pr-sentinel test suite.

Three constraints shaped everything in here, and they are the same three that
apply to the engine itself:

* **No network, no semgrep, no API key.** Anything that would need one is
  either exercised through a recorded payload or through
  `pr_sentinel.tier2.provider.ScriptedProvider`.
* **Nothing outside a temporary directory.** A test that leaves state behind
  is a test that passes for the wrong reason the second time it runs.
* **Real objects wherever possible.** The helpers build genuine `Config`,
  `Diff` and `ReviewContext` values rather than mocks, so a test that passes
  is evidence about the engine and not about the double.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any, Iterable

from pr_sentinel.config import Config, MODE_PRESETS, PackPin
from pr_sentinel.context import PullRequest, ReviewContext, UntrustedText
from pr_sentinel.diff import Diff, parse_unified_diff
from pr_sentinel.models import (
    Engine,
    Finding,
    Location,
    Provenance,
    Severity,
    Tier,
)
from pr_sentinel.tier2.provider import Completion, ModelError, ScriptedProvider

#: The engine checkout. `packs/` under it is the real curated pack directory,
#: used deliberately: pack resolution tested against a synthetic fixture would
#: not notice the day a shipped pack.yml stops parsing.
REPO_ROOT = Path(__file__).resolve().parents[1]
PACKS_DIR = REPO_ROOT / "packs"


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------


def make_config(
    mode: str = "gated",
    packs: Iterable[str | PackPin] = ("core",),
    *,
    authority: dict[Severity, Any] | None = None,
    **overrides: Any,
) -> Config:
    """A `Config` as `parse_config` would have produced it.

    Built through the same `MODE_PRESETS` expansion the parser uses, so a test
    using this helper is not quietly asserting against a second, divergent
    notion of what `gated` means.
    """
    cfg = Config(
        packs=[p if isinstance(p, PackPin) else PackPin.parse(str(p)) for p in packs],
        mode=mode,
        authority=dict(authority if authority is not None else MODE_PRESETS[mode]),
    )
    for key, value in overrides.items():
        setattr(cfg, key, value)
    return cfg


# ---------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------


_TIER_FOR_ENGINE = {
    Engine.PROJECT_CHECK: Tier.PROJECT,
    Engine.SEMGREP: Tier.DETERMINISTIC,
    Engine.SCRIPT: Tier.DETERMINISTIC,
    Engine.AGENT: Tier.AGENT,
}


def make_finding(
    rule_id: str = "core.example",
    severity: Severity | str = Severity.MEDIUM,
    *,
    engine: Engine = Engine.SCRIPT,
    tier: Tier | None = None,
    path: str | None = "src/app.ts",
    line: int | None = 12,
    title: str | None = None,
    message: str = "Something a human may need to look at.",
    rationale: str = "Stated so the finding is not suppressed on sight.",
    pack: str = "core",
    **kwargs: Any,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=title or f"{rule_id} fired",
        message=message,
        rationale=rationale,
        pack=pack,
        tier=tier if tier is not None else _TIER_FOR_ENGINE[engine],
        engine=engine,
        location=Location(path=path, line=line) if path else None,
        **kwargs,
    )


def make_provenance(**kwargs: Any) -> Provenance:
    defaults: dict[str, Any] = {"engine_version": "0.1.0"}
    defaults.update(kwargs)
    return Provenance(**defaults)


# ---------------------------------------------------------------------------
# filesystem / git
# ---------------------------------------------------------------------------


def write_tree(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        target = Path(root) / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def git(root: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(root),
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout


def git_init(root: Path) -> None:
    git(root, "init", "-q", ".")
    git(root, "config", "user.email", "test@example.invalid")
    git(root, "config", "user.name", "pr-sentinel tests")
    git(root, "config", "commit.gpgsign", "false")


def git_commit_all(root: Path, message: str) -> str:
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", message)
    return git(root, "rev-parse", "HEAD").strip()


class TempDirTestCase(unittest.TestCase):
    """Base class giving each test its own throwaway directory."""

    def setUp(self) -> None:
        super().setUp()
        self._tmp = tempfile.mkdtemp(prefix="pr-sentinel-test-")
        self.tmp = Path(self._tmp)
        self.addCleanup(shutil.rmtree, self._tmp, True)

    def make_repo(self, files: dict[str, str] | None = None) -> Path:
        root = self.tmp / "repo"
        root.mkdir(parents=True, exist_ok=True)
        if files:
            write_tree(root, files)
        return root


# ---------------------------------------------------------------------------
# review context
# ---------------------------------------------------------------------------


def make_pr(**kwargs: Any) -> PullRequest:
    title = kwargs.pop("title", "Add a thing")
    body = kwargs.pop("body", "It adds the thing.")
    return PullRequest(
        number=kwargs.pop("number", 7),
        title=UntrustedText(title, "pr-title"),
        body=UntrustedText(body, "pr-body"),
        **kwargs,
    )


def make_context(
    repo_root: Path,
    diff: Diff | None = None,
    *,
    config: Config | None = None,
    packs: Iterable[Any] = (),
    pr: PullRequest | None = None,
    lore: str | None = None,
    head_ref: str = "HEAD",
) -> ReviewContext:
    return ReviewContext(
        repo_root=Path(repo_root),
        config=config or make_config(),
        diff=diff if diff is not None else Diff(),
        pr=pr or make_pr(),
        packs=list(packs),
        lore=lore,
        head_ref=head_ref,
    )


def diff_of(text: str) -> Diff:
    """Parse a literal unified diff. Trims a leading newline so tests can use
    triple-quoted strings that start on their own line."""
    return parse_unified_diff(text.lstrip("\n"))


def synthetic_diff(files: dict[str, list[tuple[int, str]]]) -> Diff:
    """Build a `Diff` directly from `{path: [(head_line, text), ...]}`.

    Some tests care only about "this PR added these lines at these numbers"
    and rendering a whole unified diff to express that adds noise without
    adding coverage.
    """
    from pr_sentinel.diff import ChangedFile, ChangeKind, Hunk

    out = []
    for path, added in files.items():
        hunk = Hunk(
            old_start=added[0][0] if added else 1,
            old_count=0,
            new_start=added[0][0] if added else 1,
            new_count=len(added),
            added_lines=list(added),
        )
        out.append(ChangedFile(path=path, kind=ChangeKind.MODIFIED, hunks=[hunk]))
    return Diff(out)


# ---------------------------------------------------------------------------
# model providers
# ---------------------------------------------------------------------------

#: System-prompt fragments unique to each kind of call, so a scripted
#: response can be routed without reproducing a whole prompt.
TRIAGE_NEEDLE = "You are the triage step"
VERIFY_NEEDLE = "You are the verification step"


def pass_needle(name: str) -> str:
    return f"## Your concern: {name}"


def scripted(*pairs: tuple[str, str], default: str = "") -> ScriptedProvider:
    return ScriptedProvider(list(pairs), default=default)


class FailingProvider(ScriptedProvider):
    """A `ScriptedProvider` whose matching calls raise `ModelError`.

    Needed for exactly one claim, which cannot be made any other way: that a
    model call that *fails* drops the finding rather than letting it through.
    Fail-open there would silently disable verification on a flaky API day.
    """

    def __init__(
        self,
        fail_on: str,
        responses: list[tuple[str, str]] | None = None,
        default: str = "",
    ) -> None:
        super().__init__(responses, default=default)
        self._fail_on = fail_on

    def complete(self, *, system: str, prompt: str, model: str, **kwargs: Any) -> Completion:
        if self._fail_on in system or self._fail_on in prompt:
            self.prompts.append((model, prompt))
            raise ModelError("connection reset by peer")
        return super().complete(system=system, prompt=prompt, model=model, **kwargs)


def json_response(payload: str) -> str:
    """Wrap a JSON body in a fenced block, the way a model tends to."""
    return "Here you go:\n\n```json\n" + payload.strip() + "\n```\n"
