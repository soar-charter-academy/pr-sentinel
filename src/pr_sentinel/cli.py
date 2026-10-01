"""The `sentinel` command line.

    sentinel review    run a review against a checkout
    sentinel validate  check config, pack pins and local rules without running
    sentinel packs     list what this engine ships
    sentinel checks    list the deterministic script checks
    sentinel learn     propose a lore entry and rule from a fixing commit

`review` writes nothing unless `--publish` is passed. That default matters:
it means anyone can run the exact review their CI will run, against their own
checkout, before pushing — and can do it without credentials. A review engine
you cannot run locally is one whose findings arrive as surprises.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .config import ConfigError, load_config
from .context import PullRequest
from .diff import DiffError
from .models import Severity
from .packs.loader import PackError, discover_packs, resolve_packs
from .policy import CHECK_NAME_COMBINED, CHECK_NAME_DETERMINISTIC, check_run_output
from .render.comment import MARKER, render_comment
from .run import review as run_review
from .tier1.engine import adapter_specs, available_checks, packs_missing_checks

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_BLOCKED = 2
EXIT_ERROR = 3


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_ERROR
    try:
        return args.handler(args)
    except (ConfigError, PackError, DiffError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        return EXIT_ERROR


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="An independent PR reviewer: deterministic guarantees plus judgment.",
    )
    parser.add_argument("--version", action="version", version=f"pr-sentinel {__version__}")
    sub = parser.add_subparsers(dest="command")

    # -- review -----------------------------------------------------------
    p_review = sub.add_parser("review", help="review a pull request or a diff")
    p_review.add_argument("--repo", default=".", help="path to the checkout (default: .)")
    p_review.add_argument("--base", default=None, help="base ref (default: from event, or main)")
    p_review.add_argument("--head", default="HEAD", help="head ref (default: HEAD)")
    p_review.add_argument("--config", default=None, help="path to .pr-sentinel.yml")
    p_review.add_argument("--packs-dir", default=None, help="override the pack directory")
    p_review.add_argument("--no-tier0", action="store_true", help="skip project checks")
    p_review.add_argument("--no-agent", action="store_true", help="skip the agent tier")
    p_review.add_argument(
        "--publish",
        action="store_true",
        help="write the comment and check-runs to GitHub (needs GITHUB_TOKEN)",
    )
    p_review.add_argument("--format", choices=("markdown", "json"), default="markdown")
    p_review.add_argument("--output", default=None, help="write the comment to a file")
    p_review.add_argument(
        "--strict",
        action="store_true",
        help="exit non-zero if any part of the deterministic tier did not run",
    )
    p_review.add_argument(
        "--fail-on",
        default=None,
        choices=[s.value for s in Severity],
        help="exit non-zero at or above this severity, regardless of mode",
    )
    p_review.set_defaults(handler=_cmd_review)

    # -- validate ---------------------------------------------------------
    p_validate = sub.add_parser(
        "validate", help="check config, pack pins and local rules without reviewing"
    )
    p_validate.add_argument("--repo", default=".")
    p_validate.add_argument("--config", default=None)
    p_validate.add_argument("--packs-dir", default=None)
    p_validate.set_defaults(handler=_cmd_validate)

    # -- packs ------------------------------------------------------------
    p_packs = sub.add_parser("packs", help="list the packs this engine ships")
    p_packs.add_argument("--packs-dir", default=None)
    p_packs.add_argument("--json", action="store_true")
    p_packs.set_defaults(handler=_cmd_packs)

    # -- checks -----------------------------------------------------------
    p_checks = sub.add_parser("checks", help="list the deterministic script checks")
    p_checks.add_argument("--json", action="store_true")
    p_checks.set_defaults(handler=_cmd_checks)

    # -- learn ------------------------------------------------------------
    p_learn = sub.add_parser(
        "learn", help="propose a lore entry and candidate rule from a fixing commit"
    )
    p_learn.add_argument("commit", help="the commit that fixed the bug")
    p_learn.add_argument("--repo", default=".")
    p_learn.add_argument("--model", default="claude-sonnet-5-5")
    p_learn.add_argument(
        "--write",
        default=None,
        help="write the proposal to this file instead of stdout",
    )
    p_learn.add_argument(
        "--append-lore",
        default=None,
        help="append the proposed lore entry to this file (you still commit it)",
    )
    p_learn.set_defaults(handler=_cmd_learn)

    return parser


# ---------------------------------------------------------------------------
# review
# ---------------------------------------------------------------------------


def _cmd_review(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    pr = PullRequest.from_env()
    base = args.base or (pr.base_ref if pr else "main")
    head = args.head if args.head != "HEAD" else (pr.head_sha if pr and pr.head_sha else "HEAD")

    provider = None
    if not args.no_agent:
        provider = _make_provider()

    result = run_review(
        repo,
        base=base,
        head=head,
        config_path=args.config,
        packs_dir=args.packs_dir,
        pr=pr,
        provider=provider,
        run_tier0_checks=not args.no_tier0,
        run_agent=not args.no_agent,
    )

    if args.format == "json":
        payload = result.verdict.to_dict()
        payload["auto_merge"] = {
            "safe": result.recommendation.safe,
            "reasons": result.recommendation.reasons,
        }
        payload["degraded"] = result.degraded_notes
        print(json.dumps(payload, indent=2))
    else:
        body = render_comment(
            result.verdict,
            result.recommendation,
            degraded_notes=result.degraded_notes,
            dropped_count=result.dropped_count,
        )
        if args.output:
            Path(args.output).write_text(body, encoding="utf-8")
            print(f"wrote {args.output}")
        else:
            print(body)

    if args.publish:
        _publish(result, pr)

    return _exit_code(result, args)


def _exit_code(result, args: argparse.Namespace) -> int:
    if args.strict and result.degraded_notes:
        print(
            "error: part of the deterministic tier did not run and --strict was given",
            file=sys.stderr,
        )
        return EXIT_ERROR
    if args.fail_on:
        threshold = Severity.parse(args.fail_on)
        if any(f.severity.rank >= threshold.rank for f in result.verdict.findings):
            return EXIT_BLOCKED
    if result.verdict.should_fail_check:
        return EXIT_BLOCKED
    if result.verdict.findings:
        return EXIT_FINDINGS
    return EXIT_OK


def _publish(result, pr: PullRequest | None) -> None:
    from .gh.client import GitHubClient, GitHubError

    client = GitHubClient.from_env()
    if client is None:
        print(
            "warning: --publish given but GITHUB_TOKEN/GITHUB_REPOSITORY are not set; "
            "nothing was published",
            file=sys.stderr,
        )
        return
    if pr is None or pr.number is None:
        print("warning: --publish given but no pull request context was found", file=sys.stderr)
        return

    body = render_comment(
        result.verdict,
        result.recommendation,
        degraded_notes=result.degraded_notes,
        dropped_count=result.dropped_count,
    )
    try:
        client.upsert_comment(pr.number, body, MARKER)
    except GitHubError as exc:
        print(f"error: could not write the review comment: {exc}", file=sys.stderr)

    if not pr.head_sha:
        return

    outputs = check_run_output(result.verdict, result.recommendation)
    for name, conclusion in (
        (CHECK_NAME_COMBINED, result.verdict.conclusion),
        (CHECK_NAME_DETERMINISTIC, result.recommendation.conclusion),
    ):
        out = outputs[name]
        client.create_check_run(
            name=name,
            head_sha=pr.head_sha,
            conclusion=conclusion,
            title=out["title"],
            summary=out["summary"],
            details_url=result.verdict.provenance.run_url,
        )


def _make_provider():
    from .tier2.provider import AnthropicProvider, NoCredentials

    try:
        return AnthropicProvider()
    except NoCredentials as exc:
        print(f"note: {exc}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------


def _cmd_validate(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    problems: list[str] = []
    notes: list[str] = []

    cfg = load_config(repo, args.config)
    notes.extend(cfg.warnings)
    print(f"config: {cfg.source_path or '(defaults)'}")
    print(f"mode:   {cfg.mode}")
    print("authority:")
    for severity in Severity:
        print(f"  {severity.value:<9} -> {cfg.authority_for(severity).value}")

    packs, warnings = resolve_packs(cfg, args.packs_dir, engine_version=__version__)
    notes.extend(warnings)
    print("\npacks:")
    for pack in packs:
        print(
            f"  {pack.name:<16} {pack.version}  (pinned `{pack.pinned_as}`)  "
            f"{len(pack.rule_files)} rule file(s), {len(pack.script_checks)} check(s), "
            f"{len(pack.adapters)} adapter(s)"
        )
        if not pack.briefing:
            problems.append(
                f"pack {pack.name} has no briefing.md, so it contributes rules but "
                "teaches the agent tier nothing. A pack is supposed to be both halves."
            )

    missing = packs_missing_checks(packs)
    for entry in missing:
        problems.append(f"enabled check not implemented by this engine: {entry}")

    problems.extend(_report_adapters(packs, notes))

    # Local rules, validated exactly as a real run would.
    import tempfile

    from .tier1.local_rules import load_local_rules

    with tempfile.TemporaryDirectory() as staging:
        local = load_local_rules(repo, cfg.local_rules_path, staging_dir=Path(staging))
    print(f"\nlocal rules: {len(local.rule_ids)} accepted")
    for rule_id in local.rule_ids:
        print(f"  {rule_id}")
    problems.extend(local.rejections)
    notes.extend(local.adjustments)

    if cfg.lore_path:
        lore = repo / cfg.lore_path
        print(f"\nlore: {cfg.lore_path} " + ("found" if lore.is_file() else "NOT FOUND"))
        if not lore.is_file():
            problems.append(
                f"lore file `{cfg.lore_path}` is configured but missing. The `lore` "
                "pass will have nothing to check against."
            )

    from .tier1.semgrep_runner import semgrep_version

    version = semgrep_version()
    print(f"\nsemgrep: {version or 'NOT INSTALLED'}")
    if not version:
        problems.append(
            "semgrep is not installed. The deterministic rule tier will not run, so "
            "critical guarantees will not be enforced."
        )

    if notes:
        print("\nnotes:")
        for note in notes:
            print(f"  - {note}")

    if problems:
        print("\nproblems:")
        for problem in problems:
            print(f"  - {problem}")
        return EXIT_FINDINGS

    print("\nok")
    return EXIT_OK


def _report_adapters(packs, notes: list[str]) -> list[str]:
    """Which external tools the enabled packs want, and which are installed.

    This is the question `sentinel validate` exists to answer for the adapter
    layer, and answering it badly would undo the layer's whole premise. Since
    DESIGN-V2 s3 most of the deterministic tier is other people's tools, so
    "is my configuration valid" now largely means "is `zizmor` on this
    machine". A `validate` that printed `ok` while `gitleaks` was absent
    would be telling a user their secret scanning is configured when nothing
    is going to read the diff for credentials.

    Three outcomes, and they are deliberately not graded the same way:

    * **installed** — printed with the version, because that is what gets
      recorded in provenance and what a reader will want when a finding moves.
    * **required and absent** — a problem. `validate` exits non-zero. The
      install hint is printed, because the useful output of a failed
      validation is the command that fixes it.
    * **optional and absent** — a note. Coverage lost, no guarantee lost, and
      `validate` still exits zero. Promoting this to a problem would mean
      nobody could get a green `validate` without a Socket API key and a
      reachable Postgres, and a check that cannot pass is a check people stop
      running.
    """
    from .adapters import all_adapters, get, missing_required_adapters, tool_version, which

    specs = adapter_specs(packs)
    problems: list[str] = []

    print("\nadapters:")
    if not specs:
        print("  (none enabled by the resolved packs)")

    for entry in missing_required_adapters(specs):
        problems.append(
            f"pack enables unknown adapter `{entry}`. This engine does not implement "
            f"it, so that tool is NOT running. Check your pack pin."
        )

    seen: set[str] = set()
    for spec in specs:
        if spec.adapter_id in seen:
            continue
        seen.add(spec.adapter_id)

        registered = get(spec.adapter_id)
        if registered is None:
            print(f"  {spec.adapter_id:<20} UNKNOWN TO THIS ENGINE  (pack {spec.pack})")
            continue

        label = "required" if registered.required else "optional"
        if not spec.enabled:
            print(f"  {spec.adapter_id:<20} disabled by pack {spec.pack}")
            notes.append(
                f"adapter `{spec.adapter_id}` is switched off by pack {spec.pack}, so "
                f"`{registered.tool}` is not running even though it is installed."
            )
            continue

        binary = which(registered.tool)
        if binary:
            version = tool_version(binary) or "version unknown"
            print(f"  {spec.adapter_id:<20} {version}  ({label})")
            continue

        print(f"  {spec.adapter_id:<20} NOT INSTALLED  ({label})")
        message = (
            f"`{registered.tool}` is not installed, so the checks `{spec.adapter_id}` "
            f"provides will NOT run. {registered.install_hint}".strip()
        )
        if registered.required:
            problems.append(
                message
                + " This adapter is REQUIRED: while it is absent, reviews will "
                "withhold `pr-sentinel/deterministic` rather than report a clean run."
            )
        else:
            notes.append(message)

    # Adapters this engine has that nothing enabled. Worth one line: the
    # commonest reason a tool is not running is that no pack asked for it,
    # and that is invisible from the output above.
    unused = sorted(set(all_adapters()) - seen)
    if unused:
        print(
            "  (available but not enabled by any resolved pack: "
            + ", ".join(unused)
            + ")"
        )

    return problems


# ---------------------------------------------------------------------------
# packs / checks
# ---------------------------------------------------------------------------


def _cmd_packs(args: argparse.Namespace) -> int:
    packs = discover_packs(args.packs_dir)
    if args.json:
        print(
            json.dumps(
                {
                    name: {
                        "version": str(pack.version),
                        "description": pack.description,
                        "rules": len(pack.rule_files),
                        "checks": [c.check_id for c in pack.script_checks],
                        "adapters": [a.adapter_id for a in pack.adapters],
                        "briefing_passes": pack.briefing_passes,
                    }
                    for name, pack in sorted(packs.items())
                },
                indent=2,
            )
        )
        return EXIT_OK

    if not packs:
        print("no packs found", file=sys.stderr)
        return EXIT_ERROR
    for name, pack in sorted(packs.items()):
        print(f"{name}@{pack.version}")
        print(f"  {pack.description}")
        print(
            f"  {len(pack.rule_files)} semgrep rule file(s), "
            f"{len(pack.script_checks)} script check(s), "
            f"{len(pack.adapters)} adapter(s)"
        )
        if pack.adapters:
            print(f"  adapters: {', '.join(a.adapter_id for a in pack.adapters)}")
        print(f"  pin as: {name}@^{pack.version.major}.{pack.version.minor}")
        print()
    return EXIT_OK


def _cmd_checks(args: argparse.Namespace) -> int:
    checks = available_checks()
    if args.json:
        print(
            json.dumps(
                {
                    cid: {
                        "severity": c.default_severity.value,
                        "title": c.title,
                        "reads_whole_repo": c.reads_whole_repo,
                    }
                    for cid, c in sorted(checks.items())
                },
                indent=2,
            )
        )
        return EXIT_OK
    for cid, check in sorted(checks.items()):
        print(f"{cid:<44} {check.default_severity.value:<9} {check.title}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# learn
# ---------------------------------------------------------------------------


def _cmd_learn(args: argparse.Namespace) -> int:
    from .learn import append_lore, learn_from_commit

    provider = _make_provider()
    if provider is None:
        print("error: `sentinel learn` needs ANTHROPIC_API_KEY", file=sys.stderr)
        return EXIT_ERROR

    proposal = learn_from_commit(
        Path(args.repo).resolve(), args.commit, provider, model=args.model
    )
    rendered = proposal.render()

    if args.write:
        Path(args.write).write_text(rendered, encoding="utf-8")
        print(f"wrote {args.write}")
    else:
        print(rendered)

    if args.append_lore and proposal.lore_entry.strip():
        append_lore(Path(args.append_lore), proposal.lore_entry)
        print(f"\nappended the lore entry to {args.append_lore} — review it before committing.")

    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
