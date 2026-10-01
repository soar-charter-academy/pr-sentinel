"""Supabase's own database advisors, instead of our three imitations of them.

DESIGN-V2 §3. v1 implemented `rls-enabled-no-policy`, `security-definer-view`
and `mutable-search-path` by reading migration text. All three are
*published Supabase lints* — `0008_rls_enabled_no_policy`,
`0010_security_definer_view`, `0011_function_search_path_mutable` — and
Supabase runs them against the live schema rather than against the diff. That
difference is the whole argument: a policy added in migration 42 and dropped
in migration 57 reads as present in the text and is absent in the database,
and only the database knows which.

So this adapter shells out to `supabase db lint`, which executes the lint set
server-side and reports what is actually true of the schema. Those three
checks of ours are deleted. The ones we keep — `migration-numbering`,
`migration-immutability`, `missing-grants` — are facts about how this team
branches and about soar's `service_role` lore, which no upstream linter
knows.

`required=False`, and the honesty matters more here than anywhere else in
the layer. This adapter needs a reachable Postgres. A PR runner on a fork,
or any runner without `--linked` credentials or a `db_url`, cannot provide
one, and that is the normal case rather than a misconfiguration. If it were
`required=True` the deterministic status would be withheld on most PRs and
people would turn it off. So when it cannot connect, it says in plain words
that the advisors **did not run** and that nothing here should be read as the
schema having passed them — the one sentence that stops a degraded run from
being mistaken for a clean one.

**Findings carry no file location, deliberately.** An advisor reports a
database object (`public.students`, `public.award_points()`), not a line of
SQL. We attribute to a changed migration only when exactly one changed file
mentions that object by name, and mark the attribution as inferred. Guessing
a line number for a finding that came from `pg_catalog` would be inventing
evidence.
"""

from __future__ import annotations

import json
import re
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

ADAPTER_ID = "supabase-advisors"

SQL_GLOBS = ["supabase/migrations/*.sql", "*.sql"]

DOCS = "https://supabase.com/docs/guides/database/database-linter"

#: Supabase's advisor levels, as emitted in its lint output.
_LEVELS = {
    "error": Severity.HIGH,
    "warn": Severity.MEDIUM,
    "warning": Severity.MEDIUM,
    "info": Severity.LOW,
    "note": Severity.LOW,
}

#: The published lint catalogue, keyed by Supabase's own numbered name. The
#: `description` strings are transcribed from Supabase's database-linter
#: documentation — they are the upstream rationale, not ours. The table exists
#: because `supabase db lint` does not always echo the description back in its
#: JSON, and a finding whose reason we cannot state gets suppressed by policy
#: (DESIGN §7). Anything not in this table still reports, with a rationale
#: that admits the reason is missing.
KNOWN_LINTS: dict[str, tuple[str, str, str]] = {
    # name: (category, title, upstream description)
    "0001_unindexed_foreign_keys": (
        "PERFORMANCE",
        "Unindexed foreign keys",
        "Identifies foreign key constraints without a covering index. An "
        "unindexed foreign key makes joins and cascading deletes scan the "
        "referencing table.",
    ),
    "0002_auth_users_exposed": (
        "SECURITY",
        "Exposed auth.users",
        "Detects views or tables in an API-exposed schema that expose "
        "`auth.users` data to anonymous or authenticated roles.",
    ),
    "0003_auth_rls_initplan": (
        "PERFORMANCE",
        "Auth RLS initialisation plan",
        "Detects row-level security policies that re-evaluate `auth.<fn>()` "
        "or `current_setting()` for every row. Wrapping the call in a "
        "subquery lets the planner evaluate it once per statement.",
    ),
    "0004_no_primary_key": (
        "PERFORMANCE",
        "No primary key",
        "Detects tables without a primary key, which cannot be replicated or "
        "efficiently addressed row by row.",
    ),
    "0005_unused_index": (
        "PERFORMANCE",
        "Unused index",
        "Detects indexes that have never been used, which cost write "
        "throughput and storage for no read benefit.",
    ),
    "0006_multiple_permissive_policies": (
        "PERFORMANCE",
        "Multiple permissive policies",
        "Detects tables with multiple permissive policies for the same role "
        "and action. Every permissive policy must be executed for every "
        "relevant query.",
    ),
    "0007_policy_exists_rls_disabled": (
        "SECURITY",
        "Policy exists but RLS is disabled",
        "Detects tables that have row-level security policies defined but do "
        "not have row-level security enabled, so the policies are not "
        "enforced at all.",
    ),
    "0008_rls_enabled_no_policy": (
        "SECURITY",
        "RLS enabled with no policy",
        "Detects tables with row-level security enabled but no policies, "
        "which denies all access through the API to non-privileged roles.",
    ),
    "0009_duplicate_index": (
        "PERFORMANCE",
        "Duplicate index",
        "Detects identical indexes on the same table and columns, which "
        "duplicate write cost for no additional read benefit.",
    ),
    "0010_security_definer_view": (
        "SECURITY",
        "Security definer view",
        "Detects views defined with the SECURITY DEFINER property. Such a "
        "view executes with the permissions of its owner, bypassing the "
        "row-level security of the querying user.",
    ),
    "0011_function_search_path_mutable": (
        "SECURITY",
        "Function search path is mutable",
        "Detects functions where the `search_path` parameter is not set. A "
        "mutable search path lets a caller shadow the objects the function "
        "references, which is a privilege-escalation vector for SECURITY "
        "DEFINER functions.",
    ),
    "0012_auth_allow_anonymous_sign_ins": (
        "SECURITY",
        "Anonymous sign-ins enabled",
        "Detects that anonymous sign-ins are enabled, which means the `anon` "
        "role is reachable with a real session and every policy granting it "
        "access applies to the public internet.",
    ),
    "0013_rls_disabled_in_public": (
        "SECURITY",
        "RLS disabled in public schema",
        "Detects tables in an API-exposed schema that do not have row-level "
        "security enabled, so their rows are readable by any role with "
        "schema access.",
    ),
    "0014_extension_in_public": (
        "SECURITY",
        "Extension in public schema",
        "Detects extensions installed in the public schema, where their "
        "objects are exposed through the API and can be shadowed.",
    ),
    "0015_rls_references_user_metadata": (
        "SECURITY",
        "RLS policy references user metadata",
        "Detects row-level security policies that reference "
        "`auth.jwt() -> 'user_metadata'`. User metadata is editable by the "
        "end user, so a policy that trusts it is a policy the user can "
        "rewrite.",
    ),
    "0016_materialized_view_in_api": (
        "SECURITY",
        "Materialized view in API",
        "Detects materialized views in an API-exposed schema. Materialized "
        "views do not support row-level security, so their contents are "
        "returned in full.",
    ),
    "0017_foreign_table_in_api": (
        "SECURITY",
        "Foreign table in API",
        "Detects foreign tables in an API-exposed schema. Foreign tables do "
        "not respect row-level security.",
    ),
    "0018_unsupported_reg_types": (
        "SECURITY",
        "Unsupported reg types",
        "Detects columns using `reg*` types, which are not stable across "
        "dumps and restores and can break the API.",
    ),
    "0019_insufficient_mfa_options": (
        "SECURITY",
        "Insufficient MFA options",
        "Detects projects with too few multi-factor authentication options "
        "enabled, which weakens account takeover resistance.",
    ),
    "0020_fkey_to_auth_unique": (
        "SECURITY",
        "Foreign key to a non-unique auth column",
        "Detects foreign keys referencing a column in the auth schema that is "
        "not guaranteed unique.",
    ),
    "0021_table_bloat": (
        "PERFORMANCE",
        "Table bloat",
        "Detects tables with a high proportion of dead tuples, which slows "
        "sequential scans and inflates storage.",
    ),
}

_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@register(
    ADAPTER_ID,
    tool="supabase",
    description=(
        "Supabase's published database advisors (RLS enabled with no policy, "
        "security definer views, mutable function search_path, auth RLS "
        "initplan, and the rest), run against the live schema."
    ),
    required=False,
    applies_to=SQL_GLOBS,
    install_hint=(
        "Install the Supabase CLI (`brew install supabase/tap/supabase`, "
        "`npm i -g supabase`, or the release binary). Optional because it "
        "needs a reachable Postgres: pass `--linked` credentials or a "
        "`db_url` option. When it cannot connect, the advisors do NOT run and "
        "the schema has NOT been checked — that is not the same as passing."
    ),
    homepage=DOCS,
)
def run_supabase_advisors(ctx: AdapterContext, spec: AdapterSpec) -> AdapterResult:
    registered = get(ADAPTER_ID)
    assert registered is not None

    binary = which("supabase")
    if not binary:
        return missing_tool_result(
            registered,
            extra=(
                "No Supabase advisor ran against the schema, so do not read "
                "this run as the schema having passed them."
            ),
        )

    result = AdapterResult(version=tool_version(binary))

    globs = spec.option("sql_globs") or SQL_GLOBS
    changed_sql = sorted(p for p in ctx.changed(*globs))
    if not changed_sql:
        result.notes.append(
            "supabase-advisors: no migration or SQL file changed in this PR, so "
            "the schema advisors were not run."
        )
        result.ran = True
        return result

    args = ["db", "lint", "--level", str(spec.option("level", "warning")), "--output", "json"]
    db_url = spec.option("db_url") or ctx.env.get("SUPABASE_DB_URL")
    if db_url:
        args += ["--db-url", str(db_url)]
    elif spec.option("linked", False):
        args.append("--linked")
    for schema in spec.option("schema") or []:
        args += ["--schema", str(schema)]

    outcome = run_tool(
        binary, args, ctx.repo_root, timeout=int(spec.option("timeout", 300))
    )
    if outcome is None:
        result.errors.append(
            "`supabase` is installed but could not be executed (timeout or "
            "killed). The database advisors did NOT run against the schema; "
            "this run says nothing about whether it passes them."
        )
        return result

    code, stdout, stderr = outcome

    # `supabase db lint` exits 0 when it completed, whether or not it found
    # lints — the lints are data, not a failure. A non-zero exit means the CLI
    # itself failed, and in practice that almost always means it could not
    # reach a database: no `--linked` project, no `db_url`, no local stack
    # running. That is the expected state on a PR runner, so it is reported as
    # a plainly-worded degradation rather than as an engine error.
    if code != 0:
        detail = _trim(stderr or stdout)
        result.notes.append(
            "supabase-advisors did NOT run: `supabase db lint` exited "
            f"{code}, which normally means no database was reachable "
            "(no linked project, no `db_url`, no local stack). The schema "
            "advisors — including RLS-enabled-with-no-policy, security "
            "definer views and mutable function search_path — were therefore "
            "NOT evaluated. This is not a pass; it is an absence of "
            f"evidence. CLI said: {detail}"
        )
        return result

    entries, parse_error = _parse(stdout)
    if parse_error is not None:
        result.errors.append(
            f"`supabase db lint` exited 0 but its output could not be read "
            f"({parse_error}), so no advisor finding could be extracted. The "
            f"schema was not checked by this adapter."
        )
        return result

    for entry in entries:
        finding = _to_finding(entry, spec, ctx, changed_sql)
        if finding is not None:
            result.findings.append(finding)

    result.ran = True
    result.notes.append(
        f"supabase-advisors ran against the schema and returned "
        f"{len(result.findings)} advisor finding(s). Advisors report database "
        f"objects, not diff lines, so these are facts about the schema as it "
        f"stands rather than about the changed files."
    )
    return result


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------


def _parse(stdout: str) -> tuple[list[dict[str, Any]], str | None]:
    """Normalise both shapes `supabase db lint --output json` has produced.

    The advisor shape is a list of `{name, title, level, categories,
    description, detail, remediation, metadata}`. The older plpgsql_check
    shape is a list of `{level, query, issues: [{level, message, statement}]}`
    where `query` is the function being checked. Both are accepted because
    which one you get depends on the CLI version, and an adapter that breaks
    on a CLI upgrade is an adapter that gets disabled.
    """
    text = (stdout or "").strip()
    if not text:
        return [], None  # completed with nothing to report
    try:
        payload = json.loads(text)
    except ValueError as exc:
        return [], str(exc)

    if isinstance(payload, dict):
        for key in ("lints", "results", "advisors"):
            if isinstance(payload.get(key), list):
                payload = payload[key]
                break
        else:
            payload = [payload]
    if not isinstance(payload, list):
        return [], "output was not a JSON array"

    out: list[dict[str, Any]] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("issues"), list):
            out.extend(_flatten_plpgsql(item))
        else:
            out.append(item)
    return out, None


def _flatten_plpgsql(item: dict[str, Any]) -> list[dict[str, Any]]:
    """Turn one plpgsql_check function report into advisor-shaped entries."""
    target = str(item.get("query") or item.get("function") or "").strip()
    flattened: list[dict[str, Any]] = []
    for issue in item.get("issues") or []:
        if not isinstance(issue, dict):
            continue
        statement = issue.get("statement") or {}
        message = str(issue.get("message") or "").strip()
        state = str(issue.get("sqlState") or "").strip()
        flattened.append(
            {
                # plpgsql_check identifies an issue by SQLSTATE, not by a lint
                # name, so the rule id carries the state and the title carries
                # the message — otherwise every issue in a function would
                # fingerprint identically and dedup would hide all but one.
                "name": f"plpgsql_check_{state}" if state else "plpgsql_check",
                "title": message[:120] or "plpgsql_check",
                "level": issue.get("level") or item.get("level") or "warning",
                # plpgsql_check's message *is* the upstream explanation; it is
                # the rationale verbatim rather than a paraphrase of one.
                "description": message,
                "detail": message,
                "categories": ["CORRECTNESS"],
                "metadata": {
                    "name": target,
                    "type": "function",
                    "statement": str(statement.get("text") or "").strip(),
                    "function_line": statement.get("lineNumber"),
                },
            }
        )
    return flattened


def _to_finding(
    entry: dict[str, Any],
    spec: AdapterSpec,
    ctx: AdapterContext,
    changed_sql: list[str],
) -> Finding | None:
    name = str(entry.get("name") or entry.get("lint") or "").strip()
    if not name:
        return None

    level = str(entry.get("level") or "warn").strip().lower()
    severity = _clamp(_LEVELS.get(level, Severity.MEDIUM), spec)

    known = KNOWN_LINTS.get(name) or KNOWN_LINTS.get(_numbered(name))
    category = str((entry.get("categories") or [None])[0] or (known[0] if known else "")).upper()

    metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
    obj = _object_name(metadata)

    detail = str(entry.get("detail") or "").strip()
    description = str(entry.get("description") or "").strip()
    title = str(entry.get("title") or (known[1] if known else name)).strip()

    message = detail or description or f"{title}: {obj or 'schema'}"

    # Rationale, in preference order: whatever Supabase said in this run,
    # then Supabase's own published description for this numbered lint, then
    # an admission that we do not have one.
    rationale = (
        description
        or (known[2] if known else "")
        or (
            f"Reported by Supabase's database advisor `{name}`, which did not "
            f"supply a description in this run and is not in the catalogue "
            f"this adapter knows. See {DOCS}?lint={name}."
        )
    )

    remediation = str(entry.get("remediation") or "").strip() or f"{DOCS}?lint={name}"
    path, inferred = _attribute(obj, ctx, changed_sql)

    return Finding(
        rule_id=f"{ADAPTER_ID}.{name}",
        severity=severity,
        title=title[:120],
        message=message,
        rationale=rationale,
        pack=spec.pack,
        tier=Tier.DETERMINISTIC,
        engine=Engine.SCRIPT,
        location=Location(path) if path else None,
        metadata={
            "adapter": ADAPTER_ID,
            "upstream_rule": name,
            "upstream_level": level,
            "category": category,
            "object": obj,
            "object_type": str(metadata.get("type") or ""),
            "schema": str(metadata.get("schema") or ""),
            "help_uri": remediation,
            "location_inferred": inferred,
            "source": (
                "live schema via `supabase db lint`, not the diff — this "
                "finding describes the database, not the changed file"
            ),
        },
    )


def _numbered(name: str) -> str:
    """Match `rls_enabled_no_policy` against `0008_rls_enabled_no_policy`.

    Supabase's API returns the unnumbered name while its documentation and
    CLI use the numbered one. Accepting both keeps the catalogue useful.
    """
    for key in KNOWN_LINTS:
        if key.split("_", 1)[-1] == name:
            return key
    return name


def _object_name(metadata: dict[str, Any]) -> str:
    schema = str(metadata.get("schema") or "").strip()
    name = str(metadata.get("name") or metadata.get("entity") or "").strip()
    if schema and name and not name.startswith(f"{schema}."):
        return f"{schema}.{name}"
    return name


def _attribute(obj: str, ctx: AdapterContext, changed_sql: list[str]) -> tuple[str | None, bool]:
    """Point at a changed migration only when it is unambiguous.

    An advisor finding has no file. If the object it names appears in exactly
    one changed SQL file, that file is almost certainly where it came from and
    saying so helps the reader. If it appears in several, or none, we say
    nothing — a wrong file link costs more than a missing one.
    """
    bare = obj.rsplit(".", 1)[-1]
    if not bare or not _NAME_RE.fullmatch(bare):
        return None, False
    needle = re.compile(rf"\b{re.escape(bare)}\b")
    hits: list[str] = []
    for path in changed_sql:
        try:
            text = (ctx.repo_root / path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if needle.search(text):
            hits.append(path)
        if len(hits) > 1:
            return None, False
    if len(hits) == 1:
        return hits[0], True
    return None, False


def _trim(text: str, limit: int = 400) -> str:
    collapsed = " ".join((text or "").split())
    return collapsed[:limit] or "(empty)"
