"""Supabase/Postgres migration checks — the four that are ours to make.

This module held seven checks. Three are gone, and the `supabase-advisors`
adapter replaces them (DESIGN-V2 §3): `rls-enabled-no-policy`,
`security-definer-view` and `mutable-search-path` were reimplementations of
Supabase advisors 0008, 0010 and 0011. Theirs win for a reason better than
provenance — they run against the live schema. Ours read migration text and
had to reconstruct the schema's state from the files, which means they could
not see a policy created in the dashboard, a view altered by a later
migration they failed to parse, or anything applied outside the repo. A lint
that models the database is always losing to one that queries it.

The four that remain are not about Postgres at all, which is exactly why
nobody else has them:

* `migration-numbering` and `migration-immutability` are facts about how
  *this team branches* — two concurrent branches picking the same timestamp,
  an applied migration edited in place. Supabase cannot advise on that; it
  is a property of the git history, not of the schema.
* `missing-grants` is soar lore. "`service_role` needs its own GRANT,
  separate from `authenticated`" has four documented occurrences in this
  repository's decisions log (DESIGN s8). It is not general knowledge and no
  advisor checks it.
* `permissive-policy` is kept because its severity is a local fact. The
  pattern is general, but *why it is `critical` here* is DESIGN s8: student
  Google accounts share the staff email domain, so `authenticated` means
  every child in the school. A generic linter has no way to know that and
  would rightly grade it lower.

The SQL lexer below stays. The surviving checks need it, and so does
`privacy_edu.py`, which imports a dozen helpers from here.

DESIGN s8 is the reason these are graded the way they are. In soar-app,
student Google accounts live on the *same* email domain as staff accounts,
distinguished only by a numeric prefix. Every student therefore authenticates
successfully. `using (true)` and a bare `auth.role() = 'authenticated'` are
consequently the same policy: "any signed-in person may read this table", and
in a K-8 school "any signed-in person" means several hundred children. That
local fact is why the RLS rules here are `critical` rather than `high`.

There is no SQL parser in the dependency set and there is not going to be one
(DESIGN s5 keeps the runtime dependencies at PyYAML). So this module does the
smallest thing that is actually correct: one scanning pass that understands
Postgres lexical structure — line comments, block comments, single-quoted
strings with doubled-quote escapes, double-quoted identifiers, and
dollar-quoted function bodies — and uses it to strip comments and split
statements *before* any pattern matching happens. Regex over raw SQL gets
`-- using (true)` wrong, gets a `;` inside a plpgsql body wrong, and reports
`SECURITY DEFINER` from inside a string literal. Regex over lexed statements
does not.

The bias throughout is against false positives. A critical finding that fires
on a correct policy is worse than no rule at all, because the next one gets
dismissed unread.
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from ...diff import ChangedFile, ChangeKind
from ...models import Finding, Severity
from .base import CheckSpec, register

if TYPE_CHECKING:  # pragma: no cover
    from ...context import ReviewContext


MAX_FINDINGS = 20
MAX_SQL_BYTES = 4 * 1024 * 1024
MAX_MIGRATION_FILES = 2000
SQL_GLOBS = ["*.sql"]

DEFAULT_MIGRATIONS_DIR = "supabase/migrations"

#: Roles that are supposed to see everything. A policy scoped only to these is
#: not a finding; `service_role` bypassing RLS is the point of `service_role`.
PRIVILEGED_ROLES = {
    "service_role",
    "postgres",
    "supabase_admin",
    "supabase_auth_admin",
    "supabase_storage_admin",
    "supabase_realtime_admin",
    "dashboard_user",
    "authenticator",
}

#: Roles that mean "the public internet" or "any logged-in person".
OPEN_ROLES = {"public", "anon", "authenticated"}


# ==========================================================================
# Lexing
# ==========================================================================

_DOLLAR_TAG_RE = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$")

_IDENT = r'(?:"[^"]*"|[a-z_][a-z0-9_$]*)'
_QUALIFIED = rf"(?:{_IDENT}\s*\.\s*)?{_IDENT}"


@dataclass
class Statement:
    """One `;`-terminated SQL statement, already stripped of comments.

    Two views of the same text, because different checks need different
    things. `text` keeps string literals (a policy predicate genuinely reads
    `'authenticated'`). `skeleton` additionally blanks dollar-quoted function
    bodies, so that `SECURITY DEFINER` or `SET search_path` inside a plpgsql
    body is not mistaken for the function's own attribute list.
    """

    text: str
    skeleton: str
    start_line: int
    end_line: int

    @property
    def norm(self) -> str:
        return _collapse(self.text)

    @property
    def norm_skeleton(self) -> str:
        return _collapse(self.skeleton)


def _collapse(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def lex_sql(text: str) -> list[Statement]:
    """Split SQL into statements, blanking comments. Never raises.

    Comments are replaced with spaces rather than deleted so that character
    offsets — and therefore line numbers — stay true to the original file.
    """
    if not text:
        return []
    if len(text) > MAX_SQL_BYTES:
        text = text[:MAX_SQL_BYTES]

    n = len(text)
    clean = list(text)
    skel = list(text)
    newlines = [i for i, ch in enumerate(text) if ch == "\n"]

    def blank(start: int, end: int, target: list[str]) -> None:
        for k in range(max(0, start), min(end, n)):
            if target[k] != "\n":
                target[k] = " "

    bounds: list[tuple[int, int]] = []
    stmt_start = 0
    i = 0

    while i < n:
        ch = text[i]

        if ch == "-" and text.startswith("--", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j, clean)
            blank(i, j, skel)
            i = j
            continue

        if ch == "/" and text.startswith("/*", i):
            # Postgres block comments nest, unlike C's.
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth += 1
                    j += 2
                elif text.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            blank(i, j, clean)
            blank(i, j, skel)
            i = j
            continue

        if ch == "'":
            j = i + 1
            while j < n:
                if text[j] == "'":
                    if j + 1 < n and text[j + 1] == "'":
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
            blank(i + 1, j - 1, skel)
            i = j
            continue

        if ch == '"':
            j = i + 1
            while j < n:
                if text[j] == '"':
                    if j + 1 < n and text[j + 1] == '"':
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
            i = j
            continue

        if ch == "$":
            tag_match = _DOLLAR_TAG_RE.match(text, i)
            if tag_match:
                tag = tag_match.group(0)
                close = text.find(tag, tag_match.end())
                j = close + len(tag) if close >= 0 else n
                body_end = close if close >= 0 else n
                blank(tag_match.end(), body_end, skel)
                i = j
                continue

        if ch == ";":
            bounds.append((stmt_start, i))
            stmt_start = i + 1

        i += 1

    bounds.append((stmt_start, n))

    def line_at(offset: int) -> int:
        return bisect.bisect_right(newlines, max(0, offset - 1)) + 1

    clean_text = "".join(clean)
    skel_text = "".join(skel)
    statements: list[Statement] = []
    for start, end in bounds:
        body = clean_text[start:end]
        if not body.strip():
            continue
        lead = len(body) - len(body.lstrip())
        statements.append(
            Statement(
                text=body,
                skeleton=skel_text[start:end],
                start_line=line_at(start + lead),
                end_line=line_at(max(start, end - 1)),
            )
        )
    return statements


# ==========================================================================
# Small SQL helpers
# ==========================================================================


def _unquote(ident: str) -> str:
    ident = ident.strip()
    if len(ident) >= 2 and ident[0] == '"' and ident[-1] == '"':
        return ident[1:-1].replace('""', '"')
    return ident.lower()


def _table_key(raw: str) -> str:
    """`public.students`, `"Students"`, `students` -> a comparable key."""
    parts = [p for p in re.split(r"\s*\.\s*", raw.strip()) if p]
    if not parts:
        return ""
    if len(parts) == 1:
        return f"public.{_unquote(parts[0])}"
    return f"{_unquote(parts[-2])}.{_unquote(parts[-1])}"


def _match_paren(text: str, open_index: int) -> int:
    """Index just past the `)` matching the `(` at `open_index`, or -1."""
    depth = 0
    i = open_index
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "'":
            i += 1
            while i < n:
                if text[i] == "'":
                    if i + 1 < n and text[i + 1] == "'":
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def _clause_body(norm: str, pattern: str) -> str | None:
    """The parenthesised body of e.g. `using (...)`, or None."""
    match = re.search(pattern, norm)
    if not match:
        return None
    open_index = norm.find("(", match.end() - 1)
    if open_index < 0:
        return None
    close = _match_paren(norm, open_index)
    if close < 0:
        return None
    return norm[open_index + 1 : close - 1]


def _split_top(pred: str, op: str) -> list[str]:
    """Split on a boolean operator at paren depth zero, outside strings."""
    parts: list[str] = []
    depth = start = i = 0
    n, oplen = len(pred), len(op)
    while i < n:
        ch = pred[i]
        if ch == "'":
            i += 1
            while i < n:
                if pred[i] == "'":
                    if i + 1 < n and pred[i + 1] == "'":
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0 and pred.startswith(op, i):
            before_ok = i == 0 or not (pred[i - 1].isalnum() or pred[i - 1] == "_")
            after = i + oplen
            after_ok = after >= n or not (pred[after].isalnum() or pred[after] == "_")
            if before_ok and after_ok:
                parts.append(pred[start:i])
                start = i = after
                continue
        i += 1
    parts.append(pred[start:])
    return [p.strip() for p in parts if p.strip()]


def _strip_outer_parens(pred: str) -> str:
    pred = pred.strip()
    while pred.startswith("(") and _match_paren(pred, 0) == len(pred):
        pred = pred[1:-1].strip()
    return pred


# Predicates that qualify nothing. Each is written against a form that has
# already been lowercased, whitespace-collapsed and had casts removed.
_VACUOUS_ATOMS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^true$"), "the predicate is literally `true`"),
    (
        re.compile(r"^auth\.role\s*\(\s*\)\s*=\s*'authenticated'$"),
        "the only qualification is `auth.role() = 'authenticated'`",
    ),
    (
        re.compile(r"^'authenticated'\s*=\s*auth\.role\s*\(\s*\)$"),
        "the only qualification is `auth.role() = 'authenticated'`",
    ),
    (
        re.compile(r"^auth\.role\s*\(\s*\)\s*(?:=\s*any\s*)?in\s*\(\s*'authenticated'\s*\)$"),
        "the only qualification is `auth.role() in ('authenticated')`",
    ),
    (
        re.compile(r"^current_user\s*=\s*'authenticated'$"),
        "the only qualification is `current_user = 'authenticated'`",
    ),
    (
        re.compile(r"^auth\.uid\s*\(\s*\)\s+is\s+not\s+null$"),
        "the only qualification is `auth.uid() is not null`, which is true for every signed-in "
        "account",
    ),
    (
        re.compile(r"^auth\.jwt\s*\(\s*\)\s+is\s+not\s+null$"),
        "the only qualification is `auth.jwt() is not null`, which is true for every signed-in "
        "account",
    ),
]


def _atom_reason(pred: str) -> str | None:
    atom = _strip_outer_parens(pred)
    atom = re.sub(r"::\s*(?:text|varchar|name|bool|boolean|uuid)\b", "", atom)
    # `(select auth.uid())` is the recommended performance form and means the
    # same thing as `auth.uid()`; unwrap it so the atom patterns still match.
    atom = re.sub(r"\(\s*select\s+(auth\.\w+\s*\(\s*\))\s*\)", r"\1", atom)
    atom = re.sub(r"\s+", " ", atom).strip()
    for pattern, reason in _VACUOUS_ATOMS:
        if pattern.match(atom):
            return reason
    return None


def _vacuous_reason(pred: str, depth: int = 0) -> str | None:
    """Why `pred` authorises everyone, or None if it qualifies anything.

    The boolean algebra is the whole false-positive defence:

    * `a OR true` is true, so one vacuous disjunct condemns the predicate.
    * `a AND true` is `a`, so an AND fires only if *every* conjunct is vacuous.

    Anything this function does not recognise returns None. A predicate it
    cannot analyse is not reported.
    """
    if depth > 8:
        return None
    pred = _strip_outer_parens(pred)
    if not pred:
        return None

    disjuncts = _split_top(pred, "or")
    if len(disjuncts) > 1:
        for part in disjuncts:
            reason = _vacuous_reason(part, depth + 1)
            if reason:
                return f"{reason}, and it sits in an `OR`, so the whole predicate is true"
        return None

    conjuncts = _split_top(pred, "and")
    if len(conjuncts) > 1:
        reasons = [_vacuous_reason(part, depth + 1) for part in conjuncts]
        if all(reasons):
            return "; ".join(dict.fromkeys(r for r in reasons if r))
        return None

    return _atom_reason(pred)


# ==========================================================================
# File gathering
# ==========================================================================


@dataclass
class SqlFile:
    path: str
    statements: list[Statement]
    changed: ChangedFile | None = None
    lines: list[str] = field(default_factory=list)

    @property
    def is_new(self) -> bool:
        return self.changed is not None and self.changed.kind is ChangeKind.ADDED


def _migrations_dir(spec: CheckSpec) -> str:
    raw = str(spec.option("migrations_dir", DEFAULT_MIGRATIONS_DIR) or "").strip()
    return (raw or DEFAULT_MIGRATIONS_DIR).replace("\\", "/").strip("/")


def _in_migrations(path: str, migrations_dir: str) -> bool:
    norm = path.replace("\\", "/").lstrip("./")
    return norm.startswith(f"{migrations_dir}/")


def _read(ctx: ReviewContext, path: str) -> str | None:
    try:
        return ctx.read(path)
    except OSError:
        return None


def changed_sql_files(ctx: ReviewContext) -> Iterator[SqlFile]:
    """`.sql` files this PR changed and that still exist at head."""
    for changed in ctx.diff.live_files:
        if changed.is_binary or changed.suffix != ".sql":
            continue
        text = _read(ctx, changed.path)
        if not text:
            continue
        yield SqlFile(
            path=changed.path,
            statements=lex_sql(text),
            changed=changed,
            lines=text.splitlines(),
        )


def migration_corpus(ctx: ReviewContext, migrations_dir: str) -> list[SqlFile]:
    """Every migration on disk, in apply order, plus any changed `.sql`.

    Apply order is filename order, which is the same order Supabase uses, and
    it matters: a policy created in `003` covers a table whose RLS was enabled
    in `002`, and the reverse arrangement is a real bug.
    """
    by_path: dict[str, SqlFile] = {}
    root = ctx.repo_root / migrations_dir
    try:
        candidates = sorted(p for p in root.rglob("*.sql") if p.is_file())
    except OSError:
        candidates = []

    for path in candidates[:MAX_MIGRATION_FILES]:
        try:
            if path.stat().st_size > MAX_SQL_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = path.relative_to(ctx.repo_root).as_posix()
        by_path[rel] = SqlFile(path=rel, statements=lex_sql(text), lines=text.splitlines())

    for sql in changed_sql_files(ctx):
        existing = by_path.get(sql.path)
        if existing is None:
            by_path[sql.path] = sql
        else:
            existing.changed = sql.changed

    return [by_path[k] for k in sorted(by_path)]


def _pr_owns(sql: SqlFile, statement: Statement) -> bool:
    """Did this PR write any part of this statement?

    Whole-repo checks read the whole migrations directory but still only
    report what the PR is responsible for. The one check that used to be
    exempt — `rls-enabled-no-policy`, where the missing half *was* the
    finding — is now the `supabase-advisors` adapter's, so there is no
    exception left.
    """
    changed = sql.changed
    if changed is None:
        return False
    if changed.kind is ChangeKind.ADDED or not changed.hunks:
        return True
    added = changed.added_line_numbers
    return any(statement.start_line <= n <= statement.end_line for n in added)


def _snippet(sql: SqlFile, statement: Statement, limit: int = 240) -> str:
    text = re.sub(r"\s+", " ", statement.text).strip()
    return text[:limit] + ("…" if len(text) > limit else "")


# ==========================================================================
# supabase.permissive-policy
# ==========================================================================

_CREATE_POLICY_RE = re.compile(
    rf"^create\s+policy\s+(?:if\s+not\s+exists\s+)?({_IDENT})\s+on\s+({_QUALIFIED})"
)
_RESTRICTIVE_RE = re.compile(r"\bas\s+restrictive\b")
_TO_ROLES_RE = re.compile(rf"\bto\s+({_IDENT}(?:\s*,\s*{_IDENT})*)")


@register(
    "supabase.permissive-policy",
    default_severity=Severity.CRITICAL,
    title="RLS policy authorises every signed-in account",
    description=(
        "A policy whose predicate is `true`, or whose only qualification is that the caller "
        "is authenticated, grants access to the entire user base."
    ),
    applies_to=SQL_GLOBS,
)
def permissive_policy(ctx: ReviewContext, spec: CheckSpec) -> Iterable[Finding]:
    """Catch policies that qualify nobody.

    `using (true)` is the obvious case. The one that actually keeps being
    written is `auth.role() = 'authenticated'`, because it reads like a
    restriction. It is not one. It says "anybody with an account", and DESIGN
    s8 records the local fact that makes that catastrophic here: student Google
    accounts sit on the staff email domain under a numeric prefix, so every
    student authenticates. A table guarded by bare `authenticated` is a table
    every child in the school can read. In a repo where the only accounts are
    employees the same rule would reasonably be `high`; here it is `critical`
    and it blocks.

    The predicate must be *entirely* vacuous before this fires. `auth.uid() =
    user_id and auth.role() = 'authenticated'` is a real policy and is not
    reported. Policies scoped only to `service_role` are not reported, because
    that role bypasses RLS anyway. `AS RESTRICTIVE` policies are not reported,
    because a restrictive `true` grants nothing — it ANDs with the permissive
    set.
    """
    findings: list[Finding] = []

    for sql in changed_sql_files(ctx):
        for statement in sql.statements:
            if len(findings) >= MAX_FINDINGS:
                return findings
            norm = statement.norm
            match = _CREATE_POLICY_RE.match(norm)
            if not match:
                continue
            if not _pr_owns(sql, statement):
                continue

            policy_name, table = _unquote(match.group(1)), _table_key(match.group(2))

            head = re.split(r"\busing\s*\(|\bwith\s+check\s*\(", norm)[0]
            if _RESTRICTIVE_RE.search(head):
                continue  # a restrictive policy only ever narrows

            roles = _policy_roles(head)
            if roles and roles <= PRIVILEGED_ROLES:
                continue  # service_role bypasses RLS; scoping to it grants nothing new

            for clause, pattern in (
                ("USING", r"\busing\s*\("),
                ("WITH CHECK", r"\bwith\s+check\s*\("),
            ):
                body = _clause_body(norm, pattern)
                if body is None:
                    continue
                reason = _vacuous_reason(body)
                if reason is None:
                    continue

                role_note = (
                    f"It applies to `{', '.join(sorted(roles))}`. "
                    if roles
                    else "It has no `TO` clause, so it applies to `public`. "
                )
                verb = (
                    "every row is readable/updatable"
                    if clause == "USING"
                    else "every row is writable"
                )

                findings.append(
                    spec.finding(
                        title=f"Policy `{policy_name}` on `{table}` qualifies nobody",
                        message=(
                            f"`{clause} ({body.strip()})` on policy `{policy_name}` "
                            f"({table}): {reason}. {role_note}"
                            f"With this policy in place, {verb} by anyone the role covers.\n\n"
                            "In this repository that is not a theoretical widening. Student "
                            "Google accounts share the staff email domain under a numeric "
                            "prefix (DESIGN s8), so every student is `authenticated`. A bare "
                            "`authenticated` predicate authorises the entire student body — "
                            "which is why this rule is `critical` here and would reasonably be "
                            "`high` in a repository whose only accounts are employees.\n\n"
                            "Write a predicate that names the relationship that makes access "
                            "legitimate, for example:\n\n"
                            "```sql\n"
                            f"create policy \"{policy_name}\" on {table}\n"
                            "  for select to authenticated\n"
                            "  using (auth.uid() = owner_id);\n"
                            "```\n\n"
                            "If the table genuinely holds nothing sensitive, say so in a comment "
                            "above the policy and dismiss this with that reason — the reason is "
                            "the part that matters."
                        ),
                        rationale=(
                            "`authenticated` is not an authorisation decision, it is an "
                            "authentication fact. Because student accounts authenticate against "
                            "the same domain as staff accounts, a predicate that only checks "
                            "for a session grants every student read access to this table. "
                            "That has already been the shape of past incidents in this "
                            "codebase, which is why it is deterministic and blocking rather "
                            "than a judgment call."
                        ),
                        path=sql.path,
                        line=statement.start_line,
                        end_line=statement.end_line,
                        snippet=_snippet(sql, statement),
                        policy=policy_name,
                        table=table,
                        clause=clause,
                    )
                )
                break  # one finding per policy, not one per clause

    return findings


def _policy_roles(head: str) -> set[str]:
    match = _TO_ROLES_RE.search(head)
    if not match:
        return set()
    return {_unquote(r) for r in match.group(1).split(",") if r.strip()}


# ==========================================================================
# supabase.missing-grants
# ==========================================================================

_CREATE_TABLE_RE = re.compile(
    rf"^create\s+(?:global\s+|local\s+|temp\w*\s+|unlogged\s+)*table\s+"
    rf"(?:if\s+not\s+exists\s+)?({_QUALIFIED})"
)
_CREATE_SCHEMA_RE = re.compile(rf"^create\s+schema\s+(?:if\s+not\s+exists\s+)?({_IDENT})")
_GRANT_RE = re.compile(r"^grant\s+(.+?)\s+on\s+(.+?)\s+to\s+(.+?)\s*$", re.DOTALL)


@register(
    "supabase.missing-grants",
    default_severity=Severity.HIGH,
    title="New object granted to `authenticated` but not `service_role`",
    description=(
        "`service_role` needs its own GRANT. Bypassing RLS is not the same as holding the "
        "table privilege."
    ),
    applies_to=SQL_GLOBS,
    reads_whole_repo=True,
)
def missing_grants(ctx: ReviewContext, spec: CheckSpec) -> Iterable[Finding]:
    """New table or schema granted to `authenticated` but not to `service_role`.

    DESIGN s8, verbatim from the decisions log: "`service_role` needs its own
    GRANT, separate from `authenticated`. RLS bypass is not grant bypass." Four
    recorded occurrences — `core` 027, `monday_school` 029, System 2 tables
    030, `signage` 039 — which is the definition of a rule-shaped hole. It is
    here because it has been made four times, not because it is subtle.

    The confusion is understandable. `service_role` bypasses row level
    security, so it feels omnipotent. It is not: RLS and the SQL privilege
    system are separate gates, and bypassing one says nothing about the other.
    A `service_role` key with no `GRANT` gets `permission denied for table`,
    usually from a server-side job, usually at the worst time.

    This only fires where a grant to `authenticated` already exists, so it
    reads as "you granted one role and forgot the other" rather than as a
    complaint about every table that has no grants at all.
    """
    migrations_dir = _migrations_dir(spec)
    corpus = migration_corpus(ctx, migrations_dir)
    if not corpus:
        return []

    table_grants: dict[str, set[str]] = {}
    schema_table_grants: dict[str, set[str]] = {}
    schema_grants: dict[str, set[str]] = {}

    for sql in corpus:
        for statement in sql.statements:
            match = _GRANT_RE.match(statement.norm)
            if not match:
                continue
            target, roles_raw = match.group(2).strip(), match.group(3)
            roles = {_unquote(r) for r in roles_raw.split(",") if r.strip()}

            all_tables = re.match(
                rf"all\s+(?:tables|sequences|routines|functions)\s+in\s+schema\s+({_IDENT})",
                target,
            )
            if all_tables:
                schema_table_grants.setdefault(_unquote(all_tables.group(1)), set()).update(roles)
                continue

            schema_target = re.match(rf"schema\s+({_IDENT})", target)
            if schema_target:
                schema_grants.setdefault(_unquote(schema_target.group(1)), set()).update(roles)
                continue

            target = re.sub(r"^(?:table|sequence|function|routine)\s+", "", target)
            for obj in re.split(r"\s*,\s*", target):
                if obj.strip():
                    table_grants.setdefault(_table_key(obj), set()).update(roles)

    findings: list[Finding] = []

    for sql in corpus:
        if sql.changed is None:
            continue
        for statement in sql.statements:
            if len(findings) >= MAX_FINDINGS:
                return findings
            norm = statement.norm
            if not _pr_owns(sql, statement):
                continue

            table_match = _CREATE_TABLE_RE.match(norm)
            schema_match = _CREATE_SCHEMA_RE.match(norm)
            if table_match:
                key = _table_key(table_match.group(1))
                schema = key.split(".")[0]
                roles = table_grants.get(key, set()) | schema_table_grants.get(schema, set())
                kind, label, target_sql = "table", key, key
            elif schema_match:
                key = _unquote(schema_match.group(1))
                roles = schema_grants.get(key, set())
                kind, label, target_sql = "schema", key, f"schema {key}"
            else:
                continue

            open_roles = roles & OPEN_ROLES
            if not open_roles or "service_role" in roles:
                continue

            granted = ", ".join(f"`{r}`" for r in sorted(open_roles))
            example = (
                f"grant usage on schema {label} to service_role;"
                if kind == "schema"
                else f"grant select, insert, update, delete on {label} to service_role;"
            )
            findings.append(
                spec.finding(
                    title=f"New {kind} `{label}` has no `service_role` grant",
                    message=(
                        f"This PR creates {kind} `{label}` and grants it to {granted}, but "
                        "nothing under "
                        f"`{migrations_dir}/` grants anything on it to `service_role`.\n\n"
                        "`service_role` bypasses row level security, which is what makes this "
                        "easy to miss, but RLS and table privileges are separate gates. Without "
                        "its own `GRANT`, a server-side call using the service key gets "
                        f"`permission denied for {kind} {label}` — typically from a scheduled "
                        "job or an edge function, typically not in the change that introduced "
                        "it.\n\n"
                        "Add it in this migration:\n\n"
                        f"```sql\n{example}\n```\n\n"
                        "This is a documented repeat: DESIGN s8 records four prior occurrences "
                        "(`core` 027, `monday_school` 029, System 2 tables 030, `signage` 039). "
                        "The rule exists because the mistake keeps being made, not because it "
                        "is hard to understand."
                    ),
                    rationale=(
                        "RLS bypass is not grant bypass. `service_role` skipping row level "
                        "security says nothing about whether it holds the `SELECT` privilege on "
                        f"{label}, and the failure appears later, in server-side code, rather "
                        "than in the migration that omitted it. Four occurrences in this "
                        "repository's decisions log put it well past the threshold where a "
                        "deterministic check is cheaper than remembering."
                    ),
                    path=sql.path,
                    line=statement.start_line,
                    end_line=statement.end_line,
                    snippet=_snippet(sql, statement),
                    object=label,
                    object_kind=kind,
                    granted_to=sorted(roles),
                )
            )

    return findings


# ==========================================================================
# supabase.migration-numbering
# ==========================================================================

_PREFIX_RE = re.compile(r"^(\d+)")


@register(
    "supabase.migration-numbering",
    default_severity=Severity.HIGH,
    title="Migration prefix collides or sorts before an applied migration",
    description=(
        "Migrations apply in filename order and are recorded by version. A duplicate or "
        "out-of-order prefix breaks `db push` on environments that are already ahead."
    ),
    applies_to=SQL_GLOBS,
    reads_whole_repo=True,
)
def migration_numbering(ctx: ReviewContext, spec: CheckSpec) -> Iterable[Finding]:
    """New migrations must sort after everything already applied.

    Supabase orders migrations by the numeric prefix of the filename and
    records applied versions in `supabase_migrations.schema_migrations`. Two
    failure modes follow, and DESIGN s8 records both as things that have
    already happened here:

    *Collision.* Two concurrent branches each add `20260214...`. Both are green
    on their own branch, because neither can see the other. The second merge is
    what breaks, and it breaks for whoever merges second rather than for
    whoever caused it.

    *Out-of-order.* A migration numbered below the highest already-applied
    version is skipped on environments that are ahead — production accepts it,
    a fresh local database applies it in a different order, and the two schemas
    diverge without anything failing.

    Only migrations *added by this PR* are reported. A pre-existing collision
    is someone else's PR.
    """
    migrations_dir = _migrations_dir(spec)

    added: list[tuple[str, str]] = []
    for changed in ctx.diff.files:
        if changed.kind is not ChangeKind.ADDED:
            continue
        if not _in_migrations(changed.path, migrations_dir) or changed.suffix != ".sql":
            continue
        prefix = _prefix_of(changed.path)
        if prefix:
            added.append((changed.path, prefix))
    if not added:
        return []

    added_paths = {path for path, _ in added}
    existing: dict[str, list[str]] = {}
    root = ctx.repo_root / migrations_dir
    try:
        on_disk = sorted(p for p in root.rglob("*.sql") if p.is_file())
    except OSError:
        on_disk = []
    for path in on_disk[:MAX_MIGRATION_FILES]:
        try:
            rel = path.relative_to(ctx.repo_root).as_posix()
        except ValueError:
            continue
        if rel in added_paths:
            continue
        prefix = _prefix_of(rel)
        if prefix:
            existing.setdefault(prefix, []).append(rel)

    findings: list[Finding] = []
    highest = max(existing, key=_prefix_sort_key) if existing else None

    for path, prefix in sorted(added):
        if len(findings) >= MAX_FINDINGS:
            break

        collisions = list(existing.get(prefix, []))
        collisions += [p for p, pre in added if pre == prefix and p != path]
        if collisions:
            findings.append(
                spec.finding(
                    title=f"Migration prefix `{prefix}` is already taken",
                    message=(
                        f"`{path}` uses prefix `{prefix}`, which is already used by "
                        + ", ".join(f"`{c}`" for c in sorted(collisions))
                        + ".\n\nSupabase keys applied migrations by this version string. Two "
                        "files sharing it means one of them is either skipped or applied "
                        "against the wrong assumption about schema state, depending on which "
                        "environment is how far ahead.\n\n"
                        "This is the concurrent-branch failure: two branches each generated a "
                        "migration without being able to see the other's, both were green in "
                        "isolation, and the break lands on whoever merges second. Regenerate "
                        "this migration with a current timestamp and re-run it locally against "
                        "a database that already has the other one."
                    ),
                    rationale=(
                        "Migration version strings are the primary key of the applied-migrations "
                        "table. A duplicate is not a style problem; it makes \"has this run?\" "
                        "unanswerable, and the answer differs per environment. It cannot be "
                        "detected on either branch alone, which is exactly why it has to be "
                        "checked at merge."
                    ),
                    path=path,
                    line=1,
                    prefix=prefix,
                    collides_with=sorted(collisions),
                )
            )
            continue

        if highest and _prefix_sort_key(prefix) < _prefix_sort_key(highest):
            findings.append(
                spec.finding(
                    title=f"Migration `{prefix}` sorts before existing `{highest}`",
                    message=(
                        f"`{path}` has prefix `{prefix}`, which sorts before "
                        f"`{existing[highest][0]}` — a migration that already exists on the base "
                        "branch and has almost certainly been applied.\n\n"
                        "On an environment that has already run the later migration, this one is "
                        "out of order: depending on tooling it is skipped or applied after the "
                        "migrations it was written to precede. A database created fresh from the "
                        "directory applies it in the *other* order. The two schemas then differ "
                        "with nothing having failed, which is the worst available outcome.\n\n"
                        "Rename it to a timestamp later than "
                        f"`{highest}` and confirm it still applies cleanly on top of current "
                        "`main`."
                    ),
                    rationale=(
                        "Filename order is apply order. A migration inserted below the high-water "
                        "mark produces a different schema depending on whether a database is new "
                        "or existing, and neither path reports an error. Divergence that does not "
                        "fail is found later and by accident."
                    ),
                    path=path,
                    line=1,
                    prefix=prefix,
                    highest_existing=highest,
                )
            )

    return findings


def _prefix_of(path: str) -> str | None:
    match = _PREFIX_RE.match(Path(path).name)
    return match.group(1) if match else None


def _prefix_sort_key(prefix: str) -> tuple[int, int, str]:
    """Numeric where possible, lexical otherwise, never raising on junk."""
    try:
        return (0, int(prefix), "")
    except ValueError:
        return (1, 0, prefix)


# ==========================================================================
# supabase.migration-immutability
# ==========================================================================


@register(
    "supabase.migration-immutability",
    default_severity=Severity.CRITICAL,
    title="An existing migration was edited or deleted",
    description=(
        "Migrations are immutable once applied. Editing one changes only databases that "
        "have not run it yet."
    ),
    applies_to=SQL_GLOBS,
    reads_whole_repo=True,
)
def migration_immutability(ctx: ReviewContext, spec: CheckSpec) -> Iterable[Finding]:
    """A migration that exists on the base branch must not be changed.

    Once a migration has run, its version is recorded and its file is never
    read again. Editing it therefore does nothing to any database that has
    already applied it — production keeps the old schema — while a database
    created from scratch gets the new one. Deleting it is worse: the recorded
    version now has no file, and a fresh database never reaches the state
    production is in. Either way there is no error, and the two schemas drift
    apart silently. DESIGN s8 lists this among the mistakes already made here.

    The fix is always the same shape: leave the applied migration alone and add
    a new one that makes the correction forward.

    A rename counts. The filename *is* the version, so renaming an applied
    migration orphans its recorded version exactly as deleting it would. A file
    both added and edited within this PR is reported as `added` by the diff and
    is correctly not flagged.
    """
    migrations_dir = _migrations_dir(spec)
    findings: list[Finding] = []

    for changed in ctx.diff.files:
        if len(findings) >= MAX_FINDINGS:
            break
        path = changed.path if changed.kind is not ChangeKind.DELETED else changed.path
        if not _in_migrations(path, migrations_dir):
            # A rename *out* of the migrations directory still orphans it.
            if not (changed.old_path and _in_migrations(changed.old_path, migrations_dir)):
                continue
        if Path(path).suffix.lower() != ".sql":
            continue

        if changed.kind is ChangeKind.MODIFIED:
            verb, detail = (
                "modified",
                f"`{path}` is edited by this PR: "
                f"{len(changed.added_lines)} line(s) added, "
                f"{len(changed.removed_lines)} removed.",
            )
        elif changed.kind is ChangeKind.DELETED:
            verb, detail = "deleted", f"`{path}` is removed by this PR."
        elif changed.kind is ChangeKind.RENAMED:
            verb, detail = (
                "renamed",
                f"`{changed.old_path}` is renamed to `{path}` by this PR.",
            )
        else:
            continue

        findings.append(
            spec.finding(
                title=f"Existing migration {verb}: `{Path(path).name}`",
                message=(
                    f"{detail}\n\n"
                    "This migration exists on the base branch, so every environment that has "
                    "run it has its version recorded and will never read the file again. "
                    f"{'Editing' if verb == 'modified' else 'Removing'} it changes nothing "
                    "about those databases; it changes only databases created from scratch "
                    "afterwards. Nothing errors. The schemas simply stop matching, and the "
                    "difference surfaces weeks later as a column that exists locally and not in "
                    "production, or the reverse.\n\n"
                    "Add a new migration that makes the correction forward instead:\n\n"
                    "```sql\n"
                    "-- supabase/migrations/<new timestamp>_fix_<thing>.sql\n"
                    "alter table public.example add column if not exists corrected_field text;\n"
                    "```\n\n"
                    "The only safe exception is a migration that has provably never been applied "
                    "anywhere — including every developer machine and every preview branch. "
                    "That is a claim about the world, not about the code, so it has to be made "
                    "by a human and written down."
                ),
                rationale=(
                    "Applied migrations are recorded by version, not by content, so an edit is "
                    "invisible to every database that already ran the original. The result is "
                    "two schemas that both look correct against the repository and disagree "
                    "with each other, with no failure at the point of the mistake. DESIGN s8 "
                    "records this as a mistake this codebase has already made."
                ),
                path=path,
                line=1,
                change_kind=changed.kind.value,
                old_path=changed.old_path,
            )
        )

    return findings
