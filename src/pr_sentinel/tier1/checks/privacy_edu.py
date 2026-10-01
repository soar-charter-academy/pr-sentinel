"""`privacy-edu` pack: nonbinding, legally-adjacent surface flagging.

DESIGN s11 is the whole brief, and the distinction it draws is the one thing
this module must never blur:

* **It flags surfaces.** "This PR grants `SELECT` on a student-PII column to
  `authenticated`." "This PR added a student identifier to an analytics
  event."
* **It never rules on compliance.** Nothing here says a change is FERPA-
  compliant, or that it isn't. That judgment belongs to a human, and for
  anything consequential, to counsel.

The framing is enforced structurally rather than by remembering. Every
finding in this module is built by `_flag()`, which requires `frameworks` and
`verify_hint` as keyword arguments, sets `nonbinding=True`, and appends
`NOT_LEGAL_ADVICE` to the message. There is no other path to a `Finding` in
this file, so a finding cannot be emitted without the caveat attached.

The frameworks are *named*, not interpreted. FERPA, COPPA (in a TK-8 setting
"under 13" is very nearly the whole student body, so it is engaged by default
rather than occasionally), and state student-privacy statutes as a category —
those vary by state and are the ones a reviewer is most likely never to have
heard of, which is exactly why naming them is worth doing.

Everything here is mechanical. Several checks are proximity heuristics rather
than dataflow analysis, and each says so in its own rationale; a privacy
reviewer who thinks this module traces data is worse off than one who knows
it does not.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ...diff import ChangedFile, ChangeKind
from ...models import Finding, Severity
from .base import CheckSpec, register
from .util import as_list, glob_match
from .supabase_sql import (
    OPEN_ROLES,
    Statement,
    _CREATE_POLICY_RE,
    _GRANT_RE,
    _QUALIFIED,
    _collapse,
    _clause_body,
    _migrations_dir,
    _policy_roles,
    _pr_owns,
    _snippet,
    _split_top,
    _strip_outer_parens,
    _table_key,
    _unquote,
    _vacuous_reason,
    changed_sql_files,
    lex_sql,
    migration_corpus,
)

if TYPE_CHECKING:  # pragma: no cover
    from ...context import ReviewContext


MAX_FINDINGS = 20

#: Suffixes treated as client/server JavaScript-family source. `.gs` is here
#: because Google Apps Script is where a school codebase's Sheets and Gmail
#: sinks actually live, and it is the file type most likely to move student
#: data into a spreadsheet.
JS_SUFFIXES = {
    ".js", ".jsx", ".mjs", ".cjs",
    ".ts", ".tsx", ".mts", ".cts",
    ".vue", ".svelte", ".gs",
}

JS_GLOBS = [
    "*.js", "*.jsx", "*.mjs", "*.cjs",
    "*.ts", "*.tsx", "*.mts", "*.cts",
    "*.vue", "*.svelte", "*.gs",
]


# ==========================================================================
# The nonbinding contract
# ==========================================================================

FERPA = "FERPA (20 U.S.C. 1232g / 34 CFR Part 99) - education records"
COPPA = (
    "COPPA (15 U.S.C. 6501 et seq.) - online collection from children under 13, "
    "which in a TK-8 setting is nearly the entire student body"
)
STATE = (
    "State student-privacy statutes - these vary by state (California SOPIPA/AB 1584, "
    "New York Education Law 2-d, Illinois SOPPA and equivalents elsewhere) and are the "
    "category most often missed"
)

#: Appended verbatim to every message this module emits.
NOT_LEGAL_ADVICE = (
    "---\n"
    "**Not legal advice, and not a compliance ruling.** This check flags a *surface* "
    "and names the frameworks plausibly engaged by it. It does not determine whether "
    "this change is permitted, whether an exception applies, or whether an existing "
    "agreement already covers it. Those are human decisions, and anything "
    "consequential should be confirmed with counsel or whoever holds data-governance "
    "responsibility for this system."
)


def _flag(
    spec: CheckSpec,
    *,
    frameworks: list[str],
    verify_hint: str,
    message: str,
    rationale: str,
    **kwargs: Any,
) -> Finding:
    """The only way this module builds a finding.

    `frameworks` and `verify_hint` are required positionally-by-keyword rather
    than optional, so the DESIGN s11 contract cannot be satisfied by accident
    or forgotten under time pressure. The disclaimer is appended here rather
    than written into each message for the same reason.
    """
    return spec.finding(
        message=message.rstrip() + "\n\n" + NOT_LEGAL_ADVICE,
        rationale=rationale,
        nonbinding=True,
        frameworks=list(frameworks),
        verify_hint=verify_hint,
        **kwargs,
    )


# ==========================================================================
# PII name lexicon
# ==========================================================================

DEFAULT_PII_COLUMNS: list[str] = [
    "first_name",
    "last_name",
    "student_name",
    "dob",
    "date_of_birth",
    "ssn",
    "address",
    "phone",
    "email",
    "guardian_*",
    "parent_*",
    "iep",
    "504",
    "free_lunch",
    "frl",
    "ethnicity",
    "race",
    "gender",
    "medical_*",
    "disability",
    "student_id",
    "sis_id",
]

DEFAULT_PII_TABLES: list[str] = [
    "students",
    "enrollments",
    "guardians",
    "health_*",
    "iep_*",
    "discipline",
    "attendance",
]

#: Names that identify a specific child rather than describing one. Kept
#: separate from the PII list because `privacy-edu.analytics-student-identifier`
#: is about *identifiability* in a telemetry stream, which is the COPPA
#: question, and `gender` in an aggregate event is a different conversation
#: from `student_id` in one.
DEFAULT_STUDENT_IDENTIFIERS: list[str] = [
    "student",
    "student_id",
    "student_uuid",
    "student_email",
    "student_name",
    "student_number",
    "sis_id",
    "ssid",
    "perm_id",
    "state_student_id",
    "pupil_*",
    "learner_*",
]

_WORD_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z][a-z]*|[a-z]+|[0-9]+")
_TOKEN_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*|[0-9]+")

#: A token whose last word is one of these describes a *quantity* derived from
#: PII, not the PII itself. `studentCount` in an analytics event is an
#: aggregate; firing on it teaches people the check does not understand code.
_AGGREGATE_TAIL = {
    "count", "total", "num", "number", "length", "len", "size", "index", "idx",
    "page", "sum", "avg", "average", "min", "max", "rate", "pct", "percent",
    "type", "kind", "label", "column", "columns", "field", "fields", "key",
    "keys", "schema", "placeholder", "format", "mask", "regex", "pattern",
}

#: A token starting with one of these is a predicate; its value is a boolean,
#: not a person's data.
_PREDICATE_HEAD = {"is", "has", "can", "should", "was", "were", "does"}


def _words(token: str) -> list[str]:
    """`studentId`, `student_id`, `STUDENT_ID`, `student-id` -> ['student','id']."""
    return [w.lower() for w in _WORD_RE.findall(token.replace("_", " ").replace("-", " "))]


class PiiLexicon:
    """Word-sequence matching over identifiers, in place of a regex soup.

    Matching on word sequences rather than substrings is what makes this
    usable. `address` matches `address` and `homeAddress` but not
    `ipAddressPool`... actually it matches that too, which is the honest
    trade: the alternative is case-sensitive substring matching, which misses
    `userEmail` entirely because the `e` is capitalised. Missing real PII is
    the worse error for a check whose entire job is to notice.

    Two deliberate exclusions keep it from being noise: a token whose final
    word is an aggregate (`studentCount`) and a token that is a predicate
    (`hasEmail`) are not PII, they are facts *about* PII.
    """

    __slots__ = ("_matchers",)

    def __init__(self, names: Iterable[str]) -> None:
        matchers: list[tuple[str, tuple[str, ...]]] = []
        for raw in names:
            name = str(raw).strip().rstrip("*").strip("_-")
            if not name:
                continue
            words = tuple(_words(name))
            if words:
                matchers.append((str(raw).strip(), words))
        # Longest first so the reported label is the most specific one that
        # matched: `student_id` rather than `student`.
        matchers.sort(key=lambda m: -len(m[1]))
        self._matchers = matchers

    def token_label(self, token: str) -> str | None:
        words = _words(token)
        if not words:
            return None
        if words[-1] in _AGGREGATE_TAIL or words[0] in _PREDICATE_HEAD:
            return None
        for label, target in self._matchers:
            n = len(target)
            if n > len(words):
                continue
            for i in range(len(words) - n + 1):
                if tuple(words[i : i + n]) == target:
                    return label
        return None

    def matches(self, text: str) -> list[tuple[str, str]]:
        """(source token, lexicon label) pairs found in `text`, deduplicated."""
        out: dict[str, str] = {}
        for token in _TOKEN_RE.findall(text or ""):
            if token in out:
                continue
            label = self.token_label(token)
            if label:
                out[token] = label
        return list(out.items())

    def hit(self, text: str) -> bool:
        return bool(self.matches(text))


def _pii_lexicon(spec: CheckSpec) -> PiiLexicon:
    names = as_list(spec.option("pii_columns", DEFAULT_PII_COLUMNS)) or DEFAULT_PII_COLUMNS
    return PiiLexicon(names + as_list(spec.option("extra_pii_columns", [])))


def _pii_table_patterns(spec: CheckSpec) -> list[str]:
    names = as_list(spec.option("pii_tables", DEFAULT_PII_TABLES)) or DEFAULT_PII_TABLES
    return [n.lower() for n in names + as_list(spec.option("extra_pii_tables", []))]


def _is_pii_table(table_key: str, patterns: list[str]) -> str | None:
    """`public.students` against `students` / `health_*`. Returns the pattern."""
    bare = table_key.rsplit(".", 1)[-1].lower()
    for pattern in patterns:
        if fnmatch.fnmatch(bare, pattern) or bare == pattern:
            return pattern
    return None


def _describe(hits: Iterable[tuple[str, str]], limit: int = 6) -> str:
    seen = list(dict.fromkeys(token for token, _label in hits))
    shown = ", ".join(f"`{t}`" for t in seen[:limit])
    return shown + (f" (+{len(seen) - limit} more)" if len(seen) > limit else "")


# ==========================================================================
# privacy-edu.widens-pii-read
# ==========================================================================

_ALTER_POLICY_RE = re.compile(rf"^alter\s+policy\s+(\S+)\s+on\s+({_QUALIFIED})")
_CREATE_VIEW_RE = re.compile(
    rf"^create\s+(?:or\s+replace\s+)?(?:temp\w*\s+|recursive\s+|materialized\s+)*view\s+"
    rf"({_QUALIFIED})"
)
_ADD_COLUMN_RE = re.compile(
    rf"^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?({_QUALIFIED})\b.*?"
    rf"\badd\s+column\s+(?:if\s+not\s+exists\s+)?([A-Za-z_\"][A-Za-z0-9_$\"]*)",
)


@dataclass
class _Grant:
    privileges: set[str]
    columns: set[str]
    roles: set[str]
    target: str
    scope: str  # "object" | "schema-tables" | "schema"


def _parse_grant(norm: str) -> _Grant | None:
    """Parse a lexed `GRANT` statement. Returns None for anything unrecognised.

    Unrecognised means *not reported*. A grant this cannot parse is a grant
    this does not understand, and guessing is how a privacy check earns a
    reputation for crying wolf.
    """
    match = _GRANT_RE.match(norm)
    if not match:
        return None
    privs_raw, target_raw, roles_raw = match.group(1), match.group(2).strip(), match.group(3)

    privileges = set(re.findall(r"\b(select|insert|update|delete|references|all)\b", privs_raw))
    columns = {
        _unquote(c.strip())
        for group in re.finditer(r"\(([^)]*)\)", privs_raw)
        for c in group.group(1).split(",")
        if c.strip()
    }
    roles = {_unquote(r) for r in roles_raw.split(",") if r.strip()}
    if not roles:
        return None

    all_tables = re.match(
        r"all\s+(?:tables|sequences|routines|functions)\s+in\s+schema\s+(\S+)", target_raw
    )
    if all_tables:
        return _Grant(privileges, columns, roles, _unquote(all_tables.group(1)), "schema-tables")

    schema_target = re.match(r"schema\s+(\S+)", target_raw)
    if schema_target:
        return _Grant(privileges, columns, roles, _unquote(schema_target.group(1)), "schema")

    target = re.sub(r"^(?:table|sequence|function|routine|view)\s+", "", target_raw)
    first = re.split(r"\s*,\s*", target)[0].strip()
    if not first:
        return None
    return _Grant(privileges, columns, roles, _table_key(first), "object")


def _reads(grant: _Grant) -> bool:
    return bool(grant.privileges & {"select", "all"}) or not grant.privileges


def _removed_statements(changed: ChangedFile) -> list[Statement]:
    """The PR's removed lines, lexed as SQL.

    This is an approximation and is treated as one. Removed lines are not a
    valid SQL file — they are the deleted half of a diff, so a statement whose
    tail was left untouched arrives truncated. It is good enough for the only
    question asked of it, which is "did something *like this* exist before,
    and if so, what roles and predicates did it name". Where the answer is
    ambiguous the checks below fall back to not reporting.
    """
    text = "\n".join(t for _, t in changed.removed_lines)
    return lex_sql(text) if text.strip() else []


def _open_read_map(statements: Iterable[Statement]) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Which objects/schemas are readable by `public`, `anon` or `authenticated`."""
    per_object: dict[str, set[str]] = {}
    per_schema: dict[str, set[str]] = {}
    for statement in statements:
        grant = _parse_grant(statement.norm)
        if grant is None or not _reads(grant):
            continue
        open_roles = grant.roles & OPEN_ROLES
        if not open_roles:
            continue
        if grant.scope == "object":
            per_object.setdefault(grant.target, set()).update(open_roles)
        elif grant.scope == "schema-tables":
            per_schema.setdefault(grant.target, set()).update(open_roles)
    return per_object, per_schema


def _broad_readers(
    key: str, per_object: dict[str, set[str]], per_schema: dict[str, set[str]]
) -> set[str]:
    return per_object.get(key, set()) | per_schema.get(key.split(".")[0], set())


@register(
    "privacy-edu.widens-pii-read",
    default_severity=Severity.HIGH,
    title="This PR widens read access to student PII",
    description=(
        "A grant, a policy predicate or a view/table definition changed in a direction that "
        "lets a broader role read a student-PII column. Nonbinding: the surface is flagged, "
        "compliance is not decided."
    ),
    applies_to=["*.sql"],
    reads_whole_repo=True,
)
def widens_pii_read(ctx: ReviewContext, spec: CheckSpec) -> Iterable[Finding]:
    """Compare what this PR removed against what it added, on PII surfaces.

    This is the one check in the pack where removed-vs-added comparison is the
    point rather than an optimisation. "Widening" is not a property of a line;
    it is a property of a *delta*. `grant select on public.students to
    authenticated` is unremarkable if that grant already existed and the PR
    merely reformatted the migration, and is the most consequential line in
    the diff if the prior grant named `service_role`.

    Three shapes are examined, all mechanical:

    1. A `GRANT SELECT` (or `ALL`) on a PII table, or naming a PII column, to
       `public` / `anon` / `authenticated`, where the removed half of the diff
       does not show that role already holding it.
    2. A policy on a PII table whose predicate lost conjuncts, became vacuous,
       or whose `TO` clause gained a broader role, relative to the policy of
       the same name that this PR removed.
    3. A PII column newly appearing in a view definition, or added by
       `ALTER TABLE ... ADD COLUMN`, where the object is already granted to a
       broad role — so the column inherits an audience that was decided
       elsewhere, in a migration nobody is reading during this review.

    Case 3 needs the whole migration corpus to answer "already readable by
    whom", which is why this check reads beyond the diff. Where the corpus
    cannot be read, it degrades to the grants visible in the changed files and
    reports less rather than guessing.
    """
    lexicon = _pii_lexicon(spec)
    table_patterns = _pii_table_patterns(spec)
    findings: list[Finding] = []
    seen: set[tuple[str, int, str]] = set()

    try:
        corpus = migration_corpus(ctx, _migrations_dir(spec))
    except Exception:  # noqa: BLE001 - a check must never crash the run
        corpus = []

    corpus_statements = [s for sql in corpus for s in sql.statements]
    changed = list(changed_sql_files(ctx))
    if not changed:
        return []
    if not corpus_statements:
        corpus_statements = [s for sql in changed for s in sql.statements]

    per_object, per_schema = _open_read_map(corpus_statements)

    for sql in changed:
        if sql.changed is None:
            continue
        before = _removed_statements(sql.changed)
        before_norm = [s.norm for s in before]
        removed_text = _collapse("\n".join(t for _, t in sql.changed.removed_lines))

        for statement in sql.statements:
            if len(findings) >= MAX_FINDINGS:
                return findings
            if not _pr_owns(sql, statement):
                continue
            norm = statement.norm

            for finding in (
                _grant_widening(spec, sql, statement, norm, before, lexicon, table_patterns)
                or _policy_loosening(
                    spec, sql, statement, norm, before, removed_text, table_patterns
                )
                or _column_exposure(
                    spec,
                    sql,
                    statement,
                    norm,
                    before_norm,
                    corpus,
                    lexicon,
                    table_patterns,
                    per_object,
                    per_schema,
                )
            ):
                key = (sql.path, statement.start_line, finding.title)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(finding)

    return findings


def _grant_widening(
    spec: CheckSpec,
    sql: Any,
    statement: Statement,
    norm: str,
    before: list[Statement],
    lexicon: PiiLexicon,
    table_patterns: list[str],
) -> list[Finding]:
    grant = _parse_grant(norm)
    if grant is None or not _reads(grant):
        return []
    broad = grant.roles & OPEN_ROLES
    if not broad:
        return []

    if grant.scope == "object":
        pattern = _is_pii_table(grant.target, table_patterns)
        column_hits = [(c, lexicon.token_label(c)) for c in sorted(grant.columns)]
        pii_columns = [(c, lbl) for c, lbl in column_hits if lbl]
        if not pattern and not pii_columns:
            return []
        subject = f"`{grant.target}`"
        if pii_columns:
            subject += f" columns {_describe(pii_columns)}"
        target_key = grant.target
    elif grant.scope == "schema-tables":
        # `grant select on all tables in schema X to anon` is the widest
        # possible statement and cannot be reasoned about column by column.
        subject = f"every table in schema `{grant.target}`"
        target_key = grant.target
        pattern = None
        pii_columns = []
    else:
        return []

    # Did the removed half already show this role reading this object? If so
    # the statement is a rewrite, not a widening, and reporting it would train
    # people to ignore the rule during routine migration cleanups.
    prior_roles: set[str] = set()
    for old in before:
        old_grant = _parse_grant(old.norm)
        if old_grant is None or not _reads(old_grant):
            continue
        if old_grant.scope == grant.scope and old_grant.target == target_key:
            prior_roles |= old_grant.roles
    new_roles = broad - prior_roles
    if not new_roles:
        return []

    prior_note = (
        f"The removed half of this diff granted read on the same object to "
        f"`{'`, `'.join(sorted(prior_roles))}`, so this is a widening from that set."
        if prior_roles
        else "No removed line in this PR shows an equivalent prior grant, so this reads as a new "
        "audience rather than a restatement of an existing one."
    )

    return [
        _flag(
            spec,
            title=f"Read access to {subject} widened to `{'`, `'.join(sorted(new_roles))}`",
            message=(
                f"This PR grants read access on {subject} to "
                f"`{'`, `'.join(sorted(new_roles))}`.\n\n"
                f"{prior_note}\n\n"
                "`authenticated` means every account that can sign in. `anon` and `public` mean "
                "every caller, signed in or not. In this deployment student accounts sign in "
                "against the same identity provider as staff accounts (DESIGN s8), so an "
                "`authenticated` grant on a student table is a grant to the student body, "
                "including to children reading each other's records.\n\n"
                "What this check is *not* saying: it is not saying the grant is wrong, and it "
                "is not saying it violates anything. Wide read access on a roster table is "
                "sometimes exactly the design, with the narrowing done by row level security "
                "rather than by the grant. That is a legitimate pattern and this check cannot "
                "see it from the `GRANT` alone."
            ),
            rationale=(
                "Read scope on student records is decided by the combination of a `GRANT` and "
                "an RLS policy, and the `GRANT` half is the one that moves silently: it lands "
                "in a migration, applies immediately, and produces no error and no visible "
                "behaviour change for the person who wrote it. Comparing the added statement "
                "against the removed one is the only way to distinguish a genuine widening from "
                "a migration being reformatted, which is why this check reads both halves of "
                "the diff rather than only added lines."
            ),
            frameworks=[FERPA, COPPA, STATE],
            verify_hint=(
                f"Confirm which row level security policies constrain {subject} for the roles "
                "named here, and whether every account holding those roles has a legitimate "
                "educational interest in the rows they can now reach. If the narrowing is done "
                "by RLS rather than by the grant, point at the policy by name."
            ),
            path=sql.path,
            line=statement.start_line,
            end_line=statement.end_line,
            snippet=_snippet(sql, statement),
            surface="grant",
            object=target_key,
            widened_to=sorted(new_roles),
            prior_roles=sorted(prior_roles),
            pii_table_pattern=pattern,
            pii_columns=[c for c, _ in pii_columns],
        )
    ]


def _policy_predicate(norm: str) -> str | None:
    body = _clause_body(norm, r"\busing\s*\(")
    return body.strip() if body else None


def _conjunct_set(pred: str) -> set[str]:
    return {_collapse(p) for p in _split_top(_strip_outer_parens(pred), "and")}


def _policy_loosening(
    spec: CheckSpec,
    sql: Any,
    statement: Statement,
    norm: str,
    before: list[Statement],
    removed_text: str,
    table_patterns: list[str],
) -> list[Finding]:
    match = _CREATE_POLICY_RE.match(norm) or _ALTER_POLICY_RE.match(norm)
    if not match:
        return []
    policy, table = _unquote(match.group(1)), _table_key(match.group(2))
    pattern = _is_pii_table(table, table_patterns)
    if not pattern:
        return []

    head = re.split(r"\busing\s*\(|\bwith\s+check\s*\(", norm)[0]
    new_roles = _policy_roles(head) or {"public"}
    new_pred = _policy_predicate(norm)

    old_roles: set[str] = set()
    old_pred: str | None = None
    for old in before:
        old_match = _CREATE_POLICY_RE.match(old.norm) or _ALTER_POLICY_RE.match(old.norm)
        if not old_match:
            continue
        if _unquote(old_match.group(1)) != policy or _table_key(old_match.group(2)) != table:
            continue
        old_head = re.split(r"\busing\s*\(|\bwith\s+check\s*\(", old.norm)[0]
        old_roles |= _policy_roles(old_head) or {"public"}
        old_pred = _policy_predicate(old.norm) or old_pred

    if old_pred is None and new_pred is not None and removed_text.count("using (") == 1:
        # The common case defeats statement-level matching: a policy edit
        # usually touches only the `using (...)` line, so the removed half of
        # the diff is a clause fragment rather than a parseable `CREATE
        # POLICY`. Reading the clause straight out of the removed text
        # recovers it. Gated on there being exactly one `using (` among the
        # removed lines, so the fragment cannot be attributed to the wrong
        # policy when a migration rewrites several at once.
        old_pred = _clause_body(removed_text, r"\busing\s*\(")

    reasons: list[str] = []

    widened_roles = (new_roles & OPEN_ROLES) - old_roles
    if old_roles and widened_roles:
        reasons.append(
            f"the `TO` clause gained `{'`, `'.join(sorted(widened_roles))}` "
            f"(previously `{'`, `'.join(sorted(old_roles))}`)"
        )

    if new_pred is not None:
        vacuous_now = _vacuous_reason(new_pred)
        vacuous_before = _vacuous_reason(old_pred) if old_pred else None
        if vacuous_now and not vacuous_before:
            reasons.append(
                f"the `USING` predicate now qualifies nobody - {vacuous_now}"
                + (f", where previously it read `{old_pred}`" if old_pred else "")
            )
        elif old_pred is not None and not vacuous_now:
            old_conjuncts = _conjunct_set(old_pred)
            new_conjuncts = _conjunct_set(new_pred)
            dropped = old_conjuncts - new_conjuncts
            if dropped and new_conjuncts < old_conjuncts:
                shown = ", ".join(f"`{d}`" for d in sorted(dropped)[:4])
                reasons.append(
                    f"the `USING` predicate dropped {len(dropped)} condition(s) it previously "
                    f"required ({shown}) and added none"
                )

    if not reasons:
        return []

    return [
        _flag(
            spec,
            title=f"Policy `{policy}` on `{table}` was loosened",
            message=(
                f"`{table}` matches this pack's student-PII table list (`{pattern}`), and policy "
                f"`{policy}` on it changed in a permissive direction: "
                + "; ".join(reasons)
                + ".\n\n"
                "A policy predicate is the row-level answer to \"which children's records may "
                "this caller see\". Removing a conjunct from it does not fail, does not log, and "
                "does not change any UI - it changes the size of the result set, and only for "
                "callers who were previously excluded.\n\n"
                "This check compares the policy this PR removed against the one it added. It "
                "does not evaluate whether the new predicate is correct; a predicate can drop a "
                "condition and still be right because the condition moved into a view, a "
                "function or a different policy."
            ),
            rationale=(
                "Policy edits are the highest-leverage privacy change a migration can make and "
                "the lowest-visibility one: the diff shows a modified SQL string, not the "
                "hundreds of additional rows that string now returns. Reporting only on a "
                "mechanical comparison against the removed version keeps this out of the way "
                "when a policy is merely renamed or reformatted, and surfaces it precisely when "
                "the set of conditions genuinely shrank."
            ),
            frameworks=[FERPA, COPPA, STATE],
            verify_hint=(
                f"Run the new predicate against a representative non-privileged account and "
                f"compare the row count on `{table}` before and after. Confirm the conditions "
                "that were dropped are enforced somewhere else, and name where."
            ),
            path=sql.path,
            line=statement.start_line,
            end_line=statement.end_line,
            snippet=_snippet(sql, statement),
            surface="policy",
            policy=policy,
            table=table,
            new_roles=sorted(new_roles),
            prior_roles=sorted(old_roles),
        )
    ]


def _column_exposure(
    spec: CheckSpec,
    sql: Any,
    statement: Statement,
    norm: str,
    before_norm: list[str],
    corpus: list[Any],
    lexicon: PiiLexicon,
    table_patterns: list[str],
    per_object: dict[str, set[str]],
    per_schema: dict[str, set[str]],
) -> list[Finding]:
    view = _CREATE_VIEW_RE.match(norm)
    column = _ADD_COLUMN_RE.match(norm)
    if not view and not column:
        return []

    if view:
        key = _table_key(view.group(1))
        kind = "view"
        new_hits = lexicon.matches(norm)
        if not new_hits:
            return []
        prior = _prior_definition_text(key, before_norm, corpus, sql.path)
        if prior is None:
            # No earlier definition anywhere: this is a brand new view, not a
            # widening of an existing one. Out of scope for this check.
            return []
        prior_tokens = {t for t, _ in lexicon.matches(prior)}
        added_hits = [(t, lbl) for t, lbl in new_hits if t not in prior_tokens]
        if not added_hits:
            return []
        detail = (
            f"`{key}` is an existing view, and this PR's definition of it selects "
            f"{_describe(added_hits)} which the previous definition did not."
        )
    else:
        key = _table_key(column.group(1))
        kind = "table"
        name = _unquote(column.group(2))
        label = lexicon.token_label(name)
        if not label:
            return []
        added_hits = [(name, label)]
        detail = f"`ALTER TABLE {key} ADD COLUMN {name}` adds a student-PII column to `{key}`."

    readers = _broad_readers(key, per_object, per_schema)
    if not readers:
        # Without evidence that something broad can already read the object,
        # this is a new column, not a new exposure. Not reported.
        return []

    return [
        _flag(
            spec,
            title=f"Student-PII column added to broadly readable {kind} `{key}`",
            message=(
                f"{detail}\n\n"
                f"`{key}` is already granted read access to "
                f"`{'`, `'.join(sorted(readers))}`, so the new column inherits that audience "
                "immediately. No grant appears in this PR, which is what makes this easy to "
                "miss during review: the line that decided who can read the column was written "
                "in a different migration, possibly years ago, and is not in this diff.\n\n"
                "The question is not whether adding the column is correct - it may well be - but "
                "whether the audience attached to the object is the right audience for *this* "
                "field. A roster view that legitimately exposes names to every signed-in account "
                "is a different proposition once it also exposes a home address or an IEP flag."
            ),
            rationale=(
                "Column-level exposure is inherited from the object, not declared at the column. "
                "Adding a field to an object someone else made world-readable produces a "
                "permission change with no permission statement anywhere in the diff, so no "
                "amount of careful reading of this PR would reveal it. Joining the added column "
                "to the pre-existing grant is the only way to see it, and that join needs the "
                "migration corpus rather than the diff."
            ),
            frameworks=[FERPA, COPPA, STATE],
            verify_hint=(
                f"Check the grants and policies on `{key}` and decide whether the roles that can "
                "already read it should also read this field. If not, the field belongs in a "
                "separate object with its own grants rather than behind a policy exception."
            ),
            path=sql.path,
            line=statement.start_line,
            end_line=statement.end_line,
            snippet=_snippet(sql, statement),
            surface=f"{kind}-column",
            object=key,
            readable_by=sorted(readers),
            pii_columns=[t for t, _ in added_hits],
        )
    ]


def _prior_definition_text(
    key: str, before_norm: list[str], corpus: list[Any], current_path: str
) -> str | None:
    """The most recent earlier definition of a view, or None if there is none."""
    for norm in reversed(before_norm):
        match = _CREATE_VIEW_RE.match(norm)
        if match and _table_key(match.group(1)) == key:
            return norm
    latest: str | None = None
    for sql in corpus:
        if sql.path == current_path:
            continue
        for statement in sql.statements:
            match = _CREATE_VIEW_RE.match(statement.norm)
            if match and _table_key(match.group(1)) == key:
                latest = statement.norm
    return latest


# ==========================================================================
# Shared JS/TS scanning
# ==========================================================================

_COMMENT_START_RE = re.compile(r"^\s*(?://|\*|/\*|#|<!--)")


def _is_comment_line(text: str) -> bool:
    """Approximate, and deliberately so.

    A full JS lexer is out of scope for a check that must never raise. This
    catches the case that matters — a commented-out `console.log(email)`, or
    a JSDoc block naming a PII field — and lets a trailing `// note` on a real
    line through, which is harmless because the real line is the finding.
    """
    return bool(_COMMENT_START_RE.match(text))


@dataclass
class _Window:
    """An added line plus one line either side, as the checks below see it."""

    line: int
    added: str
    text: str


def _js_files(ctx: ReviewContext) -> Iterator[ChangedFile]:
    for changed in ctx.diff.live_files:
        if changed.is_binary:
            continue
        if Path(changed.path).suffix.lower() in JS_SUFFIXES:
            yield changed


def _windows(ctx: ReviewContext, changed: ChangedFile, radius: int = 1) -> Iterator[_Window]:
    """Added lines with their immediate neighbours from the head file.

    Adjacency is read from the head revision rather than from the diff, so a
    single added `console.log(payload)` under an untouched
    `const payload = { email }` is still seen. Only lines this PR added ever
    *originate* a finding; the neighbours supply context, which is the
    compromise DESIGN asks for — report on added lines, but do not pretend a
    statement is one line long.
    """
    lines = ctx.read_lines(changed.path)
    for number, text in changed.added_lines:
        if _is_comment_line(text):
            continue
        if lines and 1 <= number <= len(lines):
            lo, hi = max(1, number - radius), min(len(lines), number + radius)
            window = "\n".join(lines[lo - 1 : hi])
        else:
            window = text
        yield _Window(line=number, added=text, text=window)


def _js_match_paren(text: str, open_index: int) -> int:
    """Index just past the `)` matching `(` at `open_index`, or -1.

    Unlike the SQL helper in `supabase_sql`, this has to cope with three
    quote characters and with backslash escapes, because JS template literals
    routinely contain both parentheses and apostrophes.
    """
    depth = 0
    i, n = open_index, len(text)
    while i < n:
        ch = text[i]
        if ch in "'\"`":
            quote = ch
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def _call_payload(text: str, call_end: int) -> str:
    """The argument list of a call whose `(` sits at `call_end - 1`."""
    open_index = text.rfind("(", 0, call_end)
    if open_index < 0:
        return ""
    close = _js_match_paren(text, open_index)
    if close < 0:
        return text[open_index + 1 :]
    return text[open_index + 1 : close - 1]


@dataclass
class _Cluster:
    """One reportable group: a sink kind in a file, with the lines it hit."""

    path: str
    kind: str
    tokens: list[str] = field(default_factory=list)
    lines: list[int] = field(default_factory=list)
    snippet: str = ""

    def record(self, line: int, tokens: Iterable[str], snippet: str) -> None:
        if not self.lines:
            self.snippet = snippet
        if line not in self.lines:
            self.lines.append(line)
        for token in tokens:
            if token not in self.tokens:
                self.tokens.append(token)

    @property
    def where(self) -> str:
        shown = ", ".join(str(n) for n in self.lines[:5])
        return shown + (f" and {len(self.lines) - 5} more" if len(self.lines) > 5 else "")


# ==========================================================================
# privacy-edu.pii-new-sink
# ==========================================================================

_SINK_PATTERNS: list[tuple[str, str, str]] = [
    (
        "log",
        r"\bconsole\s*\.\s*(?:log|info|warn|error|debug|trace|table|dir)\s*\(",
        "a console log",
    ),
    (
        "log",
        r"\b(?:logger|log|Logger|winston|pino)\s*\.\s*"
        r"(?:log|info|warn|warning|error|debug|trace|fatal|verbose)\s*\(",
        "a logger call",
    ),
    (
        "analytics",
        r"\b(?:track|logEvent|gtag|identify|capture)\s*\(|"
        r"\b(?:posthog|mixpanel|amplitude|analytics|segment|heap)\s*\.\s*\w+\s*\(",
        "an analytics or telemetry event",
    ),
    (
        "email",
        r"\b(?:sendEmail|sendMail|send_mail|sendTemplatedEmail|sendBulkEmail)\s*\(|"
        r"\b(?:MailApp|GmailApp)\s*\.\s*\w+\s*\(|"
        r"\b(?:transporter|mailer|sgMail|ses|resend)\s*\.\s*(?:send\w*|emails)\b",
        "an outbound email",
    ),
    (
        "google",
        r"\b(?:SpreadsheetApp|DriveApp|DocumentApp)\s*\.|"
        r"\.\s*(?:appendRow|setValues|setValue|insertSheet)\s*\(|"
        r"\bspreadsheets\s*\.\s*values\s*\.\s*(?:append|update)\s*\(|"
        r"\bdrive\s*\.\s*files\s*\.\s*(?:create|update)\s*\(",
        "a Google Sheets or Drive write",
    ),
]

DEFAULT_THIRD_PARTY_SDKS: list[str] = [
    "openai", "anthropic", "stripe", "twilio", "sendgrid", "Sentry", "sentry",
    "datadogLogs", "datadogRum", "LogRocket", "FullStory", "hotjar", "Intercom",
    "clarity", "Rollbar", "Bugsnag", "Smartsheet", "airtable", "zapier",
]

DEFAULT_INTERNAL_HOSTS: list[str] = [
    "localhost", "127.0.0.1", "0.0.0.0", "::1", "*.local", "*.internal",
]

_NETWORK_CALL_RE = re.compile(r"\b(?:fetch|axios(?:\s*\.\s*\w+)?|got|superagent)\s*\(")
_URL_RE = re.compile(r"https?://([A-Za-z0-9._\-]+)")


def _external_host(window: str, internal: list[str]) -> str | None:
    for match in _URL_RE.finditer(window):
        host = match.group(1).lower()
        if any(fnmatch.fnmatch(host, p.lower()) for p in internal):
            continue
        return host
    return None


@register(
    "privacy-edu.pii-new-sink",
    default_severity=Severity.HIGH,
    title="Student PII appears to reach a new sink",
    description=(
        "A PII-shaped identifier and a log, analytics, email, Google Sheets/Drive, "
        "third-party SDK or external network call co-occur on lines this PR added. "
        "Nonbinding surface flag, not a dataflow result."
    ),
    applies_to=JS_GLOBS,
)
def pii_new_sink(ctx: ReviewContext, spec: CheckSpec) -> Iterable[Finding]:
    """PII-shaped names next to a call that leaves the process.

    Be clear about what this is: **proximity, not dataflow.** It notices that
    a token whose name looks like student PII appears on the same line as, or
    immediately beside, a call that writes data somewhere it can be read later
    — a log aggregator, an analytics vendor, an inbox, a spreadsheet, a third
    party's API. It does not prove the value reaches the sink, and it will
    miss a case where the PII arrives through a variable named `d`.

    That trade is deliberate. A real dataflow analysis for JavaScript is not
    something to build on stdlib and regex, and the alternative to a proximity
    heuristic here is no check at all. The failure modes are asymmetric in the
    right direction: a false positive costs a reviewer ten seconds, and a
    false negative is the status quo. What makes it acceptable is that the
    finding names the tokens and the sink it saw, so a reader can dismiss it
    without opening the file.

    One tuned exception: the email sink is not reported when the only
    PII-shaped token is the recipient address itself. `sendEmail(email,
    subject, body)` would otherwise fire on every mail call ever written,
    which is the single fastest way to get a pack disabled.
    """
    lexicon = _pii_lexicon(spec)
    sdks = as_list(spec.option("third_party_sdks", DEFAULT_THIRD_PARTY_SDKS))
    internal = as_list(spec.option("internal_hosts", DEFAULT_INTERNAL_HOSTS))
    sink_res = [(kind, re.compile(pattern), label) for kind, pattern, label in _SINK_PATTERNS]
    sdk_re = (
        re.compile(r"\b(?:" + "|".join(re.escape(s) for s in sdks) + r")\s*\.\s*\w+\s*\(")
        if sdks
        else None
    )

    clusters: dict[tuple[str, str], _Cluster] = {}
    labels: dict[tuple[str, str], str] = {}

    for changed in _js_files(ctx):
        for window in _windows(ctx, changed):
            hits = lexicon.matches(window.text)
            if not hits:
                continue
            tokens = [t for t, _ in hits]

            for kind, pattern, label in sink_res:
                if not pattern.search(window.text):
                    continue
                if kind == "email" and all(lbl == "email" for _t, lbl in hits):
                    continue  # the recipient address is not the finding
                key = (changed.path, kind)
                clusters.setdefault(key, _Cluster(changed.path, kind)).record(
                    window.line, tokens, window.added.strip()[:200]
                )
                labels[key] = label

            if sdk_re and sdk_re.search(window.text):
                key = (changed.path, "third-party")
                clusters.setdefault(key, _Cluster(changed.path, "third-party")).record(
                    window.line, tokens, window.added.strip()[:200]
                )
                labels[key] = "a third-party SDK call"

            if _NETWORK_CALL_RE.search(window.text):
                host = _external_host(window.text, internal)
                if host:
                    key = (changed.path, "network")
                    clusters.setdefault(key, _Cluster(changed.path, "network")).record(
                        window.line, tokens, window.added.strip()[:200]
                    )
                    labels[key] = f"an HTTP request to `{host}`"

    findings: list[Finding] = []
    for key in sorted(clusters, key=lambda k: (k[0], k[1])):
        if len(findings) >= MAX_FINDINGS:
            break
        cluster = clusters[key]
        label = labels[key]
        findings.append(
            _flag(
                spec,
                title=f"PII-shaped values near {label} in `{cluster.path}`",
                message=(
                    f"On line(s) {cluster.where} of `{cluster.path}`, this PR added code where "
                    f"{label} sits alongside identifier(s) "
                    f"{_describe((t, '') for t in cluster.tokens)}, whose names match this "
                    "pack's student-PII list.\n\n"
                    "**This is a proximity heuristic, not dataflow analysis.** It sees that the "
                    "names are adjacent; it has not proven the value reaches the sink. If the "
                    "identifier is a column name in a query, a TypeScript type, or a field that "
                    "is redacted before it gets there, this is a false positive and dismissing "
                    "it costs nothing.\n\n"
                    "Where it is not a false positive, the thing to notice is that the sink is "
                    "usually outside the system's own access controls. Log aggregators, "
                    "analytics vendors, inboxes and spreadsheets each have their own retention "
                    "period, their own audience, and in most cases no row level security at "
                    "all - so data that was correctly restricted in the database becomes "
                    "readable by whoever can open the destination."
                ),
                rationale=(
                    "The database's access controls stop at the edge of the database. A student "
                    "record that only two people can query becomes a student record anyone with "
                    "log access can read, indefinitely, the moment it is passed to "
                    f"{label}. That transition happens in one line, produces no error, and is "
                    "invisible in code review unless someone is specifically looking for it - "
                    "which is the gap this check exists to fill, at the cost of some false "
                    "positives it reports honestly."
                ),
                frameworks=[FERPA, COPPA, STATE],
                verify_hint=(
                    "Read the line and decide whether a real student value reaches the "
                    "destination. If it does, check who can read that destination, how long it "
                    "retains data, and - for anything leaving your infrastructure - whether "
                    "the vendor is covered by an existing data-privacy agreement."
                ),
                path=cluster.path,
                line=cluster.lines[0],
                snippet=cluster.snippet,
                sink=cluster.kind,
                identifiers=cluster.tokens[:12],
                hit_lines=cluster.lines[:20],
                detection="proximity-heuristic",
            )
        )
    return findings


# ==========================================================================
# privacy-edu.analytics-student-identifier
# ==========================================================================

_ANALYTICS_CALL_RE = re.compile(
    r"\b(?:track|logEvent|gtag|identify)\s*\(|"
    r"\bposthog\s*\.\s*capture\s*\(|"
    r"\bmixpanel\s*\.\s*(?:track|identify|people\s*\.\s*set)\s*\(|"
    r"\banalytics\s*\.\s*\w+\s*\(|"
    r"\b(?:amplitude|heap|segment)\s*\.\s*\w+\s*\("
)


@register(
    "privacy-edu.analytics-student-identifier",
    default_severity=Severity.HIGH,
    title="New analytics event carries a student identifier",
    description=(
        "A telemetry call added by this PR has a student identifier or PII-shaped field in "
        "its payload. Nonbinding: names the frameworks, does not decide compliance."
    ),
    applies_to=JS_GLOBS,
)
def analytics_student_identifier(ctx: ReviewContext, spec: CheckSpec) -> Iterable[Finding]:
    """Telemetry that can be tied back to a specific child.

    Separate from `pii-new-sink` even though analytics is one of its sinks,
    because the question is different. `pii-new-sink` asks "did data leave".
    This asks "is the stream that left *identifiable*", which is the COPPA
    question and the one a state student-privacy statute is most likely to
    have an opinion about. An event carrying `{grade: 4, correct: true}` is
    ordinary product telemetry; the same event carrying `{studentId}` is a
    per-child behavioural record held by a vendor.

    The payload is read by bracket-matching from the call's opening paren, so
    an identifier that merely appears on the same line outside the call —
    `if (studentId) track('seen')` — is not reported. That is the main
    precision win over the proximity check, and it is why this can be a
    narrower, more confident finding.

    Two grades of hit are distinguished in the message: a direct student
    identifier (`student_id`, `sis_id`), and a PII-shaped field that is not
    inherently a student identifier (`email`, `dob`). The second is still
    reported, because in a TK-8 product the account behind an email address
    is overwhelmingly likely to be a child's, but the message says which kind
    it found so the reader can weigh it.
    """
    pii = _pii_lexicon(spec)
    students = PiiLexicon(
        as_list(spec.option("student_identifiers", DEFAULT_STUDENT_IDENTIFIERS))
        or DEFAULT_STUDENT_IDENTIFIERS
    )

    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    for changed in _js_files(ctx):
        for window in _windows(ctx, changed, radius=3):
            if len(findings) >= MAX_FINDINGS:
                return findings
            # The call must be on the line this PR added, not merely nearby;
            # otherwise every edit inside an existing instrumented block
            # re-reports the same event. The added line's offset within the
            # window is then used to read *this* call's arguments - anchoring
            # on the window's first match instead attributes a neighbouring
            # `track()`'s payload to this one, which is how a check starts
            # reporting fields that are not there.
            match = _ANALYTICS_CALL_RE.search(window.added)
            if not match:
                continue
            key = (changed.path, window.line)
            if key in seen:
                continue

            offset = window.text.find(window.added)
            scope = window.text if offset >= 0 else window.added
            payload = _call_payload(scope, max(offset, 0) + match.end())
            if not payload.strip():
                continue

            direct = students.matches(payload)
            indirect = [h for h in pii.matches(payload) if h[0] not in {t for t, _ in direct}]
            if not direct and not indirect:
                continue

            seen.add(key)
            call = window.added.strip()[:200]
            if direct:
                headline = (
                    f"the payload names {_describe(direct)}, which identif"
                    f"{'y' if len(direct) > 1 else 'ies'} a specific student"
                )
                kind = "direct-identifier"
            else:
                headline = (
                    f"the payload names {_describe(indirect)}, which is PII-shaped rather than "
                    "an explicit student identifier - but in a TK-8 product the person behind "
                    "it is almost certainly a child"
                )
                kind = "pii-shaped-field"

            extra = f" It also carries {_describe(indirect)}." if direct and indirect else ""

            findings.append(
                _flag(
                    spec,
                    title=f"Analytics event in `{changed.path}` carries a student identifier",
                    message=(
                        f"Line {window.line} of `{changed.path}` adds a telemetry call and "
                        f"{headline}.{extra}\n\n"
                        f"```\n{call}\n```\n\n"
                        "Once an event stream is keyed to an individual student it stops being "
                        "product analytics and becomes a per-child behavioural record held by "
                        "whoever receives it. That record has a retention policy you did not "
                        "write, an access list you do not control, and - if the vendor is not "
                        "already covered by an agreement - a recipient nobody has reviewed.\n\n"
                        "The usual mitigations, none of which this check can see for you: send "
                        "an opaque per-install pseudonym instead of the SIS identifier, drop the "
                        "field and aggregate server-side, or confirm the vendor is already under "
                        "a data-privacy agreement that names this category of data."
                    ),
                    rationale=(
                        "Analytics payloads are the least-reviewed data egress in a codebase. "
                        "They are added to answer a product question, they are one object "
                        "literal long, they never fail, and nobody diffs them again. Attaching "
                        "a student identifier to one converts anonymous usage data into "
                        "identifiable records about minors, held by a third party, with no "
                        "change visible anywhere in the application's own behaviour. Reading "
                        "the bracket-matched payload rather than the surrounding line keeps "
                        "this specific enough to be worth reading every time it fires."
                    ),
                    frameworks=[COPPA, FERPA, STATE],
                    verify_hint=(
                        "Identify the service receiving this event and confirm (a) whether a "
                        "data-privacy or student-data agreement with that vendor is already in "
                        "place and covers identifiable minor data, and (b) whether the "
                        "identifier can be replaced with a pseudonym that does not resolve back "
                        "to the SIS."
                    ),
                    path=changed.path,
                    line=window.line,
                    snippet=call,
                    identifiers=[t for t, _ in direct] or [t for t, _ in indirect],
                    identifier_kind=kind,
                )
            )

    return findings


# ==========================================================================
# privacy-edu.pii-in-url
# ==========================================================================

_QUERY_PARAM_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_\-]*)=")
_SEARCH_PARAM_RE = re.compile(
    r"(?:searchParams|params|query|qs)\s*\.\s*(?:set|append)\s*\(\s*[\"'`]([^\"'`]+)[\"'`]"
)
_URLSEARCHPARAMS_RE = re.compile(r"\bnew\s+URLSearchParams\s*\(")
_REDIRECT_RE = re.compile(
    r"\bwindow\s*\.\s*location(?:\s*\.\s*(?:href|assign|replace|search|pathname))?\s*(?:=|\()|"
    r"\blocation\s*\.\s*(?:href|assign|replace)\s*(?:=|\()|"
    r"\bres\s*\.\s*redirect\s*\(|"
    r"\b(?:navigate|router\s*\.\s*(?:push|replace)|redirect)\s*\("
)
_URLISH_TEMPLATE_RE = re.compile(r"`[^`]*(?:https?://|/)[^`]*\$\{[^}]+\}[^`]*`")


@register(
    "privacy-edu.pii-in-url",
    default_severity=Severity.HIGH,
    title="Student PII placed in a URL",
    description=(
        "A PII-shaped value in a URL path, query string, redirect target or "
        "`window.location` assignment. Nonbinding surface flag."
    ),
    applies_to=JS_GLOBS,
)
def pii_in_url(ctx: ReviewContext, spec: CheckSpec) -> Iterable[Finding]:
    """PII in a URL, which is the leakiest place to put it.

    A URL is not a private channel. It is written to the browser history of a
    shared classroom device, to the server access log of every host it passes
    through, to the `Referer` header sent to whatever third-party script the
    next page loads, and into whatever link-shortening or chat preview service
    someone pastes it into. None of these are covered by the application's own
    access controls and several are not under its control at all.

    This is why the check is separate from `pii-new-sink` despite the overlap:
    a URL is a sink with an unbounded and mostly invisible audience, and
    "identifiers belong in the body, not the path" is a rule that can be
    applied without knowing anything about the feature.

    Four constructions are matched: a literal `?field=` / `&field=` where the
    field name is PII-shaped; a `searchParams.set('field', ...)` or
    `params.append(...)` with a PII-shaped key; a `URLSearchParams(...)`
    constructed from a PII-shaped identifier; and a URL-shaped template
    literal or redirect target with a PII-shaped interpolation.
    """
    lexicon = _pii_lexicon(spec)
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    for changed in _js_files(ctx):
        for window in _windows(ctx, changed):
            if len(findings) >= MAX_FINDINGS:
                return findings
            key = (changed.path, window.line)
            if key in seen:
                continue

            construction: str | None = None
            tokens: list[str] = []

            for match in _QUERY_PARAM_RE.finditer(window.added):
                if lexicon.token_label(match.group(1)):
                    construction = "a literal query-string parameter"
                    tokens.append(match.group(1))

            if not construction:
                for match in _SEARCH_PARAM_RE.finditer(window.added):
                    if lexicon.token_label(match.group(1)):
                        construction = "a query parameter set through `URLSearchParams`"
                        tokens.append(match.group(1))

            usp = _URLSEARCHPARAMS_RE.search(window.added)
            if not construction and usp:
                hits = lexicon.matches(_call_payload(window.added, usp.end()))
                if hits:
                    construction = "a `URLSearchParams` payload"
                    tokens = [t for t, _ in hits]

            if not construction:
                template = _URLISH_TEMPLATE_RE.search(window.added)
                if template:
                    hits = lexicon.matches(template.group(0))
                    if hits:
                        construction = "a URL built from a template literal"
                        tokens = [t for t, _ in hits]

            if not construction and _REDIRECT_RE.search(window.added):
                hits = lexicon.matches(window.added)
                if hits:
                    construction = "a navigation or redirect target"
                    tokens = [t for t, _ in hits]

            if not construction or not tokens:
                continue

            seen.add(key)
            findings.append(
                _flag(
                    spec,
                    title=f"Student PII in a URL in `{changed.path}`",
                    message=(
                        f"Line {window.line} of `{changed.path}` puts "
                        f"{_describe((t, '') for t in tokens)} into {construction}.\n\n"
                        f"```\n{window.added.strip()[:200]}\n```\n\n"
                        "A URL is the least private part of a request. It is recorded in browser "
                        "history on devices that in a school are shared between children; in the "
                        "access logs of every proxy, CDN and server on the path, usually with a "
                        "longer retention than the application's own data; and in the `Referer` "
                        "header sent to any third-party script the destination page loads. It is "
                        "also the part of a request people copy and paste.\n\n"
                        "The standard fix is to move the identifier into the request body for a "
                        "write, or to use an opaque token that the server resolves for a read. "
                        "If the value must appear in a link - a per-student report URL, say - a "
                        "short-lived signed token is what keeps the link from being both "
                        "permanent and guessable."
                    ),
                    rationale=(
                        "Every other sink in this pack has one audience you can enumerate. A URL "
                        "has several you cannot: shared-device browser history, upstream access "
                        "logs, and the `Referer` header. A student identifier in a path is "
                        "therefore disclosed to parties that never appear anywhere in the "
                        "codebase, and it stays disclosed after the record itself is deleted, "
                        "because log retention is set by someone else. Moving it into the body "
                        "costs one line and removes the entire category."
                    ),
                    frameworks=[FERPA, COPPA, STATE],
                    verify_hint=(
                        "Confirm whether this URL is logged by your hosting provider or CDN and "
                        "for how long, and whether the page it reaches loads any third-party "
                        "script that would receive it as a `Referer`. If the identifier must be "
                        "in the link, check that it is opaque and expiring rather than the "
                        "durable SIS identifier."
                    ),
                    path=changed.path,
                    line=window.line,
                    snippet=window.added.strip()[:200],
                    construction=construction,
                    identifiers=tokens[:12],
                )
            )

    return findings


# ==========================================================================
# privacy-edu.test-data-bleed
# ==========================================================================

DEFAULT_TEST_PATH_GLOBS: list[str] = [
    "test/", "tests/", "__tests__/", "__mocks__/", "spec/", "specs/",
    "fixture/", "fixtures/", "seed/", "seeds/", "mock/", "mocks/",
    "demo/", "sample/", "samples/", "e2e/", "cypress/", "playwright/",
    "*.test.*", "*.spec.*", "*seed*.sql", "*fixture*", "*.stories.*",
]

#: Domains that announce themselves as fake. A fixture using one of these is
#: a fixture doing the right thing, and firing on it would penalise exactly
#: the behaviour this check wants to encourage.
SYNTHETIC_DOMAINS: set[str] = {
    "example.com", "example.org", "example.net", "example.edu",
    "test.com", "test.org", "testing.com", "localhost", "invalid",
    "domain.com", "email.com", "sample.com", "fake.com", "dummy.com",
    "foo.com", "bar.com", "acme.com", "nowhere.com", "noreply.com",
    "mailinator.com", "yopmail.com", "mailtrap.io", "ethereal.email",
}
_SYNTHETIC_TLDS = (".example", ".test", ".invalid", ".localhost", ".local")

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})")
_NAME_VALUE_RE = re.compile(
    r"[\"']?(?:first_?name|last_?name|student_?name|full_?name|legal_?name)[\"']?\s*[:=]\s*"
    r"[\"']([A-Z][a-z]{1,20}(?:[ '\-][A-Z][a-z]{1,20})*)[\"']",
    re.IGNORECASE,
)
_DOB_VALUE_RE = re.compile(
    r"[\"']?(?:dob|date_?of_?birth|birth_?date|birthday)[\"']?\s*[:=]\s*"
    r"[\"']?((?:19|20)\d\d-\d\d-\d\d|\d{1,2}/\d{1,2}/(?:19|20)\d\d)",
    re.IGNORECASE,
)
_TEST_LOCALPART_RE = re.compile(
    r"\b(?:test|tester|demo|qa|sandbox|sample|fixture|dummy|fake|seed|e2e|staging)"
    r"[._\-+0-9]*@",
    re.IGNORECASE,
)
_TEST_CONST_RE = re.compile(
    r"\b(?:TEST|DEMO|MOCK|FAKE|STUB|SEED|QA|SANDBOX|DUMMY)_[A-Z0-9_]*"
    r"(?:USER|ACCOUNT|EMAIL|LOGIN|STUDENT|CREDENTIAL)S?\b"
)

SCANNED_SUFFIXES = JS_SUFFIXES | {".py", ".sql", ".json", ".yml", ".yaml", ".csv"}


#: Values that occupy a name field without being a name.
_PLACEHOLDER_NAMES = {
    "test", "testing", "tester", "demo", "sample", "example", "foo", "bar",
    "baz", "qux", "dummy", "fake", "mock", "stub", "student", "teacher",
    "user", "first", "last", "name", "firstname", "lastname", "fullname",
    "johndoe", "janedoe", "doe", "anon", "anonymous", "placeholder", "todo",
    "lorem", "ipsum", "alice", "bob", "aaa", "abc", "xyz",
}


def _synthetic_domain(domain: str) -> bool:
    low = domain.lower()
    return low in SYNTHETIC_DOMAINS or low.endswith(_SYNTHETIC_TLDS)


def _realistic_name(value: str) -> bool:
    """Does this name-field value look like it belongs to an actual person?

    The regex that finds these only knows "capitalised word in a name field",
    which `"Aaa"` and `"Test"` satisfy as happily as `"Marisol"` does. Without
    this filter the two-signal rule fires on the correct, obviously-synthetic
    fixture, which is the one case the check most needs to stay quiet about.

    Three cheap tests, all about placeholder shape rather than about names:
    a known placeholder word, fewer than three distinct letters (`Aaa`,
    `Bbb`), or too short to be a name at all.
    """
    flat = re.sub(r"[^A-Za-z]", "", value).lower()
    if len(flat) < 3:
        return False
    if flat in _PLACEHOLDER_NAMES:
        return False
    if any(part.lower() in _PLACEHOLDER_NAMES for part in re.split(r"[ '\-]+", value) if part):
        return False
    return len(set(flat)) >= 3


@register(
    "privacy-edu.test-data-bleed",
    default_severity=Severity.MEDIUM,
    title="Real-looking student data in fixtures, or test accounts in production code",
    description=(
        "Realistic names, dates of birth and live-domain email addresses in seed/fixture/test "
        "files, or hardcoded test and demo accounts in production source. Nonbinding."
    ),
    applies_to=[
        "*.js", "*.jsx", "*.ts", "*.tsx", "*.mjs", "*.cjs", "*.gs",
        "*.json", "*.sql", "*.py", "*.csv", "*.yml", "*.yaml",
    ],
)
def test_data_bleed(ctx: ReviewContext, spec: CheckSpec) -> Iterable[Finding]:
    """Data crossing the line between the real system and the fake one.

    Two directions, one rule, because they are the same mistake seen from
    either side and a reviewer thinks about them together.

    *Real data into fixtures.* Someone needed test data, exported twenty rows
    from the SIS, and committed them. It works perfectly, which is the
    problem: the file now holds real children's names, birthdates and contact
    addresses, in a repository with a wider read audience than the database
    they came from, in git history forever, and copied to every developer
    machine and CI runner that ever checks the branch out. A fixture is not
    covered by the access controls the data was living under.

    *Test accounts into production.* The reverse leak. A hardcoded
    `demo@school.org` in a non-test code path is usually a bypass someone
    left in, and a bypass in an application holding student records is an
    access-control hole with a friendly name.

    The fixture half deliberately requires **two independent signals** from
    {a capitalised name assigned to a name field, a parseable date of birth,
    an email on a domain that is not obviously synthetic}. One signal alone is
    what normal, correct fixtures look like. Synthetic domains — anything at
    `example.com` or under `.test` / `.invalid` — are excluded entirely.
    """
    test_globs = as_list(spec.option("test_path_globs", DEFAULT_TEST_PATH_GLOBS))
    test_globs = test_globs or DEFAULT_TEST_PATH_GLOBS
    findings: list[Finding] = []

    for changed in ctx.diff.live_files:
        if len(findings) >= MAX_FINDINGS:
            break
        if changed.is_binary or changed.kind is ChangeKind.DELETED:
            continue
        if Path(changed.path).suffix.lower() not in SCANNED_SUFFIXES:
            continue
        added = "\n".join(t for _, t in changed.added_lines)
        if not added.strip():
            continue

        if glob_match(changed.path, test_globs):
            finding = _fixture_bleed(spec, changed, added)
        else:
            finding = _production_test_account(spec, changed)
        if finding is not None:
            findings.append(finding)

    return findings


def _fixture_bleed(spec: CheckSpec, changed: ChangedFile, added: str) -> Finding | None:
    names = [m.group(1) for m in _NAME_VALUE_RE.finditer(added) if _realistic_name(m.group(1))]
    dobs = [m.group(1) for m in _DOB_VALUE_RE.finditer(added)]
    emails = [m.group(0) for m in _EMAIL_RE.finditer(added) if not _synthetic_domain(m.group(1))]

    if sum([bool(names), bool(dobs), bool(emails)]) < 2:
        return None

    line = next(
        (
            n
            for n, t in changed.added_lines
            if _NAME_VALUE_RE.search(t) or _DOB_VALUE_RE.search(t) or _EMAIL_RE.search(t)
        ),
        None,
    )

    detail = []
    if names:
        detail.append(f"{len(names)} name field(s) with capitalised human-looking values")
    if dobs:
        detail.append(f"{len(dobs)} parseable date(s) of birth")
    if emails:
        domains = sorted({e.split("@")[1].lower() for e in emails})[:4]
        detail.append(
            f"{len(emails)} email address(es) on non-synthetic domain(s) "
            f"({', '.join('`' + d + '`' for d in domains)})"
        )

    return _flag(
        spec,
        title=f"`{changed.path}` looks like it contains real student data",
        message=(
            f"`{changed.path}` is a test, seed or fixture file, and the lines this PR adds "
            "contain " + "; ".join(detail) + ".\n\n"
            "Two or more of those signals together is the shape of an export from a live "
            "system rather than of hand-written fixture data. If that is what it is, the "
            "records have moved from a database with access controls into a git repository "
            "with a different and usually wider audience - and into the history of every "
            "clone, fork and CI cache, where deleting the file later does not remove them.\n\n"
            "If the data is synthetic and merely realistic, this is a false positive. It is "
            "worth making that obvious anyway: `@example.com` addresses and clearly invented "
            "names cost nothing and mean nobody has to ask this question again, including this "
            "check, which excludes synthetic domains entirely."
        ),
        rationale=(
            "Fixture files are the one place student data escapes without any deliberate "
            "decision being made. Nobody grants access to a fixture; it simply inherits the "
            "repository's audience, which is larger than the database's and includes every "
            "machine that has ever cloned the branch. Requiring two independent signals keeps "
            "this quiet on ordinary fixtures, and excluding `example.com` and `.test` means the "
            "check never penalises the correct behaviour."
        ),
        frameworks=[FERPA, COPPA, STATE],
        verify_hint=(
            "Ask the author where this data came from. If any of it originated in the SIS or "
            "the production database, it needs replacing with synthetic values, and the commits "
            "that carried it should be treated as a disclosure rather than simply reverted."
        ),
        path=changed.path,
        line=line,
        signals={"names": len(names), "dobs": len(dobs), "live_domain_emails": len(emails)},
        detection="fixture-realism",
    )


def _production_test_account(spec: CheckSpec, changed: ChangedFile) -> Finding | None:
    hits: list[tuple[int, str]] = []
    for number, text in changed.added_lines:
        if _is_comment_line(text):
            continue
        email = _EMAIL_RE.search(text)
        if not email:
            continue
        address = email.group(0)
        if (
            _TEST_LOCALPART_RE.search(address)
            or _synthetic_domain(email.group(1))
            or _TEST_CONST_RE.search(text)
        ):
            hits.append((number, address))

    if not hits:
        return None

    lines = ", ".join(str(n) for n, _ in hits[:5])
    accounts = ", ".join(f"`{a}`" for a in dict.fromkeys(a for _, a in hits))[:300]

    return _flag(
        spec,
        title=f"Test or demo account hardcoded in `{changed.path}`",
        message=(
            f"`{changed.path}` is not a test file, and this PR adds {accounts} at line(s) "
            f"{lines}.\n\n"
            "A hardcoded test or demo address in a production code path is almost always one of "
            "three things: a bypass that skips a permission check for a known account, a "
            "recipient that was meant to be configuration, or a leftover from local debugging. "
            "The first is an access-control hole with a reassuring name - and in a system "
            "holding student records, an account that skips checks is an account that can read "
            "children's data without appearing in any policy.\n\n"
            "If the address is a legitimate service account, move it into configuration so it "
            "is visible and rotatable. If it is fixture data that ended up in the wrong file, "
            "move the data."
        ),
        rationale=(
            "Special-cased accounts are invisible to every other control in the system. They do "
            "not appear in a role, a grant or a policy, so reviewing the access model will "
            "never reveal them; the only place they exist is a string comparison somewhere in "
            "application code. That is precisely what a diff-time check can see and nothing "
            "else will, which is why it is worth one `medium` finding even though many hits "
            "turn out to be harmless."
        ),
        frameworks=[FERPA, STATE],
        verify_hint=(
            "Trace what this address is compared against. If it gates a permission check, "
            "confirm the account cannot be registered by anyone outside the intended set, and "
            "prefer moving the decision into the role or policy model where it is auditable."
        ),
        path=changed.path,
        line=hits[0][0],
        snippet=hits[0][1],
        accounts=[a for _, a in hits[:10]],
        detection="test-account-in-production",
    )
