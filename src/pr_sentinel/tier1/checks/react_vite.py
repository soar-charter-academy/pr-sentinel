"""`react-vite` pack script checks.

Two rules, both about the same underlying fact: **the client bundle is
public.** Everything Vite compiles into it — every `VITE_`-prefixed variable,
every value substituted through `define:` — is shipped to the browser and can
be read by anyone who opens devtools or fetches the asset. There is no
runtime, no server, and no obscurity involved; a "secret" in a client bundle
is a published secret with a delay.

`client-env-secrets` is `critical` because it is the one mistake in this pack
that cannot be undone by a follow-up commit. Once a key has been served in an
asset it is compromised, and the remediation is rotation, not deletion.

`browser-storage` is the quieter of the two and is scoped accordingly: by
default it reports only PII-shaped values being written to browser storage,
because "this project uses localStorage" is not a finding. The
unsupported-context mode — where the project's rendering context does not
have working browser storage at all — is opt-in via a path-glob option, since
only the consuming repo knows which of its files run inside a sandboxed
iframe, a service worker, or a server render.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING

from ...diff import ChangedFile
from ...models import Finding, Severity
from .base import CheckSpec, register
from .util import as_list, glob_match
from .privacy_edu import (
    DEFAULT_PII_COLUMNS,
    JS_GLOBS,
    JS_SUFFIXES,
    PiiLexicon,
    _is_comment_line,
)

if TYPE_CHECKING:  # pragma: no cover
    from ...context import ReviewContext


MAX_FINDINGS = 20

ENV_GLOBS = [".env", ".env.*"]
VITE_CONFIG_GLOBS = ["vite.config.*", "vitest.config.*"]


# ==========================================================================
# react-vite.client-env-secrets
# ==========================================================================

#: Name shapes that say "this value authenticates something". Checked as
#: whole words against the `_`-separated name, so `KEYBOARD_LAYOUT` does not
#: match `_KEY`.
_SECRET_WORDS = {
    "secret", "token", "password", "passwd", "pwd", "credential", "credentials",
    "private", "privatekey", "apikey", "accesskey", "signingkey", "clientsecret",
}

#: `*_KEY` is secret-bearing by default. These three suffixes are the
#: documented exceptions: a Supabase anon key, a Stripe publishable key and
#: anything explicitly named public are *designed* to ship to the client, and
#: firing on them would make the rule wrong on the single most common line in
#: a Vite `.env` file.
_PUBLIC_KEY_SUFFIXES = ("_PUBLIC_KEY", "_ANON_KEY", "_PUBLISHABLE_KEY")

_SERVICE_ROLE_RE = re.compile(r"SERVICE_ROLE", re.IGNORECASE)

_ENV_ASSIGN_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")
_IMPORT_META_RE = re.compile(r"\bimport\s*\.\s*meta\s*\.\s*env\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)")
_IMPORT_META_INDEX_RE = re.compile(
    r"\bimport\s*\.\s*meta\s*\.\s*env\s*\[\s*[\"']([A-Za-z_][A-Za-z0-9_]*)[\"']\s*\]"
)
_PROCESS_ENV_RE = re.compile(r"\bprocess\s*\.\s*env\s*(?:\.\s*|\[\s*[\"'])([A-Za-z_][A-Za-z0-9_]*)")
_DEFINE_RE = re.compile(r"\bdefine\s*:")

DEFAULT_CLIENT_ROOTS = [
    "src/", "app/", "client/", "frontend/", "web/", "components/", "pages/",
    "islands/", "public/",
]


def _secret_shape(name: str) -> str | None:
    """Why this variable name looks secret-bearing, or None.

    Returns a phrase, not a boolean, because the finding has to say *why* it
    fired — a rule that reports `VITE_STRIPE_KEY` without explaining which
    part of the name triggered it is a rule people argue with instead of fix.
    """
    upper = name.upper()
    if _SERVICE_ROLE_RE.search(upper):
        return "it names `SERVICE_ROLE`"
    if upper.endswith(_PUBLIC_KEY_SUFFIXES):
        return None  # designed to be public; see _PUBLIC_KEY_SUFFIXES
    words = [w for w in upper.split("_") if w]
    if not words:
        return None
    lowered = [w.lower() for w in words]
    for word in lowered:
        if word in _SECRET_WORDS:
            return f"it contains `{word.upper()}`"
    if lowered[-1] == "key":
        return "it ends in `_KEY`"
    if "private" in "".join(lowered):
        return "it contains `PRIVATE`"
    return None


def _is_env_file(path: str) -> bool:
    name = Path(path.replace("\\", "/")).name.lower()
    return name == ".env" or name.startswith(".env.")


def _in_client_root(path: str, roots: list[str]) -> bool:
    norm = path.replace("\\", "/").lstrip("./")
    return any(norm.startswith(r.strip("/") + "/") or glob_match(norm, [r]) for r in roots)


def _scannable(ctx: ReviewContext) -> Iterator[ChangedFile]:
    for changed in ctx.diff.live_files:
        if not changed.is_binary:
            yield changed


@register(
    "react-vite.client-env-secrets",
    default_severity=Severity.CRITICAL,
    title="Secret-shaped value reachable from the client bundle",
    description=(
        "A `VITE_`-prefixed or `define:`-injected variable whose name looks secret-bearing. "
        "Anything prefixed `VITE_` is compiled into the bundle and is public."
    ),
    applies_to=JS_GLOBS + ENV_GLOBS + VITE_CONFIG_GLOBS,
)
def client_env_secrets(ctx: ReviewContext, spec: CheckSpec) -> Iterable[Finding]:
    """Secrets that Vite will compile into a file the browser downloads.

    The `VITE_` prefix is not a namespace. It is an instruction: Vite inlines
    every variable carrying it as a literal string into the built JavaScript,
    which is then served as a static asset. There is no server-side step, no
    request-time substitution, and nothing to configure differently in
    production. A `VITE_`-prefixed secret is published the moment the site
    deploys, and it stays published in whatever CDN caches and archive copies
    the asset reached.

    `SERVICE_ROLE` is the worst case and is called out separately. A Supabase
    service-role key bypasses row level security entirely — it is the
    credential every policy in the database is written to keep people away
    from. Shipping it to the browser does not weaken access control; it
    removes it, for every table, for anyone who views source. In this
    codebase that means the entire student record set (DESIGN s8, s11).

    Four surfaces are examined: declarations in `.env*` files, reads of
    `import.meta.env.VITE_*` in source, values injected through `define:` in
    a Vite config, and `process.env.*` secret-shaped reads in files under a
    client source root — where the bundler will inline them just the same.

    `VITE_SUPABASE_ANON_KEY`, `VITE_STRIPE_PUBLISHABLE_KEY` and anything
    ending `_PUBLIC_KEY` are excluded by name. Those are designed to be
    public; a rule that flags them is wrong on the most common line in a Vite
    `.env` file and gets switched off within a day.
    """
    roots = as_list(spec.option("client_roots", DEFAULT_CLIENT_ROOTS)) or DEFAULT_CLIENT_ROOTS
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    for changed in _scannable(ctx):
        suffix = Path(changed.path).suffix.lower()
        env_file = _is_env_file(changed.path)
        vite_config = glob_match(changed.path, VITE_CONFIG_GLOBS)
        source = suffix in JS_SUFFIXES
        if not (env_file or vite_config or source):
            continue

        define_block = vite_config and _DEFINE_RE.search(ctx.read(changed.path) or "") is not None

        for number, text in changed.added_lines:
            if len(findings) >= MAX_FINDINGS:
                return findings
            if _is_comment_line(text):
                continue

            for name, surface in _candidates(text, env_file, source, define_block):
                if not name.startswith("VITE_") and surface == "env-declaration":
                    # A non-`VITE_` variable in `.env` is never bundled. That
                    # is the whole point of the prefix, and flagging it would
                    # make this rule fire on every correct server-side secret.
                    continue
                if surface == "process-env" and not _in_client_root(changed.path, roots):
                    continue
                reason = _secret_shape(name)
                if not reason:
                    continue
                key = (changed.path, name)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    _secret_finding(spec, changed.path, number, text, name, reason, surface)
                )

    return findings


def _candidates(
    text: str, env_file: bool, source: bool, define_block: bool
) -> list[tuple[str, str]]:
    """(variable name, surface) pairs visible on one added line."""
    out: list[tuple[str, str]] = []
    if env_file:
        match = _ENV_ASSIGN_RE.match(text)
        if match:
            out.append((match.group(1), "env-declaration"))
    if source or define_block:
        for pattern in (_IMPORT_META_RE, _IMPORT_META_INDEX_RE):
            out.extend((m.group(1), "import-meta-env") for m in pattern.finditer(text))
        surface = "vite-define" if define_block else "process-env"
        out.extend((m.group(1), surface) for m in _PROCESS_ENV_RE.finditer(text))
    return out


_SURFACE_PHRASE = {
    "env-declaration": (
        "declared in an environment file with the `VITE_` prefix, which tells Vite to inline "
        "it into the client bundle"
    ),
    "import-meta-env": (
        "read through `import.meta.env`, which Vite replaces at build time with the literal "
        "value in the emitted JavaScript"
    ),
    "vite-define": (
        "injected through `define:` in the Vite config, which performs a literal text "
        "substitution into the bundle - the `VITE_` prefix is not even required for this one"
    ),
    "process-env": (
        "read from `process.env` inside a client source root, where the bundler inlines it "
        "into the shipped JavaScript exactly as it would a `VITE_` variable"
    ),
}


def _secret_finding(
    spec: CheckSpec, path: str, line: int, text: str, name: str, reason: str, surface: str
) -> Finding:
    service_role = bool(_SERVICE_ROLE_RE.search(name))
    phrase = _SURFACE_PHRASE.get(surface, "reachable from the client bundle")

    if service_role:
        emphasis = (
            "\n\n**This is the worst case.** A `service_role` key bypasses row level security "
            "by design - it is the credential every policy in the database exists to keep "
            "people away from. In the browser it is not a weakened control, it is no control: "
            "anyone who views source gets full read and write on every table, including the "
            "student records that RLS was written to protect. Treat this key as compromised "
            "from the moment the asset was served, rotate it in the Supabase dashboard, and "
            "move whatever needed it to an edge function or another server-side context.\n"
        )
    else:
        emphasis = (
            "\n\nIf this value is genuinely public - a Supabase anon key, a Stripe publishable "
            "key, a restricted-by-referrer Maps key - then it belongs in the bundle and this is "
            "a false positive worth dismissing with that reason. Renaming it to end in "
            "`_PUBLIC_KEY`, `_ANON_KEY` or `_PUBLISHABLE_KEY` makes the intent explicit and "
            "stops this check from asking again.\n"
        )

    return spec.finding(
        title=f"`{name}` is a secret-shaped value in the client bundle",
        message=(
            f"`{name}` is {phrase}, and {reason}.\n\n"
            f"```\n{text.strip()[:200]}\n```\n\n"
            "The client bundle is a static file served to every visitor. There is no runtime "
            "substitution step and no environment to configure differently in production - "
            "whatever Vite inlines at build time is in the JavaScript that ships, readable by "
            "anyone who opens devtools or fetches the asset directly."
            f"{emphasis}\n"
            "If the value is a real secret, the fix is always the same shape: keep it "
            "server-side and put an endpoint in front of it. Remove the `VITE_` prefix, move "
            "the call into an edge function, a serverless route or a backend service, and have "
            "the client ask that endpoint instead of holding the credential."
        ),
        rationale=(
            "A secret in a client bundle is not at risk of exposure; it is already exposed, to "
            "everyone, from the moment the site deploys. That makes this unusual among "
            "findings - deleting the line in a follow-up commit fixes the source and does "
            "nothing about the credential, because the built asset was already downloaded and "
            "may still sit in a CDN cache. The only remediation is rotation, and rotation is "
            "cheap now and expensive after someone finds it. The name-shape heuristic is "
            "deliberately loose with three documented exclusions, because the cost of asking "
            "about a publishable key is a dismissal and the cost of missing a service-role key "
            "is the entire database."
        ),
        path=path,
        line=line,
        snippet=text.strip()[:200],
        variable=name,
        surface=surface,
        service_role=service_role,
    )


# ==========================================================================
# react-vite.browser-storage
# ==========================================================================

_STORAGE_RE = re.compile(
    r"\b(localStorage|sessionStorage|indexedDB|window\s*\.\s*localStorage|"
    r"window\s*\.\s*sessionStorage)\b"
)
_STORAGE_WRITE_RE = re.compile(
    r"\b(?:localStorage|sessionStorage)\s*(?:\.\s*setItem\s*\(|\[\s*[\"'`][^\"'`]+[\"'`]\s*\]\s*=|"
    r"\.\s*[A-Za-z_$][A-Za-z0-9_$]*\s*=)|"
    r"\b(?:objectStore|store)\s*\.\s*(?:put|add)\s*\("
)


@register(
    "react-vite.browser-storage",
    default_severity=Severity.MEDIUM,
    title="Browser storage holding PII, or used where it does not work",
    description=(
        "By default, PII-shaped values written to `localStorage`/`sessionStorage`/"
        "`indexedDB`. With `unsupported_contexts` set, any browser-storage use in those paths."
    ),
    applies_to=JS_GLOBS,
)
def browser_storage(ctx: ReviewContext, spec: CheckSpec) -> Iterable[Finding]:
    """Two questions about browser storage, only one of them on by default.

    **On by default: what is being stored.** `localStorage` is unencrypted,
    origin-scoped, permanent until something clears it, and readable by every
    script on the page including any third-party tag. On a shared classroom
    device it survives the child logging out and is still there for whoever
    sits down next. Writing a name, a date of birth or a student identifier
    there is a durable local copy of a student record outside every control
    the application has.

    This is scoped to *writes of PII-shaped values* rather than to storage use
    in general, because "this React app uses localStorage" is true of nearly
    every React app and reporting it would be pure noise. The check has to be
    useful on day one without configuration, and this is the version of it
    that is.

    **Opt-in: where it is being used.** Some rendering contexts have no
    working browser storage at all — a sandboxed iframe, an Apps Script
    `HtmlService` page, a server-rendered pass, a service worker. There the
    call does not fail loudly; it throws on access or silently no-ops, and the
    feature is quietly broken for everyone. Only the consuming repo knows
    which of its files run in such a context, so this half activates only when
    `unsupported_contexts` names the path globs, and then reports *any*
    storage use in them.
    """
    unsupported = as_list(spec.option("unsupported_contexts", []))
    lexicon = PiiLexicon(
        as_list(spec.option("pii_columns", DEFAULT_PII_COLUMNS)) or DEFAULT_PII_COLUMNS
    )
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    for changed in ctx.diff.live_files:
        if changed.is_binary or Path(changed.path).suffix.lower() not in JS_SUFFIXES:
            continue
        in_unsupported = bool(unsupported) and glob_match(changed.path, unsupported)

        for number, text in changed.added_lines:
            if len(findings) >= MAX_FINDINGS:
                return findings
            if _is_comment_line(text) or not _STORAGE_RE.search(text):
                continue
            key = (changed.path, number)
            if key in seen:
                continue

            if in_unsupported:
                seen.add(key)
                findings.append(_unsupported_finding(spec, changed.path, number, text))
                continue

            if not _STORAGE_WRITE_RE.search(text):
                continue
            hits = lexicon.matches(text)
            if not hits:
                continue
            seen.add(key)
            findings.append(
                _pii_storage_finding(spec, changed.path, number, text, [t for t, _ in hits])
            )

    return findings


def _pii_storage_finding(
    spec: CheckSpec, path: str, line: int, text: str, tokens: list[str]
) -> Finding:
    named = ", ".join(f"`{t}`" for t in tokens[:6])
    return spec.finding(
        title=f"PII-shaped value written to browser storage in `{path}`",
        message=(
            f"Line {line} of `{path}` writes {named} into browser storage.\n\n"
            f"```\n{text.strip()[:200]}\n```\n\n"
            "`localStorage` has no expiry, no encryption and no per-user partition beyond the "
            "origin. It persists after sign-out, survives the tab closing, and is readable by "
            "every script running on the page - including any analytics or support widget "
            "added later by someone who has never seen this line.\n\n"
            "On school hardware that matters more than usual: devices are shared between "
            "children and between class periods, so the previous pupil's data is simply still "
            "there for the next one. `sessionStorage` narrows the window to the tab's lifetime "
            "and is a real improvement; keeping the value in memory, or fetching it again when "
            "needed, removes the exposure rather than shortening it."
        ),
        rationale=(
            "Data written to browser storage leaves the server's jurisdiction entirely. No "
            "policy, grant or audit log applies to it, revoking a user's access does not remove "
            "their local copy, and deleting the record in the database leaves the copy on the "
            "device untouched. On a shared classroom device the practical result is one "
            "child's record readable by the next child to use the machine, which is a disclosure "
            "with no attacker in it. The check is narrowed to PII-shaped writes because "
            "reporting all browser-storage use would be noise in any React codebase."
        ),
        path=path,
        line=line,
        snippet=text.strip()[:200],
        identifiers=tokens[:12],
        mode="pii-write",
    )


def _unsupported_finding(spec: CheckSpec, path: str, line: int, text: str) -> Finding:
    return spec.finding(
        title=f"Browser storage used in an unsupported context: `{path}`",
        message=(
            f"Line {line} of `{path}` uses browser storage, and this path matches this check's "
            "`unsupported_contexts` list - paths this project has declared as running somewhere "
            "browser storage does not work.\n\n"
            f"```\n{text.strip()[:200]}\n```\n\n"
            "The reason this is configured rather than detected is that the failure is "
            "context-dependent and silent. In a sandboxed iframe, an Apps Script `HtmlService` "
            "page, a service worker or a server-rendered pass, the access either throws on a "
            "property nobody is catching or returns `null` forever. Either way the surrounding "
            "feature degrades without an error that points here.\n\n"
            "Persist through whatever mechanism this context actually supports - a server "
            "round-trip, the host page via `postMessage`, or in-memory state for the lifetime "
            "of the view."
        ),
        rationale=(
            "This is a correctness finding, not a security one, and it is configured per repo "
            "because only the repo knows its own rendering contexts. It is worth a rule at all "
            "because the failure mode is the expensive kind: no exception reaches a log, the "
            "feature merely never remembers anything, and the eventual debugging session starts "
            "from the symptom rather than from the line that caused it."
        ),
        path=path,
        line=line,
        snippet=text.strip()[:200],
        mode="unsupported-context",
    )
