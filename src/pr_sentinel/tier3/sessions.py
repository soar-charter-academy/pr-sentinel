"""Session providers: how a persona comes to hold an authenticated session.

DESIGN-V2 §5.2. The original plan was to hand a model the reviewer
credentials and let it sign in. That does not work, and the reason is not
permissions: some identity providers detect and refuse browser automation,
correct credentials and all. But the identity provider is usually only how
humans get in — the thing holding the session is something that can often be
asked directly. So sessions come from a pluggable provider, and the provider
is a config choice rather than a code change.

Four of them ship:

* `supabase-password` — a one-time human setup sets a password on each
  persona account; the tier calls the token endpoint and builds the
  `localStorage` entry the JS client expects. Recommended where it applies,
  because nothing interactive is involved.
* `storage-state` — a human signs in by hand once per persona and the
  cookies and local storage are sealed and replayed. Works against anything a
  human can sign into, which is why it is the fallback for an identity
  provider that cannot be driven.
* `http-login` — an ordinary form or JSON login and a cookie jar.
* `oidc-client-credentials` — a machine-to-machine token, bearer only.

Three rules run through all of them.

**Expiry is a first-class outcome, not an error.** A session that has expired
returns `SessionStatus.EXPIRED` so the caller can report "session expired,
runtime review skipped" and withhold its status. §5.2 again: the tier never
reports a clean run it did not perform, and an expired session is the
commonest way it would come to.

**Never return a usable-looking session that was not verified.** Every
provider that can check its own work does, with a cheap authenticated call.
A `Session` with `status is OK` is a claim that somebody actually tried it.

**No token and no password is ever logged, rendered, or put in an error
message, a note or a repr.** Error text is assembled from a status code and,
at most, an auth server's short machine-readable error *code*, filtered
against a strict charset so a server that echoes a credential back cannot
launder it through us. `_scrub` is the second line of defence. The first is
that the values are never interpolated in the first place.

**The service-role key is never read by this module.** `FORBIDDEN_SECRETS` is
enforced in `SecretStore`, which is the only way a provider gets a secret.
§6's safety argument is that row-level security confines the persona accounts
to test data; a key that bypasses RLS makes that argument vacuous, so the
module that could use one refuses to be able to.

Stdlib only, and every HTTP call goes through an injectable `Transport`, so
the whole file is exercisable with no network.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, runtime_checkable

from .models import Session, SessionStatus

DEFAULT_TIMEOUT = 20

#: Refused by name, in `SecretStore`. Not a lint: the module must be unable
#: to hold one of these, because the whole safety argument of §6 is that RLS
#: confines the persona accounts and these keys bypass RLS.
FORBIDDEN_SECRETS = frozenset(
    {
        "SUPABASE_SERVICE_ROLE_KEY",
        "SERVICE_ROLE_KEY",
        "SUPABASE_SERVICE_KEY",
        "SUPABASE_JWT_SECRET",
        "SUPABASE_SECRET",
        "DATABASE_URL",
        "POSTGRES_PASSWORD",
    }
)

#: Treated as expired this far before the nominal expiry. A session that dies
#: thirty seconds into a crawl produces a half-finished inventory, which §5.4
#: must not read as "no change".
EXPIRY_MARGIN_SECONDS = 120


class SecretRefused(RuntimeError):
    """Raised when something asks this module for a credential it must not hold.

    Deliberately an exception rather than a `None`: a caller that asked for
    the service-role key has a bug in its config or its intent, and either way
    continuing quietly with a missing secret would turn a refusal into a
    confusing authentication failure much later.
    """


class SecretStore:
    """The only way a provider obtains a credential.

    Thin on purpose. It exists for three properties: the forbidden names are
    refused in one place, `__repr__` cannot leak, and every value the module
    holds is registered so `_scrub` can strip it from anything on its way out.
    """

    __slots__ = ("_values",)

    def __init__(self, values: Mapping[str, str] | None = None) -> None:
        self._values: dict[str, str] = {}
        for key, value in (values or {}).items():
            self._set(str(key), value)

    def _set(self, key: str, value: Any) -> None:
        if key.upper() in FORBIDDEN_SECRETS:
            raise SecretRefused(
                f"{key} must never be given to the runtime session layer. §6's "
                "safety argument is that row-level security confines the persona "
                "accounts to test data, and this key bypasses row-level security. "
                "Use a persona password instead."
            )
        if value is None:
            return
        self._values[key] = str(value)

    def get(self, key: str, default: str | None = None) -> str | None:
        if key.upper() in FORBIDDEN_SECRETS:
            raise SecretRefused(f"{key} must never be read by the session layer.")
        return self._values.get(key, default)

    def __contains__(self, key: object) -> bool:
        return str(key) in self._values

    def __len__(self) -> int:
        return len(self._values)

    def names(self) -> list[str]:
        return sorted(self._values)

    def all_values(self) -> tuple[str, ...]:
        """Every secret held, for `_scrub`. Never for rendering."""
        return tuple(v for v in self._values.values() if v)

    def __repr__(self) -> str:
        return f"SecretStore({len(self._values)} secrets: {', '.join(self.names())})"

    __str__ = __repr__


# ---------------------------------------------------------------------------
# redaction
# ---------------------------------------------------------------------------

#: Things that look like a credential wherever they appear. Applied to any
#: text that leaves this module, after the known secret values have been
#: stripped, because the one we did not register is the one that leaks.
_TOKEN_SHAPES = (
    # JWTs, which is what every provider here deals in.
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}"),
    # Long opaque strings: refresh tokens, API keys, session ids.
    re.compile(r"\b[A-Za-z0-9_\-]{32,}\b"),
    re.compile(r"\b[A-Fa-f0-9]{32,}\b"),
)

REDACTED = "[redacted]"


def _scrub(text: Any, secrets: SecretStore | None = None, *, extra: tuple[str, ...] = ()) -> str:
    """Remove credentials from text on its way out of this module.

    Order matters: exact known values first (so a short password is caught
    even though it does not look like a token), then the shape patterns.
    """
    out = str(text or "")
    values = list(extra)
    if secrets is not None:
        values += list(secrets.all_values())
    for value in sorted({v for v in values if v and len(v) >= 3}, key=len, reverse=True):
        out = out.replace(value, REDACTED)
    for pattern in _TOKEN_SHAPES:
        out = pattern.sub(REDACTED, out)
    return out


#: An auth server's machine-readable error code is useful and an auth
#: server's prose is not worth the risk — some echo the submitted identifier,
#: and one that echoed a password would launder it through our error message.
#: So only a short lowercase code survives.
_ERROR_CODE = re.compile(r"^[a-z][a-z0-9_.\-]{1,48}$")


def _error_code(body: Any) -> str | None:
    if not isinstance(body, dict):
        return None
    for key in ("error_code", "error", "code", "msg", "message"):
        value = body.get(key)
        if isinstance(value, str) and _ERROR_CODE.match(value.strip()):
            return value.strip()
    return None


# ---------------------------------------------------------------------------
# the HTTP seam
# ---------------------------------------------------------------------------


@dataclass
class HttpRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None
    timeout: int = DEFAULT_TIMEOUT

    def __repr__(self) -> str:
        # Headers carry `apikey` and `Authorization`; a body carries a
        # password. Neither appears here, because a stack trace or a debug log
        # containing this object must not be a credential disclosure.
        return (
            f"HttpRequest({self.method} {_strip_query(self.url)}, "
            f"headers={sorted(self.headers)}, body={'yes' if self.body else 'no'})"
        )


@dataclass
class HttpResponse:
    status: int
    body: bytes = b""
    headers: list[tuple[str, str]] = field(default_factory=list)

    def json(self) -> Any:
        try:
            return json.loads(self.body.decode("utf-8", errors="replace"))
        except ValueError:
            return None

    def set_cookies(self) -> list[str]:
        return [v for k, v in self.headers if k.lower() == "set-cookie"]

    def __repr__(self) -> str:
        # A response body is a token and `Set-Cookie` is a session. Length
        # only.
        return f"HttpResponse({self.status}, {len(self.body)} bytes)"


#: Every provider takes one of these. Tests pass a function over a dict; CI
#: gets `urllib_transport`. There is no code path that reaches the network
#: without going through this parameter.
Transport = Callable[[HttpRequest], HttpResponse]


def _strip_query(url: str) -> str:
    """A query string can hold a token, so URLs are logged without one."""
    return url.split("?", 1)[0]


def urllib_transport(request: HttpRequest) -> HttpResponse:
    """The live transport. `urllib`, because the engine's dependency list is
    PyYAML and a reviewer that drags a tree into CI is poorly placed to
    lecture anyone about supply chain."""
    parsed = urllib.parse.urlparse(request.url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"refusing a non-HTTP target: {parsed.scheme or 'no scheme'}")
    req = urllib.request.Request(  # noqa: S310 - scheme checked above
        request.url,
        data=request.body,
        headers=dict(request.headers),
        method=request.method.upper(),
    )
    try:
        with urllib.request.urlopen(req, timeout=request.timeout) as response:  # noqa: S310
            return HttpResponse(
                status=int(response.status),
                body=response.read(),
                headers=list(response.headers.items()),
            )
    except urllib.error.HTTPError as exc:
        # A 4xx is data here, not an exception: a 400 from a token endpoint is
        # the normal way to learn a password is wrong.
        return HttpResponse(
            status=int(exc.code),
            body=exc.read() or b"",
            headers=list(exc.headers.items()) if exc.headers else [],
        )


# ---------------------------------------------------------------------------
# the protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class SessionProvider(Protocol):
    """How a persona gets a session.

    One method, and it does not raise. Every failure mode — bad credentials,
    an unreachable target, an expired capture, a missing secret — comes back
    as a `Session` with a status, because the caller's job is to decide
    between "explore" and "skip and withhold the status", and an exception
    would make the second one look like a crashed run.
    """

    @property
    def name(self) -> str: ...

    def mint(self, persona: str, identity: str) -> Session: ...


def _now() -> int:
    return int(time.time())


def _expiry_status(expires_at: int | None, *, margin: int = EXPIRY_MARGIN_SECONDS) -> SessionStatus:
    if expires_at is None:
        return SessionStatus.OK
    return SessionStatus.EXPIRED if expires_at - margin <= _now() else SessionStatus.OK


def _iso(epoch: int | None) -> str | None:
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(timespec="seconds")


def _expires_epoch(payload: Mapping[str, Any]) -> int | None:
    """Read an expiry from a token response, in either of its usual forms."""
    raw = payload.get("expires_at")
    if isinstance(raw, (int, float)) and raw > 0:
        return int(raw)
    if isinstance(raw, str):
        try:
            return int(
                datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
            )
        except ValueError:
            pass
    expires_in = payload.get("expires_in")
    if isinstance(expires_in, (int, float)) and expires_in > 0:
        return _now() + int(expires_in)
    return None


def _failed(persona: str, provider: str, error: str, identity: str | None = None) -> Session:
    return Session(
        persona=persona,
        status=SessionStatus.FAILED,
        provider=provider,
        identity=identity,
        error=error,
    )


def _expired(persona: str, provider: str, error: str, identity: str | None = None) -> Session:
    """An expired session is reported, never retried silently.

    The caller reports "session expired, runtime review skipped" and withholds
    its status. A provider that quietly refreshed instead would be making the
    decision about whether a review happened, which is not its decision.
    """
    return Session(
        persona=persona,
        status=SessionStatus.EXPIRED,
        provider=provider,
        identity=identity,
        error=error,
    )


# ---------------------------------------------------------------------------
# supabase-password
# ---------------------------------------------------------------------------

_PROJECT_REF = re.compile(r"^([a-z0-9]{8,40})\.supabase\.(co|in|red)$", re.IGNORECASE)


def project_ref(url: str) -> str | None:
    """The project ref, which is the middle of the `localStorage` key name.

    Returned as None for a custom domain rather than guessed. Guessing wrong
    produces a storage state the browser ignores — a session that looks fine
    and authenticates nothing, which is the one outcome this module is not
    allowed to produce.
    """
    host = urllib.parse.urlparse(url).hostname or ""
    match = _PROJECT_REF.match(host)
    return match.group(1).lower() if match else None


class SupabasePasswordProvider:
    """Mint a session from the Supabase token endpoint.

    Why this is the recommended provider where it applies: the identity
    provider humans use may refuse automation, but it is only the identity
    provider. Supabase holds the session and will issue one for a password,
    with no browser and nothing to detect. The password is set once, by a
    human, locally, using a key that never comes near CI.

    The anon key is required and is not a secret in the usual sense — it is
    shipped to every browser — but row-level security still applies to it,
    which is exactly the property §6 depends on.
    """

    name = "supabase-password"

    def __init__(
        self,
        url: str,
        anon_key: str,
        *,
        passwords: Mapping[str, str] | SecretStore | None = None,
        transport: Transport | None = None,
        ref: str | None = None,
        verify: bool = True,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self._url = url.rstrip("/")
        self._anon_key = anon_key
        self._secrets = (
            passwords if isinstance(passwords, SecretStore) else SecretStore(passwords)
        )
        self._transport = transport or urllib_transport
        self._ref = ref or project_ref(self._url)
        self._verify = verify
        self._timeout = timeout

    def __repr__(self) -> str:
        return (
            f"SupabasePasswordProvider(url={_strip_query(self._url)}, "
            f"ref={self._ref}, {self._secrets!r})"
        )

    __str__ = __repr__

    # -- minting ---------------------------------------------------------

    def mint(self, persona: str, identity: str) -> Session:
        if not self._ref:
            return _failed(
                persona,
                self.name,
                "Could not determine the Supabase project ref from the configured "
                "URL, and without it the browser storage key would be wrong — the "
                "session would look fine and authenticate nothing. Set "
                "`session.ref` explicitly.",
                identity,
            )
        password = self._secrets.get(persona) or self._secrets.get(identity)
        if not password:
            return Session(
                persona=persona,
                status=SessionStatus.UNAVAILABLE,
                provider=self.name,
                identity=identity,
                error=(
                    "No password is configured for this persona. Run the one-time "
                    "setup that sets persona passwords, then supply them as the "
                    "`SENTINEL_PERSONA_PASSWORDS` secret."
                ),
            )

        endpoint = f"{self._url}/auth/v1/token?grant_type=password"
        request = HttpRequest(
            method="POST",
            url=endpoint,
            headers={
                "content-type": "application/json",
                "apikey": self._anon_key,
                "authorization": f"Bearer {self._anon_key}",
                "accept": "application/json",
            },
            body=json.dumps({"email": identity, "password": password}).encode("utf-8"),
            timeout=self._timeout,
        )

        try:
            response = self._transport(request)
        except Exception as exc:  # transport is injected; it may raise anything
            return _failed(
                persona,
                self.name,
                f"The token endpoint could not be reached: "
                f"{_scrub(type(exc).__name__, self._secrets)}.",
                identity,
            )

        if response.status != 200:
            code = _error_code(response.json())
            detail = f" ({code})" if code else ""
            # 400 and 401 from this endpoint mean the credential is wrong or
            # the account is not confirmed. That is FAILED, not EXPIRED:
            # nothing here has expired, and a caller that retried later would
            # get the same answer.
            return _failed(
                persona,
                self.name,
                f"Sign-in was refused with HTTP {response.status}{detail}.",
                identity,
            )

        payload = response.json()
        if not isinstance(payload, dict) or not payload.get("access_token"):
            return _failed(
                persona,
                self.name,
                "The token endpoint returned 200 with no access token in the body.",
                identity,
            )

        expires_at = _expires_epoch(payload)
        if _expiry_status(expires_at) is SessionStatus.EXPIRED:
            return _expired(
                persona,
                self.name,
                "The minted session was already at or past its expiry, so it would "
                "not survive a crawl. Session expired, runtime review skipped.",
                identity,
            )

        access_token = str(payload["access_token"])
        if self._verify and not self._verify_token(access_token):
            return _expired(
                persona,
                self.name,
                "The minted token was rejected by the user endpoint, so it could "
                "not be verified. A session that was not verified is never "
                "reported as usable.",
                identity,
            )

        return Session(
            persona=persona,
            status=SessionStatus.OK,
            provider=self.name,
            storage_state=self.storage_state(payload),
            access_token=access_token,
            identity=identity,
            expires_at=_iso(expires_at),
        )

    def _verify_token(self, access_token: str) -> bool:
        """One cheap authenticated call. §5.2's rule about never reporting a
        run that did not happen starts here: a token nobody tried is a claim,
        not a session."""
        try:
            response = self._transport(
                HttpRequest(
                    method="GET",
                    url=f"{self._url}/auth/v1/user",
                    headers={
                        "apikey": self._anon_key,
                        "authorization": f"Bearer {access_token}",
                        "accept": "application/json",
                    },
                    timeout=self._timeout,
                )
            )
        except Exception:
            return False
        return response.status == 200

    # -- the browser's view ----------------------------------------------

    def storage_key(self) -> str:
        return f"sb-{self._ref}-auth-token"

    def storage_state(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        """Build what the Supabase JS client expects to find.

        The client reads its session out of `localStorage` under
        `sb-<project-ref>-auth-token`, as the serialised session object the
        token endpoint returned. So this is a pass-through of the response's
        session fields rather than a reconstruction: a hand-built object with
        a field missing produces a client that thinks it is signed out, and
        the failure appears as "the app rendered the login screen" three
        layers away from the cause.
        """
        session_object = {
            "access_token": payload.get("access_token"),
            "token_type": payload.get("token_type", "bearer"),
            "expires_in": payload.get("expires_in"),
            "expires_at": _expires_epoch(payload),
            "refresh_token": payload.get("refresh_token"),
            "user": payload.get("user") or {},
        }
        origin = _origin(self._url)
        return {
            "cookies": [],
            "origins": [
                {
                    "origin": origin,
                    "localStorage": [
                        {"name": self.storage_key(), "value": json.dumps(session_object)}
                    ],
                }
            ],
            # Recorded so the driver can put the entry under the application's
            # origin too. Supabase's client reads it from wherever the app runs,
            # not from the API origin, and only the driver knows the app's URL.
            "_sentinel": {"storage_key": self.storage_key(), "api_origin": origin},
        }


def _origin(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return url.rstrip("/")
    return f"{parsed.scheme}://{parsed.netloc}"


# ---------------------------------------------------------------------------
# storage-state, and the capture side
# ---------------------------------------------------------------------------

CAPTURE_MAGIC = b"PRS-SESSION-1\n"


@dataclass
class Capture:
    """One by-hand sign-in, sealed for replay."""

    persona: str
    identity: str
    storage_state: dict[str, Any]
    captured_at: str
    expires_at: str | None = None

    def __repr__(self) -> str:
        return (
            f"Capture(persona={self.persona!r}, identity={self.identity!r}, "
            f"captured_at={self.captured_at!r}, expires_at={self.expires_at!r}, "
            f"state=<{len(self.storage_state.get('cookies', []))} cookies, "
            f"{len(self.storage_state.get('origins', []))} origins>)"
        )

    __str__ = __repr__


def seal_capture(
    capture: Capture,
    *,
    encrypt: Callable[[bytes], bytes] | None = None,
    allow_plaintext: bool = False,
) -> bytes:
    """Serialise a captured session for storage.

    The capture-side half of `storage-state`, used by `sentinel session
    capture` once the browser half has signed in by hand and handed back a
    storage state.

    Encryption is injected rather than implemented. Two reasons, and the
    second is the real one: the engine's dependency list is PyYAML, and
    rolling a cipher out of `hashlib` to avoid adding a dependency would be a
    worse outcome than either alternative. So the envelope is sealed by
    whatever the platform already has — an Actions secret, `age`, `sops`, a
    KMS call — and this function refuses to write a plaintext file unless the
    caller says in as many words that it is a throwaway.

    The tag is integrity, not authenticity: it catches a truncated or
    corrupted capture, which is a real and silent failure mode, and claims
    nothing more.
    """
    payload = json.dumps(
        {
            "persona": capture.persona,
            "identity": capture.identity,
            "captured_at": capture.captured_at,
            "expires_at": capture.expires_at,
            "storage_state": capture.storage_state,
        },
        sort_keys=True,
    ).encode("utf-8")

    if encrypt is None:
        if not allow_plaintext:
            raise SecretRefused(
                "Refusing to write a captured session in plaintext. A capture is a "
                "live session for a real account; at rest it must be encrypted by "
                "whatever your platform already uses (an Actions secret, `age`, "
                "`sops`, a KMS key). Pass `encrypt=`, or pass "
                "`allow_plaintext=True` for a throwaway you are about to delete."
            )
        sealed = payload
        marker = b"plain"
    else:
        sealed = encrypt(payload)
        marker = b"sealed"

    tag = hashlib.sha256(sealed).hexdigest()[:32].encode("ascii")
    return CAPTURE_MAGIC + marker + b"\n" + tag + b"\n" + base64.b64encode(sealed)


def open_capture(
    blob: bytes | str, *, decrypt: Callable[[bytes], bytes] | None = None
) -> Capture:
    """Read a sealed capture back. Raises `ValueError` on anything malformed.

    Raising here rather than returning a status is deliberate and local: this
    is the capture *file format*, and a provider calls it inside a try so the
    session-level contract (never raise, return a status) still holds.
    """
    raw = blob.encode("utf-8") if isinstance(blob, str) else bytes(blob)
    if not raw.startswith(CAPTURE_MAGIC):
        raise ValueError("not a pr-sentinel session capture")
    rest = raw[len(CAPTURE_MAGIC) :]
    try:
        marker, tag, body = rest.split(b"\n", 2)
        sealed = base64.b64decode(body, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("captured session is malformed") from exc

    if not hmac.compare_digest(
        hashlib.sha256(sealed).hexdigest()[:32].encode("ascii"), tag
    ):
        raise ValueError(
            "captured session failed its integrity check; it is truncated or "
            "corrupted. Re-capture rather than replaying it."
        )

    if marker == b"sealed":
        if decrypt is None:
            raise ValueError(
                "this capture is encrypted and no decryptor was configured; "
                "refusing to guess"
            )
        sealed = decrypt(sealed)

    data = json.loads(sealed.decode("utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("storage_state"), dict):
        raise ValueError("captured session contains no storage state")
    return Capture(
        persona=str(data.get("persona", "")),
        identity=str(data.get("identity", "")),
        storage_state=data["storage_state"],
        captured_at=str(data.get("captured_at", "")),
        expires_at=data.get("expires_at"),
    )


def capture_instructions(persona: str, target: str) -> str:
    """What a human has to do, in the words the checklist uses.

    This is the step that cannot be automated, and saying so plainly is the
    point of §5.2a — an owner who thinks the tool will handle sign-in loses an
    afternoon to an anti-bot wall before finding out otherwise.
    """
    return (
        f"Run `sentinel session capture --persona {persona}`. A real browser opens "
        f"at {target}. Sign in by hand as the `{persona}` probe account — not as "
        "yourself, and not with the shared reviewer login (§6a: one glance at the "
        "actor has to answer 'is this us'). When the application has finished "
        "loading, return to the terminal and confirm. The cookies and local "
        "storage are sealed and written out; store the result as a secret. Repeat "
        "when it expires, which it will."
    )


class StorageStateProvider:
    """Replay a session a human captured by hand.

    The fallback that works everywhere, and the only option when the identity
    provider cannot be driven. Its cost is honest: somebody has to re-capture
    when the sessions expire, and expiry is why `EXPIRED` exists as a status
    rather than as an error.
    """

    name = "storage-state"

    def __init__(
        self,
        *,
        source: Mapping[str, str] | None = None,
        directory: str | Path | None = None,
        decrypt: Callable[[bytes], bytes] | None = None,
    ) -> None:
        """`source` maps persona -> sealed capture (a secret's value);
        `directory` holds `<persona>.session` files. A secret is preferred: a
        file on disk is a live session sitting in a workspace."""
        self._source = dict(source or {})
        self._directory = Path(directory) if directory else None
        self._decrypt = decrypt

    def __repr__(self) -> str:
        return (
            f"StorageStateProvider(personas={sorted(self._source)}, "
            f"directory={self._directory}, encrypted={self._decrypt is not None})"
        )

    __str__ = __repr__

    def _blob(self, persona: str) -> bytes | None:
        if persona in self._source:
            return str(self._source[persona]).encode("utf-8")
        if self._directory is None:
            return None
        # The persona name is validated upstream by `untrusted.clean_name`,
        # but this is the one place a name would become a path, so it is
        # checked again here rather than trusted across a module boundary.
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", persona):
            return None
        candidate = self._directory / f"{persona}.session"
        try:
            return candidate.read_bytes()
        except OSError:
            return None

    def mint(self, persona: str, identity: str) -> Session:
        blob = self._blob(persona)
        if blob is None:
            return Session(
                persona=persona,
                status=SessionStatus.UNAVAILABLE,
                provider=self.name,
                identity=identity,
                error=(
                    f"No captured session for `{persona}`. "
                    + capture_instructions(persona, "the target")
                ),
            )
        try:
            capture = open_capture(blob, decrypt=self._decrypt)
        except (ValueError, OSError, json.JSONDecodeError) as exc:
            return _failed(
                persona,
                self.name,
                f"The captured session could not be read: {_scrub(exc)}",
                identity,
            )

        expires_at = None
        if capture.expires_at:
            try:
                expires_at = int(
                    datetime.fromisoformat(
                        capture.expires_at.replace("Z", "+00:00")
                    ).timestamp()
                )
            except ValueError:
                expires_at = None

        if _expiry_status(expires_at) is SessionStatus.EXPIRED:
            return _expired(
                persona,
                self.name,
                "The captured session has expired. Session expired, runtime review "
                "skipped. " + capture_instructions(persona, "the target"),
                capture.identity or identity,
            )

        if not capture.storage_state.get("cookies") and not capture.storage_state.get(
            "origins"
        ):
            return _failed(
                persona,
                self.name,
                "The captured session has neither cookies nor local storage, so it "
                "would not authenticate anything. Re-capture it.",
                identity,
            )

        return Session(
            persona=persona,
            status=SessionStatus.OK,
            provider=self.name,
            storage_state=capture.storage_state,
            identity=capture.identity or identity,
            expires_at=capture.expires_at,
        )


# ---------------------------------------------------------------------------
# http-login
# ---------------------------------------------------------------------------

_COOKIE_ATTRS = {"path", "domain", "expires", "max-age", "samesite", "secure", "httponly"}


def _parse_set_cookie(header: str, default_domain: str) -> dict[str, Any] | None:
    """Turn one `Set-Cookie` header into a storage-state cookie.

    Enough of RFC 6265 to replay a session and no more. The attributes that
    matter for replay are name, value, domain and path; the rest are the
    browser's business.
    """
    parts = [p.strip() for p in header.split(";") if p.strip()]
    if not parts or "=" not in parts[0]:
        return None
    name, _, value = parts[0].partition("=")
    cookie: dict[str, Any] = {
        "name": name.strip(),
        "value": value.strip(),
        "domain": default_domain,
        "path": "/",
        "httpOnly": False,
        "secure": False,
    }
    for attr in parts[1:]:
        key, _, attr_value = attr.partition("=")
        key = key.strip().lower()
        if key not in _COOKIE_ATTRS:
            continue
        if key == "domain" and attr_value.strip():
            cookie["domain"] = attr_value.strip().lstrip(".")
        elif key == "path" and attr_value.strip():
            cookie["path"] = attr_value.strip()
        elif key == "httponly":
            cookie["httpOnly"] = True
        elif key == "secure":
            cookie["secure"] = True
    return cookie if cookie["name"] else None


class HttpLoginProvider:
    """An ordinary form or JSON login, and the cookie jar it produces.

    Configurable rather than clever: field names, encoding, the success
    statuses and an optional token field, because "post the credentials and
    keep the cookies" is the same shape in Django, Rails, Express and
    whatever the target turns out to be, and the differences are all names.
    """

    name = "http-login"

    def __init__(
        self,
        login_url: str,
        *,
        credentials: Mapping[str, str] | SecretStore | None = None,
        transport: Transport | None = None,
        method: str = "POST",
        encoding: str = "form",  # "form" | "json"
        username_field: str = "email",
        password_field: str = "password",  # noqa: S107 - a field name, not a password
        extra_fields: Mapping[str, str] | None = None,
        token_field: str | None = None,
        success_statuses: tuple[int, ...] = (200, 201, 204, 302, 303),
        origin: str | None = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self._url = login_url
        self._secrets = (
            credentials if isinstance(credentials, SecretStore) else SecretStore(credentials)
        )
        self._transport = transport or urllib_transport
        self._method = method.upper()
        self._encoding = encoding.lower()
        self._username_field = username_field
        self._password_field = password_field
        self._extra = dict(extra_fields or {})
        self._token_field = token_field
        self._success = tuple(success_statuses)
        self._origin = origin or _origin(login_url)
        self._timeout = timeout

    def __repr__(self) -> str:
        return (
            f"HttpLoginProvider(url={_strip_query(self._url)}, "
            f"encoding={self._encoding}, {self._secrets!r})"
        )

    __str__ = __repr__

    def mint(self, persona: str, identity: str) -> Session:
        password = self._secrets.get(persona) or self._secrets.get(identity)
        if not password:
            return Session(
                persona=persona,
                status=SessionStatus.UNAVAILABLE,
                provider=self.name,
                identity=identity,
                error=(
                    "No credential is configured for this persona. Create a persona "
                    "account on the test target and supply its password as a secret."
                ),
            )

        fields = {
            self._username_field: identity,
            self._password_field: password,
            **self._extra,
        }
        if self._encoding == "json":
            body = json.dumps(fields).encode("utf-8")
            content_type = "application/json"
        else:
            body = urllib.parse.urlencode(fields).encode("utf-8")
            content_type = "application/x-www-form-urlencoded"

        try:
            response = self._transport(
                HttpRequest(
                    method=self._method,
                    url=self._url,
                    headers={"content-type": content_type, "accept": "application/json"},
                    body=body,
                    timeout=self._timeout,
                )
            )
        except Exception as exc:
            return _failed(
                persona,
                self.name,
                f"The login endpoint could not be reached: "
                f"{_scrub(type(exc).__name__, self._secrets)}.",
                identity,
            )

        if response.status not in self._success:
            code = _error_code(response.json())
            detail = f" ({code})" if code else ""
            return _failed(
                persona,
                self.name,
                f"Login was refused with HTTP {response.status}{detail}.",
                identity,
            )

        domain = urllib.parse.urlparse(self._origin).hostname or ""
        cookies = [
            cookie
            for cookie in (
                _parse_set_cookie(header, domain) for header in response.set_cookies()
            )
            if cookie
        ]

        token: str | None = None
        expires_at: int | None = None
        payload = response.json()
        if isinstance(payload, dict):
            if self._token_field and isinstance(payload.get(self._token_field), str):
                token = payload[self._token_field]
            expires_at = _expires_epoch(payload)

        if not cookies and not token:
            # 200 and nothing to replay is the dangerous case: many login
            # forms answer 200 with the login page re-rendered and an error
            # on it. Calling that a session would mean exploring as an
            # anonymous user and reporting it as a role.
            return _failed(
                persona,
                self.name,
                f"Login returned HTTP {response.status} but set no cookie and "
                "returned no token, so there is nothing to replay. A form that "
                "re-renders itself on a bad credential answers 200 too, which is "
                "why this is not treated as success.",
                identity,
            )

        if _expiry_status(expires_at) is SessionStatus.EXPIRED:
            return _expired(
                persona,
                self.name,
                "The session returned by the login endpoint was already expired.",
                identity,
            )

        return Session(
            persona=persona,
            status=SessionStatus.OK,
            provider=self.name,
            storage_state={"cookies": cookies, "origins": []},
            access_token=token,
            identity=identity,
            expires_at=_iso(expires_at),
        )


# ---------------------------------------------------------------------------
# oidc-client-credentials
# ---------------------------------------------------------------------------


class OidcClientCredentialsProvider:
    """A machine-to-machine token. Bearer only, no browser, no storage state.

    For a service-style target there is no UI to crawl, so this returns a
    token and nothing else — `storage_state` stays empty and the driver's API
    transport is the only thing that can use it. Verification is the grant
    itself: the issuer authenticated the client before it issued anything,
    which is a stronger check than any call we could make afterwards.
    """

    name = "oidc-client-credentials"

    def __init__(
        self,
        token_url: str,
        *,
        client_id: str,
        client_secret: str | None = None,
        secrets: Mapping[str, str] | SecretStore | None = None,
        secret_name: str = "OIDC_CLIENT_SECRET",  # noqa: S107 - a secret name, not a secret
        scope: str | None = None,
        audience: str | None = None,
        transport: Transport | None = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self._url = token_url
        self._client_id = client_id
        store = secrets if isinstance(secrets, SecretStore) else SecretStore(secrets)
        if client_secret:
            store = SecretStore({**{secret_name: client_secret}})
        self._secrets = store
        self._secret_name = secret_name
        self._scope = scope
        self._audience = audience
        self._transport = transport or urllib_transport
        self._timeout = timeout

    def __repr__(self) -> str:
        return (
            f"OidcClientCredentialsProvider(token_url={_strip_query(self._url)}, "
            f"client_id={self._client_id!r}, {self._secrets!r})"
        )

    __str__ = __repr__

    def mint(self, persona: str, identity: str) -> Session:
        secret = self._secrets.get(self._secret_name)
        if not secret:
            return Session(
                persona=persona,
                status=SessionStatus.UNAVAILABLE,
                provider=self.name,
                identity=identity,
                error=(
                    f"No `{self._secret_name}` is configured. Register a dedicated "
                    "probe client with the issuer — not an application client — and "
                    "supply its secret."
                ),
            )

        fields = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": secret,
        }
        if self._scope:
            fields["scope"] = self._scope
        if self._audience:
            fields["audience"] = self._audience

        try:
            response = self._transport(
                HttpRequest(
                    method="POST",
                    url=self._url,
                    headers={
                        "content-type": "application/x-www-form-urlencoded",
                        "accept": "application/json",
                    },
                    body=urllib.parse.urlencode(fields).encode("utf-8"),
                    timeout=self._timeout,
                )
            )
        except Exception as exc:
            return _failed(
                persona,
                self.name,
                f"The token endpoint could not be reached: "
                f"{_scrub(type(exc).__name__, self._secrets)}.",
                identity,
            )

        if response.status != 200:
            code = _error_code(response.json())
            detail = f" ({code})" if code else ""
            return _failed(
                persona,
                self.name,
                f"The token request was refused with HTTP {response.status}{detail}.",
                identity,
            )

        payload = response.json()
        if not isinstance(payload, dict) or not payload.get("access_token"):
            return _failed(
                persona,
                self.name,
                "The token endpoint returned 200 with no access token in the body.",
                identity,
            )

        expires_at = _expires_epoch(payload)
        if _expiry_status(expires_at) is SessionStatus.EXPIRED:
            return _expired(
                persona,
                self.name,
                "The issued token was already expired.",
                identity,
            )

        return Session(
            persona=persona,
            status=SessionStatus.OK,
            provider=self.name,
            storage_state={},
            access_token=str(payload["access_token"]),
            identity=identity,
            expires_at=_iso(expires_at),
        )


# ---------------------------------------------------------------------------
# the offline twin
# ---------------------------------------------------------------------------


class ScriptedSessionProvider:
    """Canned sessions, for tests and dry runs.

    The tier above this one — crawler, differential probe, PII watcher,
    explorer — has to be testable without a target to sign into, and the
    interesting cases to script are the unhappy ones: a persona whose session
    expired mid-run, a persona whose provider is unavailable. Those are the
    paths where "report a clean run" would be the wrong behaviour, so they are
    the paths that most need a test.
    """

    name = "scripted"

    def __init__(
        self,
        sessions: Mapping[str, Session] | None = None,
        *,
        default_status: SessionStatus = SessionStatus.OK,
    ) -> None:
        self._sessions = dict(sessions or {})
        self._default_status = default_status
        self.minted: list[str] = []

    def __repr__(self) -> str:
        return f"ScriptedSessionProvider(personas={sorted(self._sessions)})"

    __str__ = __repr__

    def script(self, persona: str, session: Session) -> None:
        self._sessions[persona] = session

    def mint(self, persona: str, identity: str) -> Session:
        self.minted.append(persona)
        existing = self._sessions.get(persona)
        if existing is not None:
            return existing
        if self._default_status is not SessionStatus.OK:
            return Session(
                persona=persona,
                status=self._default_status,
                provider=self.name,
                identity=identity,
                error=f"scripted {self._default_status.value}",
            )
        return Session(
            persona=persona,
            status=SessionStatus.OK,
            provider=self.name,
            storage_state={"cookies": [], "origins": []},
            access_token="scripted-token",
            identity=identity,
            expires_at=_iso(_now() + 3600),
        )


# ---------------------------------------------------------------------------
# construction from config
# ---------------------------------------------------------------------------


def build_provider(
    config: Mapping[str, Any],
    secrets: Mapping[str, str] | None = None,
    *,
    transport: Transport | None = None,
) -> SessionProvider:
    """Build the configured provider from a `session:` block.

    Raises `ValueError` for an unknown provider rather than defaulting to
    one. A target whose config names a provider that does not exist has a
    typo, and silently signing in a different way than the config says is
    worse than not starting.
    """
    kind = str(config.get("provider", "")).strip().lower()
    store = SecretStore(secrets)

    if kind == "supabase-password":
        return SupabasePasswordProvider(
            url=str(config.get("url", "")),
            anon_key=str(config.get("anon_key", "")),
            passwords=_persona_passwords(config, store),
            transport=transport,
            ref=config.get("ref"),
            verify=bool(config.get("verify", True)),
        )
    if kind == "storage-state":
        return StorageStateProvider(
            source=_captures(config, store),
            directory=config.get("directory"),
        )
    if kind == "http-login":
        return HttpLoginProvider(
            login_url=str(config.get("login_url", "")),
            credentials=_persona_passwords(config, store),
            transport=transport,
            method=str(config.get("method", "POST")),
            encoding=str(config.get("encoding", "form")),
            username_field=str(config.get("username_field", "email")),
            password_field=str(config.get("password_field", "password")),
            extra_fields=config.get("extra_fields") or {},
            token_field=config.get("token_field"),
            origin=config.get("origin"),
        )
    if kind == "oidc-client-credentials":
        return OidcClientCredentialsProvider(
            token_url=str(config.get("token_url", "")),
            client_id=str(config.get("client_id", "")),
            secrets=store,
            secret_name=str(config.get("client_secret_from", "OIDC_CLIENT_SECRET")).replace(
                "secret:", ""
            ),
            scope=config.get("scope"),
            audience=config.get("audience"),
            transport=transport,
        )
    if kind == "scripted":
        return ScriptedSessionProvider()
    raise ValueError(
        f"unknown session provider {kind!r}; expected one of supabase-password, "
        "storage-state, http-login, oidc-client-credentials"
    )


def _secret_ref(value: Any) -> str | None:
    """`secret:NAME` -> `NAME`. A plain string is not treated as a secret
    reference, because a config that inlined a password should fail to find
    one rather than quietly work."""
    text = str(value or "")
    return text[len("secret:") :] if text.startswith("secret:") else None


def _persona_passwords(config: Mapping[str, Any], store: SecretStore) -> dict[str, str]:
    """Read the persona -> password map out of a single secret.

    One secret holding a JSON object, rather than one secret per persona: a
    tier that needs eight CI secrets to run is a tier nobody configures, and
    the eight would rot independently.
    """
    name = _secret_ref(config.get("passwords_from") or config.get("credentials_from"))
    if not name:
        return {}
    raw = store.get(name)
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except ValueError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    return {str(k): str(v) for k, v in parsed.items() if v}


def _captures(config: Mapping[str, Any], store: SecretStore) -> dict[str, str]:
    name = _secret_ref(config.get("state_from"))
    if not name:
        return {}
    raw = store.get(name)
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except ValueError:
        return {}
    if isinstance(parsed, dict):
        return {str(k): str(v) for k, v in parsed.items() if v}
    return {}
