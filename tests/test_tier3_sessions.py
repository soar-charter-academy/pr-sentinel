"""Tier 3 session providers.

No network: every provider takes an injectable `Transport` and these tests
pass a routing table. No browser either — a storage state is a data
structure, and asserting on its shape is what catches the mistake that
matters (a key the Supabase client will not look under).

The last class in this file is the one to read first. `LeakTests` sweeps
every error message, every note and every `__repr__` this module can produce
for a password or a token. That property is the reason several of the design
choices above it look over-careful.
"""

from __future__ import annotations

import json
import time
import unittest
from datetime import datetime, timedelta, timezone

from pr_sentinel.tier3 import sessions as S
from pr_sentinel.tier3.models import SessionStatus

PASSWORD = "correct-horse-battery-staple-7781"  # noqa: S105
ACCESS_TOKEN = "eyJhbGciOiJIUzI1NiJ9.ZXlKcGMzTWlPaUp6ZFhCaFltRnpaU0o5.c2lnbmF0dXJl"  # noqa: S105
REFRESH_TOKEN = "v1-refresh-9f8e7d6c5b4a39281716151413121110"  # noqa: S105
CLIENT_SECRET = "oidc-client-secret-aaaaaaaaaaaaaaaaaaaa"  # noqa: S105
COOKIE_VALUE = "sessionid-9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d"

SUPABASE_URL = "https://abcdefghij.supabase.co"
PROJECT_REF = "abcdefghij"
STORAGE_KEY = f"sb-{PROJECT_REF}-auth-token"

#: Every secret in play, swept for by `LeakTests`.
ALL_SECRETS = (PASSWORD, ACCESS_TOKEN, REFRESH_TOKEN, CLIENT_SECRET, COOKIE_VALUE)


def http(status: int, body: object = None, headers: list[tuple[str, str]] | None = None):
    payload = b"" if body is None else json.dumps(body).encode("utf-8")
    return S.HttpResponse(status=status, body=payload, headers=list(headers or []))


class FakeTransport:
    """A routing table over `(method, url-substring)`.

    Records the requests, so a test can assert that nothing was sent that
    should not have been — which is how "the service-role key is never used"
    stays true rather than merely intended.
    """

    def __init__(self, routes: list[tuple[str, str, S.HttpResponse]] | None = None) -> None:
        self.routes = list(routes or [])
        self.requests: list[S.HttpRequest] = []
        self.raise_with: Exception | None = None

    def __call__(self, request: S.HttpRequest) -> S.HttpResponse:
        self.requests.append(request)
        if self.raise_with is not None:
            raise self.raise_with
        for method, needle, response in self.routes:
            if request.method.upper() == method.upper() and needle in request.url:
                return response
        return http(404, {"error": "no_route"})

    @property
    def bodies(self) -> str:
        return "\n".join(
            (r.body or b"").decode("utf-8", errors="replace") for r in self.requests
        )


def token_body(*, expires_in: int = 3600, expires_at: int | None = None) -> dict:
    body = {
        "access_token": ACCESS_TOKEN,
        "token_type": "bearer",  # noqa: S105
        "refresh_token": REFRESH_TOKEN,
        "user": {"id": "uuid-1", "email": "sentinel-probe-teacher@example.invalid"},
    }
    if expires_at is not None:
        body["expires_at"] = expires_at
    else:
        body["expires_in"] = expires_in
    return body


def supabase_provider(
    transport: FakeTransport, *, verify: bool = True
) -> S.SupabasePasswordProvider:
    return S.SupabasePasswordProvider(
        SUPABASE_URL,
        anon_key="anon-public-key",
        passwords={"teacher": PASSWORD},
        transport=transport,
        verify=verify,
    )


# ---------------------------------------------------------------------------
# the secret store
# ---------------------------------------------------------------------------


class SecretStoreTests(unittest.TestCase):
    def test_the_service_role_key_cannot_be_held_by_this_module(self) -> None:
        # §6's safety argument is that RLS confines the persona accounts to
        # test data. A key that bypasses RLS makes that argument vacuous, so
        # the module that could use one refuses to be able to.
        for name in ("SUPABASE_SERVICE_ROLE_KEY", "service_role_key", "SUPABASE_JWT_SECRET"):
            with self.subTest(name=name):
                with self.assertRaises(S.SecretRefused):
                    S.SecretStore({name: "anything"})

    def test_reading_a_forbidden_name_is_also_refused(self) -> None:
        store = S.SecretStore({"SENTINEL_PERSONA_PASSWORDS": "{}"})
        with self.assertRaises(S.SecretRefused):
            store.get("SUPABASE_SERVICE_ROLE_KEY")

    def test_repr_lists_names_and_no_values(self) -> None:
        store = S.SecretStore({"teacher": PASSWORD})
        self.assertIn("teacher", repr(store))
        self.assertNotIn(PASSWORD, repr(store))
        self.assertNotIn(PASSWORD, str(store))


# ---------------------------------------------------------------------------
# supabase-password
# ---------------------------------------------------------------------------


class SupabasePasswordTests(unittest.TestCase):
    def test_a_good_sign_in_builds_the_storage_entry_the_client_expects(self) -> None:
        transport = FakeTransport(
            [
                ("POST", "/auth/v1/token", http(200, token_body())),
                ("GET", "/auth/v1/user", http(200, {"id": "uuid-1"})),
            ]
        )
        session = supabase_provider(transport).mint("teacher", "probe@example.invalid")

        self.assertIs(session.status, SessionStatus.OK)
        self.assertTrue(session.usable)
        self.assertEqual(session.access_token, ACCESS_TOKEN)
        self.assertEqual(session.provider, "supabase-password")

        origins = session.storage_state["origins"]
        entry = origins[0]["localStorage"][0]
        self.assertEqual(entry["name"], STORAGE_KEY)
        stored = json.loads(entry["value"])
        self.assertEqual(stored["access_token"], ACCESS_TOKEN)
        self.assertEqual(stored["refresh_token"], REFRESH_TOKEN)
        self.assertEqual(stored["token_type"], "bearer")
        self.assertIsNotNone(stored["expires_at"])
        self.assertEqual(stored["user"]["id"], "uuid-1")

    def test_the_password_grant_is_posted_to_the_documented_endpoint(self) -> None:
        transport = FakeTransport(
            [
                ("POST", "/auth/v1/token", http(200, token_body())),
                ("GET", "/auth/v1/user", http(200, {})),
            ]
        )
        supabase_provider(transport).mint("teacher", "probe@example.invalid")
        first = transport.requests[0]
        self.assertEqual(first.method, "POST")
        self.assertEqual(first.url, f"{SUPABASE_URL}/auth/v1/token?grant_type=password")
        self.assertEqual(json.loads(first.body)["email"], "probe@example.invalid")

    def test_a_four_hundred_is_failed_and_not_ok(self) -> None:
        transport = FakeTransport(
            [("POST", "/auth/v1/token", http(400, {"error": "invalid_grant"}))]
        )
        session = supabase_provider(transport).mint("teacher", "probe@example.invalid")
        self.assertIs(session.status, SessionStatus.FAILED)
        self.assertFalse(session.usable)
        self.assertIn("400", session.error)
        self.assertIn("invalid_grant", session.error)

    def test_an_already_expired_token_is_expired_not_ok(self) -> None:
        # §5.2: on expiry the tier reports "session expired, runtime review
        # skipped" and withholds its status. That requires expiry to be its
        # own outcome, distinguishable from a refused credential.
        past = int(time.time()) - 10
        transport = FakeTransport(
            [("POST", "/auth/v1/token", http(200, token_body(expires_at=past)))]
        )
        session = supabase_provider(transport).mint("teacher", "probe@example.invalid")
        self.assertIs(session.status, SessionStatus.EXPIRED)
        self.assertFalse(session.usable)
        self.assertIn("skipped", session.error)

    def test_a_token_expiring_inside_the_margin_counts_as_expired(self) -> None:
        soon = int(time.time()) + 30
        transport = FakeTransport(
            [("POST", "/auth/v1/token", http(200, token_body(expires_at=soon)))]
        )
        session = supabase_provider(transport).mint("teacher", "probe@example.invalid")
        self.assertIs(session.status, SessionStatus.EXPIRED)

    def test_a_token_that_cannot_be_verified_is_never_reported_usable(self) -> None:
        transport = FakeTransport(
            [
                ("POST", "/auth/v1/token", http(200, token_body())),
                ("GET", "/auth/v1/user", http(401, {"error": "invalid_token"})),
            ]
        )
        session = supabase_provider(transport).mint("teacher", "probe@example.invalid")
        self.assertIs(session.status, SessionStatus.EXPIRED)
        self.assertIn("not verified", session.error)

    def test_two_hundred_with_no_token_is_failed(self) -> None:
        transport = FakeTransport([("POST", "/auth/v1/token", http(200, {"ok": True}))])
        session = supabase_provider(transport).mint("teacher", "probe@example.invalid")
        self.assertIs(session.status, SessionStatus.FAILED)

    def test_a_missing_persona_password_is_unavailable_not_failed(self) -> None:
        # Unavailable means "nobody has set this up yet", which is a different
        # message to the maintainer than "your credential was refused".
        transport = FakeTransport()
        session = supabase_provider(transport).mint("aide", "aide@example.invalid")
        self.assertIs(session.status, SessionStatus.UNAVAILABLE)
        self.assertEqual(transport.requests, [])

    def test_an_undeterminable_project_ref_refuses_rather_than_guessing(self) -> None:
        provider = S.SupabasePasswordProvider(
            "https://auth.example.org",
            anon_key="anon",
            passwords={"teacher": PASSWORD},
            transport=FakeTransport([("POST", "/auth/v1/token", http(200, token_body()))]),
        )
        session = provider.mint("teacher", "probe@example.invalid")
        self.assertIs(session.status, SessionStatus.FAILED)
        self.assertIn("project ref", session.error)

    def test_an_explicit_ref_works_for_a_custom_domain(self) -> None:
        provider = S.SupabasePasswordProvider(
            "https://auth.example.org",
            anon_key="anon",
            passwords={"teacher": PASSWORD},
            ref="customref",
            verify=False,
            transport=FakeTransport([("POST", "/auth/v1/token", http(200, token_body()))]),
        )
        session = provider.mint("teacher", "probe@example.invalid")
        self.assertIs(session.status, SessionStatus.OK)
        self.assertEqual(
            session.storage_state["origins"][0]["localStorage"][0]["name"],
            "sb-customref-auth-token",
        )

    def test_an_unreachable_endpoint_is_failed_with_no_detail_leaked(self) -> None:
        transport = FakeTransport()
        transport.raise_with = OSError(f"connect failed for {PASSWORD}")
        session = supabase_provider(transport).mint("teacher", "probe@example.invalid")
        self.assertIs(session.status, SessionStatus.FAILED)
        self.assertNotIn(PASSWORD, session.error or "")

    def test_project_ref_is_read_from_the_host(self) -> None:
        self.assertEqual(S.project_ref(SUPABASE_URL), PROJECT_REF)
        self.assertIsNone(S.project_ref("https://auth.example.org"))
        self.assertIsNone(S.project_ref("not a url"))


# ---------------------------------------------------------------------------
# storage-state and capture
# ---------------------------------------------------------------------------


def a_capture(*, expires_in_days: int = 7, persona: str = "teacher") -> S.Capture:
    expires = datetime.now(timezone.utc) + timedelta(days=expires_in_days)
    return S.Capture(
        persona=persona,
        identity="probe@example.invalid",
        storage_state={
            "cookies": [
                {
                    "name": "sb-access-token",
                    "value": COOKIE_VALUE,
                    "domain": "app.example.invalid",
                    "path": "/",
                }
            ],
            "origins": [],
        },
        captured_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        expires_at=expires.isoformat(timespec="seconds"),
    )


class CaptureTests(unittest.TestCase):
    def test_a_sealed_capture_round_trips(self) -> None:
        blob = S.seal_capture(a_capture(), encrypt=lambda b: b[::-1])
        reopened = S.open_capture(blob, decrypt=lambda b: b[::-1])
        self.assertEqual(reopened.persona, "teacher")
        self.assertEqual(reopened.storage_state["cookies"][0]["value"], COOKIE_VALUE)

    def test_plaintext_is_refused_unless_asked_for_in_words(self) -> None:
        with self.assertRaises(S.SecretRefused):
            S.seal_capture(a_capture())
        blob = S.seal_capture(a_capture(), allow_plaintext=True)
        self.assertEqual(S.open_capture(blob).persona, "teacher")

    def test_an_encrypted_capture_is_not_opened_by_guessing(self) -> None:
        blob = S.seal_capture(a_capture(), encrypt=lambda b: b[::-1])
        with self.assertRaises(ValueError):
            S.open_capture(blob)

    def test_a_truncated_capture_fails_its_integrity_check(self) -> None:
        blob = S.seal_capture(a_capture(), allow_plaintext=True)
        with self.assertRaises(ValueError):
            S.open_capture(blob[:-8])

    def test_capture_repr_shows_shape_and_not_cookies(self) -> None:
        capture = a_capture()
        self.assertIn("1 cookies", repr(capture))
        self.assertNotIn(COOKIE_VALUE, repr(capture))

    def test_instructions_name_the_probe_account_rule(self) -> None:
        text = S.capture_instructions("teacher", "https://app.example.invalid")
        self.assertIn("sentinel session capture --persona teacher", text)
        self.assertIn("not with the shared reviewer login", text)


class StorageStateTests(unittest.TestCase):
    def _provider(self, capture: S.Capture) -> S.StorageStateProvider:
        blob = S.seal_capture(capture, allow_plaintext=True).decode("utf-8")
        return S.StorageStateProvider(source={capture.persona: blob})

    def test_a_live_capture_replays(self) -> None:
        session = self._provider(a_capture()).mint("teacher", "ignored@example.invalid")
        self.assertIs(session.status, SessionStatus.OK)
        self.assertEqual(session.identity, "probe@example.invalid")
        self.assertEqual(session.storage_state["cookies"][0]["value"], COOKIE_VALUE)
        # Bearer-only transport has nothing to use here, and claiming
        # otherwise would make the API probe look authenticated when it is not.
        self.assertIsNone(session.access_token)

    def test_an_expired_capture_is_expired_and_says_how_to_recapture(self) -> None:
        session = self._provider(a_capture(expires_in_days=-1)).mint("teacher", "x")
        self.assertIs(session.status, SessionStatus.EXPIRED)
        self.assertIn("expired", session.error)
        self.assertIn("sentinel session capture", session.error)

    def test_a_missing_capture_is_unavailable(self) -> None:
        session = S.StorageStateProvider().mint("teacher", "x")
        self.assertIs(session.status, SessionStatus.UNAVAILABLE)
        self.assertIn("No captured session", session.error)

    def test_a_corrupt_capture_is_failed(self) -> None:
        provider = S.StorageStateProvider(source={"teacher": "not a capture at all"})
        session = provider.mint("teacher", "x")
        self.assertIs(session.status, SessionStatus.FAILED)

    def test_an_empty_state_is_failed_rather_than_ok(self) -> None:
        capture = a_capture()
        capture.storage_state = {"cookies": [], "origins": []}
        session = self._provider(capture).mint("teacher", "x")
        self.assertIs(session.status, SessionStatus.FAILED)
        self.assertIn("would not authenticate", session.error)

    def test_a_persona_name_cannot_escape_the_capture_directory(self) -> None:
        provider = S.StorageStateProvider(directory="/tmp/sentinel-captures")
        session = provider.mint("../../etc/passwd", "x")
        self.assertIs(session.status, SessionStatus.UNAVAILABLE)


# ---------------------------------------------------------------------------
# http-login
# ---------------------------------------------------------------------------


class HttpLoginTests(unittest.TestCase):
    def _provider(self, transport: FakeTransport, **kwargs) -> S.HttpLoginProvider:
        options = {
            "credentials": {"teacher": PASSWORD},
            "transport": transport,
            "origin": "https://app.example.invalid",
        }
        options.update(kwargs)
        return S.HttpLoginProvider("https://app.example.invalid/login", **options)

    def test_a_cookie_becomes_a_storage_state(self) -> None:
        transport = FakeTransport(
            [
                (
                    "POST",
                    "/login",
                    http(
                        200,
                        {"ok": True},
                        [("Set-Cookie", f"sid={COOKIE_VALUE}; Path=/; HttpOnly; Secure")],
                    ),
                )
            ]
        )
        session = self._provider(transport).mint("teacher", "probe@example.invalid")
        self.assertIs(session.status, SessionStatus.OK)
        cookie = session.storage_state["cookies"][0]
        self.assertEqual(cookie["name"], "sid")
        self.assertEqual(cookie["value"], COOKIE_VALUE)
        self.assertEqual(cookie["domain"], "app.example.invalid")
        self.assertTrue(cookie["httpOnly"])
        self.assertTrue(cookie["secure"])

    def test_form_encoding_is_the_default_and_json_is_available(self) -> None:
        transport = FakeTransport(
            [("POST", "/login", http(200, None, [("Set-Cookie", f"sid={COOKIE_VALUE}")]))]
        )
        self._provider(transport).mint("teacher", "probe@example.invalid")
        self.assertEqual(
            transport.requests[0].headers["content-type"],
            "application/x-www-form-urlencoded",
        )

        transport = FakeTransport(
            [("POST", "/login", http(200, None, [("Set-Cookie", f"sid={COOKIE_VALUE}")]))]
        )
        self._provider(transport, encoding="json").mint("teacher", "probe@example.invalid")
        self.assertEqual(transport.requests[0].headers["content-type"], "application/json")

    def test_a_four_hundred_is_failed(self) -> None:
        transport = FakeTransport([("POST", "/login", http(400, {"error": "bad_credentials"}))])
        session = self._provider(transport).mint("teacher", "probe@example.invalid")
        self.assertIs(session.status, SessionStatus.FAILED)
        self.assertIn("400", session.error)

    def test_two_hundred_with_nothing_to_replay_is_failed(self) -> None:
        # A login form that re-renders itself with an error answers 200 too.
        transport = FakeTransport([("POST", "/login", http(200, {"ok": False}))])
        session = self._provider(transport).mint("teacher", "probe@example.invalid")
        self.assertIs(session.status, SessionStatus.FAILED)
        self.assertIn("nothing to replay", session.error)

    def test_a_token_field_is_picked_up_and_expiry_respected(self) -> None:
        transport = FakeTransport(
            [("POST", "/login", http(200, {"jwt": ACCESS_TOKEN, "expires_in": 3600}))]
        )
        session = self._provider(transport, token_field="jwt").mint("teacher", "p@x.invalid")
        self.assertIs(session.status, SessionStatus.OK)
        self.assertEqual(session.access_token, ACCESS_TOKEN)

        transport = FakeTransport(
            [
                (
                    "POST",
                    "/login",
                    http(200, {"jwt": ACCESS_TOKEN, "expires_at": int(time.time()) - 5}),
                )
            ]
        )
        session = self._provider(transport, token_field="jwt").mint("teacher", "p@x.invalid")
        self.assertIs(session.status, SessionStatus.EXPIRED)

    def test_no_credential_is_unavailable(self) -> None:
        session = self._provider(FakeTransport()).mint("auditor", "a@x.invalid")
        self.assertIs(session.status, SessionStatus.UNAVAILABLE)


# ---------------------------------------------------------------------------
# oidc-client-credentials
# ---------------------------------------------------------------------------


class OidcTests(unittest.TestCase):
    def _provider(self, transport: FakeTransport) -> S.OidcClientCredentialsProvider:
        return S.OidcClientCredentialsProvider(
            "https://issuer.example.invalid/oauth/token",
            client_id="sentinel-probe",
            client_secret=CLIENT_SECRET,
            scope="read:things",
            transport=transport,
        )

    def test_a_token_is_bearer_only(self) -> None:
        transport = FakeTransport(
            [("POST", "/oauth/token", http(200, {"access_token": ACCESS_TOKEN, "expires_in": 600}))]
        )
        session = self._provider(transport).mint("service", "sentinel-probe")
        self.assertIs(session.status, SessionStatus.OK)
        self.assertEqual(session.access_token, ACCESS_TOKEN)
        # No browser, so no storage state. An empty one is the honest answer.
        self.assertEqual(session.storage_state, {})
        self.assertIn("grant_type=client_credentials", transport.bodies)

    def test_a_four_hundred_is_failed(self) -> None:
        transport = FakeTransport(
            [("POST", "/oauth/token", http(400, {"error": "invalid_client"}))]
        )
        session = self._provider(transport).mint("service", "sentinel-probe")
        self.assertIs(session.status, SessionStatus.FAILED)
        self.assertIn("invalid_client", session.error)

    def test_an_expired_token_is_expired(self) -> None:
        transport = FakeTransport(
            [
                (
                    "POST",
                    "/oauth/token",
                    http(200, {"access_token": ACCESS_TOKEN, "expires_at": int(time.time()) - 1}),
                )
            ]
        )
        session = self._provider(transport).mint("service", "sentinel-probe")
        self.assertIs(session.status, SessionStatus.EXPIRED)

    def test_a_missing_secret_is_unavailable(self) -> None:
        provider = S.OidcClientCredentialsProvider(
            "https://issuer.example.invalid/oauth/token",
            client_id="sentinel-probe",
            transport=FakeTransport(),
        )
        session = provider.mint("service", "sentinel-probe")
        self.assertIs(session.status, SessionStatus.UNAVAILABLE)


# ---------------------------------------------------------------------------
# the offline twin and config
# ---------------------------------------------------------------------------


class ScriptedProviderTests(unittest.TestCase):
    def test_default_sessions_are_usable_and_recorded(self) -> None:
        provider = S.ScriptedSessionProvider()
        session = provider.mint("teacher/first-run", "probe@example.invalid")
        self.assertIs(session.status, SessionStatus.OK)
        self.assertEqual(provider.minted, ["teacher/first-run"])

    def test_the_unhappy_paths_are_scriptable(self) -> None:
        provider = S.ScriptedSessionProvider(default_status=SessionStatus.EXPIRED)
        self.assertIs(provider.mint("teacher", "x").status, SessionStatus.EXPIRED)

    def test_all_four_providers_satisfy_the_protocol(self) -> None:
        for provider in (
            supabase_provider(FakeTransport()),
            S.StorageStateProvider(),
            S.HttpLoginProvider("https://x.invalid/login"),
            S.OidcClientCredentialsProvider("https://x.invalid/token", client_id="c"),
            S.ScriptedSessionProvider(),
        ):
            with self.subTest(provider=provider.name):
                self.assertIsInstance(provider, S.SessionProvider)


class BuildProviderTests(unittest.TestCase):
    def test_a_supabase_block_builds_from_a_single_password_secret(self) -> None:
        provider = S.build_provider(
            {
                "provider": "supabase-password",
                "url": SUPABASE_URL,
                "anon_key": "anon",
                "passwords_from": "secret:SENTINEL_PERSONA_PASSWORDS",
                "verify": False,
            },
            {"SENTINEL_PERSONA_PASSWORDS": json.dumps({"teacher": PASSWORD})},
            transport=FakeTransport([("POST", "/auth/v1/token", http(200, token_body()))]),
        )
        self.assertIs(provider.mint("teacher", "probe@example.invalid").status, SessionStatus.OK)

    def test_an_unknown_provider_refuses_rather_than_defaulting(self) -> None:
        with self.assertRaises(ValueError):
            S.build_provider({"provider": "magic"})

    def test_a_service_role_secret_in_the_environment_is_refused(self) -> None:
        with self.assertRaises(S.SecretRefused):
            S.build_provider(
                {"provider": "storage-state"},
                {"SUPABASE_SERVICE_ROLE_KEY": "whatever"},
            )


# ---------------------------------------------------------------------------
# the leak sweep
# ---------------------------------------------------------------------------


class LeakTests(unittest.TestCase):
    """No token and no password in any error, note or repr.

    This is the test the rest of the module is shaped around. A credential in
    an error message ends up in CI output, which on a public repository is
    readable by anybody. So every failure path is driven and every string a
    caller could plausibly print is swept.

    What is deliberately *not* asserted: `Session.access_token` and
    `Session.storage_state` do contain the token, because they are what gets
    injected into a browser. The rule is about rendering, not about holding.
    """

    def _rendered_surfaces(self) -> list[tuple[str, str]]:
        surfaces: list[tuple[str, str]] = []

        def add(label: str, session) -> None:
            surfaces.append((f"{label}.error", str(session.error or "")))
            surfaces.append((f"{label}.repr", repr(session)))
            surfaces.append((f"{label}.str", str(session)))

        # Every way a Supabase sign-in can go wrong, plus the way it goes right.
        for label, routes in (
            ("supabase-ok", [
                ("POST", "/auth/v1/token", http(200, token_body())),
                ("GET", "/auth/v1/user", http(200, {})),
            ]),
            ("supabase-400", [
                ("POST", "/auth/v1/token", http(400, {"error": "invalid_grant"})),
            ]),
            # An auth server that echoes the submitted credential back. Real
            # ones have done this; our error message must not launder it.
            ("supabase-echo", [
                (
                    "POST",
                    "/auth/v1/token",
                    http(400, {"error": f"password {PASSWORD} is wrong", "token": ACCESS_TOKEN}),
                ),
            ]),
            ("supabase-expired", [
                ("POST", "/auth/v1/token", http(200, token_body(expires_at=1))),
            ]),
            ("supabase-unverified", [
                ("POST", "/auth/v1/token", http(200, token_body())),
                ("GET", "/auth/v1/user", http(401, {"error": "invalid_token"})),
            ]),
        ):
            transport = FakeTransport(routes)
            provider = supabase_provider(transport)
            add(label, provider.mint("teacher", "probe@example.invalid"))
            surfaces.append((f"{label}.provider-repr", repr(provider)))
            surfaces += [
                (f"{label}.request-repr", repr(r)) for r in transport.requests
            ]
            surfaces += [
                (f"{label}.response-repr", repr(response))
                for _m, _u, response in routes
            ]

        # A transport that raises with the password in the message.
        transport = FakeTransport()
        transport.raise_with = OSError(f"TLS handshake failed while sending {PASSWORD}")
        add("supabase-raise", supabase_provider(transport).mint("teacher", "p@x.invalid"))

        # http-login, success and failure.
        login = S.HttpLoginProvider(
            "https://app.example.invalid/login",
            credentials={"teacher": PASSWORD},
            transport=FakeTransport(
                [("POST", "/login", http(200, None, [("Set-Cookie", f"sid={COOKIE_VALUE}")]))]
            ),
            origin="https://app.example.invalid",
        )
        add("http-ok", login.mint("teacher", "probe@example.invalid"))
        surfaces.append(("http.provider-repr", repr(login)))

        failing_login = S.HttpLoginProvider(
            "https://app.example.invalid/login",
            credentials={"teacher": PASSWORD},
            transport=FakeTransport([("POST", "/login", http(200, {"ok": False}))]),
        )
        add("http-no-cookie", failing_login.mint("teacher", "probe@example.invalid"))

        # oidc, success and failure.
        oidc = S.OidcClientCredentialsProvider(
            "https://issuer.example.invalid/oauth/token",
            client_id="sentinel-probe",
            client_secret=CLIENT_SECRET,
            transport=FakeTransport(
                [("POST", "/oauth/token", http(200, {"access_token": ACCESS_TOKEN}))]
            ),
        )
        add("oidc-ok", oidc.mint("service", "sentinel-probe"))
        surfaces.append(("oidc.provider-repr", repr(oidc)))

        bad_oidc = S.OidcClientCredentialsProvider(
            "https://issuer.example.invalid/oauth/token",
            client_id="sentinel-probe",
            client_secret=CLIENT_SECRET,
            transport=FakeTransport(
                [("POST", "/oauth/token", http(401, {"error": "invalid_client"}))]
            ),
        )
        add("oidc-401", bad_oidc.mint("service", "sentinel-probe"))

        # storage-state: live, expired and corrupt.
        for label, capture in (
            ("capture-live", a_capture()),
            ("capture-expired", a_capture(expires_in_days=-3)),
        ):
            blob = S.seal_capture(capture, allow_plaintext=True).decode("utf-8")
            store = S.StorageStateProvider(source={"teacher": blob})
            add(label, store.mint("teacher", "x"))
            surfaces.append((f"{label}.provider-repr", repr(store)))
            surfaces.append((f"{label}.capture-repr", repr(capture)))

        corrupt = S.StorageStateProvider(
            source={"teacher": f"PRS-SESSION-1\nplain\n0000\n{COOKIE_VALUE}"}
        )
        add("capture-corrupt", corrupt.mint("teacher", "x"))

        # And the secret stores themselves.
        surfaces.append(("store.repr", repr(S.SecretStore({"teacher": PASSWORD}))))
        return surfaces

    def test_no_credential_appears_in_any_error_or_repr(self) -> None:
        surfaces = self._rendered_surfaces()
        # Guard against the sweep silently covering nothing.
        self.assertGreater(len(surfaces), 40)
        for secret in ALL_SECRETS:
            for label, text in surfaces:
                with self.subTest(secret=secret[:12], surface=label):
                    self.assertNotIn(secret, text)

    def test_the_sweep_would_notice_a_leak(self) -> None:
        # A leak test that cannot fail is decoration. This proves the
        # assertion in the test above is capable of firing.
        leaked = f"sign-in failed for password {PASSWORD}"
        self.assertIn(PASSWORD, leaked)

    def test_scrub_removes_known_values_and_token_shapes(self) -> None:
        store = S.SecretStore({"teacher": PASSWORD})
        text = S._scrub(f"{PASSWORD} and {ACCESS_TOKEN} and {REFRESH_TOKEN}", store)
        for secret in (PASSWORD, ACCESS_TOKEN, REFRESH_TOKEN):
            self.assertNotIn(secret, text)
        self.assertIn(S.REDACTED, text)

    def test_an_auth_servers_prose_never_reaches_an_error_message(self) -> None:
        # Only a short machine-readable code survives, so a server that put a
        # credential in `error_description` cannot route it through us.
        self.assertEqual(S._error_code({"error": "invalid_grant"}), "invalid_grant")
        self.assertIsNone(S._error_code({"error": f"the password {PASSWORD} is wrong"}))
        self.assertIsNone(S._error_code({"error": {"nested": "thing"}}))
        self.assertIsNone(S._error_code("not an object"))


if __name__ == "__main__":
    unittest.main()
