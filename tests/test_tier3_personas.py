"""Tier 3: archetypes, credential recon, role synthesis and matrix pruning.

Everything here runs with no network, no API key and no browser. Model calls
go through `ScriptedProvider`; repositories are real temporary directories,
because the recon and role-synthesis passes are mostly file reading and a
test against a mocked filesystem would be a test of the mock.
"""

from __future__ import annotations

import json
import unittest

from pr_sentinel.models import Severity
from pr_sentinel.tier3 import archetypes as A
from pr_sentinel.tier3 import matrix, recon, roles
from pr_sentinel.tier3.models import Capability, Persona, Role
from pr_sentinel.tier3.untrusted import clean_name, clean_names, clean_text

from tests.helpers import (
    TempDirTestCase,
    diff_of,
    json_response,
    make_context,
    scripted,
    write_tree,
)

C = Capability

#: A cast shaped like soar-app's, so the pruning assertions are about the same
#: eight-by-twelve matrix DESIGN-V2 §5.1a argues about.
SOAR_ROLES = [
    Role("student", "A student.", (C.READ_OWN, C.WRITE_OWN), "profiles.role"),
    Role("teacher", "A teacher.", (C.READ_ASSIGNED, C.WRITE_ASSIGNED), "profiles.role"),
    Role("aide", "An aide.", (C.READ_ASSIGNED, C.WRITE_ASSIGNED), "profiles.role"),
    Role(
        "admin",
        "An administrator.",
        (C.READ_ALL, C.WRITE_ASSIGNED, C.ADMINISTER),
        "profiles.role",
    ),
    Role("reviewer", "A reviewer.", (C.READ_ALL,), "profiles.role"),
    Role("auditor", "An auditor.", (C.READ_ALL,), "profiles.role"),
    Role("parent", "A parent.", (C.READ_OWN,), "profiles.role"),
    Role("grandparent", "A grandparent.", (C.READ_OWN,), "profiles.role"),
]


# ---------------------------------------------------------------------------
# archetypes
# ---------------------------------------------------------------------------


class ArchetypeTests(unittest.TestCase):
    EXPECTED = (
        "chaotic-actor",
        "tech-timid",
        "adversarial-probe",
        "power-user",
        "first-run",
        "returning-stale",
        "slow-network",
        "small-screen",
        "assistive-tech",
        "locale-other",
        "interrupted",
        "boundary-data",
    )

    def test_all_twelve_are_shipped(self) -> None:
        self.assertEqual(len(A.ARCHETYPES), 12)
        self.assertEqual(set(A.ARCHETYPE_NAMES), set(self.EXPECTED))

    def test_only_adversarial_probe_may_go_below_the_ui(self) -> None:
        # DESIGN-V2 §11: the probe gets direct API access precisely because
        # the holes that matter are reachable with a session and curl. Nothing
        # else does, and a second archetype acquiring the flag by accident is
        # a widening of what the tier is allowed to do.
        probing = {a.name for a in A.ARCHETYPES if a.probes_api}
        self.assertEqual(probing, {"adversarial-probe"})

    def test_exactly_three_archetypes_mutate(self) -> None:
        # §5.7: mutation is off by default and the ones that do it need a
        # teardown. The set is asserted, not counted, because adding a fourth
        # silently is how data appears in a shared database with nothing
        # recorded to delete it.
        self.assertEqual(
            {a.name for a in A.mutating()},
            {"chaotic-actor", "boundary-data", "interrupted"},
        )

    def test_environment_flags(self) -> None:
        self.assertEqual(A.by_name("small-screen").viewport, (390, 844))
        self.assertIsNone(A.by_name("chaotic-actor").viewport)
        self.assertEqual(A.by_name("slow-network").network, "slow-3g")
        self.assertEqual(A.by_name("interrupted").network, "offline-flap")
        self.assertIsNone(A.by_name("first-run").network)
        self.assertTrue(A.by_name("assistive-tech").keyboard_only)
        self.assertTrue(A.by_name("power-user").keyboard_only)
        self.assertFalse(A.by_name("tech-timid").keyboard_only)
        self.assertEqual(A.by_name("locale-other").locale, "ar-SA")
        self.assertIsNone(A.by_name("power-user").locale)

    def test_network_profiles_are_from_the_declared_vocabulary(self) -> None:
        for archetype in A.ARCHETYPES:
            self.assertIn(archetype.network, (None, "slow-3g", "offline-flap"))

    def test_every_charter_says_what_counts_as_a_problem(self) -> None:
        # The charter is what an exploring agent is given. One that says what
        # to try but not what to report produces a list of everything the model
        # noticed, which is the failure mode §5.6 calls the noisiest.
        for archetype in A.ARCHETYPES:
            with self.subTest(archetype.name):
                self.assertGreater(len(archetype.charter), 400)
                self.assertIn("problem is", archetype.charter)

    def test_charters_are_domain_free(self) -> None:
        # They ship with the engine and must transfer to any software.
        forbidden = ("student", "teacher", "grade", "school", "invoice", "patient")
        for archetype in A.ARCHETYPES:
            lowered = archetype.charter.lower() + archetype.description.lower()
            for word in forbidden:
                with self.subTest(archetype=archetype.name, word=word):
                    self.assertNotIn(word, lowered)

    def test_resolve_accepts_all_and_drops_inventions(self) -> None:
        self.assertEqual(A.resolve("all"), A.ARCHETYPES)
        self.assertEqual(A.resolve(None), A.ARCHETYPES)
        self.assertEqual(
            [a.name for a in A.resolve(["small-screen", "not-an-archetype"])],
            ["small-screen"],
        )


# ---------------------------------------------------------------------------
# untrusted model output
# ---------------------------------------------------------------------------


class UntrustedNameTests(unittest.TestCase):
    def test_names_are_normalised_within_a_strict_charset(self) -> None:
        self.assertEqual(clean_name("Teacher"), "teacher")
        self.assertEqual(clean_name("  front_desk  "), "front-desk")
        self.assertEqual(clean_name("Site Admin"), "site-admin")

    def test_a_name_can_never_become_a_path_a_url_or_a_flag(self) -> None:
        for hostile in (
            "../../etc/passwd",
            "/etc/passwd",
            "..\\windows",
            "http://evil.example/x",
            "file:///etc/shadow",
            "~/.ssh/id_rsa",
            "--output=/tmp/x",
            "C:\\Windows",
            "a" * 200,
            "",
            None,
            42,
            {"role": "admin"},
        ):
            with self.subTest(hostile=hostile):
                self.assertIsNone(clean_name(hostile))

    def test_lists_are_capped_deduplicated_and_confined(self) -> None:
        self.assertEqual(
            clean_names(["Teacher", "teacher", "nope"], allowed={"teacher"}),
            ["teacher"],
        )
        self.assertEqual(len(clean_names([f"role-{i}" for i in range(500)], limit=10)), 10)
        self.assertEqual(clean_names("not-a-list"), [])

    def test_prose_is_flattened_and_capped(self) -> None:
        self.assertEqual(clean_text("a\n\tb\x07c"), "a b c")
        self.assertLessEqual(len(clean_text("x" * 900, max_chars=100)), 100)


# ---------------------------------------------------------------------------
# credential reconnaissance
# ---------------------------------------------------------------------------

#: Deliberately recognisable, so a leak assertion is unambiguous about which
#: value escaped.
SERVICE_ROLE_VALUE = "LEAK-service-role-eyJhbGciOiJIUzI1NiJ9.aaaaaaaa.bbbbbbbb"
ANON_VALUE = "LEAK-anon-key-value-0123456789"
GOOGLE_SECRET_VALUE = "LEAK-google-client-secret-value"  # noqa: S105

SUPABASE_REPO = {
    "package.json": json.dumps(
        {
            "name": "target",
            "dependencies": {"@supabase/supabase-js": "^2.45.0", "react": "^18.2.0"},
        }
    ),
    "src/lib/supabaseClient.ts": (
        "import { createClient } from '@supabase/supabase-js';\n"
        "export const supabase = createClient(import.meta.env.VITE_SUPABASE_URL, "
        "import.meta.env.VITE_SUPABASE_ANON_KEY);\n"
        "export const current = () => supabase.auth.getSession();\n"
    ),
    "src/components/SignIn.tsx": (
        "export function SignIn() {\n"
        "  const go = () => supabase.auth.signInWithOAuth({ provider: 'google' });\n"
        "  return <button onClick={go}>Continue</button>;\n"
        "}\n"
    ),
    ".env.example": (
        "# the project\n"
        f"VITE_SUPABASE_URL=https://abcdefghij.supabase.co\n"
        f"VITE_SUPABASE_ANON_KEY={ANON_VALUE}\n"
        f"SUPABASE_SERVICE_ROLE_KEY={SERVICE_ROLE_VALUE}\n"
    ),
}

OAUTH_ONLY_REPO = {
    "package.json": json.dumps(
        {"name": "target", "dependencies": {"next-auth": "^4.24.0", "next": "^14.1.0"}}
    ),
    "src/auth/options.ts": (
        "import GoogleProvider from 'next-auth/providers/google';\n"
        "export const authOptions = {\n"
        "  providers: [GoogleProvider({ clientId: process.env.GOOGLE_CLIENT_ID })],\n"
        "};\n"
    ),
    "src/auth/guard.tsx": (
        "export function RequireAuth({ children }) {\n"
        "  const session = useSession();\n"
        "  return session ? children : null;\n"
        "}\n"
    ),
    ".env.local": (
        "NEXTAUTH_URL=http://localhost:3000\n"
        "GOOGLE_CLIENT_ID=1234-abc.apps.googleusercontent.com\n"
        f"GOOGLE_CLIENT_SECRET={GOOGLE_SECRET_VALUE}\n"
    ),
}


class ReconTests(TempDirTestCase):
    def _ctx(self, files: dict[str, str]):
        root = self.make_repo(files)
        return make_context(root)

    def test_supabase_repo_is_classified_and_gets_the_password_provider(self) -> None:
        result = recon.reconnoitre(self._ctx(SUPABASE_REPO))
        self.assertEqual(result.auth_system, recon.AUTH_SUPABASE)
        self.assertEqual(result.provider, recon.PROVIDER_SUPABASE_PASSWORD)
        # §5.2's whole point: the identity provider blocks automation and does
        # not have to be involved, because Supabase holds the session.
        self.assertTrue(result.automated_signin_possible)
        self.assertIn("SUPABASE_URL", "".join(result.env_var_names))
        self.assertIn(
            "session",
            result.to_yaml(),
        )

    def test_supabase_draft_names_the_password_secret_and_the_human_step(self) -> None:
        result = recon.reconnoitre(self._ctx(SUPABASE_REPO))
        names = {s.name for s in result.secrets_required}
        self.assertIn("SENTINEL_PERSONA_PASSWORDS", names)
        self.assertFalse(names & set(recon.FORBIDDEN_IN_CI))
        self.assertTrue(
            any("service-role" in step or "service role" in step for step in result.human_steps),
            result.human_steps,
        )

    def test_oauth_only_repo_says_automated_sign_in_is_blocked(self) -> None:
        result = recon.reconnoitre(self._ctx(OAUTH_ONLY_REPO))
        self.assertEqual(result.auth_system, recon.AUTH_OAUTH_ONLY)
        self.assertEqual(result.provider, recon.PROVIDER_STORAGE_STATE)
        self.assertFalse(result.automated_signin_possible)
        self.assertIn("capture", (result.blocked_reason or "").lower())
        self.assertIn(
            "SENTINEL_SESSION_STATE", {s.name for s in result.secrets_required}
        )

    def test_empty_repo_is_unknown_rather_than_a_guess(self) -> None:
        result = recon.reconnoitre(self._ctx({"README.md": "a project"}))
        self.assertEqual(result.auth_system, recon.AUTH_UNKNOWN)
        self.assertEqual(result.provider, recon.PROVIDER_STORAGE_STATE)
        self.assertFalse(result.automated_signin_possible)

    def test_recon_reads_variable_names_and_never_a_value(self) -> None:
        # The hard rule of §5.2a. Every rendered surface is swept, not just
        # the one a careless implementation would leak through.
        for files, leaks in (
            (SUPABASE_REPO, (SERVICE_ROLE_VALUE, ANON_VALUE)),
            (OAUTH_ONLY_REPO, (GOOGLE_SECRET_VALUE,)),
        ):
            result = recon.reconnoitre(self._ctx(files))
            surfaces = [
                result.checklist(),
                result.to_yaml(),
                json.dumps(result.session_config()),
                repr(result),
                "\n".join(e.render() for e in result.evidence),
                "\n".join(result.env_var_names),
                "\n".join(result.notes),
                "\n".join(result.human_steps),
                "\n".join(f"{s.name} {s.why} {s.how}" for s in result.secrets_required),
            ]
            for leak in leaks:
                for surface in surfaces:
                    with self.subTest(leak=leak):
                        self.assertNotIn(leak, surface)

    def test_the_name_of_a_forbidden_key_is_noted_but_never_requested(self) -> None:
        result = recon.reconnoitre(self._ctx(SUPABASE_REPO))
        # Knowing the variable exists is useful; asking an owner to paste it
        # into CI would undo §6's safety argument.
        self.assertIn("SUPABASE_SERVICE_ROLE_KEY", result.env_var_names)
        self.assertNotIn(
            "SUPABASE_SERVICE_ROLE_KEY", {s.name for s in result.secrets_required}
        )
        self.assertIn("Never put these in CI", result.checklist())

    def test_a_model_asking_for_the_service_role_key_is_refused(self) -> None:
        provider = scripted(
            (
                "credential reconnaissance",
                json_response(
                    json.dumps(
                        {
                            "auth_system": "supabase-auth",
                            "provider": "supabase-password",
                            "confidence": "high",
                            "automated_signin_possible": True,
                            "summary": "Supabase holds the session.",
                            "secrets_required": [
                                {
                                    "name": "SUPABASE_SERVICE_ROLE_KEY",
                                    "why": "so you can do anything",
                                    "how": "copy it from the dashboard",
                                },
                                {
                                    "name": "SENTINEL_PERSONA_PASSWORDS",
                                    "why": "one password per persona",
                                    "how": "the one-time local setup",
                                },
                            ],
                            "human_steps": ["Create the probe accounts."],
                            "notes": [],
                        }
                    )
                ),
            )
        )
        result = recon.reconnoitre(self._ctx(SUPABASE_REPO), provider)
        self.assertTrue(result.model_used)
        self.assertNotIn(
            "SUPABASE_SERVICE_ROLE_KEY", {s.name for s in result.secrets_required}
        )
        self.assertTrue(any("Refused" in n for n in result.notes), result.notes)

    def test_garbage_from_the_model_leaves_the_deterministic_result_standing(self) -> None:
        provider = scripted(("credential reconnaissance", "I'm afraid I can't do that."))
        result = recon.reconnoitre(self._ctx(SUPABASE_REPO), provider)
        self.assertEqual(result.auth_system, recon.AUTH_SUPABASE)
        self.assertEqual(result.provider, recon.PROVIDER_SUPABASE_PASSWORD)
        self.assertTrue(any("parseable" in n for n in result.notes), result.notes)

    def test_an_invented_provider_falls_back_to_the_classification_default(self) -> None:
        provider = scripted(
            (
                "credential reconnaissance",
                json_response(
                    json.dumps(
                        {
                            "auth_system": "supabase-auth",
                            "provider": "../../bin/sh",
                            "confidence": "high",
                            "summary": "ok",
                        }
                    )
                ),
            )
        )
        result = recon.reconnoitre(self._ctx(SUPABASE_REPO), provider)
        self.assertEqual(result.provider, recon.PROVIDER_SUPABASE_PASSWORD)
        self.assertTrue(any("does not exist" in n for n in result.notes), result.notes)


# ---------------------------------------------------------------------------
# role synthesis and drift
# ---------------------------------------------------------------------------

ROLE_REPO = {
    "supabase/migrations/0001_roles.sql": (
        "create type user_role as enum ('student', 'teacher', 'counselor');\n"
        "alter table public.profiles add column role user_role not null default 'student';\n"
        "create policy \"students read own\" on public.points\n"
        "  for select using (auth.uid() = user_id and role = 'student');\n"
        "create policy \"teachers read section\" on public.points\n"
        "  for select using (role = 'teacher');\n"
        "grant select on public.points to authenticated;\n"
    ),
    "src/auth/guards.tsx": (
        "export const allowedRoles = ['student', 'teacher', 'counselor'];\n"
        "export function requireRole('teacher') {}\n"
        "export const isAdmin = (u) => u.app_metadata.role === 'admin';\n"
    ),
    "src/components/Chart.tsx": "export const Chart = () => <svg />;\n",
}


class RoleSynthesisTests(TempDirTestCase):
    def _ctx(self, files: dict[str, str] = None):
        return make_context(self.make_repo(files if files is not None else ROLE_REPO))

    def test_artefacts_are_the_auth_files_and_not_the_whole_repo(self) -> None:
        artefacts = roles.auth_artefacts(self._ctx())
        paths = {a.path for a in artefacts}
        self.assertIn("supabase/migrations/0001_roles.sql", paths)
        self.assertIn("src/auth/guards.tsx", paths)
        self.assertNotIn("src/components/Chart.tsx", paths)

    def test_heuristic_synthesis_reads_roles_off_the_auth_model(self) -> None:
        result = roles.synthesise_roles(self._ctx())
        self.assertFalse(result.model_used)
        self.assertTrue({"student", "teacher", "counselor"} <= result.names, result.names)
        # Postgres' own roles are how policies are written, not people.
        self.assertNotIn("authenticated", result.names)
        self.assertNotIn("service-role", result.names)
        self.assertTrue(all(r.description for r in result.roles))
        self.assertTrue(all(r.derived_from for r in result.roles))
        self.assertTrue(any("heuristic" in n for n in result.notes), result.notes)

    def test_synthesis_is_never_empty_even_with_no_auth_model(self) -> None:
        # An empty role set means no personas, which means a runtime tier that
        # explores nothing and would report it as clean.
        result = roles.synthesise_roles(self._ctx({"README.md": "hello"}))
        self.assertGreaterEqual(len(result.roles), 2)
        self.assertTrue(any("almost certainly wrong" in n for n in result.notes))

    def test_model_synthesis_is_validated_and_hostile_names_dropped(self) -> None:
        provider = scripted(
            (
                "role-synthesis step",
                json_response(
                    json.dumps(
                        {
                            "roles": [
                                {
                                    "name": "Teacher",
                                    "description": "Teaches sections.",
                                    "expected": ["read-assigned", "write-assigned", "nonsense"],
                                    "derived_from": "profiles.role",
                                    "must_not_reach": ["records outside their sections"],
                                },
                                {
                                    "name": "../../etc/passwd",
                                    "description": "hostile",
                                    "expected": ["read-all"],
                                },
                                {
                                    "name": "service_role",
                                    "description": "a database role",
                                    "expected": ["administer"],
                                },
                                {
                                    "name": "counselor",
                                    "description": "Supports students.",
                                    "expected": ["read-assigned"],
                                    "derived_from": "user_role enum",
                                },
                            ],
                            "notes": ["the enum was the clearest evidence"],
                        }
                    )
                ),
            )
        )
        result = roles.synthesise_roles(self._ctx(), provider)
        self.assertTrue(result.model_used)
        self.assertEqual(result.names, {"teacher", "counselor"})
        teacher = next(r for r in result.roles if r.name == "teacher")
        self.assertEqual(
            teacher.expected, (Capability.READ_ASSIGNED, Capability.WRITE_ASSIGNED)
        )
        self.assertTrue(any("failed validation" in n for n in result.notes), result.notes)

    def test_a_model_returning_one_role_falls_back_to_the_heuristic(self) -> None:
        provider = scripted(
            (
                "role-synthesis step",
                json_response(json.dumps({"roles": [{"name": "user", "description": "a user"}]})),
            )
        )
        result = roles.synthesise_roles(self._ctx(), provider)
        self.assertFalse(result.model_used)
        self.assertTrue({"student", "teacher"} <= result.names)

    def test_fingerprint_is_stable_and_ignores_unrelated_edits(self) -> None:
        ctx = self._ctx()
        first = roles.auth_fingerprint(ctx)
        self.assertEqual(first, roles.auth_fingerprint(ctx))
        # A file with no auth lines changing must not look like the auth model
        # moving, or the drift detector fires on every PR and gets ignored.
        write_tree(ctx.repo_root, {"src/components/Chart.tsx": "export const Chart = 1;\n"})
        self.assertEqual(first, roles.auth_fingerprint(ctx))

    def test_drift_fires_when_the_auth_model_changes(self) -> None:
        ctx = self._ctx()
        committed = roles.auth_fingerprint(ctx)
        self.assertFalse(roles.detect_drift(committed, ctx).changed)

        write_tree(
            ctx.repo_root,
            {
                "supabase/migrations/0002_counselor.sql": (
                    "create policy \"counselors read\" on public.points\n"
                    "  for select using (role = 'counselor');\n"
                )
            },
        )
        drift = roles.detect_drift(committed, ctx)
        self.assertTrue(drift.changed)
        self.assertEqual(drift.committed, committed)
        self.assertNotEqual(drift.current, committed)
        self.assertIn("fingerprint", drift.note)

    def test_a_missing_committed_fingerprint_counts_as_drift(self) -> None:
        drift = roles.detect_drift(None, self._ctx())
        self.assertTrue(drift.changed)
        self.assertIn("never been checked", drift.note)

    def test_a_new_role_nobody_probes_becomes_a_finding(self) -> None:
        ctx = self._ctx()
        drift, synthesis, findings = roles.role_drift_findings(
            ctx, committed_fingerprint="stale0000000000", committed_roles=["student", "teacher"]
        )
        self.assertTrue(drift.changed)
        self.assertIsNotNone(synthesis)
        added = [f for f in findings if f.severity is Severity.HIGH]
        self.assertEqual(len(added), 1)
        finding = added[0]
        self.assertEqual(finding.rule_id, "runtime.role-drift")
        self.assertIn("counselor", finding.title)
        self.assertIn("counselor", finding.message)
        self.assertIn("counselor", finding.metadata["added_roles"])
        self.assertTrue(finding.rationale)

    def test_a_role_the_auth_model_lost_is_reported_more_quietly(self) -> None:
        ctx = self._ctx()
        _drift, _synthesis, findings = roles.role_drift_findings(
            ctx,
            committed_fingerprint="stale0000000000",
            committed_roles=["student", "teacher", "counselor", "admin", "ghost"],
        )
        self.assertEqual([f.severity for f in findings], [Severity.MEDIUM])
        self.assertIn("ghost", findings[0].message)

    def test_no_drift_means_no_resynthesis_and_no_finding(self) -> None:
        ctx = self._ctx()
        committed = roles.auth_fingerprint(ctx)
        drift, synthesis, findings = roles.role_drift_findings(
            ctx, committed, ["student", "teacher", "counselor"]
        )
        self.assertFalse(drift.changed)
        self.assertIsNone(synthesis)
        self.assertEqual(findings, [])


# ---------------------------------------------------------------------------
# plausibility pruning
# ---------------------------------------------------------------------------


class PruneTests(unittest.TestCase):
    def test_heuristic_pruning_cuts_the_cross_product_to_about_thirty(self) -> None:
        result = matrix.prune_matrix(SOAR_ROLES)
        self.assertEqual(result.considered, 96)
        self.assertTrue(result.heuristic)
        self.assertLessEqual(len(result.personas), 30)
        self.assertGreaterEqual(len(result.personas), 20)
        self.assertTrue(any("heuristic" in n for n in result.notes), result.notes)

    def test_the_two_combinations_the_spec_names_are_decided_correctly(self) -> None:
        # §5.1a: "A chaotic-asshole teacher is a combination that does not
        # describe anyone; a tech-timid grandparent is half your real support
        # burden."
        names = set(matrix.prune_matrix(SOAR_ROLES).names)
        self.assertNotIn("teacher/chaotic-actor", names)
        self.assertIn("grandparent/tech-timid", names)

    def test_every_role_keeps_an_adversarial_probe(self) -> None:
        result = matrix.prune_matrix(SOAR_ROLES)
        probed = {p.role.name for p in result.by_archetype("adversarial-probe")}
        self.assertEqual(probed, {r.name for r in SOAR_ROLES})

    def test_every_kept_persona_carries_a_justification(self) -> None:
        for persona in matrix.prune_matrix(SOAR_ROLES).personas:
            with self.subTest(persona.name):
                self.assertTrue(persona.plausibility.strip())

    def test_pruning_is_deterministic(self) -> None:
        self.assertEqual(
            matrix.prune_matrix(SOAR_ROLES).names, matrix.prune_matrix(SOAR_ROLES).names
        )

    def test_a_model_may_keep_combinations_the_heuristic_would_cut(self) -> None:
        provider = scripted(
            (
                "plausibility-pruning step",
                json_response(
                    json.dumps(
                        {
                            "keep": [
                                {
                                    "role": "grandparent",
                                    "archetype": "tech-timid",
                                    "plausibility": "Opens this once a term, from a text link.",
                                },
                                {
                                    "role": "teacher",
                                    "archetype": "power-user",
                                    "plausibility": "In this every period of every day.",
                                },
                            ],
                            "dropped_because": ["staff are fast, not chaotic"],
                            "notes": ["parents skew mobile"],
                        }
                    )
                ),
            )
        )
        result = matrix.prune_matrix(SOAR_ROLES, None, provider)
        self.assertFalse(result.heuristic)
        self.assertEqual(
            result.names, ["grandparent/tech-timid", "teacher/power-user"]
        )
        self.assertIn(
            "Opens this once a term, from a text link.",
            [p.plausibility for p in result.personas],
        )

    def test_invented_names_are_dropped_not_run(self) -> None:
        provider = scripted(
            (
                "plausibility-pruning step",
                json_response(
                    json.dumps(
                        {
                            "keep": [
                                {"role": "teacher", "archetype": "tech-timid", "plausibility": "x"},
                                {"role": "superuser", "archetype": "tech-timid"},
                                {"role": "teacher", "archetype": "../../etc/passwd"},
                                "not even an object",
                            ]
                        }
                    )
                ),
            )
        )
        result = matrix.prune_matrix(SOAR_ROLES, None, provider)
        self.assertEqual(result.names, ["teacher/tech-timid"])
        self.assertTrue(any("does not exist" in n for n in result.notes), result.notes)

    def test_garbage_from_the_model_degrades_to_the_heuristic(self) -> None:
        for bad in ("", "sure thing!", json_response("{}"), json_response('{"keep": []}')):
            with self.subTest(bad=bad[:20]):
                result = matrix.prune_matrix(
                    SOAR_ROLES, None, scripted(("plausibility-pruning step", bad))
                )
                self.assertTrue(result.heuristic)
                self.assertTrue(result.personas)
                self.assertTrue(any("heuristic" in n for n in result.notes))

    def test_an_empty_role_set_says_skip_rather_than_pretending(self) -> None:
        result = matrix.prune_matrix([])
        self.assertEqual(result.personas, [])
        self.assertTrue(any("skipped" in n for n in result.notes), result.notes)

    def test_committed_form_keeps_the_justifications(self) -> None:
        config = matrix.as_config(matrix.prune_matrix(SOAR_ROLES))
        self.assertEqual(config["pruning"]["method"], "heuristic")
        self.assertEqual(config["pruning"]["considered"], 96)
        self.assertTrue(all(p["plausibility"] for p in config["personas"]))


# ---------------------------------------------------------------------------
# PR-aware selection
# ---------------------------------------------------------------------------

RLS_DIFF = """
diff --git a/supabase/migrations/0014_widen.sql b/supabase/migrations/0014_widen.sql
--- a/supabase/migrations/0014_widen.sql
+++ b/supabase/migrations/0014_widen.sql
@@ -1,3 +1,6 @@
 begin;
+drop policy "teachers read own sections" on public.points;
+create policy "teachers read all" on public.points
+  for select using (auth.uid() is not null);
 commit;
"""

FORM_DIFF = """
diff --git a/src/components/AwardPoints.tsx b/src/components/AwardPoints.tsx
--- a/src/components/AwardPoints.tsx
+++ b/src/components/AwardPoints.tsx
@@ -4,3 +4,6 @@
 export function AwardPoints() {
+  return <form onSubmit={save}>
+    <input name="points" maxLength={4} />
+  </form>;
 }
"""

CSS_DIFF = """
diff --git a/src/styles/app.css b/src/styles/app.css
--- a/src/styles/app.css
+++ b/src/styles/app.css
@@ -1,2 +1,4 @@
 .shell {
+  position: fixed;
+  z-index: 40;
 }
"""

DOC_DIFF = """
diff --git a/docs/notes.md b/docs/notes.md
--- a/docs/notes.md
+++ b/docs/notes.md
@@ -1,2 +1,3 @@
 # Notes
+A sentence about nothing in particular.
"""


class SelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        # The full matrix, so selection is choosing rather than being
        # constrained by what pruning happened to keep.
        self.pool = [
            Persona(role=role, archetype=archetype, plausibility="full matrix, for the test")
            for role in SOAR_ROLES
            for archetype in A.ARCHETYPES
        ]

    def test_an_rls_change_selects_adversarial_probe_for_every_role(self) -> None:
        result = matrix.select_for_pr(self.pool, diff_of(RLS_DIFF), limit=32)
        self.assertTrue(result.heuristic)
        self.assertIn("authorization", result.signals)
        probed = {p.role.name for p in result.personas if p.archetype.name == "adversarial-probe"}
        self.assertEqual(probed, {r.name for r in SOAR_ROLES})
        self.assertIn("adversarial-probe", result.reasoning)

    def test_the_probe_fills_the_budget_before_weaker_signals_do(self) -> None:
        result = matrix.select_for_pr(self.pool, diff_of(RLS_DIFF), limit=8)
        self.assertEqual({p.archetype.name for p in result.personas}, {"adversarial-probe"})
        self.assertTrue(any("not run" in n for n in result.notes), result.notes)

    def test_a_form_change_selects_the_three_disruptive_archetypes(self) -> None:
        result = matrix.select_for_pr(self.pool, diff_of(FORM_DIFF), limit=32)
        self.assertEqual(
            {p.archetype.name for p in result.personas},
            {"chaotic-actor", "boundary-data", "interrupted"},
        )

    def test_a_css_change_selects_the_two_populations_it_can_break(self) -> None:
        result = matrix.select_for_pr(self.pool, diff_of(CSS_DIFF), limit=32)
        self.assertEqual(
            {p.archetype.name for p in result.personas},
            {"small-screen", "assistive-tech"},
        )

    def test_an_uncharacterisable_diff_runs_a_smoke_test_and_says_so(self) -> None:
        result = matrix.select_for_pr(self.pool, diff_of(DOC_DIFF), limit=32)
        self.assertEqual(result.signals, [])
        self.assertEqual(
            {p.archetype.name for p in result.personas}, {"first-run", "small-screen"}
        )
        self.assertIn("weak evidence", result.reasoning)

    def test_reasoning_is_always_returned_for_the_comment(self) -> None:
        for text in (RLS_DIFF, FORM_DIFF, CSS_DIFF, DOC_DIFF):
            with self.subTest(text=text[:40]):
                self.assertTrue(matrix.select_for_pr(self.pool, diff_of(text)).reasoning)

    def test_a_model_selection_is_confined_to_the_committed_set(self) -> None:
        provider = scripted(
            (
                "persona selection step",
                json_response(
                    json.dumps(
                        {
                            "selected": [
                                {"role": "teacher", "archetype": "adversarial-probe"},
                                {"role": "nobody", "archetype": "adversarial-probe"},
                            ],
                            "reasoning": "The policy predicate widened; probe as each role.",
                            "notes": [],
                        }
                    )
                ),
            )
        )
        result = matrix.select_for_pr(self.pool, diff_of(RLS_DIFF), provider)
        self.assertFalse(result.heuristic)
        self.assertEqual(result.names, ["teacher/adversarial-probe"])
        self.assertIn("widened", result.reasoning)
        self.assertTrue(any("not in the committed set" in n for n in result.notes))

    def test_a_model_that_selects_nothing_falls_back_rather_than_skipping(self) -> None:
        provider = scripted(("persona selection step", json_response('{"selected": []}')))
        result = matrix.select_for_pr(self.pool, diff_of(RLS_DIFF), provider, limit=32)
        self.assertTrue(result.heuristic)
        self.assertTrue(result.personas)
        self.assertTrue(any("heuristic selection was used" in n for n in result.notes))

    def test_an_empty_persona_set_is_a_skipped_review_not_a_clean_one(self) -> None:
        result = matrix.select_for_pr([], diff_of(RLS_DIFF))
        self.assertEqual(result.personas, [])
        self.assertIn("skipped review, not a clean one", result.reasoning)


if __name__ == "__main__":
    unittest.main()
