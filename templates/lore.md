<!--
-------------------------------------------------------------------------------
GOES IN:  <your-repo>/.pr-sentinel/lore.md
          (referenced by `lore:` in .pr-sentinel.yml)
-------------------------------------------------------------------------------
This file stays in YOUR repo and never goes near the engine. That split is what
makes a public reviewer safe to point at a private codebase, and it is also
what makes the reviewer yours: same engine + different lore = a different
reviewer.

The entries below are real ones for soar-app, distilled from its
docs/DECISIONS-LOG.md. Replace them with yours. If you have a decisions log, an
incident channel or a "we keep doing this" wiki page, that is your source
material - it already reads like a set of review rules waiting to be extracted.

WHAT A GOOD ENTRY LOOKS LIKE

  - It states a FACT ABOUT THIS REPO that a competent outsider could not know.
    "Student Google accounts share the staff email domain" is lore. "Validate
    your inputs" is not - it is true everywhere, so it belongs in a pack, or
    nowhere.
  - It says WHY IT MATTERS HERE, in consequences. The agent uses this to decide
    whether a diff has re-entered the trap, so the mechanism has to be legible.
  - It CITES THE EVIDENCE: the PR, the migration number, the incident, the
    date. Four occurrences beats "this happens a lot", because the agent can
    tell whether the fifth looks like the first four.
  - It NAMES THE RULE ID it relates to, where one exists. That links a judgment
    finding back to a deterministic one, and it tells you which local rule to
    write when the pattern turns out to be mechanical after all.
  - It says WHAT CORRECT LOOKS LIKE, not only what wrong looks like. A reviewer
    that can only say "this is wrong" generates arguments; one that can say
    "this is what the last four fixes did" generates patches.

WHAT BAD LORE LOOKS LIKE

  - Generic advice. "Be careful with migrations." The agent already believes
    that and it is not repo knowledge.
  - Restating a pack rule. If `supabase.permissive-policy` already catches
    `using (true)`, lore should explain the local twist (see entry 2), not
    repeat the rule.
  - Aspirations. "We should really add tests to the sync layer." Lore is about
    mistakes already made; a wishlist here just dilutes the signal.
  - Anything secret. This file is read into model prompts. No keys, no student
    names, no customer data.
  - Unbounded length. Every entry competes for the agent's attention with every
    other. Ten sharp entries beat fifty vague ones; prune entries whose trap
    has been closed structurally.
-------------------------------------------------------------------------------
-->

# soar-app review lore

Expensive, recurring, already-made mistakes in this repository. Each entry is
something we got wrong at least once and would rather not get wrong again.

---

## 1. `service_role` needs its own GRANT, separate from `authenticated`

**Rules:** `supabase.missing-grants`, `supabase.permissive-policy`

Four occurrences so far: `core` migration 027, `monday_school` 029, the
System 2 tables in 030, and `signage` 039. Each time the fix was the same
line, and each time it was found after something broke rather than in review.

RLS bypass is not grant bypass. `service_role` skips row-level security, so it
is easy to assume it skips table privileges too. It does not — Postgres still
checks `GRANT`, and without one the backend job fails with a permission error
on a table its policies say it may read. The symptom (a 403 from PostgREST on
a table that clearly has a permissive policy) looks like an RLS problem and
sends everyone to the wrong file.

**Correct looks like:** every new table in a migration carries explicit grants
for *both* roles, e.g.
`GRANT SELECT, INSERT, UPDATE, DELETE ON <table> TO authenticated;` and a
separate `GRANT ... TO service_role;`. A migration that creates a table and
grants only `authenticated` is incomplete even if its policies are perfect.

---

## 2. `authenticated` means "any student" in this repo, not "a trusted user"

**Rules:** `supabase.permissive-policy`; the RLS-enabled-with-no-policy case
is now reported by the `supabase-advisors` adapter (Supabase lint 0008)

Student Google accounts live in the *same* email domain as staff, under a
numeric prefix. There is no domain boundary between a seventh-grader and the
business manager; both are ordinary authenticated users of the same Google
Workspace.

So `using (true)` authorizes every student, and — this is the part that gets
missed — so does the apparently careful `using (auth.role() = 'authenticated')`.
That second form reads like a security control and is not one here. It is why
the permissive-policy rule is `critical` in this repo when it might justifiably
be `high` somewhere with a staff-only identity provider.

**Correct looks like:** a predicate that names the actual subject — a join to
the staff roster, a `staff_only()` helper, a role claim the app sets — not the
mere fact of being logged in. If a reviewer cannot say which humans a policy
admits, the policy is not finished.

---

## 3. `\uXXXX` escapes in a JSX text position render as literal characters

**Rule:** `react-vite.jsx.unicode-escape-in-text`

Writing an em dash as a backslash-u escape directly between JSX tags —
`<p>Hello` then the escape for U+2014 then `world</p>` — puts the six
characters of the escape itself on the screen, backslash and all. The escape
is only interpreted inside a JavaScript string literal, and a JSX text node is
not one. It has shipped to production at least once, because it looks correct
in the diff, passes tests that assert on `textContent` written with the same
escape, and only fails in front of a human reading the page.

**Correct looks like:** the literal character pasted into the source, or an
expression container — `<p>{"..."}</p>` with the escape inside the quotes,
where it is a string literal and does get interpreted. Either is fine; the
broken form is the one with a backslash sitting directly in the markup.

---

## 4. Deployment config fails *silently* when it is wrong

**Rules:** none yet — this is the lore entry that most wants a local rule.

`firebase.json` and `.firebaserc` route two sites. When a target is mis-wired,
both sites keep serving *the app*, so nothing 404s, no build fails, and no
alert fires. The only symptom is that the wrong content is at the wrong
address, which is invisible until someone visits the URL they never visit.

Every past occurrence was found by a person noticing, days later. That is the
signature of a check-worthy failure: high cost, zero signal.

**Correct looks like:** any diff touching `firebase.json`, `.firebaserc` or a
hosting target is treated as a deploy-affecting change and gets the site
mapping stated explicitly in the PR description, target by target. Treat "the
deploy succeeded" as no evidence at all.

---

## 5. Migrations are immutable once run, and numbers collide across branches

**Rules:** `supabase.migration-immutability`, `supabase.migration-numbering`

Two separate traps that arrive together.

*Immutability:* editing a migration that has already run against any
environment means environments silently diverge. The file says one thing, the
deployed schema says another, and nothing reconciles them. The fix is always a
new migration; there is no exception to this, including for typos in comments.

*Numbering:* two branches opened in the same week both take the next number.
Both merge. Whichever applies second either fails or applies out of intended
order, depending on the tooling's mood. This has happened during ordinary
concurrent work, not during anything unusual.

**Correct looks like:** a PR that renumbers its own migration at rebase time
rather than at merge time, and never modifies an existing migration file —
`git log --follow` on a migration should show exactly one commit.
