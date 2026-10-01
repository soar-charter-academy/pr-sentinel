# pr-sentinel v2 — aggregate the known, own the novel

Supersedes parts of [`DESIGN.md`](DESIGN.md). Written 2026-09-30, after an
honest audit of what already exists in the market.

Status: **plan, for sign-off.** Nothing in §4–§6 is built.

---

## 1. What changed

v1 was built and works: 27 deterministic checks, six packs, an agent tier,
341 tests. Then we checked it against the 2026 landscape and found two things.

**Most of the deterministic tier is reinvention.** `zizmor` ships 38 Actions
audit rules against our 5 and is the de facto standard. Socket does
supply-chain behavioural analysis with registry data we cannot obtain. Three
of our seven Supabase checks are Supabase's own published advisors (0008,
0010, 0011). DESIGN.md §2 anticipated this exactly — *"Not a linter rewrite.
Where semgrep, eslint or the Supabase linter already check something, shell
out rather than reimplement"* — and the build drifted from its own spec.

**The AI tier is the weakest part of the thing we called AI-powered.** 1,313
lines against 7,344 deterministic. No tool use. No retrieval. Capped at 25
diff files. Never run against a real model. Meanwhile Anthropic's managed
Code Review runs parallel specialized agents with a verification step — our
exact architecture, plus a live shell.

So v2 inverts the ratio. Aggregate what exists. Spend our own engineering
only where nothing exists.

### The new thesis

Every reviewer in the market reads code. **None of them run the software.**

A PR that widens who can read student records is, in the end, a claim about
what a browser will render when a particular person signs in. You can argue
about that claim by reading a diff, or you can sign in and look. The second
is better evidence, and nobody is selling it.

That is the thing worth owning.

---

## 2. Revised architecture

```
PR opened
   |
   +-- Tier 0  Project checks       tests, lint, build        (ours, kept)
   |
   +-- Tier 1  Deterministic        ADAPTERS to existing tools + ~9 of our own
   |
   +-- Tier 2  Agent review         specialized passes, now WITH TOOLS
   |
   +-- Tier 3  Runtime review       boot it, sign in, explore   <-- NEW, ours
   |
   +-- Verdict -> one comment + two check-runs
```

Tier 3 is the differentiated tier. Tiers 0–2 exist to be cheap, to be
correct, and to not embarrass us; Tier 3 is the reason the project exists.

---

## 3. Tier 1 becomes an adapter layer

The engine stops implementing rules that others maintain better, and starts
normalising their output into our `Finding` model so that one comment, one
severity policy and one verdict still govern everything.

| Adapter | Replaces | Why theirs wins |
|---|---|---|
| `zizmor` | our whole `github-actions` pack | 38 rules vs 5; catches impostor commits and cache poisoning we never wrote; maintained against new Actions attack classes |
| `socket` | `supply-chain.new-dependency`, `.install-scripts` | behavioural analysis plus registry data (publish age, maintainer churn) that we provably cannot get offline |
| `supabase-advisors` | `rls-enabled-no-policy`, `security-definer-view`, `mutable-search-path` | they are Supabase's own lints, run against the live schema |
| `gitleaks` | `core/rules/secrets.yml` | vastly larger, better-tuned corpus |
| `squawk` | migration-safety judgement in the `data-model` pass | purpose-built Postgres migration linter |
| `actionlint` | workflow correctness | complements zizmor's security focus |
| `semgrep` | kept as-is | still our mechanism for repo-specific declarative rules |

An adapter is small and uniform: run the tool, parse its native output
(SARIF where available), map to `Finding` with the adapter named as the pack,
and record the tool's version in provenance. Each declares whether its
absence is degrading — a missing `zizmor` withholds the deterministic
check-run exactly as a missing semgrep does today.

### What we keep implementing ourselves

Nine checks, because nothing else has them:

- `supabase.migration-numbering`, `supabase.migration-immutability` — facts
  about how *this* team branches, not about Postgres
- `supabase.missing-grants` — the `service_role`-needs-its-own-GRANT rule is
  soar lore with four documented occurrences, not general knowledge
- `privacy-edu.*` (five) — student-PII surfacing with framework naming exists
  nowhere else
- `react-vite.client-env-secrets`, the `\uXXXX`-in-JSX-text rule

Everything else in `tier1/checks/` is deleted. That is roughly 6,000 lines
removed, and the tests that go with them.

---

## 4. Tier 2 gets tools

The complaint was fair: a model with a training cutoff, no tools, and 25 diff
files is not an analyst. It is an autocomplete with a severity field.

Tier 2 becomes a bounded tool-use loop. The tools:

| Tool | Why |
|---|---|
| `read_file(path, range)` | read the file that *calls* the changed function, which is the commonest reason a finding is wrong |
| `grep(pattern, glob)` | find the other call sites; the `parity` pass is useless without it |
| `list_dir(path)` | orient in an unfamiliar repo |
| `git_log(path)` / `git_blame(path, line)` | "has this line been churned five times" is real signal |
| `read_test(name)` | check whether the behaviour is already pinned by a test |
| `fetch_advisory(package, version)` | the one network tool, allowlisted to advisory endpoints only |

Bounded means bounded: a per-pass tool-call budget, a wall-clock cap, paths
confined to the checkout, no writes, no shell, and no arbitrary network. The
loop is ours — we are not adopting someone's agent harness — but Playwright,
ripgrep and git are tools, and using them is not reinvention.

Everything a pass produces remains a *candidate*. The verification pass is
unchanged and still drops what it cannot substantiate.

---

## 5. Tier 3 — the runtime tier

Boot the application from the PR's code, sign in as a cast of personas,
explore, and report what the software actually did.

### 5.1 Personas are a matrix, not a list

Two independent axes, which is what makes this more than scripted E2E.

**Role** — who you are in the domain. Generated per target application by the
model, from the repo's own auth model, then committed to config so it is
stable and reviewable. For soar-app: student, teacher, aide, admin, reviewer,
auditor, parent, grandparent.

**Archetype** — how you behave. Twelve, shipped with the engine, deliberately
domain-free so they transfer to any software:

| Archetype | What it is for |
|---|---|
| `chaotic-actor` | clicks everything, double-submits, hits back mid-flow, pastes junk into fields |
| `tech-timid` | slow, misreads labels, abandons flows; finds affordances that are not obvious |
| `adversarial-probe` | tampers with client state and request parameters, tries IDOR and privilege escalation |
| `power-user` | keyboard-driven, bulk actions, deep links, many tabs, expects speed |
| `first-run` | no data anywhere; empty states, onboarding, zero-item lists |
| `returning-stale` | old session, stale `localStorage`, cached assets, offline-then-online |
| `slow-network` | throttled and flaky; loading, timeout and error states |
| `small-screen` | mobile viewport and touch |
| `assistive-tech` | keyboard-only and screen-reader semantics |
| `locale-other` | different locale, long translated strings, RTL |
| `interrupted` | backgrounds the tab, drops connection mid-write, duplicate submits |
| `boundary-data` | max-length input, unicode, emoji, very large lists |

A persona is `(role, archetype, session)`. Eight roles by twelve archetypes is
96 combinations, which no PR justifies running. **Triage selects the set**:
a PR touching an RLS policy gets every role crossed with
`adversarial-probe`; a PR touching a form gets the editing roles crossed with
`chaotic-actor`, `boundary-data` and `interrupted`; a PR touching CSS gets
`small-screen` and `assistive-tech`. The selection and its reasoning go in
the comment, so a reader knows what was and was not exercised.

### 5.2 Sessions: the Google problem, honestly

The plan was to hand the model the scoped reviewer credentials and let it
sign in. That will not work, and the reason is not permissions.

**Google blocks automated sign-in.** A Playwright-driven Google login is
detected and refused — *"this browser or app may not be secure"* — commonly
with a device-verification challenge behind it. Correct credentials do not
help, and driving it anyway is against Google's terms. This is an anti-bot
wall, not an access problem.

Fortunately Google is only the *identity provider*. The thing holding the
session is Supabase Auth, and Supabase can mint a session without Google
being involved at all. So sessions come from a pluggable provider:

| Provider | How | Use |
|---|---|---|
| `supabase-password` | a one-time human-run setup uses the service-role key to set a password on each reviewer account; the runtime tier then calls `signInWithPassword` and injects the session | **recommended for soar-app** |
| `storage-state` | `sentinel session capture` opens a real browser, a human signs in by hand once per persona, and the cookies/`localStorage` are saved as an encrypted secret for replay | any app, any provider; fallback when sessions cannot be minted |
| `http-login` | ordinary form or API login | most non-OAuth apps |
| `oidc-client-credentials` | machine-to-machine token | service-style targets |

The service-role key never enters CI. What CI holds is a password for an
account that RLS confines to test data — and §6 verifies that confinement on
every run rather than trusting it.

Sessions expire. On expiry the tier reports **"session expired, runtime
review skipped"** and withholds its status. It never reports a clean run it
did not perform.

### 5.3 The capability inventory

soar-app has no router — navigation is React state — so a generic design
cannot assume a list of URLs. The portable unit is what a persona can
*reach*: rendered navigation affordances, enabled controls, and the data
regions that appear, discovered by crawling the UI rather than declared in
config.

The inventory for a persona is a set of `(screen, affordance, state)` records
with a content fingerprint per data region. It is derived the same way for a
state-based SPA, a Next.js app or a Django admin, which is what makes the
tier portable.

### 5.4 Differential access probing

The highest-value capability, and the one that is nearly deterministic.

Build the inventory for each selected persona against the **base** revision
and against the **head** revision, then diff. Report reachability that
changed:

> As `teacher`, the Reports hub was not rendered on `main` and is rendered on
> this branch. Point history for students outside the teacher's own sections
> became visible. Evidence: two screenshots, the network response that
> returned the rows, the diff of the rendered inventory.

This is checkable, reproducible, and aimed squarely at the failure mode the
lore says actually bites — an authorization change that looks fine in SQL.
Because it is a comparison rather than a judgement, it can carry higher
severity than anything else in Tier 2 or 3.

### 5.5 Runtime PII leak detection

Watch every network response and the rendered DOM. Flag personal-data-shaped
values arriving at a persona that should not have them.

This is `privacy-edu` with evidence instead of a heuristic. The code-reading
version guesses from variable names; this one observes a student's date of
birth in a response body sent to a teacher who does not teach them. Generic,
too: "did data this client should not see reach this client" is a question
about any application.

### 5.6 Agentic exploration

The open-ended one. A persona is given a charter — *"you are a grandparent
who has never used this before and wants to see your grandchild's grades"* —
and a tool loop: `click`, `type`, `read_dom`, `read_console`,
`read_network`, `screenshot`, `go_back`, `set_viewport`. It explores for a
bounded number of steps and reports what broke.

This finds what the others cannot: dead ends, flows that cannot be completed,
console errors nobody sees, a button that silently does nothing. It is also
the noisiest, so every finding carries its evidence trail into verification,
and verification for a runtime finding is strong — it can re-run the exact
step sequence and check the claim reproduces. A runtime finding that does not
reproduce is dropped.

### 5.7 Write actions need a teardown

`chaotic-actor` and `adversarial-probe` will create data: points awarded,
check-ins, survey responses. Against a shared database that is real churn.

So: every mutation the tier makes is tagged with the run id; the tier records
what it created and deletes it on teardown; mutation is off by default for
archetypes that do not need it; and destructive operations (delete a student,
change a role) are never attempted, only *probed for reachability* — we check
whether the button is there and enabled, not what it does.

---

## 6. Safety — the guardrail is also the best check

The decision is to use the real database, relying on the Hogwarts roster
(Aeries IDs 900000–900014, `is_test_data = true`) being siloed from real
students by the `hide_real_*_from_reviewer` RLS policies. That roster was
built for exactly this, and the policies are server-side, which is the right
place for them.

The engine will not simply trust that. Before any exploration, a **pre-flight
invariant**:

> Authenticate the persona. Query every table the tier will touch. If a
> single row comes back that is not marked test data, abort the run, emit a
> `critical` finding, and explore nothing.

This costs almost nothing and buys two things. It means a browsing agent can
never wander into real children's records because one boolean got flipped.
And — more useful — **it continuously tests the reviewer RLS policies
themselves.** If a PR breaks `hide_real_students_from_reviewer`, the runtime
tier is the thing that notices, immediately, and says so. The safety
mechanism is also the highest-value check in the tier.

Also fixed by construction: the runtime tier refuses to boot against a target
it was not explicitly given (never the repo's committed `.env`, which points
at production); it holds no service-role key; it runs with restricted network
egress so an exfiltration attempt by PR code is visible; and because PR code
executes with a session present, the tier runs **only on same-repo PRs behind
a maintainer-applied label**, never automatically on a fork.

---

## 7. Pointing at any software

Nothing above is soar-specific except the config. A target declares:

```yaml
runtime:
  boot:
    command: npm run dev
    port: 5173
    ready: { path: /, selector: "[data-app-ready]", timeout: 90 }
    env_from: secret            # never the repo's .env
  session:
    provider: supabase-password
  safety:
    forbid_target_matching: [ "${PROD_SUPABASE_URL}" ]
    test_data_invariant:
      tables: [ public.students, public.points ]
      predicate: is_test_data = true
  roles: [ student, teacher, aide, admin, reviewer, auditor, parent, grandparent ]
  archetypes: all
  mutations: tagged-and-torn-down
```

Swap `boot`, `session` and the invariant and the same engine points at a
Django app, a Rails app or a Next.js app. The archetypes, the inventory
algorithm, the differential probe, the PII watcher and the explorer are all
domain-free.

---

## 8. What may gate a merge

Unchanged in principle, extended by one row. Runtime findings are evidence,
but booting software is nondeterministic — a flaky network makes a false
negative — so the runtime tier gets its own advisory status and does not gate.

| Tier | Gates `pr-sentinel/deterministic`? |
|---|---|
| 0 project checks | yes |
| 1 adapters + our checks | yes |
| 2 agent review | never |
| 3 runtime review | no — **except** the §6 pre-flight invariant failure, which is a deterministic fact about data visibility and blocks |

That exception is the only place a runtime observation gets authority, and it
earns it by being a yes/no question about whether the reviewer could see real
student data.

---

## 9. Cost

Tier 3 is the expensive tier: two boots per run (base and head), a browser
per persona, and a model in the loop for exploration. Controls: triage picks
personas rather than running the matrix; differential probing is scripted
rather than model-driven once the inventory exists; exploration has a step
budget; the tier is label-gated rather than automatic; and base-revision
inventories are cached by commit so only head is rebuilt.

---

## 10. Rollout

1. Adapter layer, and delete the ~6,000 duplicated lines. Immediately useful,
   shrinks the maintenance surface.
2. Tier 2 tools. Fixes the real complaint about the AI half.
3. Tier 3 skeleton: boot, session providers, pre-flight invariant. **Ship the
   invariant before any exploration** — the guardrail precedes the thing it
   guards.
4. Capability inventory and differential access probing.
5. Runtime PII leak detection.
6. Archetypes and agentic exploration.
7. Point the runtime tier at a second, non-Supabase app. Whatever breaks is
   the real portability bug list.

---

## 11. Resolved

**Credentials: `supabase-password` first, recon before that.** soar-app uses
the Supabase provider. But a second repo will not, and asking its owner to
hand-write a session provider is the point at which they stop using this. So
the first thing the runtime tier does against an unfamiliar project is
**credential reconnaissance** (§5.2a): read the repo, work out what the auth
system is and what credentials a persona would need, and emit a draft
`session:` config plus the human steps required to obtain them. The scan is
cheap, it runs once per target, and its output is committed and reviewed.

**Label-gated, but it asks.** Runtime review runs on same-repo PRs only when
a maintainer applies `runtime-review`. PR code executing with a live session
against the shared database is worth an explicit human consent step, and the
cost profile wants it too. The gate is not silent: when triage judges runtime
review would be valuable for a PR that does not carry the label, the comment
says so and why — *"this PR changes an RLS policy; add `runtime-review` to
probe it as each role."* That gives the signal without spending the money or
taking the consent for granted. `runtime.auto: true` flips it to automatic
once the tier has earned trust.

**Roles are re-proposed on drift.** The committed role list carries a
fingerprint of the auth model it was derived from — the role columns, the
policy predicates, the guard components. When that fingerprint changes the
engine re-runs role synthesis and, if the set differs, opens the difference as
a finding: *"this PR adds a `counselor` role; the runtime persona set does not
cover it."* A new role nobody probes is the gap most likely to matter.

**`adversarial-probe` may bypass the UI, and announces itself loudly.** The
UI-only version finds UI bugs; the authorization holes that matter are
reachable by anyone with a session and `curl`, so a probe confined to
clicking buttons is testing the wrong layer. It gets direct API access —
and §6a is how it stays distinguishable from an actual attack.

---

## 5.1a Pruning the matrix with judgement, not arithmetic

Ninety-six combinations is a cross-product, and a cross-product is not a cast
of users. A chaotic-asshole teacher is a combination that does not describe
anyone; a tech-timid grandparent is half your real support burden.

So the matrix is pruned by a model, per target application, with the repo's
own auth model and lore in context. It keeps the combinations that correspond
to people who actually use this software and drops the ones that do not,
reducing roughly 96 to roughly 30. The surviving set is written to config
with a one-line justification each, so a human can argue with it — and
arguing with it is the point, because that list encodes who you think your
users are.

Three distinct model-driven steps, each customised to the project:

1. **Role synthesis** — derive the domain roles from the auth model (§11).
2. **Plausibility pruning** — 96 → ~30, keeping combinations that describe
   real humans.
3. **PR-aware selection** — of those ~30, which does *this* diff warrant.

Steps 1 and 2 run rarely and are committed. Step 3 runs per PR.

---

## 5.2a Credential reconnaissance

For an unfamiliar project, a model pass reads the repo and answers: what is
the auth system, how does a session get established, what would a test
persona need, and can a session be minted without a browser. It emits a draft
`session:` block, a list of secrets the owner must create, and the
human-in-the-loop steps that cannot be automated — *"your identity provider
blocks automated sign-in; run `sentinel session capture` once per persona."*

It never attempts to obtain a credential itself. It tells a human what to go
and get. The deliverable is a config file and a checklist.

---

## 6a. Being obviously announced

An authorization probe and an attack do the same things. The difference has
to be made legible, or the first time someone reads the logs this gets
switched off — correctly.

- **Dedicated identity.** Probes authenticate as purpose-named accounts
  (`sentinel-probe-<role>@…`), never as a human's account and never as the
  shared reviewer login. One glance at the actor answers "is this us".
- **Self-identifying requests.** Every request carries
  `X-PR-Sentinel: probe`, `X-PR-Sentinel-Run: <run-id>`,
  `X-PR-Sentinel-PR: <pr-url>` and a distinctive `User-Agent`. Any log line
  links back to the pull request that caused it.
- **A pre-registered manifest.** Before probing, the tier writes a run record
  — run id, PR, target, personas, start time, expected request budget — and
  closes it on completion. Anyone correlating an alert has the record already,
  rather than having to ask.
- **Bounded and rate-limited.** A hard request budget and a request rate low
  enough that the traffic cannot resemble a flood. Exceeding the budget aborts
  the run rather than continuing quietly.
- **Read-mostly.** Probes assert on status codes and data visibility.
  Destructive verbs are never issued; a destructive affordance is checked for
  *reachability*, not exercised. Writes are tagged with the run id and torn
  down (§5.7).
- **Egress allowlist.** The target origin and its API only. A probe can never
  reach a third party, so it can never be mistaken for one attacking someone
  else.
- **Announced to humans too.** The PR comment names the personas that probed,
  what they attempted, and the run id.
