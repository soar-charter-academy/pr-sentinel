# pr-sentinel

A reusable, agent-assisted pull-request reviewer. Lives in its own public
repo, gets pointed at any other repo, and gives an independent review and
recommendation as soon as a PR opens — ahead of human review.

Full design and reasoning: [`docs/DESIGN.md`](docs/DESIGN.md), then
[`docs/DESIGN-V2.md`](docs/DESIGN-V2.md), which supersedes parts of it after an
audit found that most of the deterministic tier was reimplementing tools other
people maintain better. §3 of that document is why the check list below is
shorter than it was.

---

## The idea in one paragraph

Two problems wear the same costume, and conflating them is how these systems
end up ignored. **Guarantees** — "no policy in this repo may ever say
`using (true)`" — are facts about text; a script decides them correctly 100%
of the time, a model ~95%, which for a security rule is worse than no rule
because you will trust it. **Judgment** — "does this PR widen who can read
student PII?" — no script answers. So: two engines, hard boundary. The
highest-stakes rules live in the deterministic engine precisely because it
cannot be reasoned with.

```
PR opened
   |
   +-- Tier 0  Project checks       npm test, lint, build, audit — fail fast, no model
   |
   +-- Tier 1  Deterministic packs  ADAPTERS to existing tools + semgrep
   |                                rules + 12 purpose-built scripts
   |
   +-- Tier 2  Agent passes         security, privacy, data-model, lore, parity
   |                                then a VERIFICATION pass
   |
   +-- Verdict -> one PR comment + two check-runs
```

The verification pass is load-bearing. Each candidate finding is re-checked
against actual source before it may enter the comment, and unverified
findings are **dropped, not softened**. That is the difference between a
reviewer you read and one you mute.

---

## Use it from another repo

```yaml
# .github/workflows/review.yml
name: PR review
on:
  pull_request:
jobs:
  review:
    uses: soar-charter-academy/pr-sentinel/.github/workflows/review.yml@v1
    secrets: inherit
```

**Pin to a tag, never `@main`.** A rule added upstream must not silently
change verdicts across every consuming repo overnight.

Then add [`templates/pr-sentinel.yml`](templates/pr-sentinel.yml) to your
repo as `.pr-sentinel.yml`:

```yaml
version: 1
packs:
  - core@^1.1            # each pack pinned independently
  - supply-chain@^1.1
  - supabase@^1.1
  - react-vite@^1.0
  - github-actions@^1.1
  - privacy-edu@^1.0

lore: .pr-sentinel/lore.md
local_rules: .pr-sentinel/rules/

mode: gated              # advisory | gated | blocking
```

`gated` is the recommended default: **guarantees block, judgment advises.**

---

## Run it locally

`sentinel review` writes nothing unless you ask it to, so you can run the
exact review your CI will run, against your own checkout, before pushing. A
review engine you cannot run locally is one whose findings arrive as
surprises.

```bash
pip install -e '.[semgrep]'

sentinel review --repo . --base main          # full review, printed
sentinel review --no-agent                    # deterministic tiers only, no API key needed
sentinel review --format json                 # machine-readable
sentinel validate                             # config, pins, local rules, adapter availability
sentinel packs                                # what this engine ships
sentinel checks                               # the deterministic script checks
sentinel learn <commit>                       # propose lore + a rule from a fixing commit
```

Exit codes: `0` clean, `1` findings but nothing blocking, `2` blocked,
`3` error.

---

## Rule packs

A pack contributes **both** halves: semgrep rules for the deterministic tier
*and* a briefing that teaches the agent tier. Enabling `supabase` gives you
the `using (true)` matcher **and** the knowledge of what Supabase RLS failure
looks like. Packs are the unit of knowledge, not merely of pattern-matching.

A pack enables some mix of three things: **adapters** (someone else's tool),
**script checks** (ours) and **semgrep rules**. The split per pack is now
quite uneven, and the table says which is which rather than blurring them.

| Pack | Adapters (theirs) | Checks + rules (ours) |
|---|---|---|
| `core` | `gitleaks` | — |
| `supply-chain` | `socket` | lockfile/manifest disagreement |
| `supabase` | `supabase-advisors`, `squawk` | `using (true)` and bare-`authenticated` policies, missing `service_role` grants, migration numbering and immutability, service-role keys in client code |
| `react-vite` | — | secrets reachable from the client bundle, `\uXXXX` in JSX text positions, browser storage holding PII |
| `github-actions` | `zizmor`, `actionlint` | — |
| `privacy-edu` | — | student-PII exposure widening, PII into new sinks, PII in URLs, analytics identifiers, test/real data bleed — **nonbinding** (see below) |

`core` and `github-actions` contribute no rules of their own at all now. They
are still packs because a pack is both halves (below): `gitleaks` scans the
diff, but it does not teach the agent tier what credential handling failure
has looked like in *this* codebase, and `zizmor` audits a workflow without
knowing which CI mistakes this repo has already made. The briefings are the
remaining half, and they are the half that was always harder to write.

Full catalogue: `sentinel checks` (12 script checks), or
[`packs/README.md`](packs/README.md).

---

## Adapters: don't reinvent

`DESIGN.md` §2 said it from the start — *"Not a linter rewrite. Where semgrep,
eslint or the Supabase linter already check something, shell out rather than
reimplement"* — and then the build drifted from its own spec and wrote 27
checks, most of which restated rules somebody else maintains full time. §3 of
`DESIGN-V2.md` corrects that. Roughly 6,000 lines were deleted.

An adapter runs the real tool, parses its native output (SARIF where
available), and normalises it into the same `Finding` model, so one severity
policy, one dedup pass, one comment and one verdict still govern everything.

| Adapter | Tool | Required? | What it replaced |
|---|---|---|---|
| `gitleaks` | gitleaks | **yes** | `core.forbidden-files` and `core/rules/secrets.yml` |
| `zizmor` | zizmor | **yes** | the whole `github-actions` pack — 5 checks |
| `socket` | Socket CLI | no | `supply-chain.install-scripts`, `.new-dependency`, `.license-drift` |
| `supabase-advisors` | Supabase CLI | no | `supabase.rls-enabled-no-policy`, `.security-definer-view`, `.mutable-search-path` |
| `squawk` | squawk | no | nothing — new breadth on Postgres migration safety |
| `actionlint` | actionlint | no | nothing — new breadth on workflow correctness |

**Why theirs and not ours, stated plainly.** zizmor ships 38 Actions audit
rules against our 5, catches impostor commits and cache poisoning we never
wrote, and is maintained against new Actions attack classes as they are
published. Socket has registry data — publish age, maintainer churn — and
behavioural analysis of package contents; our typosquat check compared names
against 180 hardcoded strings because it had no network, and skipped publish
age entirely with a comment saying so. Three of our seven Supabase checks were
Supabase's own published advisors (0008, 0010, 0011), and theirs run against
the live schema while ours guessed the schema from migration text. gitleaks
has a vastly larger and better-tuned corpus than any rule file written here.

None of that is a close call, and pretending otherwise would have meant
maintaining six worse copies of things forever.

**What is still ours, and why.** Twelve script checks, kept for one reason
each — nothing else has them:

- `supabase.migration-numbering`, `supabase.migration-immutability` — facts
  about how *this team branches*, not about Postgres. Supabase cannot advise
  on a timestamp collision between two concurrent feature branches.
- `supabase.missing-grants` — "`service_role` needs its own GRANT, separate
  from `authenticated`" is this repo's lore, with four documented
  occurrences. Not general knowledge, not in any advisor.
- `supabase.permissive-policy` — the pattern is general; the *severity* is
  local. Student Google accounts share the staff email domain here, so bare
  `authenticated` authorises every child in the school. A generic linter
  would rightly grade this lower.
- `supply-chain.lockfile-integrity` — a fact about the shape of the diff
  (two files that must move together, one of which did). Socket analyses
  packages and has no view on which files a PR touched.
- `privacy-edu.*` (five) — student-PII surfacing with framework naming
  exists nowhere else.
- `react-vite.client-env-secrets`, `react-vite.browser-storage` — `VITE_`
  inlining and browser-storage semantics, including the
  `\uXXXX`-in-JSX-text rule.

**Absence is loud.** Each adapter declares whether its absence is degrading.
A missing `gitleaks` or `zizmor` withholds `pr-sentinel/deterministic`
exactly as a missing semgrep does — on a private free-tier repo there is no
GitHub secret scanning underneath, so without gitleaks nothing in the run
read the diff for credentials, and saying "no critical findings" would be a
lie. The optional four need API keys or database connectivity, or add breadth
over checks we still perform; their absence is reported as a note and costs
coverage, not a guarantee. `sentinel validate` prints which tools are
installed, which are missing, and which of those matters.

Every adapter's tool version is recorded in the comment's provenance line.
Their rule sets move without this engine changing, so "zizmor found nothing"
is not reproducible and "zizmor 1.5.2 found nothing" is.

---

### Governance

**Curated packs** (this repo) hold rules true for anyone using that
dependency. They go through review here and land in a tagged release.

**Local rules** (`.pr-sentinel/rules/` in your repo) can be added by anyone,
with no gate beyond your own PR process. Because they run in CI, the engine
supplies the guardrails: declarative data only (never executable code),
severity capped at `high` so a local rule can never block a merge on its own,
and `id`/`message`/`rationale` all mandatory. That last one is not
bureaucracy — a finding without a stated reason gets suppressed, and a rule
that is always suppressed trains everyone to ignore the tool.

A local rule that proves useful and generalises is a candidate PR into a
curated pack. That is how the catalogue grows from real use rather than
speculation.

### Pack versions are pinned independently

Each pack carries its own version and you pin each one separately
(`supabase@^1.2`, `core@1.0.0`). If the engine ships a pack that does not
satisfy your pin, that is a **hard error**, not a warning — quietly running a
different rule set than you asked for is the failure `@main` pinning was
rejected to avoid.

---

## Per-repo lore

`.pr-sentinel/lore.md` stays in *your* repo, which is what makes a public
engine safe. It records this codebase's expensive, recurring, already-made
mistakes. Same engine + different lore = a different reviewer. That is the
design. Start from [`templates/lore.md`](templates/lore.md).

Good lore is a fact about your repository:

> `service_role` needs its own GRANT, separate from `authenticated`. Four
> occurrences. RLS bypass is not grant bypass.

Bad lore is a best practice:

> Be careful with database permissions.

---

## privacy-edu is nonbinding

The `privacy-edu` pack gives a legal-adjacent read and says so in every
finding it emits. The distinction it must never blur:

- **It flags surfaces.** "This PR exposes a student-PII column to a role that
  previously could not read it."
- **It never rules on compliance.** It does not say a change is FERPA-compliant,
  or that it isn't.

Every finding carries the surface, the framework plausibly engaged (FERPA,
COPPA, state student-privacy statutes), what a reviewer should verify, and an
explicit note that this is not legal advice. The pack's value is that it
*notices*. What to do about it is a human decision, and for anything material,
a lawyer's.

---

## Securing the reviewer itself

A code reviewer reads untrusted input and holds credentials.

- **PR content is data, never instructions.** Titles, descriptions and code
  are fenced and labelled before they reach any prompt, and an attempt to
  address the reviewer is itself reported as a finding. The deterministic
  tier is immune by construction — the strongest argument for putting
  critical rules there rather than in a prompt.
- **`pull_request`, never `pull_request_target`.** The reusable workflow
  refuses to run under the latter.
- **Least privilege:** `contents: read`, `pull-requests: write`,
  `checks: write`. Never `contents: write`.
- **No production credentials, ever.** It reviews code. If a check seems to
  need prod access, the check is wrong.
- **Provenance.** Every comment records engine version, pack versions,
  semgrep version, **each adapter's tool version** and the models, so a
  verdict is reproducible. The adapter versions matter most: those rule sets
  are maintained elsewhere and can change between two runs of the same engine
  on the same commit.
- **It runs on itself.** CodeQL, secret scanning and its own rule packs, from
  day one.

---

## Auto-merge

Supported, and deliberately indirect: the engine never merges. It publishes
`pr-sentinel/deterministic`, a status computed from scripts and semgrep
alone, and GitHub's native auto-merge is keyed to that. Agent findings and
`privacy-edu` never gate a merge — enforced in code, not by convention.

See [`docs/AUTO-MERGE.md`](docs/AUTO-MERGE.md) for the mechanism, the line
not to cross, and a staged rollout.

---

## Development

```bash
python -m unittest discover -s tests -v   # 437 tests, no network, no semgrep, no API key
ruff check src tests
python scripts/pin-actions.py --check     # every action pinned to a SHA
```

The suite runs entirely offline: semgrep output is tested from recorded
payloads and the agent tier from a `ScriptedProvider`. An agent tier that can
only be tested by spending money does not get tested.

---

## Status

Tiers 0, 1 and 2 are implemented. Tier 1 is now **12** deterministic script
checks plus six adapters across six packs; it was 27 checks before
`DESIGN-V2.md` §3, and the drop is the point rather than a regression.
Verification pass, both check-runs and the CLI are in place.

Known gaps, honestly: semgrep rule files are schema-checked but have not been
executed against a real semgrep; the adapters parse recorded tool output in
tests but have not been run against the real binaries in CI; Tier 0, the
GitHub client and the live model provider are untested offline. Tier 3 — the
runtime tier, which is the differentiated part — is not built. See
`DESIGN-V2.md` §10 for the rollout order; step 1 of 7 is done.

Apache-2.0.
