# Rule packs

A pack is the unit of *knowledge*, not merely of pattern-matching. Each one
contributes **both halves** of a review (DESIGN §5):

```
packs/supabase/
  pack.yml        metadata, version, applicability, which checks AND
                  which adapters to enable
  briefing.md     what the agent tier should know about this domain
  rules/*.yml     semgrep rules for the deterministic tier
```

Enabling `supabase` gives you the `using (true)` matcher *and* the briefing
that teaches the agent tier what Supabase RLS failure looks like. Shipping
them from one directory, versioned together, is what stops the two halves
drifting apart — a rule whose reasoning nobody wrote down gets suppressed,
and a briefing with no matcher behind it is a blog post.

## The six packs

Three things a pack can enable, and the mix is deliberately uneven:
**adapters** run an external tool somebody else maintains, **checks** are
engine code, **rules** are semgrep patterns. DESIGN-V2 §3 moved most of the
first column out of this repository, and the table distinguishes them because
blurring the line is how you end up maintaining a worse copy of zizmor.

| Pack | v | Applies to | Adapters (theirs) | Checks | Rules |
|---|---|---|---|---|---|
| `core` | 1.1.0 | always | `gitleaks` | 0 | 0 |
| `supply-chain` | 1.1.0 | manifests + lockfiles | `socket` | 1 | 0 |
| `supabase` | 1.1.0 | `*.sql` + client code | `supabase-advisors`, `squawk` | 4 | 1 |
| `react-vite` | 1.0.0 | frontend sources | — | 2 | 1 |
| `github-actions` | 1.1.0 | workflows + `action.yml` | `zizmor`, `actionlint` | 0 | 0 |
| `privacy-edu` | 1.0.0 | broad | — | 5 | 1 |

Twelve script checks in total, down from 27. What went, and where:

| Deleted | Now covered by |
|---|---|
| `core.forbidden-files`, `core.conflict-markers`, `core.huge-diff`, `core.binary-blobs`, `core/rules/secrets.yml` | `gitleaks` (a far larger, better-tuned secret corpus) |
| the five `github-actions.*` checks | `zizmor` (38 audit rules against our 5) |
| `supply-chain.install-scripts`, `.new-dependency`, `.license-drift` | `socket` (registry data and behavioural analysis we could not get offline) |
| `supabase.rls-enabled-no-policy`, `.security-definer-view`, `.mutable-search-path` | `supabase-advisors` (Supabase's own lints 0008/0010/0011, run against the live schema) |

`core` and `github-actions` now contribute **no deterministic rules of their
own**. They remain packs because of the other half: an adapter audits a
workflow, it does not teach the agent tier which CI mistakes this repository
has already made. If you are tempted to delete those two directories, read
their `briefing.md` first — that is what you would be deleting.

The four checks that survived a pack-wide deletion each did so for a stated
reason, which is worth repeating because "we wrote it" is not one:
`lockfile-integrity` is about the shape of the diff, not about a package;
`migration-numbering` and `migration-immutability` are about how this team
branches, not about Postgres; `missing-grants` is lore with four documented
occurrences; `permissive-policy` is a general pattern whose `critical`
grading depends on a local fact about who `authenticated` means here.

## `pack.yml`

Exactly the fields `pr_sentinel.packs.loader.load_pack` reads. Anything else
is ignored.

```yaml
name: supabase              # pack id; defaults to the directory name
version: 1.0.0              # semver, required for pinning. New packs start at 1.0.0
description: >-             # one paragraph, shown in `sentinel packs`
  ...
applies_to:                 # globs. Omitted or empty means "always relevant"
  - "*.sql"
  - "supabase/"
requires_engine: ">=0.1.0"  # asserted against the running engine
tags: [supabase, rls]
briefing_passes:            # which agent passes get this briefing.md
  [security, privacy, data-model, lore]
adapters:                   # external tools this pack turns on
  - supabase-advisors       # a bare string is the common case
  - id: squawk              # or a mapping, when there is more to say
    severity_ceiling: high
    enabled: true
    options: {}
checks:                     # engine script checks this pack turns on
  - id: supabase.permissive-policy
    severity: critical
    options: {}
```

`applies_to` is matched with the same matcher as `ignore.paths`: a trailing
`/` is a directory prefix, everything else is an fnmatch glob tried against
both the full path and the basename.

`briefing_passes` is a real cost control, not documentation. The agent tier
runs five narrowly briefed passes (DESIGN §9); keeping the supabase briefing
out of the `parity` prompt is tokens saved on every review. Omit the key only
if the briefing genuinely informs all five.

`checks:` chooses which of the engine's built-in script checks run and at
what severity. A pack **cannot supply check code** — script checks are engine
code, deliberately, because pack data is also the extension point offered to
consuming repos and repo-authored logic executing in CI is what DESIGN §7
rules out. `options` is passed through to the check verbatim.

`adapters:` does the same job for external tools (DESIGN-V2 §3), parsed the
same way so there is no second syntax to learn: a bare string, or a mapping
with `severity_floor`, `severity_ceiling`, `enabled` and `options`. Unknown
keys fall through into `options`, exactly as for a check.

The severity bounds are the one thing an adapter entry has that a check entry
does not, and they exist because a tool calibrates severity to its own
audience. zizmor grades informational audits as `error`, which is right for a
repo that has adopted its whole philosophy and wrong for one that has not. A
pack narrows the *range* rather than having the engine second-guess individual
findings — an adapter never rewrites a tool's message or re-decides a
specific result, because if the tool is wrong that is a bug to report
upstream, not to patch here. An unparseable severity is a hard error: a pack
that meant to cap zizmor at `medium` and typo'd it would otherwise ship
blocking findings it intended to be advisory.

Whether an adapter's absence is **degrading** is the engine's decision, not
the pack's, and it is not configurable. `gitleaks` and `zizmor` are required
because without them a class of problem is not looked for at all; the other
four need API keys or database connectivity, so their absence costs breadth
and is reported as a note. Letting a pack lower that would let a pack quietly
turn off the thing that makes a clean result mean something. Run
`sentinel validate` to see which tools are present.

## `briefing.md`

The half most people skimp on, and the half that decides whether the agent
tier is useful. 200–500 dense words. Write what a domain expert would tell a
new reviewer on their first day:

- what failure actually looks like here, concretely, with the symptom
  (Supabase RLS misconfiguration presents as *empty lists*, not as errors)
- the distinctions people reliably confuse (`anon` vs `service_role`; a
  Firebase web key vs a billable Maps key)
- **what is a false alarm**, explicitly — this is what keeps the agent from
  generating noise, and it is the section most often omitted
- the consequence, so a finding can explain itself

Do not restate rule ids; the findings already carry them. Do not write
"be careful with secrets". A briefing that could have been written without
the domain is worse than no briefing, because it costs tokens on every pass.

## `rules/*.yml`

Standard semgrep rule files. Write a semgrep rule **only where an AST pattern
genuinely beats both a script check and an existing tool**. Counting files,
comparing a PR against the rest of the repository, walking a dependency tree,
reasoning about YAML structure — all script-check work. And if a maintained
linter already matches the pattern, the answer is an adapter, not a rule:
`core` shipped a `rules/secrets.yml` until gitleaks replaced it, and
`github-actions` ships nothing because zizmor does it better. Both are correct
outcomes, not gaps.

Every rule carries, in addition to semgrep's own required keys:

```yaml
metadata:
  pack: <pack name>                 # so a finding knows where it came from
  sentinel-severity: critical|high|medium|low   # overrides semgrep's coarse severity
  title: "short human title"
  rationale: "why this rule exists — specific, not generic"
  verify: "what a human should go and check"
```

`privacy-edu` rules additionally carry `nonbinding: true` and
`frameworks: [...]`, because that pack reports surfaces and never rules on
compliance.

Rule ids are namespaced `<pack>.<area>.<rule>`, e.g.
`core.secrets.aws-access-key-id`. The leading segment is used to attribute a
finding to a pack when metadata is missing.

### The quality bar

**Before writing anything, check whether it already exists.** This is the
first question now, and getting it wrong cost this project roughly 6,000
lines. If a maintained tool checks it, write an adapter. If nothing does,
and it is a pattern, write a rule. If nothing does and it needs to count or
compare, write a script check.

**A rule that fires on correct code is worse than no rule.** It is not a
false positive, it is a training exercise teaching the team to skim past
this tool. Where precision is unreachable, say so in the briefing and leave
it to the script check or the agent tier — that is a legitimate design
choice, and the `core.secrets.google-api-key` rule (medium, with Firebase
config paths excluded) is what the compromise looks like when you take it
seriously.

### Adding a rule

1. Write the failing case first. A real snippet that should fire, and the
   nearest-neighbour snippet that must not.
2. Pick the matcher. Prefer `patterns` with `metavariable-regex` over a bare
   `pattern-regex`; anchor metavariable regexes with `^` so they behave the
   same whether semgrep applies them anchored or not.
3. Add `paths: exclude:` only where a test or fixture path genuinely changes
   the answer. For `core`'s credential rules it mostly does not — a live key
   in a fixture is still a live key, and DESIGN §12 notes a private free-tier
   repo has no GitHub secret scanning, so these rules are all it gets.
4. Write `rationale` and `verify` as if to the person who will be annoyed by
   the finding at 5pm on a Friday.
5. Validate the YAML and hand-check the schema — `id`, `message`,
   `languages`, `severity` ∈ `ERROR`/`WARNING`/`INFO`, and exactly one
   top-level matcher key (`pattern`, `patterns`, `pattern-either`,
   `pattern-regex`). Getting this wrong means the rule silently never runs:

   ```bash
   python3 -c "import yaml,sys;[yaml.safe_load(open(f)) for f in sys.argv[1:]]" packs/*/rules/*.yml
   semgrep --validate --config packs/
   ```
6. Bump the pack version. Adding a rule changes verdicts for everyone
   pinned to a range that includes it: new rule → minor; tightened or
   widened matching on an existing rule → minor; a rule removed or its
   severity raised → major.

The same applies to adapters and to removals. `core`, `supply-chain`,
`supabase` and `github-actions` went to **1.1.0** when DESIGN-V2 §3 deleted
checks and added adapters: the rule set changed, and independent pinning means
a consumer must be able to *see* that it changed. (A strict reading of the
rule above says a removal is major; the judgement here was that these
removals replace each rule with a stricter superset from a better-maintained
tool, so a consumer on `^1.0` gets more coverage rather than less. Where a
removal genuinely loses coverage, it is a major.) `react-vite` and
`privacy-edu` were untouched and stayed at 1.0.0.

## Governance: curated vs. local (DESIGN §7)

Two tiers of authorship, deliberately different in bar.

**Curated packs** — this directory, in the engine repo. Rules that are true
for anyone using that dependency. "If you use Supabase RLS, `using (true)` is
a mistake" holds in every repo, so it belongs here. Changes go through PR
review in the engine repo and land in a tagged release. This is where
accumulated judgment becomes other people's defaults.

**Local rules** — `.pr-sentinel/rules/` in the consuming repo, scanned
alongside the enabled packs. Anyone can add one without touching the engine;
no review gate beyond that repo's own PR process. Guardrails, because they
execute in CI:

- declarative only — a rule is data, never executable code
- may not raise severity above `high`. `critical` is curated-only, so a
  local rule can never block a merge on its own
- must carry an `id`, a `message` and a `rationale`

That last one is not bureaucracy. A finding without a stated reason gets
suppressed, and a rule that is always suppressed trains everyone to ignore
the tool.

Repo-specific *facts* do not belong in a local rule at all — they belong in
`.pr-sentinel/lore.md` (DESIGN §8), which the agent tier reads last and
which wins where it conflicts with a pack briefing. "Student accounts share
the staff email domain, so bare `authenticated` authorises every student" is
lore. "`using (true)` is permissive" is a curated rule.

### The promotion path

A local rule that proves useful and is genuinely *dependency-general* is a
candidate PR into a curated pack. That is how this catalogue grows from real
use rather than speculation.

1. It has fired on at least one real PR and the finding was acted on.
2. It has a near-zero false-positive rate in the repo that authored it —
   bring the numbers, including the snippet that must *not* match.
3. Strip the local facts. If the rule only makes sense given something true
   about one repository, it stays local and the fact goes in lore.
4. Open a PR against this directory: the rule, the `rationale`, the `verify`,
   a briefing amendment if it teaches something the pack does not already
   say, and the version bump.
5. Severity is re-decided on promotion. A local rule capped at `high` may
   become `critical` once curated — and may equally drop, since a severity
   justified by one repo's circumstances often is not justified in general.

The same path runs in reverse for `sentinel learn <commit>` (DESIGN §13): a
production bug that review should have caught is a rule-shaped hole, and the
proposed lore entry plus candidate rule enters at step 1.
