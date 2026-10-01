# Auto-merge

Short answer: **yes, and the current design already supports it — but not by
letting pr-sentinel merge anything.**

The aim ("once the technology is proven, let it merge when it approves") is
reachable without changing the architecture, and the way to reach it is
deliberately indirect. This document explains the mechanism, the one line you
must not cross, and a staged path for getting there.

---

## 1. The engine must never be the thing that merges

DESIGN §2 says it never auto-merges, never pushes code, never edits a PR.
DESIGN §10 gives it `contents: read` and nothing more. Both hold, and neither
is in the way.

The reason to keep them is not purity. A reviewer that can merge is a
reviewer whose compromise is a supply-chain compromise. It reads untrusted
input (PR titles, descriptions, diffs) while holding a token; the entire §10
threat model assumes that token cannot write. Give it `contents: write` and
every prompt-injection attempt in a PR description becomes an attempt to
commit to your default branch. The blast radius goes from "a wrong comment"
to "arbitrary code on main".

So the merge is performed by **GitHub's own auto-merge**, which is already
built for this, already audited, and holds no model in its decision path.
pr-sentinel's job is only to publish a status honest enough to gate on.

---

## 2. The mechanism: gate on the deterministic check-run

The engine publishes **two** statuses, and the split exists precisely for
this purpose:

| Check name | What it means | Safe to gate a merge on |
|---|---|---|
| `pr-sentinel` | The whole review, per the configured mode | **No** |
| `pr-sentinel/deterministic` | Tier 0 + Tier 1 only | **Yes** |

`pr-sentinel/deterministic` is computed in `policy.auto_merge_recommendation()`
from scripts and semgrep alone. Concretely, it is withheld when:

- Tier 0 (the project's own tests, lint, build, audit) did not pass, **or**
- any deterministic finding is at or above the threshold (default `high`), **or**
- any part of the deterministic tier failed to run.

That third condition is the one people leave out, and it is the one that makes
the other two trustworthy. If semgrep was missing, or a check raised, or a pack
pin referenced a rule this engine does not implement, the status is withheld.
A clean result from a tier that only half-ran is not a clean result, and
`test_policy.py` pins that behaviour so it cannot regress quietly.

What is **not** consulted: agent findings, the configured `mode`, and anything
derived from PR text. The status is reproducible from the code alone.

### Setting it up

1. Branch protection on your default branch → require the
   `pr-sentinel/deterministic` status check. Not `pr-sentinel`.
2. Repository settings → enable "Allow auto-merge".
3. On a PR, enable auto-merge (or automate that with a label).

pr-sentinel needs no new permission for any of this. It publishes; GitHub
decides.

---

## 3. The line not to cross: agent findings never gate

This is the same hard boundary as DESIGN §3, arriving at its practical
consequence.

The agent tier is right most of the time. "Most of the time" is a fine basis
for *telling a human something* and a terrible basis for *merging without
one*. Two specific reasons it must stay out of the merge decision:

**It takes attacker-controlled input.** PR titles, descriptions and diffs go
into its prompts. They are fenced and treated as data, and `sanitize.py` both
neutralises and reports attempts — but "we defend against prompt injection
well" is not the same claim as "prompt injection cannot affect this output".
Any path from PR text to merge authority is a path worth not having. The
deterministic tier has no such path *by construction*, which is the whole
argument for putting critical rules there.

**It is not reproducible in the way a gate needs.** Swap a model, change a
temperature, and the same PR can get a different review. A gate that moves
under you is a gate people route around.

The engine enforces this in code rather than by convention: an agent finding
at `critical` is capped to `high` on construction, and `compute_verdict()`
downgrades any agent finding that a config tries to mark blocking. Even an
explicit `authority:` block mapping every severity to `blocking` cannot make
an agent finding block. There is a test for that, from both directions.

**`privacy-edu` also never gates**, for a different reason: it is nonbinding
by design (DESIGN §11). It flags surfaces and names frameworks; it does not
rule on compliance. A merge blocked or permitted by it would be exactly the
compliance ruling it promises not to make.

---

## 4. Auto-merge means nobody read the code

Worth saying plainly, because it is easy to lose in the mechanics: a green
required check plus auto-merge means the change lands with no human having
read it. The deterministic tier is a floor, not a review. It knows nothing
about whether the feature is right.

So pair it with at least one of:

- **Require a human approval too.** Auto-merge then means "merge as soon as
  the checks pass *after* someone approved", which is genuinely useful — it
  removes the wait, not the review.
- **Restrict it to a labelled subset.** Auto-merge only on PRs carrying a
  label your automation applies to categories you have decided are safe.

For a first pass the highest-value, lowest-risk categories are the boring
ones: Dependabot patch bumps where Tier 0 passes, documentation-only changes,
and generated-file refreshes. Those are most of the merge latency and almost
none of the risk.

---

## 5. A staged path

The aim is "once the technology is proven". Here is what proving it looks
like, rather than deciding by feel.

**Stage 1 — observe.** Run in `advisory`. Publish both statuses; require
neither. You are checking that the deterministic tier is quiet on good PRs.
A single false `critical` at this stage is a design bug to fix before going
further; the whole scheme rests on those rules being exactly right.

**Stage 2 — gate humans.** Move to `gated`. Require
`pr-sentinel/deterministic` in branch protection. Merges are still manual.
This is the recommended long-term resting state even if you go no further,
and it is where the guarantee actually earns its keep.

**Stage 3 — auto-merge the boring subset.** Enable auto-merge for Dependabot
patch bumps and docs-only changes, with the deterministic check required.
Keep human approval required for everything else.

**Stage 4 — widen, with evidence.** Widen only against a measurement. The
useful one: of the production bugs you fixed in the period, how many were on
PRs where the deterministic status was clean *and* a rule could in principle
have caught it? That is what `sentinel learn` (DESIGN §13) is for — every
such bug is a rule-shaped hole, and the rate at which you are still finding
them is the honest read on whether the floor is high enough to merge over.

Two things should send you back a stage: a `critical` rule that fires on
correct code, and a production incident on an auto-merged PR. Both mean the
floor was lower than you thought.

---

## 6. What would have to change in the engine

Nothing, for stages 1–3. The two check-runs, the degraded-run handling and
the agent/deterministic boundary are all implemented and tested.

If you later want the engine to *request* auto-merge rather than leaving it
to a human or a label — enabling GitHub's auto-merge on a PR via the API —
that needs `pull-requests: write`, which the workflow already grants, and it
would still not be the engine merging: GitHub would merge when the required
checks pass. That is a small, contained change and the right one if you want
it. What should stay off the table permanently is `contents: write`.

---

## Summary

- The engine never merges. GitHub auto-merge does, keyed to a status.
- Gate on `pr-sentinel/deterministic`, never on `pr-sentinel`.
- Agent findings and `privacy-edu` never gate, enforced in code and tested.
- A withheld status on a degraded run is a feature; it is what makes a clean
  status mean something.
- Pair auto-merge with human approval or a narrow label before widening, and
  widen against the `sentinel learn` signal rather than against confidence.
