Supabase is Postgres exposed directly to the internet through PostgREST. The
network boundary you would normally rely on does not exist: the only thing
between a browser and a table is row level security. Review accordingly.

**The authorisation model, where nearly every failure lives.** A request
succeeds only if the role holds a `GRANT`, RLS permits the row, and the
schema is exposed. Independent conditions. Two consequences get missed
constantly:

- **RLS bypass is not grant bypass.** `service_role` ignores policies but
  still needs its own `GRANT`. A migration that grants to `authenticated` and
  stops will work perfectly in the app and fail only in the background job,
  the edge function, or the admin script — usually days later, usually in
  production. This is the single most repeated Supabase mistake.
- **`ENABLE ROW LEVEL SECURITY` with no policy denies everyone.** Postgres
  default-denies. The symptom is not an error, it is empty arrays: lists that
  render as "no results", never as "forbidden". Expect it to be reported as a
  UI bug.

**Predicates to stop on.** `using (true)` is the obvious one. The
non-obvious and more dangerous one is `using (auth.role() = 'authenticated')`
or a policy granted `TO authenticated` with no further qualification — this
reads as "logged-in users only" and actually means *every account in the
project*, which includes every account that can self-register. How bad that is
depends on who can get an account - a repo-specific fact, so if the lore says
something about who holds accounts, that fact decides severity, not this
briefing. Also check `WITH CHECK` separately
from `USING`: a policy with `USING` alone lets a user update a row they can
see into a state they should not be able to create — the classic
`user_id = auth.uid()` on read with no `WITH CHECK` on write, which permits
reassigning ownership.

**`SECURITY DEFINER`.** A function or view marked `SECURITY DEFINER` runs as
its owner, so the caller's RLS does not apply inside it. Sometimes that is
the point; when it is not, it is a privilege-escalation primitive. Any `SECURITY DEFINER` object must also set `search_path` explicitly (`SET
search_path = public, pg_temp` or `''`); without it, a caller who can create
objects in a schema earlier on the path can shadow a function the definer
calls and execute code as the owner.

**Migrations.** Immutable once applied. Editing one changes only the
environments that have not run it yet, so they diverge silently and `db push`
fails on a machine that is merely *ahead*. The fix for a wrong migration is
always a new one. Numbering also collides across concurrent branches: two
people both prefixing `030` is routine.

**False alarms.** A policy scoped `TO service_role` or `TO postgres` is not
permissive, it is the point. `using (true)` on a genuinely public reference
table (term dates, school list) is correct — ask whether it holds
person-level data first. `anon` keys in client code are expected;
`service_role` keys never are.
