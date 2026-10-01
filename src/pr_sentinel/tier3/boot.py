"""Booting the application under review, and reliably putting it away again.

Three things here are load-bearing rather than incidental.

**It refuses to boot against a target it was not explicitly given** (§6). The
repository's committed `.env` points at production. A tier that reads it, or
that falls back to "whatever the app defaults to", is a tier that signs a
browsing agent into real children's records the first time a config is
incomplete. So the target comes from `runtime.boot.base_url`/`port` and the
environment comes from the platform's secret store, and an absent target is a
refusal rather than a default. `forbid_target_matching` is the second half of
that: a pattern match against the resolved target — and against any URL-shaped
value in the injected environment, because a benign `localhost` target with a
production `SUPABASE_URL` behind it is the dangerous case, not the obvious one.

**A boot failure is a result, not an exception.** The commonest reason runtime
review does not happen is that `npm run dev` exited with a stack trace, and
that fact belongs in the PR comment with the captured output rather than in a
traceback nobody sees. `start()` returns a `BootResult`; it does not raise.

**Teardown is not best-effort.** A dev server left running holds a port, holds
a database connection, and on a self-hosted runner holds them until somebody
notices. The process is started in its own process group and the *group* is
signalled, because `npm run dev` is a shell that spawns the thing doing the
work and killing the shell orphans the child. `stop()` is idempotent and
safe to call after a failed start.
"""

from __future__ import annotations

import fnmatch
import os
import re
import signal
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from ..config import BootConfig
from .models import RunManifest

#: `signal.SIGKILL` does not exist on Windows. Resolved once, here, rather than
#: guarded at the two call sites.
_SIGKILL = getattr(signal, "SIGKILL", signal.SIGTERM)

#: Seconds between readiness probes. Low enough that a fast dev server does not
#: pay for the poll, high enough that a slow one is not hammered while it
#: compiles.
PROBE_INTERVAL = 1.0

#: How long the process gets to die politely before it is killed.
TERM_GRACE_SECONDS = 5.0

#: Captured output is attached to a degraded result and rendered into a PR
#: comment. The useful part of a failed boot is the first error, and the last
#: lines are where a stack trace ends up, so both ends are kept.
MAX_OUTPUT_CHARS = 4000

_URL_SHAPED = re.compile(r"https?://[^\s'\"]+", re.IGNORECASE)
_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


@dataclass
class BootResult:
    """What happened when the tier tried to run the software.

    `ok` is the only thing that licenses exploration. `refused` distinguishes
    the two failures a reader must not confuse: the application is broken
    (`ok=False, refused=False`, with its output) versus the engine declined to
    point itself at this target (`refused=True`), which is a configuration
    fact and not a fact about the code under review.
    """

    ok: bool = False
    base_url: str = ""
    stdout: str = ""
    stderr: str = ""
    refused: bool = False
    reason: str | None = None
    notes: list[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    #: Readiness probe outcome, for the comment. A 200 that never contained the
    #: selector is a different story from a connection refused.
    last_status: int | None = None

    @property
    def degraded_note(self) -> str:
        """One line for the comment's "part of this review did not run" block."""
        if self.ok:
            return ""
        if self.refused:
            return f"Runtime review did not boot: {self.reason}"
        detail = self.reason or "the boot command did not become ready"
        return f"Runtime review could not boot the application: {detail}"


class Process(Protocol):
    """The slice of `subprocess.Popen` this module uses.

    Narrow on purpose: a test injects a fake launcher and must not have to
    reimplement `Popen`. Everything a real boot needs beyond this — process
    groups, pipes to temp files — is `_spawn`'s business.
    """

    @property
    def pid(self) -> int: ...

    def poll(self) -> int | None: ...

    def wait(self, timeout: float | None = None) -> int: ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...


#: `(command, cwd, env) -> Process`.
Launcher = Callable[[str, Path, Mapping[str, str]], Process]

#: `(url, headers) -> (status, body)`. A status of 0 means "did not connect".
Prober = Callable[[str, Mapping[str, str]], "tuple[int, str]"]


# ---------------------------------------------------------------------------
# refusal — the part that matters most
# ---------------------------------------------------------------------------


def expand_env_refs(value: str, env: Mapping[str, str] | None = None) -> str:
    """Expand `${VAR}` from the injected environment, then the process one.

    The injected environment is preferred because that is where the secret
    store's values arrive; falling through to `os.environ` means a workflow can
    put `PROD_SUPABASE_URL` in the job env without also threading it through
    the boot config. An unresolvable reference is left as-is, which makes the
    pattern match nothing rather than match everything.
    """
    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if env and name in env:
            return str(env[name])
        return os.environ.get(name, match.group(0))

    return _ENV_REF.sub(replace, value or "")


def _matches(target: str, pattern: str) -> bool:
    """Substring or glob, case-insensitively.

    Both, because people write both. `${PROD_SUPABASE_URL}` expands to a bare
    origin and is meant as a substring; `*.supabase.co` is meant as a glob.
    Supporting only one of the two would make the guard silently inert for
    half the configs that use it, and a silently inert guard is worse than no
    guard because it reads as protection.
    """
    pattern = (pattern or "").strip()
    if not pattern:
        return False
    low_target, low_pattern = target.lower(), pattern.lower()
    if low_pattern in low_target:
        return True
    return fnmatch.fnmatch(low_target, low_pattern) or fnmatch.fnmatch(
        low_target, f"*{low_pattern}*"
    )


def refusal(
    target: str | None,
    *,
    forbid: list[str] | tuple[str, ...] = (),
    env: Mapping[str, str] | None = None,
    env_from: str = "secret",
) -> str | None:
    """Why this boot must not happen, or None.

    Separated from `BootedApp` so the engine can answer "would this be
    refused?" without starting anything — which is what `sentinel runtime
    probe` does in its default dry-run mode, and what a test asserts on.
    """
    if env_from != "secret":
        return (
            f"`boot.env_from` is {env_from!r}. The runtime tier takes its target "
            f"environment from the platform's secret store only. The repository's "
            f"committed `.env` points at production and is never read (§6)."
        )

    if not target or not str(target).strip():
        return (
            "no target was given. The runtime tier will not infer one from the "
            "repository or from the application's own defaults: set "
            "`runtime.boot.base_url` or `runtime.boot.port` explicitly. An inferred "
            "target is how a probe ends up signed into production (§6)."
        )

    resolved = str(target).strip()
    patterns = [expand_env_refs(str(p), env) for p in forbid]

    for pattern, raw in zip(patterns, forbid):
        if _matches(resolved, pattern):
            return (
                f"the target matches `safety.forbid_target_matching` entry {raw!r}. "
                f"The run is aborted rather than narrowed — a forbidden target is a "
                f"configuration error, and continuing against it with a live session "
                f"is the one mistake this tier cannot take back."
            )

    # The dangerous case is not a forbidden target. It is an innocuous
    # `localhost` target whose injected environment points the application at
    # production: the browser talks to the dev server, the dev server talks to
    # the real database, and the pre-flight invariant is the only thing left
    # between a crawler and real records. Check it here too.
    for name, value in sorted((env or {}).items()):
        for url in _URL_SHAPED.findall(str(value)):
            for pattern, raw in zip(patterns, forbid):
                if _matches(url, pattern):
                    return (
                        f"the injected environment variable `{name}` points at a URL "
                        f"matching `safety.forbid_target_matching` entry {raw!r}. The "
                        f"target itself is allowed, but the application would be "
                        f"talking to a forbidden backend, which is the same mistake "
                        f"one layer down."
                    )
    return None


# ---------------------------------------------------------------------------
# launching
# ---------------------------------------------------------------------------


def _spawn(command: str, cwd: Path, env: Mapping[str, str]) -> Process:
    """Start the boot command in its own process group, output to temp files.

    Pipes rather than files would be a deadlock waiting to happen: a dev
    server writes continuously, nothing reads the pipe while the readiness
    probe polls, the OS buffer fills, and the server blocks forever looking
    healthy to `poll()`. Temp files cannot fill.

    The process group is the whole point of this function. `npm run dev` is a
    shell that execs a node process that spawns a bundler; terminating the
    shell leaves the bundler holding the port. `start_new_session=True` puts
    the lot in one group so `stop()` can signal all of it.
    """
    out = tempfile.NamedTemporaryFile(  # noqa: SIM115  (closed by BootedApp.stop)
        prefix="pr-sentinel-boot-", suffix=".out", delete=False, mode="w+", encoding="utf-8"
    )
    err = tempfile.NamedTemporaryFile(  # noqa: SIM115
        prefix="pr-sentinel-boot-", suffix=".err", delete=False, mode="w+", encoding="utf-8"
    )
    kwargs: dict[str, Any] = {}
    if os.name == "posix":
        kwargs["start_new_session"] = True
    else:  # pragma: no cover - not exercised on the CI platform
        creation = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        if creation:
            kwargs["creationflags"] = creation

    proc = subprocess.Popen(  # noqa: S602  (shell is the documented contract)
        command,
        shell=True,
        cwd=str(cwd),
        env=dict(env),
        stdout=out,
        stderr=err,
        stdin=subprocess.DEVNULL,
        text=True,
        **kwargs,
    )
    # Stashed on the object so `BootedApp` can read and unlink them without a
    # second bookkeeping structure.
    proc._prs_stdout = out  # type: ignore[attr-defined]
    proc._prs_stderr = err  # type: ignore[attr-defined]
    return proc  # type: ignore[return-value]


def http_probe(url: str, headers: Mapping[str, str]) -> tuple[int, str]:
    """The default readiness probe: one GET, announced.

    Returns `(0, "")` for anything that did not reach an HTTP status, because
    "connection refused" is the normal state of a dev server that has not
    finished starting and is not worth distinguishing from a timeout.

    The manifest's headers ride along (§6a). The readiness probe is traffic
    like any other and has to be as attributable as the rest.
    """
    request = urllib.request.Request(url, headers=dict(headers), method="GET")  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
            body = response.read(200_000).decode("utf-8", errors="replace")
            return int(response.status or 0), body
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(200_000).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001  (a failed error-body read is not news)
            body = ""
        return int(exc.code), body
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return 0, ""


def _clip(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    if len(text) <= limit:
        return text
    half = limit // 2
    return (
        text[:half]
        + f"\n[... {len(text) - limit} characters of output elided ...]\n"
        + text[-half:]
    )


class BootedApp:
    """One boot of the application, with a readiness probe and a teardown.

    Used as a context manager by preference — the whole reason this is a class
    rather than a function is that `stop()` must happen even when the caller
    aborts, and `with` is the construct that makes that structural rather than
    remembered.
    """

    def __init__(
        self,
        config: BootConfig,
        *,
        manifest: RunManifest | None = None,
        env: Mapping[str, str] | None = None,
        forbid: list[str] | tuple[str, ...] = (),
        cwd: Path | str | None = None,
        launcher: Launcher | None = None,
        prober: Prober | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.config = config
        self.manifest = manifest
        #: Deliberately *not* `os.environ` plus overrides by default. The boot
        #: inherits only what it is given, so a stray `SUPABASE_URL` in the
        #: runner's environment cannot become the target.
        self.env = dict(env or {})
        self.forbid = list(forbid)
        self.cwd = Path(cwd or config.cwd or ".")
        self._launch = launcher or _spawn
        self._probe = prober or http_probe
        self._clock = clock
        self._sleep = sleep
        self._proc: Process | None = None
        self._stopped = False
        self.result = BootResult()

    # -- lifecycle ---------------------------------------------------------

    def __enter__(self) -> BootedApp:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    @property
    def base_url(self) -> str:
        return self.config.target or ""

    def start(self) -> BootResult:
        """Run the command, wait for readiness, and report. Never raises."""
        started = self._clock()
        target = self.config.target

        reason = refusal(
            target, forbid=self.forbid, env=self.env, env_from=self.config.env_from
        )
        if reason is not None:
            self.result = BootResult(refused=True, reason=reason, base_url=target or "")
            return self.result

        if not self.config.command.strip():
            self.result = BootResult(
                refused=True,
                reason="no boot command is configured, so there is nothing to run",
                base_url=target or "",
            )
            return self.result

        assert target is not None  # `refusal` returned None, so a target exists
        if self.manifest is not None and not self.manifest.target:
            self.manifest.target = target

        try:
            self._proc = self._launch(self.config.command, self.cwd, self.env)
        except OSError as exc:
            self.result = BootResult(
                reason=f"the boot command could not be started: {exc}",
                base_url=target,
                elapsed_seconds=self._clock() - started,
            )
            return self.result

        ready = self.config.ready
        url = target.rstrip("/") + "/" + ready.path.lstrip("/")
        headers = self.manifest.headers() if self.manifest else {}
        deadline = started + max(1, ready.timeout)
        last_status: int | None = None
        notes: list[str] = []

        while self._clock() < deadline:
            exited = self._proc.poll()
            if exited is not None:
                out, err = self._read_output()
                self.result = BootResult(
                    base_url=target,
                    stdout=out,
                    stderr=err,
                    reason=(
                        f"the boot command exited with status {exited} before the "
                        f"application became ready"
                    ),
                    elapsed_seconds=self._clock() - started,
                    last_status=last_status,
                )
                return self.result

            status, body = self._probe(url, headers)
            last_status = status or last_status
            if 200 <= status < 400:
                if ready.selector and ready.selector not in body:
                    # A dev server answers 200 with an empty shell well before
                    # the application has mounted. Crawling that shell yields
                    # an inventory of nothing, which diffs cleanly against
                    # another inventory of nothing — a false "no change", which
                    # is the one result this tier must never produce.
                    notes.append(
                        f"{url} answered {status} but the readiness selector "
                        f"`{ready.selector}` was not present yet"
                    )
                    self._sleep(PROBE_INTERVAL)
                    continue
                out, err = self._read_output()
                self.result = BootResult(
                    ok=True,
                    base_url=target,
                    stdout=out,
                    stderr=err,
                    elapsed_seconds=self._clock() - started,
                    last_status=status,
                    notes=notes[-1:],
                )
                return self.result
            self._sleep(PROBE_INTERVAL)

        out, err = self._read_output()
        detail = (
            f"it never answered on {url}"
            if not last_status
            else f"the last response from {url} was {last_status}"
        )
        if ready.selector and last_status and 200 <= last_status < 400:
            detail += f" without the readiness selector `{ready.selector}`"
        self.result = BootResult(
            base_url=target,
            stdout=out,
            stderr=err,
            reason=f"it did not become ready within {ready.timeout}s: {detail}",
            elapsed_seconds=self._clock() - started,
            last_status=last_status,
            notes=notes[-1:],
        )
        return self.result

    def stop(self) -> None:
        """Kill the process group. Idempotent, and never raises.

        Signalling the *group* rather than the process is the whole point: see
        `_spawn`. The escalation is polite-then-not, because a dev server that
        ignores SIGTERM still has to stop holding the port.
        """
        if self._stopped:
            return
        self._stopped = True
        proc = self._proc
        self._proc = None
        if proc is None:
            return

        try:
            if proc.poll() is None:
                self._signal_group(proc, signal.SIGTERM)
                try:
                    proc.wait(timeout=TERM_GRACE_SECONDS)
                except Exception:  # noqa: BLE001  (TimeoutExpired, or a fake)
                    self._signal_group(proc, _SIGKILL)
                    try:
                        proc.wait(timeout=TERM_GRACE_SECONDS)
                    except Exception:  # noqa: BLE001
                        pass
        except Exception:  # noqa: BLE001
            # Teardown is a best-effort cleanup of something that may already
            # be gone; a failure here must not become the run's outcome.
            pass
        finally:
            self._close_output(proc)

    def _signal_group(self, proc: Process, sig: int) -> None:
        pid = getattr(proc, "pid", None)
        killpg = getattr(os, "killpg", None)
        if pid and killpg is not None and os.name == "posix":
            try:
                killpg(os.getpgid(pid), sig)
                return
            except (ProcessLookupError, PermissionError, OSError):
                pass
        if sig == _SIGKILL:
            proc.kill()
        else:
            proc.terminate()

    # -- captured output ---------------------------------------------------

    def _read_output(self) -> tuple[str, str]:
        out = self._read_handle("_prs_stdout")
        err = self._read_handle("_prs_stderr")
        return _clip(out), _clip(err)

    def _read_handle(self, attr: str) -> str:
        handle = getattr(self._proc, attr, None)
        if handle is None:
            return ""
        try:
            handle.flush()
            path = Path(handle.name)
            return path.read_text(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            return ""

    def _close_output(self, proc: Process) -> None:
        for attr in ("_prs_stdout", "_prs_stderr"):
            handle = getattr(proc, attr, None)
            if handle is None:
                continue
            try:
                handle.close()
                Path(handle.name).unlink(missing_ok=True)
            except (OSError, ValueError):
                pass
