"""Browser and API access, behind a protocol.

Two reasons this is an abstraction rather than Playwright calls inline.

**The suite must run without a browser.** Playwright cannot be installed in
every environment the engine is developed in, and a tier that can only be
tested by downloading 300MB of Chromium does not get tested. `FakeDriver`
replays a scripted page model, so the inventory crawler, the differential
probe, the PII watcher and the explorer loop are all exercisable offline.

**The target is not always a browser.** `adversarial-probe` is permitted to
go below the UI (DESIGN-V2 §11) because the authorization holes that matter
are reachable with a session and `curl`. That is a different transport
against the same session, so it belongs behind the same seam.

Every request carries the run manifest's announcement headers (§6a). That is
enforced here, at the one place all traffic passes through, rather than
remembered at each call site.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from .models import RunManifest, Session


class BudgetExceeded(RuntimeError):
    """The run hit its request budget and stopped.

    Deliberately an abort rather than a throttle: a probe that quietly keeps
    going past its declared budget is a probe whose published manifest was a
    lie, and the manifest is the thing that makes it distinguishable from an
    attack.
    """


@dataclass
class PageState:
    """What the crawler sees. Deliberately small and serialisable."""

    url: str
    title: str = ""
    screen: str = ""
    #: (kind, label, enabled, visible)
    elements: list[tuple[str, str, bool, bool]] = field(default_factory=list)
    text: str = ""
    console: list[str] = field(default_factory=list)
    #: Raw-ish network records: method, url, status, and the response's
    #: top-level field names. Bodies are never retained wholesale.
    network: list[dict[str, Any]] = field(default_factory=list)


@runtime_checkable
class Driver(Protocol):
    """Everything Tier 3 is allowed to do to a running application."""

    def start(self, base_url: str, session: Session, manifest: RunManifest) -> None: ...

    def stop(self) -> None: ...

    def goto(self, path: str) -> PageState: ...

    def click(self, label: str) -> PageState: ...

    def type(self, label: str, text: str) -> PageState: ...

    def read(self) -> PageState: ...

    def screenshot(self, name: str) -> str | None: ...

    def set_viewport(self, width: int, height: int) -> None: ...

    def set_network(self, profile: str | None) -> None: ...

    def api(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> tuple[int, dict[str, Any] | list[Any] | None]: ...

    @property
    def requests_made(self) -> int: ...


class _BudgetedDriver:
    """Mixin enforcing the manifest's request budget and headers."""

    def __init__(self) -> None:
        self._manifest: RunManifest | None = None
        self._requests = 0

    @property
    def requests_made(self) -> int:
        return self._requests

    def _spend(self, n: int = 1) -> None:
        self._requests += n
        if self._manifest is not None:
            self._manifest.requests_made = self._requests
            if self._requests > self._manifest.request_budget:
                self._manifest.close("request budget exceeded")
                raise BudgetExceeded(
                    f"run {self._manifest.run_id} exceeded its declared budget of "
                    f"{self._manifest.request_budget} requests and was stopped. The "
                    f"published manifest has to stay true or it is not an "
                    f"announcement."
                )

    def _headers(self) -> dict[str, str]:
        return self._manifest.headers() if self._manifest else {}


@dataclass
class FakePage:
    """One screen in a scripted application, for tests."""

    screen: str
    elements: list[tuple[str, str, bool, bool]] = field(default_factory=list)
    text: str = ""
    #: label -> screen it navigates to
    links: dict[str, str] = field(default_factory=dict)
    console: list[str] = field(default_factory=list)
    network: list[dict[str, Any]] = field(default_factory=list)


class FakeDriver(_BudgetedDriver):
    """A scripted application. The whole tier is testable against this.

    Pages may be supplied per-persona, which is how a test expresses "the
    admin sees the Reports nav and the teacher does not" — the exact shape
    the differential probe exists to detect.
    """

    def __init__(
        self,
        pages: dict[str, FakePage] | None = None,
        *,
        per_persona: dict[str, dict[str, FakePage]] | None = None,
        api_responses: dict[tuple[str, str], tuple[int, Any]] | None = None,
        start_screen: str = "home",
    ) -> None:
        super().__init__()
        self._default_pages = pages or {}
        self._per_persona = per_persona or {}
        self._api = api_responses or {}
        self._start = start_screen
        self._current = start_screen
        self._session: Session | None = None
        self.started = False
        self.screenshots: list[str] = []

    # -- lifecycle -------------------------------------------------------

    def start(self, base_url: str, session: Session, manifest: RunManifest) -> None:
        self._session = session
        self._manifest = manifest
        self._current = self._start
        self.started = True

    def stop(self) -> None:
        self.started = False

    # -- pages -----------------------------------------------------------

    def _pages(self) -> dict[str, FakePage]:
        persona = self._session.persona if self._session else ""
        return self._per_persona.get(persona, self._default_pages)

    def _state(self) -> PageState:
        page = self._pages().get(self._current)
        if page is None:
            return PageState(url=f"/{self._current}", screen=self._current, text="")
        return PageState(
            url=f"/{page.screen}",
            title=page.screen,
            screen=page.screen,
            elements=list(page.elements),
            text=page.text,
            console=list(page.console),
            network=list(page.network),
        )

    def goto(self, path: str) -> PageState:
        self._spend()
        self._current = path.strip("/") or self._start
        return self._state()

    def click(self, label: str) -> PageState:
        self._spend()
        page = self._pages().get(self._current)
        if page and label in page.links:
            self._current = page.links[label]
        return self._state()

    def type(self, label: str, text: str) -> PageState:
        self._spend()
        return self._state()

    def read(self) -> PageState:
        return self._state()

    def screenshot(self, name: str) -> str | None:
        self.screenshots.append(name)
        return f"fake://{name}.png"

    def set_viewport(self, width: int, height: int) -> None:
        return None

    def set_network(self, profile: str | None) -> None:
        return None

    def api(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> tuple[int, dict[str, Any] | list[Any] | None]:
        self._spend()
        persona = self._session.persona if self._session else ""
        for key in ((f"{persona}:{method.upper()}", path), (method.upper(), path)):
            if key in self._api:
                return self._api[key]
        return 404, None
