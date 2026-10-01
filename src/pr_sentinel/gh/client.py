"""The GitHub API surface the engine uses. Deliberately tiny.

Exactly three operations: find my previous comment, write a comment, publish
a check-run. Nothing that writes to the repository, nothing that merges,
nothing that approves.

That is not an oversight; it is the DESIGN s10 permission model expressed in
code. The workflow grants `contents: read` and `pull-requests: write`, and if
this module grew a method that needed more, the method would fail rather than
the permission quietly widening.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

GITHUB_API = "https://api.github.com"


class GitHubError(RuntimeError):
    pass


@dataclass
class GitHubClient:
    token: str
    repo: str  # "owner/name"
    api_url: str = GITHUB_API

    @classmethod
    def from_env(cls) -> GitHubClient | None:
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("INPUT_GITHUB_TOKEN")
        repo = os.environ.get("GITHUB_REPOSITORY")
        if not token or not repo:
            return None
        return cls(
            token=token,
            repo=repo,
            api_url=os.environ.get("GITHUB_API_URL", GITHUB_API),
        )

    # -- plumbing --------------------------------------------------------

    def _request(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> Any:
        url = f"{self.api_url}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(  # noqa: S310
            url,
            data=data,
            method=method,
            headers={
                "authorization": f"Bearer {self.token}",
                "accept": "application/vnd.github+json",
                "x-github-api-version": "2022-11-28",
                "content-type": "application/json",
                "user-agent": "pr-sentinel",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
                payload = response.read().decode("utf-8")
                return json.loads(payload) if payload.strip() else None
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:400]
            raise GitHubError(f"{method} {path} -> {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise GitHubError(f"{method} {path} failed: {exc}") from exc

    # -- operations ------------------------------------------------------

    def find_comment(self, pr_number: int, marker: str) -> int | None:
        """Locate the engine's own previous comment, if any."""
        page = 1
        while page <= 10:
            items = self._request(
                "GET", f"/repos/{self.repo}/issues/{pr_number}/comments?per_page=100&page={page}"
            )
            if not items:
                return None
            for item in items:
                if marker in (item.get("body") or ""):
                    return int(item["id"])
            if len(items) < 100:
                return None
            page += 1
        return None

    def upsert_comment(self, pr_number: int, body: str, marker: str) -> dict[str, Any]:
        """Update the existing comment, or create the first one.

        Updating in place rather than appending keeps the PR conversation
        readable across a dozen pushes, and means the comment always reflects
        the current head rather than a trail of superseded opinions.
        """
        existing = self.find_comment(pr_number, marker)
        if existing is not None:
            return self._request(
                "PATCH", f"/repos/{self.repo}/issues/comments/{existing}", {"body": body}
            )
        return self._request(
            "POST", f"/repos/{self.repo}/issues/{pr_number}/comments", {"body": body}
        )

    def create_check_run(
        self,
        *,
        name: str,
        head_sha: str,
        conclusion: str,
        title: str,
        summary: str,
        details_url: str | None = None,
    ) -> dict[str, Any] | None:
        """Publish a check-run.

        Requires `checks: write`, which not every consuming repo will grant,
        and a token type that supports it. Failure is returned as None rather
        than raised: a missing status is a degraded review, not a broken one,
        and the comment has already been written by this point.
        """
        body: dict[str, Any] = {
            "name": name,
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": conclusion,
            "output": {"title": title[:255], "summary": summary[:65000]},
        }
        if details_url:
            body["details_url"] = details_url
        try:
            return self._request("POST", f"/repos/{self.repo}/check-runs", body)
        except GitHubError:
            return None
