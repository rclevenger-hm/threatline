from __future__ import annotations

import base64
import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, Protocol

from threatline.domain import Change, Runbook, SourceRef
from threatline.providers.base import (
    HealthStatus,
    ProviderCapability,
    ProviderHealth,
    ProviderKind,
)

_WORK_ITEM_RE = re.compile(r"\b[A-Z][A-Z0-9]{1,15}-\d+\b")
_RUNBOOK_HINTS = (
    "runbook",
    "playbook",
    "oncall",
    "on-call",
    "troubleshoot",
    "incident-response",
    "incident_response",
    "/operations/",
    "/ops/",
)


def _parse_datetime(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _work_item_ids(*values: object) -> tuple[str, ...]:
    found: list[str] = []
    for value in values:
        for match in _WORK_ITEM_RE.findall(str(value or "")):
            if match not in found:
                found.append(match)
    return tuple(found)


def _runbook_title(path: str) -> str:
    stem = PurePosixPath(path).stem.replace("_", " ").replace("-", " ").strip()
    return " ".join(part.capitalize() for part in stem.split()) or path


def _is_runbook_path(path: str) -> bool:
    lowered = "/" + path.lower().lstrip("/")
    return path.lower().endswith((".md", ".mdx", ".txt")) and any(hint in lowered for hint in _RUNBOOK_HINTS)


@dataclass(frozen=True, slots=True)
class GitHubConfig:
    token: str
    repositories: tuple[str, ...]
    api_url: str = "https://api.github.com"
    web_url: str = "https://github.com"
    verify_ssl: bool = True
    timeout_seconds: float = 30.0
    max_changes: int = 100
    max_runbooks: int = 100

    @property
    def configured(self) -> bool:
        return bool(self.token.strip() and self.repositories and self.api_url.strip())

    @classmethod
    def from_env(cls) -> GitHubConfig:
        api_url = os.environ.get("THREATLINE_GITHUB_API_URL", "https://api.github.com").strip().rstrip("/")
        web_url = os.environ.get("THREATLINE_GITHUB_WEB_URL", "").strip().rstrip("/")
        if not web_url:
            web_url = "https://github.com" if api_url == "https://api.github.com" else api_url.removesuffix("/api/v3")
        repos = tuple(
            part.strip()
            for part in os.environ.get("THREATLINE_GITHUB_REPOSITORIES", "").split(",")
            if part.strip()
        )
        verify_ssl = os.environ.get("THREATLINE_GITHUB_VERIFY_SSL", "true").strip().lower() not in {"0", "false", "no"}
        timeout = float(os.environ.get("THREATLINE_GITHUB_TIMEOUT", "30") or "30")
        max_changes = int(os.environ.get("THREATLINE_GITHUB_MAX_CHANGES", "100") or "100")
        max_runbooks = int(os.environ.get("THREATLINE_GITHUB_MAX_RUNBOOKS", "100") or "100")
        return cls(
            token=os.environ.get("THREATLINE_GITHUB_TOKEN", "").strip(),
            repositories=repos,
            api_url=api_url,
            web_url=web_url,
            verify_ssl=verify_ssl,
            timeout_seconds=max(timeout, 1.0),
            max_changes=max(1, min(max_changes, 1000)),
            max_runbooks=max(1, min(max_runbooks, 1000)),
        )


class GitHubTransport(Protocol):
    def request(
        self,
        config: GitHubConfig,
        path: str,
        *,
        query: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any]: ...


class UrlLibGitHubTransport:
    user_agent = "Threatline/1.0"

    def request(
        self,
        config: GitHubConfig,
        path: str,
        *,
        query: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any]:
        url = config.api_url.rstrip("/") + path
        if query:
            url += "?" + urllib.parse.urlencode(query, doseq=True)
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {config.token}",
                "User-Agent": self.user_agent,
                "X-GitHub-Api-Version": "2022-11-28",
            },
            method="GET",
        )
        context = None if config.verify_ssl else ssl._create_unverified_context()
        try:
            with urllib.request.urlopen(request, timeout=config.timeout_seconds, context=context) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"GitHub returned HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise RuntimeError(f"Could not reach GitHub: {exc}") from exc
        if not raw.strip():
            return {}
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError("GitHub returned non-JSON content") from exc
        if not isinstance(decoded, (dict, list)):
            raise RuntimeError("GitHub returned an unexpected response shape")
        return decoded


class GitHubProvider:
    name = "github"
    kind = ProviderKind.SOURCE

    def __init__(self, config: GitHubConfig | None = None, transport: GitHubTransport | None = None) -> None:
        self.config = config or GitHubConfig.from_env()
        self.transport = transport or UrlLibGitHubTransport()

    def capabilities(self) -> frozenset[ProviderCapability]:
        if not self.config.configured:
            return frozenset()
        return frozenset({ProviderCapability.READ_CHANGES, ProviderCapability.READ_RUNBOOKS})

    def health(self) -> ProviderHealth:
        if not self.config.configured:
            return ProviderHealth(HealthStatus.UNCONFIGURED, "GitHub connection is not configured")
        try:
            user = self.transport.request(self.config, "/user")
        except RuntimeError as exc:
            return ProviderHealth(HealthStatus.UNAVAILABLE, str(exc))
        if not isinstance(user, dict):
            return ProviderHealth(HealthStatus.UNAVAILABLE, "GitHub returned an invalid user response")
        identity = user.get("login") or user.get("name") or "authenticated user"
        return ProviderHealth(HealthStatus.HEALTHY, f"Connected as {identity}")

    def services(self):
        return []

    def work_items(self):
        return []

    def alerts(self):
        return []

    def meetings(self):
        return []

    def decisions(self):
        return []

    def changes(self) -> list[Change]:
        if not self.config.configured:
            return []
        changes: list[Change] = []
        seen_commit_shas: set[str] = set()
        for repository in self.config.repositories:
            if len(changes) >= self.config.max_changes:
                break
            pulls = self._list(repository, f"/repos/{repository}/pulls", {
                "state": "closed", "sort": "updated", "direction": "desc", "per_page": min(100, self.config.max_changes)
            })
            for pull in pulls:
                if not isinstance(pull, dict) or not pull.get("merged_at"):
                    continue
                merge_sha = str(pull.get("merge_commit_sha") or "")
                if merge_sha:
                    seen_commit_shas.add(merge_sha)
                number = pull.get("number")
                title = str(pull.get("title") or f"Pull request #{number}")
                body = str(pull.get("body") or "")
                author = str((pull.get("user") or {}).get("login") or "") or None
                url = str(pull.get("html_url") or f"{self.config.web_url}/{repository}/pull/{number}")
                changes.append(Change(
                    id=f"github:{repository}:pr:{number}",
                    title=title,
                    author=author,
                    source="github",
                    occurred_at=_parse_datetime(pull.get("merged_at")),
                    source_ref=SourceRef("github", f"{repository}#pull/{number}", url),
                    tags=(f"repo:{repository}", "pull-request"),
                    related_work_item_ids=_work_item_ids(title, body),
                ))
                if len(changes) >= self.config.max_changes:
                    break
            if len(changes) >= self.config.max_changes:
                break
            commits = self._list(repository, f"/repos/{repository}/commits", {"per_page": min(50, self.config.max_changes)})
            for commit in commits:
                if not isinstance(commit, dict):
                    continue
                sha = str(commit.get("sha") or "")
                if not sha or sha in seen_commit_shas:
                    continue
                detail = commit.get("commit") or {}
                message = str(detail.get("message") or sha[:12]).strip()
                title = message.splitlines()[0] if message else sha[:12]
                author = str((commit.get("author") or {}).get("login") or (detail.get("author") or {}).get("name") or "") or None
                url = str(commit.get("html_url") or f"{self.config.web_url}/{repository}/commit/{sha}")
                changes.append(Change(
                    id=f"github:{repository}:commit:{sha}",
                    title=title,
                    author=author,
                    source="github",
                    occurred_at=_parse_datetime((detail.get("committer") or {}).get("date") or (detail.get("author") or {}).get("date")),
                    source_ref=SourceRef("github", f"{repository}@{sha}", url),
                    tags=(f"repo:{repository}", "commit"),
                    related_work_item_ids=_work_item_ids(message),
                ))
                if len(changes) >= self.config.max_changes:
                    break
        return sorted(changes, key=lambda item: item.occurred_at, reverse=True)[: self.config.max_changes]

    def runbooks(self) -> list[Runbook]:
        if not self.config.configured:
            return []
        runbooks: list[Runbook] = []
        for repository in self.config.repositories:
            metadata = self.transport.request(self.config, f"/repos/{repository}")
            if not isinstance(metadata, dict):
                continue
            branch = str(metadata.get("default_branch") or "main")
            tree = self.transport.request(
                self.config,
                f"/repos/{repository}/git/trees/{urllib.parse.quote(branch, safe='')}",
                query={"recursive": "1"},
            )
            if not isinstance(tree, dict):
                continue
            for entry in tree.get("tree") or []:
                if not isinstance(entry, dict) or entry.get("type") != "blob":
                    continue
                path = str(entry.get("path") or "")
                if not _is_runbook_path(path):
                    continue
                url = f"{self.config.web_url}/{repository}/blob/{urllib.parse.quote(branch, safe='')}/{urllib.parse.quote(path, safe='/')}"
                runbooks.append(Runbook(
                    id=f"github:{repository}:{path}",
                    title=_runbook_title(path),
                    location=url,
                    source_ref=SourceRef("github", f"{repository}:{path}", url),
                    tags=(f"repo:{repository}",),
                ))
                if len(runbooks) >= self.config.max_runbooks:
                    return runbooks
        return runbooks

    def ownership(self, repository: str) -> list[dict[str, Any]]:
        if repository not in self.config.repositories:
            raise ValueError(f"Repository is not configured: {repository}")
        for path in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"):
            try:
                response = self.transport.request(self.config, f"/repos/{repository}/contents/{path}")
            except RuntimeError:
                continue
            if not isinstance(response, dict) or not response.get("content"):
                continue
            try:
                text = base64.b64decode(str(response["content"]), validate=False).decode("utf-8", errors="replace")
            except (ValueError, TypeError):
                continue
            rules: list[dict[str, Any]] = []
            for raw_line in text.splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                rules.append({"pattern": parts[0], "owners": parts[1:], "source": path})
            return rules
        return []

    def _list(self, repository: str, path: str, query: dict[str, Any]) -> list[Any]:
        if "/" not in repository:
            raise ValueError(f"Repository must be owner/name: {repository}")
        response = self.transport.request(self.config, path, query=query)
        if not isinstance(response, list):
            raise RuntimeError(f"GitHub returned an invalid list response for {repository}")
        return response
