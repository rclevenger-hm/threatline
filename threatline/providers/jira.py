from __future__ import annotations

import base64
import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from threatline.domain import SourceRef, WorkItem
from threatline.providers.base import (
    HealthStatus,
    ProviderCapability,
    ProviderHealth,
    ProviderKind,
)


def _parse_datetime(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    normalized = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class JiraConfig:
    base_url: str
    jql: str
    bearer_token: str = ""
    email: str = ""
    api_token: str = ""
    verify_ssl: bool = True
    timeout_seconds: float = 30.0
    max_results: int = 500

    @property
    def configured(self) -> bool:
        base = bool(self.base_url.strip() and self.jql.strip())
        bearer = bool(self.bearer_token.strip())
        basic = bool(self.email.strip() and self.api_token.strip())
        return base and (bearer or basic)

    @property
    def auth_mode(self) -> str:
        if self.bearer_token.strip():
            return "bearer"
        if self.email.strip() and self.api_token.strip():
            return "basic"
        return "none"

    @classmethod
    def from_env(cls) -> JiraConfig:
        verify_ssl = os.environ.get("THREATLINE_JIRA_VERIFY_SSL", "true").strip().lower() not in {
            "0",
            "false",
            "no",
        }
        timeout = float(os.environ.get("THREATLINE_JIRA_TIMEOUT", "30") or "30")
        max_results = int(os.environ.get("THREATLINE_JIRA_MAX_RESULTS", "500") or "500")
        return cls(
            base_url=os.environ.get("THREATLINE_JIRA_BASE_URL", "").strip().rstrip("/"),
            jql=os.environ.get("THREATLINE_JIRA_JQL", "").strip(),
            bearer_token=os.environ.get("THREATLINE_JIRA_PAT", "").strip(),
            email=os.environ.get("THREATLINE_JIRA_EMAIL", "").strip(),
            api_token=os.environ.get("THREATLINE_JIRA_API_TOKEN", "").strip(),
            verify_ssl=verify_ssl,
            timeout_seconds=max(timeout, 1.0),
            max_results=max(1, min(max_results, 5000)),
        )


class JiraTransport(Protocol):
    def request(
        self,
        config: JiraConfig,
        path: str,
        *,
        method: str = "GET",
        query: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]: ...


class UrlLibJiraTransport:
    user_agent = "Threatline/1.0"

    def request(
        self,
        config: JiraConfig,
        path: str,
        *,
        method: str = "GET",
        query: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = config.base_url.rstrip("/") + path
        if query:
            url += "?" + urllib.parse.urlencode(query, doseq=True)

        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Accept": "application/json", "User-Agent": self.user_agent}
        if config.bearer_token:
            headers["Authorization"] = f"Bearer {config.bearer_token}"
        elif config.email and config.api_token:
            raw = f"{config.email}:{config.api_token}".encode("utf-8")
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
        if body is not None:
            headers["Content-Type"] = "application/json"

        request = urllib.request.Request(url, data=body, headers=headers, method=method.upper())
        context = None if config.verify_ssl else ssl._create_unverified_context()
        try:
            with urllib.request.urlopen(request, timeout=config.timeout_seconds, context=context) as response:
                raw_response = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"Jira returned HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise RuntimeError(f"Could not reach Jira: {exc}") from exc

        if not raw_response.strip():
            return {}
        try:
            decoded = json.loads(raw_response)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Jira returned non-JSON content; authentication or an intermediary may have intercepted the request") from exc
        if not isinstance(decoded, dict):
            raise RuntimeError("Jira returned an unexpected response shape")
        return decoded


class JiraProvider:
    name = "jira"
    kind = ProviderKind.WORK

    def __init__(self, config: JiraConfig | None = None, transport: JiraTransport | None = None) -> None:
        self.config = config or JiraConfig.from_env()
        self.transport = transport or UrlLibJiraTransport()

    def capabilities(self) -> frozenset[ProviderCapability]:
        capabilities = {
            ProviderCapability.READ_WORK_ITEMS,
            ProviderCapability.COMMENT_WORK_ITEM,
            ProviderCapability.ASSIGN_WORK_ITEM,
            ProviderCapability.TRANSITION_WORK_ITEM,
        }
        return frozenset(capabilities) if self.config.configured else frozenset()

    def health(self) -> ProviderHealth:
        if not self.config.configured:
            return ProviderHealth(HealthStatus.UNCONFIGURED, "Jira connection is not configured")
        try:
            user = self.transport.request(self.config, "/rest/api/2/myself")
        except RuntimeError as exc:
            return ProviderHealth(HealthStatus.UNAVAILABLE, str(exc))
        identity = user.get("displayName") or user.get("emailAddress") or user.get("name") or "authenticated user"
        return ProviderHealth(HealthStatus.HEALTHY, f"Connected as {identity}")

    def services(self):
        return []

    def work_items(self) -> list[WorkItem]:
        if not self.config.configured:
            return []
        issues = self._search_issues()
        return [self._normalize_issue(issue) for issue in issues]

    def alerts(self):
        return []

    def changes(self):
        return []

    def runbooks(self):
        return []

    def meetings(self):
        return []

    def decisions(self):
        return []

    def comment(self, work_item_id: str, body: str) -> dict[str, Any]:
        text = body.strip()
        if not text:
            raise ValueError("Comment cannot be empty")
        return self.transport.request(
            self.config,
            f"/rest/api/2/issue/{urllib.parse.quote(work_item_id, safe='')}/comment",
            method="POST",
            payload={"body": text},
        )

    def assign_to_current_user(self, work_item_id: str) -> dict[str, Any]:
        current = self.transport.request(self.config, "/rest/api/2/myself")
        account_id = current.get("accountId")
        username = current.get("name") or current.get("key")
        if account_id:
            payload = {"accountId": account_id}
        elif username:
            payload = {"name": username}
        else:
            raise RuntimeError("Jira did not provide an assignable current-user identity")
        return self.transport.request(
            self.config,
            f"/rest/api/2/issue/{urllib.parse.quote(work_item_id, safe='')}/assignee",
            method="PUT",
            payload=payload,
        )

    def transitions(self, work_item_id: str) -> list[dict[str, str]]:
        response = self.transport.request(
            self.config,
            f"/rest/api/2/issue/{urllib.parse.quote(work_item_id, safe='')}/transitions",
        )
        result: list[dict[str, str]] = []
        for transition in response.get("transitions") or []:
            transition_id = str(transition.get("id") or "").strip()
            name = str(transition.get("name") or "").strip()
            if transition_id and name:
                result.append({"id": transition_id, "name": name})
        return result

    def transition(self, work_item_id: str, transition_id: str) -> dict[str, Any]:
        transition = transition_id.strip()
        if not transition:
            raise ValueError("Transition id cannot be empty")
        return self.transport.request(
            self.config,
            f"/rest/api/2/issue/{urllib.parse.quote(work_item_id, safe='')}/transitions",
            method="POST",
            payload={"transition": {"id": transition}},
        )

    def _search_issues(self) -> list[dict[str, Any]]:
        issues: list[dict[str, Any]] = []
        start_at = 0
        page_size = min(100, self.config.max_results)
        fields = ["summary", "status", "priority", "updated", "labels", "assignee", "project"]

        while len(issues) < self.config.max_results:
            requested = min(page_size, self.config.max_results - len(issues))
            response = self.transport.request(
                self.config,
                "/rest/api/2/search",
                method="POST",
                payload={
                    "jql": self.config.jql,
                    "startAt": start_at,
                    "maxResults": requested,
                    "fields": fields,
                },
            )
            page = response.get("issues") or []
            if not isinstance(page, list):
                raise RuntimeError("Jira search returned an invalid issues collection")
            issues.extend(issue for issue in page if isinstance(issue, dict))
            if not page:
                break
            start_at += len(page)
            total = int(response.get("total") or len(issues))
            if start_at >= total:
                break
        return issues

    def _normalize_issue(self, issue: dict[str, Any]) -> WorkItem:
        key = str(issue.get("key") or issue.get("id") or "").strip()
        if not key:
            raise RuntimeError("Jira issue is missing a key")
        fields = issue.get("fields") or {}
        summary = str(fields.get("summary") or key).strip()
        status = str((fields.get("status") or {}).get("name") or "unknown").strip()
        priority = str((fields.get("priority") or {}).get("name") or "normal").strip().lower()
        labels = tuple(str(label).strip() for label in (fields.get("labels") or []) if str(label).strip())
        return WorkItem(
            id=key,
            title=summary,
            status=status,
            priority=priority,
            service_id=None,
            source="jira",
            updated_at=_parse_datetime(fields.get("updated")),
            source_ref=SourceRef("jira", key, f"{self.config.base_url}/browse/{urllib.parse.quote(key, safe='-_.~')}"),
            tags=labels,
        )
