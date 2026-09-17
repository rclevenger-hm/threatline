from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from threatline.domain import Alert, Severity, SourceRef
from threatline.providers.base import (
    HealthStatus,
    ProviderCapability,
    ProviderHealth,
    ProviderKind,
)
from threatline.providers.observability import ObservabilityLink


@dataclass(frozen=True, slots=True)
class ZabbixConfig:
    base_url: str
    api_token: str
    service_tag: str = "service"
    verify_ssl: bool = True
    timeout_seconds: float = 30.0
    max_problems: int = 200

    @property
    def configured(self) -> bool:
        return bool(self.base_url.strip() and self.api_token.strip())

    @property
    def api_url(self) -> str:
        base = self.base_url.rstrip("/")
        return base if base.endswith("api_jsonrpc.php") else base + "/api_jsonrpc.php"

    @property
    def web_url(self) -> str:
        return self.base_url.rstrip("/").removesuffix("/api_jsonrpc.php")

    @classmethod
    def from_env(cls) -> ZabbixConfig:
        verify_ssl = os.environ.get("THREATLINE_ZABBIX_VERIFY_SSL", "true").strip().lower() not in {"0", "false", "no"}
        timeout = float(os.environ.get("THREATLINE_ZABBIX_TIMEOUT", "30") or "30")
        max_problems = int(os.environ.get("THREATLINE_ZABBIX_MAX_PROBLEMS", "200") or "200")
        return cls(
            base_url=os.environ.get("THREATLINE_ZABBIX_URL", "").strip().rstrip("/"),
            api_token=os.environ.get("THREATLINE_ZABBIX_TOKEN", "").strip(),
            service_tag=os.environ.get("THREATLINE_ZABBIX_SERVICE_TAG", "service").strip() or "service",
            verify_ssl=verify_ssl,
            timeout_seconds=max(timeout, 1.0),
            max_problems=max(1, min(max_problems, 5000)),
        )


class ZabbixTransport(Protocol):
    def request(self, config: ZabbixConfig, method: str, params: dict[str, Any]) -> Any: ...


class UrlLibZabbixTransport:
    user_agent = "Threatline/1.0"

    def request(self, config: ZabbixConfig, method: str, params: dict[str, Any]) -> Any:
        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        }
        headers = {"Content-Type": "application/json-rpc", "User-Agent": self.user_agent}
        if method != "apiinfo.version":
            headers["Authorization"] = f"Bearer {config.api_token}"
        request = urllib.request.Request(
            config.api_url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        context = None if config.verify_ssl else ssl._create_unverified_context()
        try:
            with urllib.request.urlopen(request, timeout=config.timeout_seconds, context=context) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"Zabbix returned HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise RuntimeError(f"Could not reach Zabbix: {exc}") from exc
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Zabbix returned non-JSON content") from exc
        if not isinstance(decoded, dict):
            raise RuntimeError("Zabbix returned an unexpected response shape")
        error = decoded.get("error")
        if isinstance(error, dict):
            message = str(error.get("data") or error.get("message") or "request failed")
            raise RuntimeError(f"Zabbix API error: {message}")
        return decoded.get("result")


_SEVERITY_MAP = {
    0: Severity.INFO,
    1: Severity.INFO,
    2: Severity.LOW,
    3: Severity.MEDIUM,
    4: Severity.HIGH,
    5: Severity.CRITICAL,
}


class ZabbixProvider:
    name = "zabbix"
    kind = ProviderKind.OBSERVABILITY

    def __init__(self, config: ZabbixConfig | None = None, transport: ZabbixTransport | None = None) -> None:
        self.config = config or ZabbixConfig.from_env()
        self.transport = transport or UrlLibZabbixTransport()

    def capabilities(self) -> frozenset[ProviderCapability]:
        if not self.config.configured:
            return frozenset()
        return frozenset({ProviderCapability.READ_ALERTS, ProviderCapability.READ_OBSERVABILITY_LINKS})

    def health(self) -> ProviderHealth:
        if not self.config.configured:
            return ProviderHealth(HealthStatus.UNCONFIGURED, "Zabbix connection is not configured")
        try:
            result = self.transport.request(
                self.config,
                "problem.get",
                {"output": ["eventid"], "limit": 1, "sortfield": ["eventid"], "sortorder": "DESC"},
            )
        except RuntimeError as exc:
            return ProviderHealth(HealthStatus.UNAVAILABLE, str(exc))
        if not isinstance(result, list):
            return ProviderHealth(HealthStatus.UNAVAILABLE, "Zabbix returned an invalid problem response")
        return ProviderHealth(HealthStatus.HEALTHY, "Connected to Zabbix")

    def services(self):
        return []

    def work_items(self):
        return []

    def alerts(self) -> list[Alert]:
        if not self.config.configured:
            return []
        result = self.transport.request(
            self.config,
            "problem.get",
            {
                "output": ["eventid", "objectid", "name", "severity", "clock"],
                "selectTags": ["tag", "value"],
                "recent": True,
                "sortfield": ["eventid"],
                "sortorder": "DESC",
                "limit": self.config.max_problems,
            },
        )
        if not isinstance(result, list):
            raise RuntimeError("Zabbix returned an invalid problem response")
        alerts: list[Alert] = []
        for value in result:
            if not isinstance(value, dict):
                continue
            event_id = str(value.get("eventid") or "").strip()
            if not event_id:
                continue
            tags = value.get("tags") if isinstance(value.get("tags"), list) else []
            service_id = None
            normalized_tags: list[str] = []
            for item in tags:
                if not isinstance(item, dict):
                    continue
                tag = str(item.get("tag") or "").strip()
                tag_value = str(item.get("value") or "").strip()
                if tag:
                    normalized_tags.append(f"{tag}:{tag_value}" if tag_value else tag)
                if tag.lower() == self.config.service_tag.lower() and tag_value:
                    service_id = tag_value
            try:
                severity_number = int(value.get("severity") or 0)
            except (TypeError, ValueError):
                severity_number = 0
            try:
                started_at = datetime.fromtimestamp(int(value.get("clock") or 0), tz=timezone.utc)
            except (TypeError, ValueError, OSError, OverflowError):
                started_at = datetime.now(timezone.utc)
            trigger_id = str(value.get("objectid") or "").strip()
            source_url = self.config.web_url + "/zabbix.php?action=problem.view"
            if trigger_id:
                source_url = self.config.web_url + "/tr_events.php?" + urllib.parse.urlencode(
                    {"triggerid": trigger_id, "eventid": event_id}
                )
            alerts.append(
                Alert(
                    id=f"zabbix:{event_id}",
                    title=str(value.get("name") or f"Zabbix problem {event_id}"),
                    severity=_SEVERITY_MAP.get(severity_number, Severity.INFO),
                    service_id=service_id,
                    source=self.name,
                    started_at=started_at,
                    source_ref=SourceRef(self.name, event_id, source_url),
                    tags=tuple(normalized_tags),
                )
            )
        return alerts

    def changes(self):
        return []

    def runbooks(self):
        return []

    def meetings(self):
        return []

    def decisions(self):
        return []

    def observability_links(self, service_id: str | None = None) -> list[ObservabilityLink]:
        if not self.config.configured:
            return []
        description = "Active Zabbix problems"
        if service_id:
            description += f"; correlate with tag {self.config.service_tag}={service_id}"
        return [
            ObservabilityLink(
                id="zabbix:problems",
                title="Zabbix problems",
                url=self.config.web_url + "/zabbix.php?action=problem.view",
                provider=self.name,
                service_id=None,
                kind="problems",
                description=description,
            )
        ]
