from __future__ import annotations

import os
import re
import urllib.parse
from dataclasses import dataclass
from typing import Mapping, Protocol, Sequence

from threatline.domain import Runbook, SourceRef
from threatline.providers.base import (
    ContextProvider,
    HealthStatus,
    ProviderCapability,
    ProviderHealth,
    ProviderKind,
)


@dataclass(frozen=True, slots=True)
class ObservabilityLink:
    id: str
    title: str
    url: str
    provider: str
    service_id: str | None = None
    kind: str = "dashboard"
    description: str = ""


class ObservabilityProvider(ContextProvider, Protocol):
    def observability_links(self, service_id: str | None = None) -> list[ObservabilityLink]: ...


@dataclass(frozen=True, slots=True)
class GrafanaDashboard:
    uid: str
    title: str
    service_id: str | None = None


@dataclass(frozen=True, slots=True)
class GrafanaConfig:
    base_url: str
    dashboards: tuple[GrafanaDashboard, ...]
    org_id: str = ""
    service_variable: str = "service"
    default_from: str = "now-6h"
    default_to: str = "now"

    @property
    def configured(self) -> bool:
        return bool(self.base_url.strip() and self.dashboards)

    @classmethod
    def from_env(cls) -> GrafanaConfig:
        return cls(
            base_url=os.environ.get("THREATLINE_GRAFANA_URL", "").strip().rstrip("/"),
            dashboards=parse_grafana_dashboards(os.environ.get("THREATLINE_GRAFANA_DASHBOARDS", "")),
            org_id=os.environ.get("THREATLINE_GRAFANA_ORG_ID", "").strip(),
            service_variable=os.environ.get("THREATLINE_GRAFANA_SERVICE_VARIABLE", "service").strip(),
            default_from=os.environ.get("THREATLINE_GRAFANA_FROM", "now-6h").strip() or "now-6h",
            default_to=os.environ.get("THREATLINE_GRAFANA_TO", "now").strip() or "now",
        )


def parse_grafana_dashboards(value: object) -> tuple[GrafanaDashboard, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        raw_values: Sequence[object] = [part.strip() for part in re.split(r"[;\n]+", value) if part.strip()]
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        raw_values = value
    else:
        raise ValueError("Grafana dashboards must be a list or semicolon-separated string")

    dashboards: list[GrafanaDashboard] = []
    for raw in raw_values:
        if isinstance(raw, Mapping):
            uid = str(raw.get("uid") or "").strip()
            title = str(raw.get("title") or uid).strip()
            service_id = str(raw.get("service_id") or "").strip() or None
        else:
            parts = [part.strip() for part in str(raw).split("|")]
            if len(parts) == 1:
                uid, title, service_id = parts[0], parts[0], None
            elif len(parts) == 2:
                uid, title, service_id = parts[0], parts[1], None
            elif len(parts) == 3:
                service_id, uid, title = parts
                service_id = service_id or None
            else:
                raise ValueError("Grafana dashboard entries must use uid|title or service_id|uid|title")
        if not uid:
            raise ValueError("Grafana dashboard uid cannot be blank")
        dashboards.append(GrafanaDashboard(uid=uid, title=title or uid, service_id=service_id))
    return tuple(dashboards)


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "dashboard"


class GrafanaProvider:
    name = "grafana"
    kind = ProviderKind.OBSERVABILITY

    def __init__(self, config: GrafanaConfig | None = None) -> None:
        self.config = config or GrafanaConfig.from_env()

    def capabilities(self) -> frozenset[ProviderCapability]:
        if not self.config.configured:
            return frozenset()
        return frozenset({ProviderCapability.READ_OBSERVABILITY_LINKS, ProviderCapability.READ_RUNBOOKS})

    def health(self) -> ProviderHealth:
        if not self.config.configured:
            return ProviderHealth(HealthStatus.UNCONFIGURED, "Grafana dashboard links are not configured")
        parsed = urllib.parse.urlparse(self.config.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return ProviderHealth(HealthStatus.UNAVAILABLE, "Grafana base URL must use http or https")
        return ProviderHealth(HealthStatus.HEALTHY, f"{len(self.config.dashboards)} dashboard link(s) configured")

    def observability_links(self, service_id: str | None = None) -> list[ObservabilityLink]:
        if not self.config.configured:
            return []
        links: list[ObservabilityLink] = []
        for dashboard in self.config.dashboards:
            if service_id and dashboard.service_id not in {None, service_id}:
                continue
            query: dict[str, str] = {
                "from": self.config.default_from,
                "to": self.config.default_to,
            }
            if self.config.org_id:
                query["orgId"] = self.config.org_id
            if service_id and self.config.service_variable:
                query[f"var-{self.config.service_variable}"] = service_id
            path = "/d/{}/{}".format(
                urllib.parse.quote(dashboard.uid, safe=""),
                urllib.parse.quote(_slug(dashboard.title), safe=""),
            )
            url = self.config.base_url.rstrip("/") + path + "?" + urllib.parse.urlencode(query)
            links.append(
                ObservabilityLink(
                    id=f"grafana:{dashboard.uid}",
                    title=dashboard.title,
                    url=url,
                    provider=self.name,
                    service_id=dashboard.service_id,
                    kind="dashboard",
                    description="Grafana dashboard",
                )
            )
        return links

    def services(self):
        return []

    def work_items(self):
        return []

    def alerts(self):
        return []

    def changes(self):
        return []

    def runbooks(self) -> list[Runbook]:
        return [
            Runbook(
                id=link.id,
                title=f"Dashboard · {link.title}",
                service_id=link.service_id,
                location=link.url,
                source_ref=SourceRef(self.name, link.id, link.url),
                tags=("observability:grafana", "dashboard"),
            )
            for link in self.observability_links()
        ]

    def meetings(self):
        return []

    def decisions(self):
        return []
