from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from threatline.domain import Alert, Change, Decision, Meeting, Runbook, Service, WorkItem


class ProviderKind(StrEnum):
    WORK = "work"
    SOURCE = "source"
    OBSERVABILITY = "observability"
    PAGING = "paging"
    COMMUNICATION = "communication"
    MEETING = "meeting"
    STORAGE = "storage"
    DEMO = "demo"


class ProviderCapability(StrEnum):
    READ_SERVICES = "read_services"
    READ_WORK_ITEMS = "read_work_items"
    READ_ALERTS = "read_alerts"
    READ_CHANGES = "read_changes"
    READ_RUNBOOKS = "read_runbooks"
    READ_MEETINGS = "read_meetings"
    READ_DECISIONS = "read_decisions"
    READ_OBSERVABILITY_LINKS = "read_observability_links"
    COMMENT_WORK_ITEM = "comment_work_item"
    ASSIGN_WORK_ITEM = "assign_work_item"
    TRANSITION_WORK_ITEM = "transition_work_item"


class HealthStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    UNCONFIGURED = "unconfigured"


@dataclass(frozen=True, slots=True)
class ProviderHealth:
    status: HealthStatus
    message: str = ""


class ContextReader(Protocol):
    """Read boundary consumed by the context engine."""

    name: str

    def services(self) -> list[Service]: ...
    def work_items(self) -> list[WorkItem]: ...
    def alerts(self) -> list[Alert]: ...
    def changes(self) -> list[Change]: ...
    def runbooks(self) -> list[Runbook]: ...
    def meetings(self) -> list[Meeting]: ...
    def decisions(self) -> list[Decision]: ...


class ContextProvider(ContextReader, Protocol):
    """External provider that contributes operational context."""

    kind: ProviderKind

    def capabilities(self) -> frozenset[ProviderCapability]: ...
    def health(self) -> ProviderHealth: ...
