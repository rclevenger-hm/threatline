from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class Service:
    id: str
    name: str
    owner: str | None = None
    description: str = ""


@dataclass(frozen=True, slots=True)
class WorkItem:
    id: str
    title: str
    status: str
    priority: str = "normal"
    service_id: str | None = None
    source: str = "unknown"
    updated_at: datetime = field(default_factory=utc_now)


@dataclass(frozen=True, slots=True)
class Alert:
    id: str
    title: str
    severity: Severity
    service_id: str | None = None
    source: str = "unknown"
    started_at: datetime = field(default_factory=utc_now)


@dataclass(frozen=True, slots=True)
class Change:
    id: str
    title: str
    service_id: str | None = None
    author: str | None = None
    source: str = "unknown"
    occurred_at: datetime = field(default_factory=utc_now)


@dataclass(frozen=True, slots=True)
class Runbook:
    id: str
    title: str
    service_id: str | None = None
    location: str = ""


@dataclass(frozen=True, slots=True)
class Meeting:
    id: str
    title: str
    participants: tuple[str, ...] = ()
    related_work_item_ids: tuple[str, ...] = ()
    started_at: datetime = field(default_factory=utc_now)


@dataclass(frozen=True, slots=True)
class Decision:
    id: str
    summary: str
    related_work_item_id: str | None = None
    meeting_id: str | None = None
    decided_at: datetime = field(default_factory=utc_now)
