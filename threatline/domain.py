from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import TypeAlias

SCHEMA_VERSION = 1


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EntityKind(StrEnum):
    SERVICE = "service"
    WORK_ITEM = "work_item"
    INCIDENT = "incident"
    ALERT = "alert"
    CHANGE = "change"
    RUNBOOK = "runbook"
    MEETING = "meeting"
    DECISION = "decision"
    ACTION_ITEM = "action_item"
    PERSON = "person"
    TEAM = "team"
    MESSAGE = "message"
    RECORDING = "recording"
    ATTACHMENT = "attachment"


class RelationshipKind(StrEnum):
    AFFECTS = "affects"
    BELONGS_TO = "belongs_to"
    MODIFIES = "modifies"
    DOCUMENTS = "documents"
    DISCUSSES = "discusses"
    RECORDS = "records"
    ASSIGNED_TO = "assigned_to"
    OWNS = "owns"
    REFERENCES = "references"
    RELATES_TO = "relates_to"
    CAUSED_BY = "caused_by"
    RESOLVED_BY = "resolved_by"


@dataclass(frozen=True, slots=True)
class SourceRef:
    provider: str
    external_id: str
    url: str | None = None


@dataclass(frozen=True, slots=True)
class EntityRef:
    kind: EntityKind
    id: str


@dataclass(frozen=True, slots=True)
class Relationship:
    source: EntityRef
    target: EntityRef
    kind: RelationshipKind
    attributes: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class Service:
    id: str
    name: str
    owner: str | None = None
    description: str = ""
    source_ref: SourceRef | None = None
    tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class WorkItem:
    id: str
    title: str
    status: str
    priority: str = "normal"
    service_id: str | None = None
    source: str = "unknown"
    updated_at: datetime = field(default_factory=utc_now)
    source_ref: SourceRef | None = None
    tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Incident:
    id: str
    title: str
    status: str
    severity: Severity = Severity.MEDIUM
    service_id: str | None = None
    started_at: datetime = field(default_factory=utc_now)
    resolved_at: datetime | None = None
    source_ref: SourceRef | None = None
    tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Alert:
    id: str
    title: str
    severity: Severity
    service_id: str | None = None
    source: str = "unknown"
    started_at: datetime = field(default_factory=utc_now)
    source_ref: SourceRef | None = None
    tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Change:
    id: str
    title: str
    service_id: str | None = None
    author: str | None = None
    source: str = "unknown"
    occurred_at: datetime = field(default_factory=utc_now)
    source_ref: SourceRef | None = None
    tags: tuple[str, ...] = ()
    related_work_item_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Runbook:
    id: str
    title: str
    service_id: str | None = None
    location: str = ""
    source_ref: SourceRef | None = None
    tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Meeting:
    id: str
    title: str
    participants: tuple[str, ...] = ()
    related_work_item_ids: tuple[str, ...] = ()
    started_at: datetime = field(default_factory=utc_now)
    ended_at: datetime | None = None
    source_ref: SourceRef | None = None
    tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Decision:
    id: str
    summary: str
    related_work_item_id: str | None = None
    meeting_id: str | None = None
    decided_at: datetime = field(default_factory=utc_now)
    source_ref: SourceRef | None = None
    tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ActionItem:
    id: str
    title: str
    status: str = "open"
    assignee_id: str | None = None
    due_at: datetime | None = None
    source_ref: SourceRef | None = None
    tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Person:
    id: str
    name: str
    handle: str | None = None
    email: str | None = None
    source_ref: SourceRef | None = None
    tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Team:
    id: str
    name: str
    description: str = ""
    source_ref: SourceRef | None = None
    tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Message:
    id: str
    body: str
    author_id: str | None = None
    channel_id: str | None = None
    sent_at: datetime = field(default_factory=utc_now)
    source_ref: SourceRef | None = None
    tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Recording:
    id: str
    title: str
    location: str = ""
    duration_seconds: int | None = None
    created_at: datetime = field(default_factory=utc_now)
    source_ref: SourceRef | None = None
    tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Attachment:
    id: str
    name: str
    location: str
    media_type: str | None = None
    size_bytes: int | None = None
    source_ref: SourceRef | None = None
    tags: tuple[str, ...] = ()


Entity: TypeAlias = (
    Service
    | WorkItem
    | Incident
    | Alert
    | Change
    | Runbook
    | Meeting
    | Decision
    | ActionItem
    | Person
    | Team
    | Message
    | Recording
    | Attachment
)


_ENTITY_KIND_BY_TYPE: dict[type[object], EntityKind] = {
    Service: EntityKind.SERVICE,
    WorkItem: EntityKind.WORK_ITEM,
    Incident: EntityKind.INCIDENT,
    Alert: EntityKind.ALERT,
    Change: EntityKind.CHANGE,
    Runbook: EntityKind.RUNBOOK,
    Meeting: EntityKind.MEETING,
    Decision: EntityKind.DECISION,
    ActionItem: EntityKind.ACTION_ITEM,
    Person: EntityKind.PERSON,
    Team: EntityKind.TEAM,
    Message: EntityKind.MESSAGE,
    Recording: EntityKind.RECORDING,
    Attachment: EntityKind.ATTACHMENT,
}


def entity_kind(entity: Entity) -> EntityKind:
    try:
        return _ENTITY_KIND_BY_TYPE[type(entity)]
    except KeyError as exc:
        raise TypeError(f"Unsupported entity type: {type(entity).__name__}") from exc


def entity_ref(entity: Entity) -> EntityRef:
    return EntityRef(entity_kind(entity), entity.id)
