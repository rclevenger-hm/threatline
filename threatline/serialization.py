from __future__ import annotations

from dataclasses import fields, is_dataclass
from datetime import datetime
from enum import Enum
from types import UnionType
from typing import Any, get_args, get_origin, get_type_hints

from threatline.domain import (
    ActionItem,
    Alert,
    Attachment,
    Change,
    Decision,
    Entity,
    EntityKind,
    Incident,
    Meeting,
    Message,
    Person,
    Recording,
    Runbook,
    Service,
    Team,
    WorkItem,
)

_ENTITY_TYPES: dict[EntityKind, type[Entity]] = {
    EntityKind.SERVICE: Service,
    EntityKind.WORK_ITEM: WorkItem,
    EntityKind.INCIDENT: Incident,
    EntityKind.ALERT: Alert,
    EntityKind.CHANGE: Change,
    EntityKind.RUNBOOK: Runbook,
    EntityKind.MEETING: Meeting,
    EntityKind.DECISION: Decision,
    EntityKind.ACTION_ITEM: ActionItem,
    EntityKind.PERSON: Person,
    EntityKind.TEAM: Team,
    EntityKind.MESSAGE: Message,
    EntityKind.RECORDING: Recording,
    EntityKind.ATTACHMENT: Attachment,
}


def to_jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {field.name: to_jsonable(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, dict):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(item) for item in value]
    raise TypeError(f"Cannot serialize {type(value).__name__}")


def dataclass_from_dict(cls: type[Any], data: dict[str, Any]) -> Any:
    if not is_dataclass(cls):
        raise TypeError(f"{cls!r} is not a dataclass type")
    hints = get_type_hints(cls)
    kwargs: dict[str, Any] = {}
    for field in fields(cls):
        if field.name in data:
            kwargs[field.name] = _coerce(hints.get(field.name, Any), data[field.name])
    return cls(**kwargs)


def entity_from_dict(kind: EntityKind | str, data: dict[str, Any]) -> Entity:
    entity_kind = EntityKind(kind)
    return dataclass_from_dict(_ENTITY_TYPES[entity_kind], data)


def _coerce(annotation: Any, value: Any) -> Any:
    if value is None:
        return None
    if annotation is Any:
        return value
    if annotation is datetime:
        return datetime.fromisoformat(value)
    if isinstance(annotation, type) and issubclass(annotation, Enum):
        return annotation(value)
    if isinstance(annotation, type) and is_dataclass(annotation):
        return dataclass_from_dict(annotation, value)

    origin = get_origin(annotation)
    args = get_args(annotation)

    if origin is tuple:
        item_type = args[0] if args else Any
        return tuple(_coerce(item_type, item) for item in value)
    if origin is list:
        item_type = args[0] if args else Any
        return [_coerce(item_type, item) for item in value]
    if origin is dict:
        key_type = args[0] if args else Any
        value_type = args[1] if len(args) > 1 else Any
        return {_coerce(key_type, key): _coerce(value_type, item) for key, item in value.items()}
    if origin in (UnionType, None) and isinstance(annotation, UnionType):
        for option in args:
            if option is type(None):
                continue
            try:
                return _coerce(option, value)
            except (TypeError, ValueError):
                continue
        return value

    return value
