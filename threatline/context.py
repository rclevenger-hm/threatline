from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from enum import Enum
from typing import Any

from threatline.providers.base import ContextProvider


class ContextEngine:
    def __init__(self, provider: ContextProvider) -> None:
        self.provider = provider

    def snapshot(self) -> dict[str, Any]:
        return {
            "provider": self.provider.name,
            "services": self._serialize(self.provider.services()),
            "work_items": self._serialize(self.provider.work_items()),
            "alerts": self._serialize(self.provider.alerts()),
            "changes": self._serialize(self.provider.changes()),
            "runbooks": self._serialize(self.provider.runbooks()),
            "meetings": self._serialize(self.provider.meetings()),
            "decisions": self._serialize(self.provider.decisions()),
        }

    def work_item_context(self, work_item_id: str) -> dict[str, Any] | None:
        work_item = next((item for item in self.provider.work_items() if item.id == work_item_id), None)
        if work_item is None:
            return None
        service_id = work_item.service_id
        return {
            "work_item": self._serialize_one(work_item),
            "service": self._serialize_one(next((service for service in self.provider.services() if service.id == service_id), None)),
            "alerts": self._serialize([item for item in self.provider.alerts() if item.service_id == service_id]),
            "changes": self._serialize([item for item in self.provider.changes() if item.service_id == service_id]),
            "runbooks": self._serialize([item for item in self.provider.runbooks() if item.service_id == service_id]),
            "meetings": self._serialize([item for item in self.provider.meetings() if work_item_id in item.related_work_item_ids]),
            "decisions": self._serialize([item for item in self.provider.decisions() if item.related_work_item_id == work_item_id]),
        }

    @classmethod
    def _serialize(cls, values: list[Any]) -> list[dict[str, Any]]:
        return [cls._serialize_one(value) for value in values]

    @classmethod
    def _serialize_one(cls, value: Any) -> Any:
        if value is None:
            return None
        data = asdict(value)
        for key, item in data.items():
            if isinstance(item, datetime):
                data[key] = item.isoformat()
            elif isinstance(item, Enum):
                data[key] = item.value
            elif isinstance(item, tuple):
                data[key] = list(item)
        return data
