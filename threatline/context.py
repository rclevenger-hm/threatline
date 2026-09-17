from __future__ import annotations

from typing import Any

from threatline.domain import (
    SCHEMA_VERSION,
    Alert,
    Change,
    Decision,
    EntityKind,
    EntityRef,
    Meeting,
    Relationship,
    RelationshipKind,
    Runbook,
    Service,
    WorkItem,
    entity_ref,
)
from threatline.graph import ContextGraph
from threatline.providers.base import ContextReader
from threatline.serialization import to_jsonable


class ContextEngine:
    def __init__(self, provider: ContextReader) -> None:
        self.provider = provider

    def snapshot(self) -> dict[str, Any]:
        services = self.provider.services()
        work_items = self.provider.work_items()
        alerts = self.provider.alerts()
        changes = self.provider.changes()
        runbooks = self.provider.runbooks()
        meetings = self.provider.meetings()
        decisions = self.provider.decisions()
        graph = self._build_graph(services, work_items, alerts, changes, runbooks, meetings, decisions)
        return {
            "schema_version": SCHEMA_VERSION,
            "provider": self.provider.name,
            "services": to_jsonable(services),
            "work_items": to_jsonable(work_items),
            "alerts": to_jsonable(alerts),
            "changes": to_jsonable(changes),
            "runbooks": to_jsonable(runbooks),
            "meetings": to_jsonable(meetings),
            "decisions": to_jsonable(decisions),
            "observability_links": to_jsonable(self._observability_links()),
            "relationships": to_jsonable(graph.all_relationships()),
        }

    def graph(self) -> ContextGraph:
        return self._build_graph(
            self.provider.services(),
            self.provider.work_items(),
            self.provider.alerts(),
            self.provider.changes(),
            self.provider.runbooks(),
            self.provider.meetings(),
            self.provider.decisions(),
        )

    def work_item_context(self, work_item_id: str) -> dict[str, Any] | None:
        graph = self.graph()
        ref = EntityRef(EntityKind.WORK_ITEM, work_item_id)
        work_item = graph.get(ref)
        if work_item is None:
            return None

        changes = graph.related(ref, entity_kind=EntityKind.CHANGE)
        runbooks = graph.related(ref, entity_kind=EntityKind.RUNBOOK)
        repo_tags = {
            tag
            for change in changes
            for tag in getattr(change, "tags", ())
            if tag.startswith("repo:")
        }
        if repo_tags:
            seen_runbooks = {getattr(runbook, "id", "") for runbook in runbooks}
            for candidate in graph.entities(EntityKind.RUNBOOK):
                candidate_tags = set(getattr(candidate, "tags", ()))
                candidate_id = getattr(candidate, "id", "")
                if candidate_id not in seen_runbooks and repo_tags & candidate_tags:
                    runbooks.append(candidate)
                    seen_runbooks.add(candidate_id)

        service_id = getattr(work_item, "service_id", None)
        return {
            "work_item": to_jsonable(work_item),
            "service": self._first_serialized(graph.related(ref, entity_kind=EntityKind.SERVICE)),
            "alerts": to_jsonable(graph.related(ref, entity_kind=EntityKind.ALERT)),
            "changes": to_jsonable(changes),
            "runbooks": to_jsonable(runbooks),
            "meetings": to_jsonable(graph.related(ref, entity_kind=EntityKind.MEETING)),
            "decisions": to_jsonable(graph.related(ref, entity_kind=EntityKind.DECISION)),
            "observability_links": to_jsonable(self._observability_links(service_id)),
            "relationships": to_jsonable(graph.relationships_for(ref)),
        }

    def _observability_links(self, service_id: str | None = None) -> list[Any]:
        loader = getattr(self.provider, "observability_links", None)
        if loader is None:
            return []
        try:
            values = loader(service_id)
        except Exception:
            return []
        return list(values) if values is not None else []

    @staticmethod
    def _first_serialized(values: list[Any]) -> Any:
        return to_jsonable(values[0]) if values else None

    @staticmethod
    def _build_graph(
        services: list[Service],
        work_items: list[WorkItem],
        alerts: list[Alert],
        changes: list[Change],
        runbooks: list[Runbook],
        meetings: list[Meeting],
        decisions: list[Decision],
    ) -> ContextGraph:
        graph = ContextGraph([*services, *work_items, *alerts, *changes, *runbooks, *meetings, *decisions])

        service_refs = {service.id: entity_ref(service) for service in services}
        work_refs = {item.id: entity_ref(item) for item in work_items}
        meeting_refs = {meeting.id: entity_ref(meeting) for meeting in meetings}

        for item in work_items:
            if item.service_id in service_refs:
                graph.add_relationship(Relationship(entity_ref(item), service_refs[item.service_id], RelationshipKind.BELONGS_TO))
        for alert in alerts:
            if alert.service_id in service_refs:
                graph.add_relationship(Relationship(entity_ref(alert), service_refs[alert.service_id], RelationshipKind.AFFECTS))
        for change in changes:
            if change.service_id in service_refs:
                graph.add_relationship(Relationship(entity_ref(change), service_refs[change.service_id], RelationshipKind.MODIFIES))
            for related_work_item_id in change.related_work_item_ids:
                if related_work_item_id in work_refs:
                    graph.add_relationship(Relationship(entity_ref(change), work_refs[related_work_item_id], RelationshipKind.REFERENCES))
        for runbook in runbooks:
            if runbook.service_id in service_refs:
                graph.add_relationship(Relationship(entity_ref(runbook), service_refs[runbook.service_id], RelationshipKind.DOCUMENTS))
        for meeting in meetings:
            for related_work_item_id in meeting.related_work_item_ids:
                if related_work_item_id in work_refs:
                    graph.add_relationship(Relationship(entity_ref(meeting), work_refs[related_work_item_id], RelationshipKind.DISCUSSES))
        for decision in decisions:
            if decision.related_work_item_id in work_refs:
                graph.add_relationship(Relationship(entity_ref(decision), work_refs[decision.related_work_item_id], RelationshipKind.RELATES_TO))
            if decision.meeting_id in meeting_refs:
                graph.add_relationship(Relationship(meeting_refs[decision.meeting_id], entity_ref(decision), RelationshipKind.RECORDS))

        for item in work_items:
            if item.service_id is None:
                continue
            item_ref = entity_ref(item)
            for alert in alerts:
                if alert.service_id == item.service_id:
                    graph.add_relationship(Relationship(item_ref, entity_ref(alert), RelationshipKind.RELATES_TO))
            for change in changes:
                if change.service_id == item.service_id:
                    graph.add_relationship(Relationship(item_ref, entity_ref(change), RelationshipKind.RELATES_TO))
            for runbook in runbooks:
                if runbook.service_id == item.service_id:
                    graph.add_relationship(Relationship(item_ref, entity_ref(runbook), RelationshipKind.RELATES_TO))

        return graph
