from __future__ import annotations

import unittest
from datetime import datetime, timezone

from threatline.domain import (
    EntityKind,
    EntityRef,
    Relationship,
    RelationshipKind,
    Service,
    SourceRef,
    WorkItem,
    entity_ref,
)
from threatline.graph import ContextGraph
from threatline.serialization import entity_from_dict, to_jsonable


class DomainTests(unittest.TestCase):
    def test_entity_round_trip_preserves_nested_source_ref(self) -> None:
        item = WorkItem(
            id="OPS-1",
            title="Example",
            status="open",
            updated_at=datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc),
            source_ref=SourceRef("jira", "OPS-1", "https://example.invalid/browse/OPS-1"),
            tags=("customer-impact", "payments"),
        )
        encoded = to_jsonable(item)
        decoded = entity_from_dict(EntityKind.WORK_ITEM, encoded)
        self.assertEqual(decoded, item)

    def test_graph_rejects_relationship_to_unknown_entity(self) -> None:
        service = Service("svc", "Service")
        graph = ContextGraph([service])
        relationship = Relationship(
            entity_ref(service),
            EntityRef(EntityKind.WORK_ITEM, "missing"),
            RelationshipKind.RELATES_TO,
        )
        with self.assertRaises(ValueError):
            graph.add_relationship(relationship)

    def test_graph_returns_related_entity(self) -> None:
        service = Service("svc", "Service")
        item = WorkItem("OPS-1", "Example", "open", service_id="svc")
        relationship = Relationship(entity_ref(item), entity_ref(service), RelationshipKind.BELONGS_TO)
        graph = ContextGraph([service, item], [relationship])
        related = graph.related(
            entity_ref(item),
            relationship_kind=RelationshipKind.BELONGS_TO,
            entity_kind=EntityKind.SERVICE,
        )
        self.assertEqual(related, [service])


if __name__ == "__main__":
    unittest.main()
