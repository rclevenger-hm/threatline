from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from threatline.domain import Entity, EntityKind, EntityRef, Relationship, RelationshipKind, entity_ref


class ContextGraph:
    """In-memory typed relationship graph for normalized Threatline entities."""

    def __init__(
        self,
        entities: Iterable[Entity] = (),
        relationships: Iterable[Relationship] = (),
    ) -> None:
        self._entities: dict[EntityRef, Entity] = {}
        self._outgoing: dict[EntityRef, list[Relationship]] = defaultdict(list)
        self._incoming: dict[EntityRef, list[Relationship]] = defaultdict(list)
        for entity in entities:
            self.add_entity(entity)
        for relationship in relationships:
            self.add_relationship(relationship)

    def add_entity(self, entity: Entity) -> EntityRef:
        ref = entity_ref(entity)
        if not ref.id.strip():
            raise ValueError("Entity id cannot be blank")
        existing = self._entities.get(ref)
        if existing is not None and existing != entity:
            raise ValueError(f"Conflicting entity for {ref.kind}:{ref.id}")
        self._entities[ref] = entity
        return ref

    def add_relationship(self, relationship: Relationship) -> None:
        if relationship.source not in self._entities:
            raise ValueError(f"Unknown relationship source: {relationship.source}")
        if relationship.target not in self._entities:
            raise ValueError(f"Unknown relationship target: {relationship.target}")
        if relationship in self._outgoing[relationship.source]:
            return
        self._outgoing[relationship.source].append(relationship)
        self._incoming[relationship.target].append(relationship)

    def get(self, ref: EntityRef) -> Entity | None:
        return self._entities.get(ref)

    def entities(self, kind: EntityKind | None = None) -> list[Entity]:
        values = list(self._entities.values())
        if kind is None:
            return values
        return [entity for ref, entity in self._entities.items() if ref.kind == kind]

    def relationships_for(
        self,
        ref: EntityRef,
        *,
        kind: RelationshipKind | None = None,
        direction: str = "both",
    ) -> list[Relationship]:
        if direction not in {"out", "in", "both"}:
            raise ValueError("direction must be 'out', 'in', or 'both'")
        relationships: list[Relationship] = []
        if direction in {"out", "both"}:
            relationships.extend(self._outgoing.get(ref, ()))
        if direction in {"in", "both"}:
            relationships.extend(self._incoming.get(ref, ()))
        if kind is not None:
            relationships = [relationship for relationship in relationships if relationship.kind == kind]
        return relationships

    def related(
        self,
        ref: EntityRef,
        *,
        relationship_kind: RelationshipKind | None = None,
        entity_kind: EntityKind | None = None,
        direction: str = "both",
    ) -> list[Entity]:
        result: list[Entity] = []
        seen: set[EntityRef] = set()
        for relationship in self.relationships_for(ref, kind=relationship_kind, direction=direction):
            other = relationship.target if relationship.source == ref else relationship.source
            if other in seen or (entity_kind is not None and other.kind != entity_kind):
                continue
            entity = self._entities.get(other)
            if entity is not None:
                seen.add(other)
                result.append(entity)
        return result

    def all_relationships(self) -> list[Relationship]:
        return [relationship for values in self._outgoing.values() for relationship in values]
