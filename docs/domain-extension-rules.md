# Domain extension rules

Threatline's domain model is intentionally small and organization-neutral. New entity and relationship types should be added only when a real operational workflow cannot be represented cleanly with the existing model.

These rules keep the context graph stable as providers and product surfaces grow.

## When to add a new entity

Add a new entity type only when the object has an identity and lifecycle of its own and users need to relate it to other operational context.

Before adding one, check whether the concept is better represented as:

- a field on an existing entity;
- a `SourceRef` that points back to the system of record;
- a tag or provider-specific attribute kept outside the core model; or
- a relationship between existing entities.

Vendor payload shapes are not a reason to expand the core. Providers translate vendor-specific records into the smallest useful Threatline representation.

## Entity contract

A core entity should:

1. use a stable string `id` that is unique within its normalized entity kind;
2. use `SourceRef` when an external system is authoritative for the record;
3. use timezone-aware `datetime` values for timestamps;
4. prefer immutable tuple fields for repeated values, matching the existing frozen dataclass model;
5. keep vendor-specific identifiers, enums, and nested payloads out of the core type;
6. use optional fields for information that is not universally available across providers; and
7. remain serializable with the shared serialization helpers.

A new entity must be wired through all of the core registration points in one change:

- add its value to `EntityKind`;
- add the frozen dataclass in `threatline/domain.py`;
- add it to the `Entity` type alias;
- register it in `_ENTITY_KIND_BY_TYPE`;
- register it in `_ENTITY_TYPES` in `threatline/serialization.py`; and
- add round-trip and invalid-input regression coverage.

Do not make provider code depend on an unregistered entity type. Unsupported types are intentionally rejected by `entity_kind()` rather than silently entering the graph.

## Relationship contract

Prefer an existing `RelationshipKind` when it communicates the operational meaning without ambiguity. Add a new relationship kind only when the distinction changes how a user would navigate, investigate, or act on the graph.

Relationships should:

- point to stable `EntityRef` values rather than embedding entities;
- describe durable operational meaning rather than UI placement;
- remain directional when direction conveys meaning (`caused_by`, `resolved_by`, `assigned_to`);
- use `relates_to` only when no stronger relationship is known; and
- keep small source-neutral metadata in `attributes` rather than provider payloads.

Provider-specific relationship details belong in the provider or source record unless the same concept is meaningful across multiple systems.

## Compatibility and schema versioning

`SCHEMA_VERSION` represents the serialized domain contract. Backward-compatible additions do not automatically require a schema bump, but a change that makes previously valid serialized data invalid, changes the meaning of an existing field, renames/removes a field or enum value, or requires migration must increment the schema version and include an explicit compatibility path.

When extending an existing dataclass, prefer a new field with a safe default so older serialized records can still be loaded. Do not repurpose an existing field for a new meaning.

## Provider boundary

Providers are adapters, not extensions of the domain vocabulary. A provider should normalize only the fields Threatline needs for cross-system context and retain a `SourceRef` for evidence and drill-through.

Before promoting provider data into the core model, require at least one of these conditions:

- more than one provider needs the concept;
- the concept participates in cross-provider relationships;
- the concept is required by a vendor-neutral product workflow; or
- keeping it provider-local would make handoff, investigation, or audit context materially incomplete.

Credentials, raw API responses, opaque authentication state, and provider-specific configuration never belong in domain entities.

## Required validation for a new entity or relationship

A domain extension is complete only when tests demonstrate:

- construction and validation of the new type;
- `entity_kind()` and `entity_ref()` behavior;
- JSON-compatible serialization and deserialization round-trip;
- graph insertion and relationship lookup where applicable;
- rejection or safe handling of invalid references; and
- compatibility with existing serialized fixtures when the schema version is unchanged.

If a new type is exposed through an API or UI, add boundary tests there as a separate layer rather than weakening the core-domain tests.

## Review checklist

Before merging a domain extension, a reviewer should be able to answer yes to all of the following:

- Is this concept organization-neutral?
- Does it have independent identity or relationship value?
- Could an existing entity, source reference, field, tag, or relationship represent it instead?
- Are vendor-specific details still isolated behind providers?
- Is the serialization contract explicit and tested?
- Is schema compatibility preserved or deliberately migrated?
- Can the new object participate in context without requiring one specific provider?

If any answer is unclear, keep the concept at the provider boundary until the cross-system need is better understood.
