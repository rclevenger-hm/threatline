# Threatline architecture

Threatline is being extracted as an organization-neutral product rather than published as a renamed copy of a company-specific support workspace.

## Principles

1. **Context first.** The core model represents engineering work and relationships, not vendor payloads.
2. **Providers translate.** Jira, GitHub, GitLab, Grafana, Zabbix, Mortar and future systems implement provider boundaries.
3. **Local first.** The default runtime binds to loopback and should remain useful without a hosted control plane.
4. **Explicit writes.** Reading and correlating context can be automatic; mutations of external systems require explicit user action.
5. **Progressive adoption.** Teams can start with existing systems of record and adopt native Threatline capabilities later.

## Core domain

The initial model contains `Service`, `WorkItem`, `Alert`, `Change`, `Runbook`, `Meeting`, and `Decision`. Additional objects should be introduced when a real workflow requires them.

New entity and relationship types must remain organization-neutral, preserve serialization compatibility, and keep vendor-specific payloads behind providers. See [domain extension rules](domain-extension-rules.md) for the registration, compatibility, provider-boundary, and validation contract.

## Provider boundary

`ContextProvider` supplies normalized objects to the `ContextEngine`. The demo provider proves the interface without credentials. The next provider should be Jira, migrated from Support Board after organization-specific assumptions are removed.

## Migration order

1. Jira read-only work-item provider.
2. GitHub source/change/runbook provider.
3. Observability provider.
4. Explicit provider write capabilities behind confirmation boundaries.
5. Mortar meeting and decision context.
