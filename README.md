# Threatline

Threatline is a local-first engineering operations workspace that connects work items, incidents, services, source changes, observability, runbooks, meetings, decisions, and handoffs into shared operational context.

> **Status:** early productization. The public repository starts with an organization-neutral core and demo provider while integrations are migrated behind provider interfaces.

## Run locally

Requires Python 3.12+.

```bash
python -m threatline
```

Then open <http://127.0.0.1:8080>.

To run the checks:

```bash
python -m unittest discover -s tests -v
```

Docker is also supported:

```bash
docker compose up --build
```

## Current scope

The initial baseline provides:

- a dependency-free local web runtime;
- normalized domain objects for work items, services, alerts, changes, meetings, decisions, and runbooks;
- provider interfaces that keep external systems out of core application logic;
- a demo provider so the product is immediately runnable without credentials;
- health and context APIs;
- a small Today view showing how related operational context is assembled.

Existing Support Board functionality will be migrated incrementally rather than copied with organization-specific assumptions.

## Product direction

Threatline is intended to answer a simple question: **what context does an engineer need to understand and act on the work in front of them?**

The platform is designed around explicit relationships between operational objects rather than around any single ticketing, source-control, observability, or communication vendor.

## Security model

The default runtime binds to loopback only. Integrations should use the user's own permissions and keep credentials outside browser storage. External write actions will remain explicit and user initiated.

## Licensing

No open-source license has been selected yet. Until one is added, the repository remains publicly viewable but all rights are reserved.
