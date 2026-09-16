# Threatline

Threatline is a local-first engineering operations workspace that connects work items, incidents, services, source changes, observability, runbooks, meetings, decisions, and handoffs into shared operational context.

> **Status:** early productization. The public repository starts with an organization-neutral core and demo provider while integrations are migrated behind provider interfaces.

## Why Threatline

Engineering context is usually split across ticketing systems, source control, dashboards, runbooks, incident calls, and chat history. Threatline is designed to connect those systems around the work itself so an engineer can answer questions like:

- What needs attention right now?
- What changed before this incident?
- Which service and team own it?
- Which runbook applies?
- What did the incident team decide?
- What does the next engineer need to know?

The goal is not to replace every system of record. Threatline starts as the context layer above them.

## Run locally

Requires Python 3.12+.

```bash
git clone https://github.com/rclevenger-hm/threatline.git
cd threatline
python -m threatline
```

Open <http://127.0.0.1:8080>.

The default demo provider requires no credentials and contains fictional operational data.

Docker is also supported:

```bash
docker compose up --build
```

Run the regression suite with:

```bash
python -m unittest discover -s tests -v
```

## Current baseline

The initial public baseline provides:

- a dependency-free local web runtime;
- normalized domain objects for work items, services, alerts, changes, meetings, decisions, and runbooks;
- provider interfaces that keep external systems out of core application logic;
- a demo provider so the product is immediately runnable without credentials;
- health and context APIs;
- a Today view demonstrating related operational context;
- Docker packaging;
- automated tests and CI;
- a product landing site under `site/` with GitHub Pages deployment configuration.

Existing Support Board functionality will be migrated incrementally rather than copied with organization-specific assumptions.

## Architecture

Threatline is built around explicit relationships between operational objects rather than around any one ticketing, source-control, observability, or communication vendor.

See [docs/architecture.md](docs/architecture.md).

The first provider migration target is Jira, followed by source/change/runbook context and observability.

## Security model

The default runtime binds to loopback only. Integrations should use the user's own permissions and keep credentials outside browser storage. Reading and correlating context may be automatic; external write actions remain explicit and user initiated.

## Early access

Threatline is looking for SRE, platform, DevOps, support, infrastructure, and other engineering-operations teams willing to test the product against real workflows.

[Request early access](https://github.com/rclevenger-hm/threatline/issues/new?template=early-access.yml)

The intended founding-team launch price is **$3.99 per active user per month**. Pricing and commercial capabilities are still subject to change before paid availability.

## Licensing

No open-source license has been selected yet. Until one is added, the repository is publicly viewable but all rights are reserved.
