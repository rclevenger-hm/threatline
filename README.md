# Threatline

Threatline is a local-first engineering operations workspace that connects work items, incidents, services, source changes, observability, runbooks, meetings, decisions, and handoffs into shared operational context.

> **Status:** v1.0 release development. The public repository is organization-neutral and keeps external systems behind provider interfaces.

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

On first run, Threatline opens local workspace setup. Choose the demo provider for a zero-credential evaluation, or configure Jira, GitHub, Grafana, and optional Zabbix directly in the browser. Provider credentials are not stored in browser persistence.

Docker is also supported:

```bash
docker compose up --build
```

Run the regression suite with:

```bash
python -m unittest discover -s tests -v
```

## Current v1.0 baseline

The current release baseline provides:

- typed, versioned operational domain objects and context relationships;
- provider capability discovery, diagnostics, and failure isolation;
- Jira work-item normalization with explicit comment, assign, and transition capabilities;
- GitHub.com and GitHub Enterprise source context, related changes, ownership, and runbook discovery;
- organization-neutral observability links with service-scoped Grafana deep links and optional Zabbix active-problem normalization;
- deterministic Today attention ranking and a filterable Queue;
- an investigation workspace with operational timeline, dedicated observability links, and cross-provider context;
- local Daily Notes, activity capture, and editable handoff generation;
- first-run workspace setup, provider connection tests, saved workspace selection, and browser configuration for shipped providers;
- responsive primary navigation, keyboard navigation and command palette, provider-aware empty/error states, and accessibility-focused interaction semantics;
- a demo provider so the product is immediately runnable without credentials;
- Docker packaging, automated tests, CI, and a public product site.

Packaging diagnostics, security hardening, release documentation, and final release packaging remain in the v1.0 roadmap.

## Workspace configuration

Normal workspace settings are stored locally in `~/.threatline/config.json`. Provider credentials are kept in a separate `~/.threatline/secrets.json` file with owner-only permissions where supported. The setup API returns only ordinary settings and indicators that credential fields are populated; it does not return stored credential values.

Environment-based configuration remains supported for existing local deployments. See [docs/onboarding.md](docs/onboarding.md) for setup, navigation, and configuration and [docs/observability.md](docs/observability.md) for Grafana and Zabbix behavior.

## Architecture

Threatline is built around explicit relationships between operational objects rather than around any one ticketing, source-control, observability, or communication vendor.

See [docs/architecture.md](docs/architecture.md) for the system boundaries and [docs/domain-extension-rules.md](docs/domain-extension-rules.md) for the contract for adding new core entities and relationships without leaking provider-specific schemas into the domain model.

The next v1.0 milestone is packaging and diagnostics.

## Security model

The default runtime binds to loopback only. Integrations use the user's own permissions, credentials stay outside browser persistence, and stored provider secrets are separated from ordinary workspace configuration. Reading and correlating context may be automatic; external write actions remain explicit and user initiated.

## Early access

Threatline is looking for SRE, platform, DevOps, support, infrastructure, and other engineering-operations teams willing to test the product against real workflows.

[Request early access](https://github.com/rclevenger-hm/threatline/issues/new?template=early-access.yml)

The intended founding-team launch price is **$3.99 per active user per month**. Pricing and commercial capabilities are still subject to change before paid availability.

## Licensing

No open-source license has been selected yet. Until one is added, the repository is publicly viewable but all rights are reserved.
