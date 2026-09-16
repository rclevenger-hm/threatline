# Threatline v1.0 — two-week roadmap

Target: ship a coherent, organization-neutral engineering operations workspace in two weeks.

v1.0 proves one product loop:

**connect systems → see what needs attention → investigate with cross-system context → act explicitly → produce a handoff**

## In scope

- normalized context/domain model and typed relationship graph;
- provider SDK, capability discovery, health and configuration boundaries;
- Jira provider migrated from Support Board;
- GitHub/GitHub Enterprise provider migrated from Support Board;
- generic observability baseline with Grafana links and optional Zabbix support;
- Today, Queue and Investigation experiences;
- explicit guarded Jira write actions;
- Daily Notes and editable handoff generation;
- first-run workspace/provider setup without source edits;
- local-first security baseline, diagnostics, Docker packaging and CI;
- public documentation and product site aligned to shipped functionality.

## Deferred until after v1.0

- full Mortar integration beyond stable contracts;
- native chat/messaging;
- native engineering work system;
- enterprise SSO/SCIM/RBAC beyond architectural seams;
- hosted video/transcoding;
- managed SaaS control plane.

## Execution schedule

| Day | Focus | Exit condition |
| --- | --- | --- |
| 1 | Domain foundation | Entities, typed relationships, serialization, validation and graph queries tested |
| 2 | Provider platform | Registry, capabilities, health, configuration and provider isolation work |
| 3 | Jira provider | Real work items normalize from configurable Jira; supported writes remain explicit |
| 4 | GitHub provider | Changes, ownership, runbooks/docs and work-item references normalize |
| 5 | Today + Queue | First screen prioritizes attention; queue filters/sorts real normalized work |
| 6 | Investigation | One item shows cross-system context and operational timeline |
| 7 | Notes + Handoff | Product actions and notes produce an editable shift handoff |
| 8 | Onboarding | Fresh user can configure providers or enter demo mode without editing files |
| 9 | Observability | Generic dashboard/deep-link integration and optional Zabbix baseline work |
| 10 | UX polish | Navigation, responsive states, keyboard flow, errors and accessibility pass |
| 11 | Packaging | Docker/local launch, diagnostics, config migration and cross-platform audit |
| 12 | Security + docs | Threat model, redaction tests, architecture/provider docs and site update |
| 13 | Hardening | Regression/integration tests, realistic queue performance, fresh-install validation |
| 14 | Release candidate | Release blockers fixed, version/release notes complete, v1.0 candidate ready |

## v1.0 release gates

- Fresh checkout runs in demo mode in under five minutes.
- Jira and GitHub can be configured without modifying source.
- Core contains no company-specific assumptions.
- Provider failure does not take unrelated providers down.
- Today clearly answers what needs attention.
- Investigation provides useful Jira + GitHub context and observability context when configured.
- All supported external mutations require explicit user action.
- Handoff uses actual recorded activity and remains editable.
- Secrets do not appear in browser persistence, diagnostics, exports or logs.
- CI passes on supported Python versions.
- Public documentation clearly distinguishes shipped, experimental and planned capabilities.

Release-level tracking lives in GitHub issue #10. Long-term product epics are #1 through #9.