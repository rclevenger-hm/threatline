# Threatline product principles

Threatline should become valuable by reducing the cognitive and operational cost of engineering work, not by accumulating features.

## Primary product metric

**Time and context recovered per engineer per day.**

A feature should generally do at least one of the following:

1. reduce time spent reconstructing context;
2. reduce switching between tools;
3. make the next safe action clearer;
4. preserve a decision that would otherwise disappear;
5. improve handoff quality without requiring duplicate documentation;
6. make adoption or setup materially easier;
7. increase trust through privacy, provenance, or explicit control.

Features that do none of these should not displace higher-value work.

## Product rules

### Context before replacement

Threatline should connect existing systems before trying to replace them. Jira, GitHub, Grafana, ServiceNow, GitLab, and other systems can remain systems of record while Threatline provides the operational context layer above them.

### One investigation, many sources

Users should think in terms of a work item, incident, service, or change—not vendor tabs. Related alerts, code changes, runbooks, meetings, decisions, owners, and notes should converge around the object being investigated.

### Local-first is a capability, not a limitation

Community/local deployments should remain useful without a central cloud service. Team and enterprise modes may add collaboration and policy, but local operation should remain a first-class deployment model.

### Explicit writes

Reads and context assembly may be automatic. External mutations—comments, assignment, transitions, acknowledgements, deployments, or other production-affecting actions—must remain explicit and attributable.

### Preserve provenance

Summaries, correlations, and future model-assisted features must point back to source evidence. Derived context should accelerate understanding, never silently replace the record it came from.

### Fast first value

A stranger should be able to run demo mode in minutes. Connecting a real system should be guided and testable without editing source code. The product should prove usefulness before asking for broad permissions.

### Open integration surface

Vendor-specific logic belongs behind providers. The core domain model must remain independent from any one ticketing, source-control, observability, meeting, or communication vendor.

### Earn platform scope

Messaging, native work management, video, and enterprise collaboration should be added only when the existing operational context layer creates a clear reason for users to want them inside Threatline.

## v1.0 priority order

When schedule conflicts arise, protect these in order:

1. cross-system investigation context;
2. Today/Queue usefulness;
3. provider reliability and setup;
4. notes/handoff;
5. security and diagnostics;
6. polish;
7. optional breadth.

A narrower workflow that engineers rely on is more valuable than a broad suite they occasionally explore.
