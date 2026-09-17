# Observability providers

Threatline v1.0 keeps observability integration behind the provider registry so dashboard and alert sources can fail without taking down work or source-control context.

## Contract

Observability providers use `ProviderKind.OBSERVABILITY` and advertise only the capabilities they actually implement. The v1.0 baseline adds `READ_OBSERVABILITY_LINKS` for external dashboard/problem links. Providers may also contribute normalized `Alert` entities when the upstream system exposes active problems.

`ProviderRegistry.observability_links(service_id)` isolates provider failures in the same way as the existing normalized entity reads. Context snapshots and work-item investigations include the resulting links without making the core domain depend on a specific monitoring vendor.

## Grafana

The Grafana provider is link-first. It does not require Grafana API credentials and does not copy dashboard data into Threatline.

Configure a base URL and one or more dashboards. Dashboard entries support either:

- `uid|title` for a workspace-wide dashboard;
- `service_id|uid|title` for a dashboard tied to a normalized Threatline service.

When an investigation has a service ID, Threatline adds the configured dashboard time range and service variable to the Grafana URL. Global dashboards remain available alongside service-specific dashboards.

For the current v1.0 investigation surface, Grafana links are also projected as operational link cards through the existing runbook-card path. The provider still exposes the first-class observability-link contract so the UI can render a dedicated Observability section without changing provider behavior.

Example environment configuration:

```text
THREATLINE_PROVIDERS=demo,grafana
THREATLINE_GRAFANA_URL=https://grafana.example.com
THREATLINE_GRAFANA_DASHBOARDS=checkout-api|checkout-overview|Checkout Overview;fleet|Fleet Overview
THREATLINE_GRAFANA_ORG_ID=1
THREATLINE_GRAFANA_SERVICE_VARIABLE=service
```

Workspace configuration accepts the same values through the setup API. `dashboards` may also be a JSON list of objects with `uid`, `title`, and optional `service_id` fields.

## Zabbix

Zabbix support is optional. Threatline reads active problems through the JSON-RPC API and normalizes them into `Alert` entities. Severity, start time, source links, and Zabbix tags are retained. A configurable tag name, `service` by default, maps a Zabbix problem to a Threatline service ID so the alert can appear in the related investigation.

Example environment configuration:

```text
THREATLINE_PROVIDERS=demo,zabbix
THREATLINE_ZABBIX_URL=https://zabbix.example.com
THREATLINE_ZABBIX_TOKEN=replace-me
THREATLINE_ZABBIX_SERVICE_TAG=service
```

The API token is a secret. In workspace configuration it is stored in `secrets.json`, not the ordinary configuration document, and is represented by a boolean credential indicator in setup responses.

## Boundaries

The v1.0 observability baseline intentionally does not provide metric ingestion, time-series storage, alert acknowledgement, dashboard editing, hosted telemetry, or vendor-specific automation. Those capabilities can be added later behind explicit provider capabilities without changing the core investigation model.
