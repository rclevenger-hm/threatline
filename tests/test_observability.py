from __future__ import annotations

import unittest
from typing import Any

from threatline.context import ContextEngine
from threatline.domain import Severity
from threatline.providers.base import ProviderCapability
from threatline.providers.demo import DemoProvider
from threatline.providers.factory import build_provider
from threatline.providers.observability import GrafanaConfig, GrafanaDashboard, GrafanaProvider
from threatline.providers.registry import ProviderRegistry
from threatline.providers.zabbix import ZabbixConfig, ZabbixProvider


class FakeZabbixTransport:
    def __init__(self, problems: list[dict[str, Any]]) -> None:
        self.problems = problems
        self.requests: list[tuple[str, dict[str, Any]]] = []

    def request(self, config: ZabbixConfig, method: str, params: dict[str, Any]) -> Any:
        self.requests.append((method, params))
        if method == "problem.get":
            if params.get("limit") == 1 and params.get("output") == ["eventid"]:
                return self.problems[:1]
            return self.problems
        raise AssertionError(f"Unexpected method: {method}")


class BrokenObservabilityProvider:
    name = "broken-observability"
    kind = "observability"

    def capabilities(self):
        return frozenset({ProviderCapability.READ_OBSERVABILITY_LINKS})

    def observability_links(self, service_id=None):
        raise RuntimeError("broken")

    def health(self):
        raise RuntimeError("broken")

    def services(self): return []
    def work_items(self): return []
    def alerts(self): return []
    def changes(self): return []
    def runbooks(self): return []
    def meetings(self): return []
    def decisions(self): return []


class ObservabilityTests(unittest.TestCase):
    def test_grafana_builds_service_scoped_deep_links(self) -> None:
        provider = GrafanaProvider(
            GrafanaConfig(
                base_url="https://grafana.example.com",
                dashboards=(
                    GrafanaDashboard("checkout-uid", "Checkout Overview", "checkout-api"),
                    GrafanaDashboard("global-uid", "Fleet Overview"),
                    GrafanaDashboard("data-uid", "Data Overview", "event-pipeline"),
                ),
                org_id="2",
                service_variable="service",
                default_from="now-2h",
                default_to="now",
            )
        )

        self.assertIn(ProviderCapability.READ_OBSERVABILITY_LINKS, provider.capabilities())
        links = provider.observability_links("checkout-api")
        self.assertEqual([link.title for link in links], ["Checkout Overview", "Fleet Overview"])
        self.assertIn("orgId=2", links[0].url)
        self.assertIn("from=now-2h", links[0].url)
        self.assertIn("var-service=checkout-api", links[0].url)
        self.assertNotIn("data-uid", " ".join(link.url for link in links))

    def test_grafana_links_are_reachable_from_demo_investigation(self) -> None:
        grafana = GrafanaProvider(
            GrafanaConfig(
                base_url="https://grafana.example.com",
                dashboards=(GrafanaDashboard("checkout-uid", "Checkout Overview", "checkout-api"),),
            )
        )
        engine = ContextEngine(ProviderRegistry([DemoProvider(), grafana]))

        context = engine.work_item_context("OPS-142")

        self.assertIsNotNone(context)
        assert context is not None
        self.assertEqual(context["observability_links"][0]["provider"], "grafana")
        dashboard_runbooks = [item for item in context["runbooks"] if item["id"] == "grafana:checkout-uid"]
        self.assertEqual(len(dashboard_runbooks), 1)
        self.assertTrue(dashboard_runbooks[0]["location"].startswith("https://grafana.example.com/d/checkout-uid/"))

    def test_registry_isolates_broken_observability_provider(self) -> None:
        grafana = GrafanaProvider(
            GrafanaConfig(
                base_url="https://grafana.example.com",
                dashboards=(GrafanaDashboard("fleet", "Fleet"),),
            )
        )
        registry = ProviderRegistry([BrokenObservabilityProvider(), grafana])

        links = registry.observability_links()

        self.assertEqual([link.id for link in links], ["grafana:fleet"])

    def test_zabbix_normalizes_active_problems(self) -> None:
        transport = FakeZabbixTransport(
            [
                {
                    "eventid": "4201",
                    "objectid": "99",
                    "name": "Checkout latency high",
                    "severity": "4",
                    "clock": "1700000000",
                    "tags": [
                        {"tag": "service", "value": "checkout-api"},
                        {"tag": "env", "value": "prod"},
                    ],
                }
            ]
        )
        provider = ZabbixProvider(
            ZabbixConfig("https://zabbix.example.com", "secret-token", service_tag="service"),
            transport,
        )

        self.assertEqual(provider.health().status.value, "healthy")
        alerts = provider.alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, Severity.HIGH)
        self.assertEqual(alerts[0].service_id, "checkout-api")
        self.assertEqual(alerts[0].source_ref.external_id, "4201")
        self.assertIn("eventid=4201", alerts[0].source_ref.url or "")
        self.assertIn("env:prod", alerts[0].tags)

    def test_factory_builds_workspace_observability_providers(self) -> None:
        grafana = build_provider(
            "grafana",
            {
                "base_url": "https://grafana.example.com",
                "dashboards": [{"uid": "fleet", "title": "Fleet Overview"}],
            },
            {},
        )
        zabbix = build_provider(
            "zabbix",
            {"base_url": "https://zabbix.example.com", "service_tag": "app"},
            {"api_token": "token"},
        )

        self.assertEqual(grafana.name, "grafana")
        self.assertEqual(grafana.observability_links()[0].title, "Fleet Overview")
        self.assertEqual(zabbix.name, "zabbix")
        self.assertEqual(zabbix.config.service_tag, "app")
        self.assertEqual(zabbix.config.api_token, "token")


if __name__ == "__main__":
    unittest.main()
