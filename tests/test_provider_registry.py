from __future__ import annotations

import unittest

from threatline.domain import Service
from threatline.providers.base import (
    HealthStatus,
    ProviderCapability,
    ProviderHealth,
    ProviderKind,
)
from threatline.providers.demo import DemoProvider
from threatline.providers.registry import ProviderRegistry


class FailingProvider:
    name = "broken"
    kind = ProviderKind.WORK

    def capabilities(self) -> frozenset[ProviderCapability]:
        return frozenset({ProviderCapability.READ_SERVICES})

    def health(self) -> ProviderHealth:
        raise RuntimeError("provider unavailable")

    def services(self) -> list[Service]:
        raise RuntimeError("read failed")

    def work_items(self): return []
    def alerts(self): return []
    def changes(self): return []
    def runbooks(self): return []
    def meetings(self): return []
    def decisions(self): return []


class ProviderRegistryTests(unittest.TestCase):
    def test_collects_capability_data_from_registered_provider(self) -> None:
        registry = ProviderRegistry([DemoProvider()])
        self.assertGreaterEqual(len(registry.services()), 1)
        self.assertGreaterEqual(len(registry.work_items()), 1)

    def test_provider_failure_does_not_block_other_providers(self) -> None:
        registry = ProviderRegistry([FailingProvider(), DemoProvider()])
        services = registry.services()
        self.assertTrue(any(service.id == "checkout-api" for service in services))

    def test_diagnostics_report_failed_provider_without_raising(self) -> None:
        registry = ProviderRegistry([FailingProvider(), DemoProvider()])
        diagnostics = {item.name: item for item in registry.diagnostics()}
        self.assertEqual(diagnostics["broken"].health.status, HealthStatus.UNAVAILABLE)
        self.assertEqual(diagnostics["demo"].health.status, HealthStatus.HEALTHY)

    def test_duplicate_name_is_rejected(self) -> None:
        registry = ProviderRegistry([DemoProvider()])
        with self.assertRaises(ValueError):
            registry.register(DemoProvider())


if __name__ == "__main__":
    unittest.main()
