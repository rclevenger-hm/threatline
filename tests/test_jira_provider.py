from __future__ import annotations

import unittest
from typing import Any

from threatline.providers.base import HealthStatus, ProviderCapability
from threatline.providers.jira import JiraConfig, JiraProvider


class FakeJiraTransport:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def request(self, config, path, *, method="GET", query=None, payload=None):
        self.calls.append({"path": path, "method": method, "query": query, "payload": payload})
        if path == "/rest/api/2/myself":
            return {"displayName": "Taylor Example", "accountId": "acct-1", "name": "texample"}
        if path == "/rest/api/2/search":
            return {
                "total": 1,
                "issues": [
                    {
                        "key": "OPS-42",
                        "fields": {
                            "summary": "Checkout latency elevated",
                            "status": {"name": "Investigating"},
                            "priority": {"name": "High"},
                            "updated": "2026-09-16T09:30:00+00:00",
                            "labels": ["customer-impact", "payments"],
                        },
                    }
                ],
            }
        if path.endswith("/transitions") and method == "GET":
            return {"transitions": [{"id": "31", "name": "Resolve"}]}
        return {}


class JiraProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.transport = FakeJiraTransport()
        self.config = JiraConfig(
            base_url="https://jira.example.invalid",
            jql="project = OPS AND resolution IS EMPTY",
            bearer_token="secret",
        )
        self.provider = JiraProvider(self.config, self.transport)

    def test_health_reports_authenticated_identity(self) -> None:
        health = self.provider.health()
        self.assertEqual(health.status, HealthStatus.HEALTHY)
        self.assertIn("Taylor Example", health.message)

    def test_capabilities_include_explicit_work_item_writes(self) -> None:
        capabilities = self.provider.capabilities()
        self.assertIn(ProviderCapability.READ_WORK_ITEMS, capabilities)
        self.assertIn(ProviderCapability.COMMENT_WORK_ITEM, capabilities)
        self.assertIn(ProviderCapability.ASSIGN_WORK_ITEM, capabilities)
        self.assertIn(ProviderCapability.TRANSITION_WORK_ITEM, capabilities)

    def test_search_normalizes_issue(self) -> None:
        items = self.provider.work_items()
        self.assertEqual(len(items), 1)
        item = items[0]
        self.assertEqual(item.id, "OPS-42")
        self.assertEqual(item.title, "Checkout latency elevated")
        self.assertEqual(item.status, "Investigating")
        self.assertEqual(item.priority, "high")
        self.assertEqual(item.tags, ("customer-impact", "payments"))
        self.assertEqual(item.source_ref.url, "https://jira.example.invalid/browse/OPS-42")

    def test_comment_is_explicit_post(self) -> None:
        self.provider.comment("OPS-42", "Investigating connection saturation.")
        call = self.transport.calls[-1]
        self.assertEqual(call["method"], "POST")
        self.assertEqual(call["path"], "/rest/api/2/issue/OPS-42/comment")
        self.assertEqual(call["payload"]["body"], "Investigating connection saturation.")

    def test_assign_uses_cloud_account_id_when_available(self) -> None:
        self.provider.assign_to_current_user("OPS-42")
        call = self.transport.calls[-1]
        self.assertEqual(call["method"], "PUT")
        self.assertEqual(call["payload"], {"accountId": "acct-1"})

    def test_transitions_are_discovered_before_execution(self) -> None:
        transitions = self.provider.transitions("OPS-42")
        self.assertEqual(transitions, [{"id": "31", "name": "Resolve"}])
        self.provider.transition("OPS-42", "31")
        call = self.transport.calls[-1]
        self.assertEqual(call["method"], "POST")
        self.assertEqual(call["payload"], {"transition": {"id": "31"}})

    def test_unconfigured_provider_exposes_no_capabilities(self) -> None:
        provider = JiraProvider(JiraConfig(base_url="", jql=""), self.transport)
        self.assertEqual(provider.capabilities(), frozenset())
        self.assertEqual(provider.health().status, HealthStatus.UNCONFIGURED)
        self.assertEqual(provider.work_items(), [])


if __name__ == "__main__":
    unittest.main()
