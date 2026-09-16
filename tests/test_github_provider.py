from __future__ import annotations

import base64
import unittest
from typing import Any

from threatline.context import ContextEngine
from threatline.domain import WorkItem
from threatline.providers.base import (
    HealthStatus,
    ProviderCapability,
    ProviderHealth,
    ProviderKind,
)
from threatline.providers.github import GitHubConfig, GitHubProvider
from threatline.providers.registry import ProviderRegistry


class FakeGitHubTransport:
    def request(self, config, path, *, query=None):
        if path == "/user":
            return {"login": "octo-example"}
        if path == "/repos/acme/payments/pulls":
            return [
                {
                    "number": 42,
                    "title": "OPS-42 reduce checkout contention",
                    "body": "Follow-up for OPS-42.",
                    "merged_at": "2026-09-16T09:00:00Z",
                    "merge_commit_sha": "merge-sha",
                    "html_url": "https://github.example/acme/payments/pull/42",
                    "user": {"login": "alex"},
                }
            ]
        if path == "/repos/acme/payments/commits":
            return [
                {
                    "sha": "commit-sha",
                    "html_url": "https://github.example/acme/payments/commit/commit-sha",
                    "author": {"login": "sam"},
                    "commit": {
                        "message": "DATA-88 tune consumer batch size",
                        "committer": {"date": "2026-09-16T08:00:00Z"},
                        "author": {"name": "Sam", "date": "2026-09-16T08:00:00Z"},
                    },
                }
            ]
        if path == "/repos/acme/payments":
            return {"default_branch": "main"}
        if path == "/repos/acme/payments/git/trees/main":
            return {
                "tree": [
                    {"type": "blob", "path": "docs/runbooks/checkout-latency.md"},
                    {"type": "blob", "path": "docs/architecture.md"},
                ]
            }
        if path == "/repos/acme/payments/contents/.github/CODEOWNERS":
            encoded = base64.b64encode(b"/src/payments/ @payments-team\n*.tf @platform-team\n").decode()
            return {"content": encoded}
        raise AssertionError(f"unexpected path: {path}")


class WorkStub:
    name = "work-stub"
    kind = ProviderKind.WORK

    def capabilities(self):
        return frozenset({ProviderCapability.READ_WORK_ITEMS})

    def health(self):
        return ProviderHealth(HealthStatus.HEALTHY, "ok")

    def work_items(self):
        return [WorkItem("OPS-42", "Checkout latency", "open")]

    def services(self): return []
    def alerts(self): return []
    def changes(self): return []
    def runbooks(self): return []
    def meetings(self): return []
    def decisions(self): return []


class GitHubProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = GitHubConfig(
            token="secret",
            repositories=("acme/payments",),
            api_url="https://github.example/api/v3",
            web_url="https://github.example",
        )
        self.provider = GitHubProvider(self.config, FakeGitHubTransport())

    def test_health_reports_authenticated_user(self) -> None:
        health = self.provider.health()
        self.assertEqual(health.status, HealthStatus.HEALTHY)
        self.assertIn("octo-example", health.message)

    def test_changes_include_pull_requests_commits_and_work_item_links(self) -> None:
        changes = self.provider.changes()
        self.assertEqual(len(changes), 2)
        by_tag = {change.tags[-1]: change for change in changes}
        self.assertEqual(by_tag["pull-request"].related_work_item_ids, ("OPS-42",))
        self.assertEqual(by_tag["commit"].related_work_item_ids, ("DATA-88",))

    def test_runbook_discovery_filters_general_docs(self) -> None:
        runbooks = self.provider.runbooks()
        self.assertEqual(len(runbooks), 1)
        self.assertEqual(runbooks[0].title, "Checkout Latency")
        self.assertIn("docs/runbooks/checkout-latency.md", runbooks[0].location)

    def test_codeowners_are_available_for_assignment_context(self) -> None:
        rules = self.provider.ownership("acme/payments")
        self.assertEqual(rules[0]["owners"], ["@payments-team"])
        self.assertEqual(rules[1]["pattern"], "*.tf")

    def test_related_change_is_visible_from_work_item_context(self) -> None:
        registry = ProviderRegistry([WorkStub(), self.provider])
        context = ContextEngine(registry).work_item_context("OPS-42")
        self.assertIsNotNone(context)
        assert context is not None
        self.assertEqual(len(context["changes"]), 1)
        self.assertEqual(context["changes"][0]["title"], "OPS-42 reduce checkout contention")

    def test_unconfigured_provider_is_safe(self) -> None:
        provider = GitHubProvider(GitHubConfig(token="", repositories=()), FakeGitHubTransport())
        self.assertEqual(provider.health().status, HealthStatus.UNCONFIGURED)
        self.assertEqual(provider.capabilities(), frozenset())
        self.assertEqual(provider.changes(), [])


if __name__ == "__main__":
    unittest.main()
