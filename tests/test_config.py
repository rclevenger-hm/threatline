from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from threatline.config import WorkspaceConfigStore
from threatline.providers.factory import build_registry


class WorkspaceConfigStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = WorkspaceConfigStore(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_demo_workspace_is_zero_credential_and_active(self) -> None:
        workspace = self.store.upsert_workspace(
            name="Demo operations",
            providers={"demo": {"enabled": True}},
            secrets={},
        )
        self.assertEqual(workspace.id, "demo-operations")
        self.assertEqual(self.store.active_workspace().name, "Demo operations")
        registry = build_registry(self.store)
        self.assertEqual([provider.name for provider in registry.providers()], ["demo"])
        self.assertEqual(registry.diagnostics()[0].health.status.value, "healthy")

    def test_provider_secrets_are_separate_and_never_returned(self) -> None:
        token = "github-secret-value"
        api_token = "jira-secret-value"
        self.store.upsert_workspace(
            name="Production",
            providers={
                "jira": {
                    "enabled": True,
                    "base_url": "https://jira.example.com",
                    "jql": "project = OPS",
                    "email": "operator@example.com",
                },
                "github": {
                    "enabled": True,
                    "repositories": "example/service, example/runbooks",
                },
            },
            secrets={"jira": {"api_token": api_token}, "github": {"token": token}},
        )
        public = self.store.public_state()
        encoded_public = json.dumps(public)
        self.assertNotIn(token, encoded_public)
        self.assertNotIn(api_token, encoded_public)
        providers = public["workspaces"][0]["providers"]
        self.assertTrue(providers["jira"]["credential_fields"]["api_token"])
        self.assertTrue(providers["github"]["credential_fields"]["token"])
        self.assertEqual(providers["github"]["repositories"], ["example/service", "example/runbooks"])

        active = self.store.active_workspace()
        self.assertEqual(active.secrets["github"]["token"], token)
        self.assertEqual(active.secrets["jira"]["api_token"], api_token)
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(self.store.secrets_path.stat().st_mode), 0o600)

    def test_blank_secret_updates_preserve_existing_credential(self) -> None:
        self.store.upsert_workspace(
            name="Production",
            providers={"github": {"enabled": True, "repositories": ["example/service"]}},
            secrets={"github": {"token": "keep-me"}},
        )
        self.store.upsert_workspace(
            workspace_id="production",
            name="Production",
            providers={"github": {"enabled": True, "repositories": ["example/service", "example/worker"]}},
            secrets={"github": {"token": ""}},
        )
        active = self.store.active_workspace()
        self.assertEqual(active.secrets["github"]["token"], "keep-me")
        self.assertEqual(active.providers["github"]["repositories"], ["example/service", "example/worker"])

    def test_workspace_activation_switches_provider_registry(self) -> None:
        self.store.upsert_workspace(name="Demo", providers={"demo": {"enabled": True}}, secrets={})
        self.store.upsert_workspace(
            name="Source only",
            providers={"github": {"enabled": True, "repositories": ["example/service"]}},
            secrets={"github": {"token": "token"}},
        )
        self.store.activate("demo")
        self.assertEqual([provider.name for provider in build_registry(self.store).providers()], ["demo"])
        self.store.activate("source-only")
        self.assertEqual([provider.name for provider in build_registry(self.store).providers()], ["github"])


if __name__ == "__main__":
    unittest.main()
