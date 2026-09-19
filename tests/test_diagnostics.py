from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from threatline.config import WorkspaceConfigStore
from threatline.diagnostics import build_support_bundle, support_bundle_json
from threatline.journal import WorkspaceJournal
from threatline.providers.demo import DemoProvider
from threatline.providers.registry import ProviderRegistry


class DiagnosticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.store = WorkspaceConfigStore(root / "config")
        self.secret = "support-bundle-secret-value"
        self.store.upsert_workspace(
            name="Source workspace",
            providers={
                "github": {
                    "enabled": True,
                    "repositories": ["example/service"],
                    "api_url": "https://api.github.com",
                }
            },
            secrets={"github": {"token": self.secret}},
        )
        self.registry = ProviderRegistry([DemoProvider()])
        self.journal = WorkspaceJournal(root / "data" / "journal.json", timezone_name="UTC")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_support_bundle_contains_runtime_and_provider_diagnostics(self) -> None:
        bundle = build_support_bundle(self.store, self.registry, self.journal)
        self.assertEqual(bundle["bundle_version"], 1)
        self.assertEqual(bundle["application"]["name"], "Threatline")
        self.assertIn("python", bundle["runtime"])
        self.assertEqual(bundle["configuration"]["versions"]["current"], 1)
        self.assertEqual(bundle["providers"][0]["name"], "demo")

    def test_support_bundle_never_contains_stored_secret_values(self) -> None:
        encoded = support_bundle_json(self.store, self.registry, self.journal).decode("utf-8")
        self.assertNotIn(self.secret, encoded)
        payload = json.loads(encoded)
        provider_state = payload["configuration"]["state"]["workspaces"][0]["providers"]["github"]
        self.assertTrue(provider_state["credential_fields"]["token"])
        self.assertNotIn("secrets", json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
