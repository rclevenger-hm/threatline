from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from threatline.runtime import ThreatlineRuntime
from threatline.settings import WorkspaceSettingsStore


class SettingsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = WorkspaceSettingsStore(Path(self.temp.name))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def connected_payload(self) -> dict[str, object]:
        return {
            "mode": "connected",
            "timezone": "UTC",
            "providers": ["jira", "github"],
            "jira": {
                "base_url": "https://jira.example.invalid",
                "jql": "project = OPS AND resolution IS EMPTY",
                "auth_mode": "bearer",
                "secret": "jira-secret",
                "verify_ssl": True,
            },
            "github": {
                "api_url": "https://github.example.invalid/api/v3",
                "web_url": "https://github.example.invalid",
                "repositories": "acme/payments, acme/platform",
                "token": "github-secret",
                "verify_ssl": True,
            },
        }

    def test_saved_status_redacts_credentials(self) -> None:
        settings, secrets = self.store.prepare(self.connected_payload())
        self.store.save(settings, secrets)
        status = self.store.public_status()
        rendered = repr(status)
        self.assertNotIn("jira-secret", rendered)
        self.assertNotIn("github-secret", rendered)
        self.assertTrue(status["jira"]["secret_configured"])
        self.assertTrue(status["github"]["token_configured"])
        self.assertEqual(status["github"]["repositories"], ["acme/payments", "acme/platform"])

    def test_secret_file_is_restrictive_where_supported(self) -> None:
        settings, secrets = self.store.prepare(self.connected_payload())
        self.store.save(settings, secrets)
        mode = stat.S_IMODE(self.store.secrets_path.stat().st_mode)
        if os.name == "posix":
            self.assertEqual(mode, 0o600)

    def test_runtime_rebuilds_providers_without_restart(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            runtime = ThreatlineRuntime(self.store)
            self.assertEqual([provider.name for provider in runtime.registry.providers()], ["demo"])
            status = runtime.save_setup(self.connected_payload())
        self.assertTrue(status["setup_complete"])
        self.assertFalse(status["needs_setup"])
        self.assertEqual([provider.name for provider in runtime.registry.providers()], ["jira", "github"])

    def test_demo_setup_requires_no_credentials(self) -> None:
        settings, secrets = self.store.prepare({"mode": "demo", "timezone": "UTC"})
        self.store.save(settings, secrets)
        self.assertTrue(self.store.configured)
        self.assertEqual(self.store.load_settings()["providers"], ["demo"])

    def test_invalid_timezone_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.store.prepare({"mode": "demo", "timezone": "Definitely/Not-A-Zone"})

    def test_environment_management_blocks_browser_save(self) -> None:
        with patch.dict(os.environ, {"THREATLINE_PROVIDERS": "demo"}, clear=True):
            runtime = ThreatlineRuntime(self.store)
            self.assertTrue(runtime.setup_status()["managed_by_environment"])
            with self.assertRaises(ValueError):
                runtime.save_setup({"mode": "demo", "timezone": "UTC"})


if __name__ == "__main__":
    unittest.main()
