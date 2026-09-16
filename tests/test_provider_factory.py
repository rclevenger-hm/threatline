from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from threatline.providers.factory import build_registry_from_env, configured_provider_names


class ProviderFactoryTests(unittest.TestCase):
    def test_demo_is_default_provider(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(configured_provider_names(), ("demo",))
            registry = build_registry_from_env()
        self.assertEqual([provider.name for provider in registry.providers()], ["demo"])

    def test_multiple_provider_names_are_deduplicated(self) -> None:
        with patch.dict(os.environ, {"THREATLINE_PROVIDERS": "demo,jira,demo"}, clear=True):
            self.assertEqual(configured_provider_names(), ("demo", "jira"))
            registry = build_registry_from_env()
        self.assertEqual([provider.name for provider in registry.providers()], ["demo", "jira"])

    def test_github_can_be_registered_with_jira(self) -> None:
        with patch.dict(os.environ, {"THREATLINE_PROVIDERS": "jira,github"}, clear=True):
            registry = build_registry_from_env()
        self.assertEqual([provider.name for provider in registry.providers()], ["jira", "github"])

    def test_unknown_provider_is_rejected(self) -> None:
        with patch.dict(os.environ, {"THREATLINE_PROVIDERS": "demo,unknown"}, clear=True):
            with self.assertRaises(ValueError):
                build_registry_from_env()


if __name__ == "__main__":
    unittest.main()
