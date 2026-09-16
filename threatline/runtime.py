from __future__ import annotations

from pathlib import Path
from typing import Any

from threatline.context import ContextEngine
from threatline.journal import WorkspaceJournal
from threatline.providers.factory import (
    build_registry_from_env,
    build_registry_from_settings,
    environment_managed,
)
from threatline.providers.registry import ProviderRegistry
from threatline.settings import WorkspaceSettingsStore


class ThreatlineRuntime:
    """Owns reloadable local configuration and provider state."""

    def __init__(self, settings_store: WorkspaceSettingsStore | None = None) -> None:
        self.settings_store = settings_store or WorkspaceSettingsStore()
        self.managed_by_environment = environment_managed()
        self.registry: ProviderRegistry
        self.engine: ContextEngine
        self.journal: WorkspaceJournal
        self.reload()

    def reload(self) -> None:
        settings = self.settings_store.load_settings()
        if self.managed_by_environment:
            self.registry = build_registry_from_env()
            timezone_name = str(settings.get("timezone") or "UTC")
        else:
            self.registry = build_registry_from_settings(settings, self.settings_store.load_secrets())
            timezone_name = str(settings.get("timezone") or "UTC")
        self.engine = ContextEngine(self.registry)
        self.journal = WorkspaceJournal(
            Path(self.settings_store.data_dir) / "journal.json",
            timezone_name=timezone_name,
        )

    def setup_status(self) -> dict[str, Any]:
        status = self.settings_store.public_status(managed_by_environment=self.managed_by_environment)
        if self.managed_by_environment:
            status["setup_complete"] = True
            status["needs_setup"] = False
            status["providers"] = [provider.name for provider in self.registry.providers()]
        return status

    def test_setup(self, payload: dict[str, Any]):
        if self.managed_by_environment:
            raise ValueError("workspace configuration is managed by environment variables")
        settings, secrets = self.settings_store.prepare(payload)
        registry = build_registry_from_settings(settings, secrets)
        return registry.diagnostics()

    def save_setup(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.managed_by_environment:
            raise ValueError("workspace configuration is managed by environment variables")
        settings, secrets = self.settings_store.prepare(payload)
        self.settings_store.save(settings, secrets)
        self.reload()
        return self.setup_status()
