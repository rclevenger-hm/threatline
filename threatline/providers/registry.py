from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, TypeVar

from threatline.domain import Alert, Change, Decision, Meeting, Runbook, Service, WorkItem
from threatline.providers.base import (
    ContextProvider,
    HealthStatus,
    ProviderCapability,
    ProviderHealth,
    ProviderKind,
)

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class ProviderDiagnostic:
    name: str
    kind: ProviderKind
    health: ProviderHealth
    capabilities: tuple[ProviderCapability, ...]


class ProviderRegistry:
    """Registry that isolates provider failures and exposes normalized reads."""

    name = "workspace"

    def __init__(self, providers: list[ContextProvider] | None = None) -> None:
        self._providers: dict[str, ContextProvider] = {}
        for provider in providers or []:
            self.register(provider)

    def register(self, provider: ContextProvider) -> None:
        if not provider.name.strip():
            raise ValueError("Provider name cannot be blank")
        if provider.name in self._providers and self._providers[provider.name] is not provider:
            raise ValueError(f"Provider already registered: {provider.name}")
        self._providers[provider.name] = provider

    def unregister(self, name: str) -> None:
        self._providers.pop(name, None)

    def get(self, name: str) -> ContextProvider | None:
        return self._providers.get(name)

    def providers(self) -> list[ContextProvider]:
        return list(self._providers.values())

    def diagnostics(self) -> list[ProviderDiagnostic]:
        diagnostics: list[ProviderDiagnostic] = []
        for provider in self.providers():
            try:
                health = provider.health()
            except Exception as exc:  # isolate provider-specific failures
                health = ProviderHealth(HealthStatus.UNAVAILABLE, str(exc))
            try:
                capabilities = tuple(sorted(provider.capabilities(), key=lambda item: item.value))
            except Exception:
                capabilities = ()
            diagnostics.append(ProviderDiagnostic(provider.name, provider.kind, health, capabilities))
        return diagnostics

    def services(self) -> list[Service]:
        return self._collect(ProviderCapability.READ_SERVICES, lambda provider: provider.services())

    def work_items(self) -> list[WorkItem]:
        return self._collect(ProviderCapability.READ_WORK_ITEMS, lambda provider: provider.work_items())

    def alerts(self) -> list[Alert]:
        return self._collect(ProviderCapability.READ_ALERTS, lambda provider: provider.alerts())

    def changes(self) -> list[Change]:
        return self._collect(ProviderCapability.READ_CHANGES, lambda provider: provider.changes())

    def runbooks(self) -> list[Runbook]:
        return self._collect(ProviderCapability.READ_RUNBOOKS, lambda provider: provider.runbooks())

    def meetings(self) -> list[Meeting]:
        return self._collect(ProviderCapability.READ_MEETINGS, lambda provider: provider.meetings())

    def decisions(self) -> list[Decision]:
        return self._collect(ProviderCapability.READ_DECISIONS, lambda provider: provider.decisions())

    def _collect(self, capability: ProviderCapability, loader: Callable[[ContextProvider], list[T]]) -> list[T]:
        values: list[T] = []
        for provider in self.providers():
            try:
                if capability not in provider.capabilities():
                    continue
                values.extend(loader(provider))
            except Exception:
                continue
        return values
