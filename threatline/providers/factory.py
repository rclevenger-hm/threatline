from __future__ import annotations

import os

from threatline.providers.demo import DemoProvider
from threatline.providers.github import GitHubProvider
from threatline.providers.jira import JiraProvider
from threatline.providers.registry import ProviderRegistry


def configured_provider_names() -> tuple[str, ...]:
    raw = os.environ.get("THREATLINE_PROVIDERS") or os.environ.get("THREATLINE_PROVIDER") or "demo"
    names: list[str] = []
    for part in raw.split(","):
        name = part.strip().lower()
        if name and name not in names:
            names.append(name)
    return tuple(names or ["demo"])


def build_registry_from_env() -> ProviderRegistry:
    providers = []
    unknown: list[str] = []
    for name in configured_provider_names():
        if name == "demo":
            providers.append(DemoProvider())
        elif name == "jira":
            providers.append(JiraProvider())
        elif name == "github":
            providers.append(GitHubProvider())
        else:
            unknown.append(name)
    if unknown:
        raise ValueError(f"Unknown Threatline providers: {', '.join(unknown)}")
    return ProviderRegistry(providers)
