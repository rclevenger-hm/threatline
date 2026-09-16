from __future__ import annotations

import os
from typing import Mapping

from threatline.config import WorkspaceConfig, WorkspaceConfigStore
from threatline.providers.demo import DemoProvider
from threatline.providers.github import GitHubConfig, GitHubProvider
from threatline.providers.jira import JiraConfig, JiraProvider
from threatline.providers.registry import ProviderRegistry


def configured_provider_names() -> tuple[str, ...]:
    raw = os.environ.get("THREATLINE_PROVIDERS") or os.environ.get("THREATLINE_PROVIDER") or "demo"
    names: list[str] = []
    for part in raw.split(","):
        name = part.strip().lower()
        if name and name not in names:
            names.append(name)
    return tuple(names or ["demo"])


def _as_bool(value: object, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in {"0", "false", "no", "off"}


def _as_float(value: object, default: float, minimum: float = 1.0) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = default
    return max(parsed, minimum)


def _as_int(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(parsed, maximum))


def build_provider(
    name: str,
    settings: Mapping[str, object] | None = None,
    secrets: Mapping[str, object] | None = None,
):
    provider_name = name.strip().lower()
    values = dict(settings or {})
    credentials = dict(secrets or {})
    if provider_name == "demo":
        return DemoProvider()
    if provider_name == "jira":
        return JiraProvider(
            JiraConfig(
                base_url=str(values.get("base_url") or "").strip().rstrip("/"),
                jql=str(values.get("jql") or "").strip(),
                bearer_token=str(credentials.get("bearer_token") or "").strip(),
                email=str(values.get("email") or "").strip(),
                api_token=str(credentials.get("api_token") or "").strip(),
                verify_ssl=_as_bool(values.get("verify_ssl"), True),
                timeout_seconds=_as_float(values.get("timeout_seconds"), 30.0),
                max_results=_as_int(values.get("max_results"), 500, 1, 5000),
            )
        )
    if provider_name == "github":
        api_url = str(values.get("api_url") or "https://api.github.com").strip().rstrip("/")
        web_url = str(values.get("web_url") or "").strip().rstrip("/")
        if not web_url:
            web_url = "https://github.com" if api_url == "https://api.github.com" else api_url.removesuffix("/api/v3")
        repositories = values.get("repositories") or ()
        if isinstance(repositories, str):
            repository_values = tuple(part.strip() for part in repositories.split(",") if part.strip())
        else:
            repository_values = tuple(str(part).strip() for part in repositories if str(part).strip())
        return GitHubProvider(
            GitHubConfig(
                token=str(credentials.get("token") or "").strip(),
                repositories=repository_values,
                api_url=api_url,
                web_url=web_url,
                verify_ssl=_as_bool(values.get("verify_ssl"), True),
                timeout_seconds=_as_float(values.get("timeout_seconds"), 30.0),
                max_changes=_as_int(values.get("max_changes"), 100, 1, 1000),
                max_runbooks=_as_int(values.get("max_runbooks"), 100, 1, 1000),
            )
        )
    raise ValueError(f"Unknown Threatline provider: {provider_name}")


def build_registry_from_workspace(workspace: WorkspaceConfig) -> ProviderRegistry:
    providers = []
    for name, settings in workspace.providers.items():
        if not _as_bool(settings.get("enabled"), True):
            continue
        providers.append(build_provider(name, settings, workspace.secrets.get(name, {})))
    return ProviderRegistry(providers)


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


def build_registry(config_store: WorkspaceConfigStore | None = None) -> ProviderRegistry:
    workspace = config_store.active_workspace() if config_store is not None else None
    return build_registry_from_workspace(workspace) if workspace is not None else build_registry_from_env()
