from __future__ import annotations

import os
from typing import Any

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


def environment_managed() -> bool:
    return "THREATLINE_PROVIDERS" in os.environ or "THREATLINE_PROVIDER" in os.environ


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


def build_registry_from_settings(settings: dict[str, Any], secrets: dict[str, str]) -> ProviderRegistry:
    providers = []
    names = [str(name).strip().lower() for name in settings.get("providers") or ["demo"]]
    if not names:
        names = ["demo"]
    for name in names:
        if name == "demo":
            providers.append(DemoProvider())
            continue
        if name == "jira":
            jira = settings.get("jira") if isinstance(settings.get("jira"), dict) else {}
            auth_mode = str(jira.get("auth_mode") or "bearer")
            providers.append(
                JiraProvider(
                    JiraConfig(
                        base_url=str(jira.get("base_url") or ""),
                        jql=str(jira.get("jql") or ""),
                        bearer_token=secrets.get("jira_pat", "") if auth_mode == "bearer" else "",
                        email=str(jira.get("email") or "") if auth_mode == "basic" else "",
                        api_token=secrets.get("jira_api_token", "") if auth_mode == "basic" else "",
                        verify_ssl=bool(jira.get("verify_ssl", True)),
                        timeout_seconds=float(jira.get("timeout_seconds") or 30.0),
                        max_results=int(jira.get("max_results") or 500),
                    )
                )
            )
            continue
        if name == "github":
            github = settings.get("github") if isinstance(settings.get("github"), dict) else {}
            providers.append(
                GitHubProvider(
                    GitHubConfig(
                        token=secrets.get("github_token", ""),
                        repositories=tuple(str(repo) for repo in github.get("repositories") or []),
                        api_url=str(github.get("api_url") or "https://api.github.com"),
                        web_url=str(github.get("web_url") or "https://github.com"),
                        verify_ssl=bool(github.get("verify_ssl", True)),
                        timeout_seconds=float(github.get("timeout_seconds") or 30.0),
                        max_changes=int(github.get("max_changes") or 100),
                        max_runbooks=int(github.get("max_runbooks") or 100),
                    )
                )
            )
            continue
        raise ValueError(f"Unknown Threatline provider: {name}")
    return ProviderRegistry(providers)
