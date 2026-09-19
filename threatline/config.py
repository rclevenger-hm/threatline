from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

CONFIG_VERSION = 1
_PROVIDER_NAMES = ("demo", "jira", "github", "grafana", "zabbix")
_SECRET_FIELDS = {
    "demo": frozenset(),
    "jira": frozenset({"bearer_token", "api_token"}),
    "github": frozenset({"token"}),
    "grafana": frozenset(),
    "zabbix": frozenset({"api_token"}),
}
_PUBLIC_FIELDS = {
    "demo": frozenset({"enabled"}),
    "jira": frozenset({"enabled", "base_url", "jql", "email", "verify_ssl", "timeout_seconds", "max_results"}),
    "github": frozenset(
        {
            "enabled",
            "repositories",
            "api_url",
            "web_url",
            "verify_ssl",
            "timeout_seconds",
            "max_changes",
            "max_runbooks",
        }
    ),
    "grafana": frozenset(
        {
            "enabled",
            "base_url",
            "dashboards",
            "org_id",
            "service_variable",
            "default_from",
            "default_to",
        }
    ),
    "zabbix": frozenset(
        {
            "enabled",
            "base_url",
            "service_tag",
            "verify_ssl",
            "timeout_seconds",
            "max_problems",
        }
    ),
}


def _slug(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    return normalized[:64] or "workspace"


def _json_object(path: Path, fallback: dict[str, Any]) -> dict[str, Any]:
    if not path.exists():
        return fallback
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read Threatline configuration: {path}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"Threatline configuration must be a JSON object: {path}")
    return payload


def _document_version(document: Mapping[str, object], path: Path) -> int:
    raw_version = document.get("version", 0)
    try:
        version = int(raw_version)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Threatline configuration version must be an integer: {path}") from exc
    if version < 0:
        raise ValueError(f"Threatline configuration version cannot be negative: {path}")
    if version > CONFIG_VERSION:
        raise ValueError(
            f"Threatline configuration version {version} is newer than supported version {CONFIG_VERSION}: {path}"
        )
    return version


def _enabled(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() not in {"", "0", "false", "no", "off"}


@dataclass(frozen=True, slots=True)
class WorkspaceConfig:
    id: str
    name: str
    providers: dict[str, dict[str, Any]]
    secrets: dict[str, dict[str, str]]

    def provider(self, name: str) -> dict[str, Any]:
        settings = dict(self.providers.get(name, {}))
        settings.update(self.secrets.get(name, {}))
        return settings


class WorkspaceConfigStore:
    """Local workspace configuration with provider credentials stored separately."""

    def __init__(self, root: Path | None = None) -> None:
        configured_root = os.environ.get("THREATLINE_CONFIG_DIR", "").strip()
        self.root = root or (Path(configured_root).expanduser() if configured_root else Path.home() / ".threatline")
        self.config_path = self.root / "config.json"
        self.secrets_path = self.root / "secrets.json"

    def has_workspaces(self) -> bool:
        return bool(self._workspaces(self._config_doc()))

    def active_workspace(self) -> WorkspaceConfig | None:
        document = self._config_doc()
        workspaces = self._workspaces(document)
        if not workspaces:
            return None
        active_id = str(document.get("active_workspace") or workspaces[0].get("id") or "")
        selected = next((item for item in workspaces if str(item.get("id") or "") == active_id), workspaces[0])
        workspace_id = str(selected.get("id") or "")
        providers = selected.get("providers") if isinstance(selected.get("providers"), dict) else {}
        secret_document = self._secrets_doc()
        all_secrets = secret_document.get("workspaces") if isinstance(secret_document.get("workspaces"), dict) else {}
        workspace_secrets = all_secrets.get(workspace_id) if isinstance(all_secrets.get(workspace_id), dict) else {}
        return WorkspaceConfig(
            id=workspace_id,
            name=str(selected.get("name") or workspace_id or "Workspace"),
            providers={str(name): dict(value) for name, value in providers.items() if isinstance(value, dict)},
            secrets={
                str(name): {str(key): str(value) for key, value in values.items() if value is not None}
                for name, values in workspace_secrets.items()
                if isinstance(values, dict)
            },
        )

    def public_state(self) -> dict[str, Any]:
        document = self._config_doc()
        secrets = self._secrets_doc()
        secret_workspaces = secrets.get("workspaces") if isinstance(secrets.get("workspaces"), dict) else {}
        workspaces: list[dict[str, Any]] = []
        for item in self._workspaces(document):
            workspace_id = str(item.get("id") or "")
            provider_settings = item.get("providers") if isinstance(item.get("providers"), dict) else {}
            workspace_secrets = secret_workspaces.get(workspace_id) if isinstance(secret_workspaces.get(workspace_id), dict) else {}
            providers: dict[str, Any] = {}
            for name, settings in provider_settings.items():
                if name not in _PROVIDER_NAMES or not isinstance(settings, dict):
                    continue
                secret_values = workspace_secrets.get(name) if isinstance(workspace_secrets.get(name), dict) else {}
                providers[name] = {
                    **settings,
                    "credential_fields": {
                        field: bool(str(secret_values.get(field) or "").strip())
                        for field in sorted(_SECRET_FIELDS[name])
                    },
                }
            workspaces.append(
                {
                    "id": workspace_id,
                    "name": str(item.get("name") or workspace_id or "Workspace"),
                    "providers": providers,
                }
            )
        return {
            "version": CONFIG_VERSION,
            "configured": bool(workspaces),
            "active_workspace": document.get("active_workspace"),
            "workspaces": workspaces,
        }

    def version_state(self) -> dict[str, int]:
        config_document = self._config_doc()
        secrets_document = self._secrets_doc()
        return {
            "current": CONFIG_VERSION,
            "config": int(config_document["version"]),
            "secrets": int(secrets_document["version"]),
        }

    def upsert_workspace(
        self,
        *,
        name: str,
        providers: Mapping[str, Mapping[str, object]],
        secrets: Mapping[str, Mapping[str, object]] | None = None,
        workspace_id: str = "",
        activate: bool = True,
    ) -> WorkspaceConfig:
        clean_name = name.strip() or "Local workspace"
        clean_id = _slug(workspace_id or clean_name)
        clean_providers = self._normalize_providers(providers)
        if not any(_enabled(settings.get("enabled", True)) for settings in clean_providers.values()):
            raise ValueError("At least one provider must be enabled")

        document = self._config_doc()
        workspaces = self._workspaces(document)
        replacement = {"id": clean_id, "name": clean_name, "providers": clean_providers}
        replaced = False
        for index, item in enumerate(workspaces):
            if str(item.get("id") or "") == clean_id:
                workspaces[index] = replacement
                replaced = True
                break
        if not replaced:
            workspaces.append(replacement)
        document = {
            "version": CONFIG_VERSION,
            "active_workspace": clean_id if activate else document.get("active_workspace"),
            "workspaces": workspaces,
        }
        if not document.get("active_workspace"):
            document["active_workspace"] = clean_id
        self._write_json(self.config_path, document)

        if secrets is not None:
            secret_document = self._secrets_doc()
            secret_workspaces = secret_document.get("workspaces") if isinstance(secret_document.get("workspaces"), dict) else {}
            existing = secret_workspaces.get(clean_id) if isinstance(secret_workspaces.get(clean_id), dict) else {}
            updated: dict[str, dict[str, str]] = {
                str(provider): {str(key): str(value) for key, value in values.items()}
                for provider, values in existing.items()
                if isinstance(values, dict)
            }
            for provider_name, values in secrets.items():
                if provider_name not in _PROVIDER_NAMES or not isinstance(values, Mapping):
                    continue
                provider_secrets = dict(updated.get(provider_name, {}))
                for key in _SECRET_FIELDS[provider_name]:
                    if key not in values:
                        continue
                    value = str(values.get(key) or "").strip()
                    if value:
                        provider_secrets[key] = value
                if provider_secrets:
                    updated[provider_name] = provider_secrets
            secret_workspaces[clean_id] = updated
            self._write_json(self.secrets_path, {"version": CONFIG_VERSION, "workspaces": secret_workspaces})

        active = self.active_workspace()
        if active is None:
            raise ValueError("Workspace configuration could not be loaded after saving")
        return active

    def activate(self, workspace_id: str) -> WorkspaceConfig:
        clean_id = workspace_id.strip()
        document = self._config_doc()
        if not any(str(item.get("id") or "") == clean_id for item in self._workspaces(document)):
            raise ValueError("Workspace not found")
        document["active_workspace"] = clean_id
        self._write_json(self.config_path, document)
        active = self.active_workspace()
        if active is None:
            raise ValueError("Workspace activation failed")
        return active

    def _normalize_providers(self, providers: Mapping[str, Mapping[str, object]]) -> dict[str, dict[str, Any]]:
        normalized: dict[str, dict[str, Any]] = {}
        for name, raw in providers.items():
            provider_name = str(name).strip().lower()
            if provider_name not in _PROVIDER_NAMES:
                raise ValueError(f"Unknown Threatline provider: {provider_name}")
            if not isinstance(raw, Mapping):
                raise ValueError(f"Provider configuration must be an object: {provider_name}")
            settings: dict[str, Any] = {}
            for key in _PUBLIC_FIELDS[provider_name]:
                if key not in raw:
                    continue
                value = raw[key]
                if key == "repositories":
                    if isinstance(value, str):
                        value = [part.strip() for part in value.split(",") if part.strip()]
                    elif isinstance(value, (list, tuple)):
                        value = [str(part).strip() for part in value if str(part).strip()]
                    else:
                        raise ValueError("GitHub repositories must be a list or comma-separated string")
                elif key == "dashboards":
                    if isinstance(value, str):
                        value = [part.strip() for part in re.split(r"[;\n]+", value) if part.strip()]
                    elif isinstance(value, (list, tuple)):
                        cleaned: list[object] = []
                        for part in value:
                            if isinstance(part, Mapping):
                                cleaned.append({str(k): v for k, v in part.items()})
                            elif str(part).strip():
                                cleaned.append(str(part).strip())
                        value = cleaned
                    else:
                        raise ValueError("Grafana dashboards must be a list or semicolon-separated string")
                settings[key] = value
            settings["enabled"] = _enabled(settings.get("enabled", True))
            normalized[provider_name] = settings
        if not normalized:
            normalized["demo"] = {"enabled": True}
        return normalized

    def _config_doc(self) -> dict[str, Any]:
        existed = self.config_path.exists()
        document = _json_object(
            self.config_path,
            {"version": CONFIG_VERSION, "active_workspace": None, "workspaces": []},
        )
        version = _document_version(document, self.config_path)
        normalized = {
            "version": CONFIG_VERSION,
            "active_workspace": document.get("active_workspace"),
            "workspaces": self._workspaces(document),
        }
        if existed and version < CONFIG_VERSION:
            self._write_json(self.config_path, normalized)
        return normalized

    def _secrets_doc(self) -> dict[str, Any]:
        existed = self.secrets_path.exists()
        document = _json_object(self.secrets_path, {"version": CONFIG_VERSION, "workspaces": {}})
        version = _document_version(document, self.secrets_path)
        workspaces = document.get("workspaces") if isinstance(document.get("workspaces"), dict) else {}
        normalized = {"version": CONFIG_VERSION, "workspaces": workspaces}
        if existed and version < CONFIG_VERSION:
            self._write_json(self.secrets_path, normalized)
        return normalized

    @staticmethod
    def _workspaces(document: Mapping[str, object]) -> list[dict[str, Any]]:
        values = document.get("workspaces")
        if not isinstance(values, list):
            return []
        return [dict(item) for item in values if isinstance(item, dict)]

    def _write_json(self, path: Path, payload: Mapping[str, object]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        temporary.replace(path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
