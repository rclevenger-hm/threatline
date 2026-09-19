from __future__ import annotations

import json
import platform
from datetime import datetime, timezone
from typing import Any

from threatline import __version__
from threatline.config import WorkspaceConfigStore
from threatline.journal import WorkspaceJournal
from threatline.providers.registry import ProviderRegistry
from threatline.serialization import to_jsonable

BUNDLE_VERSION = 1
_SENSITIVE_KEYS = {
    "api_token",
    "bearer_token",
    "password",
    "secret",
    "token",
    "authorization",
}


def _secret_values(store: WorkspaceConfigStore) -> tuple[str, ...]:
    workspace = store.active_workspace()
    if workspace is None:
        return ()
    values: list[str] = []
    for provider_secrets in workspace.secrets.values():
        for value in provider_secrets.values():
            text = str(value).strip()
            if text:
                values.append(text)
    return tuple(sorted(set(values), key=len, reverse=True))


def _redact(value: Any, secret_values: tuple[str, ...]) -> Any:
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            normalized = str(key).strip().lower()
            if normalized in _SENSITIVE_KEYS or normalized.endswith("_token") or normalized.endswith("_password"):
                cleaned[str(key)] = "[redacted]"
            else:
                cleaned[str(key)] = _redact(item, secret_values)
        return cleaned
    if isinstance(value, list):
        return [_redact(item, secret_values) for item in value]
    if isinstance(value, tuple):
        return [_redact(item, secret_values) for item in value]
    if isinstance(value, str):
        cleaned = value
        for secret in secret_values:
            cleaned = cleaned.replace(secret, "[redacted]")
        return cleaned
    return value


def build_support_bundle(
    store: WorkspaceConfigStore,
    registry: ProviderRegistry,
    journal: WorkspaceJournal,
) -> dict[str, Any]:
    """Build a support payload that excludes stored credential values."""

    public_state = store.public_state()
    payload: dict[str, Any] = {
        "bundle_version": BUNDLE_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "application": {"name": "Threatline", "version": __version__},
        "runtime": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "configuration": {
            "versions": store.version_state(),
            "state": public_state,
        },
        "providers": to_jsonable(registry.diagnostics()),
        "storage": {
            "config_present": store.config_path.exists(),
            "secrets_present": store.secrets_path.exists(),
            "journal_present": journal.path.exists(),
        },
    }
    return _redact(payload, _secret_values(store))


def support_bundle_json(
    store: WorkspaceConfigStore,
    registry: ProviderRegistry,
    journal: WorkspaceJournal,
) -> bytes:
    return (json.dumps(build_support_bundle(store, registry, journal), indent=2, sort_keys=True) + "\n").encode("utf-8")
