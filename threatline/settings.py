from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

SETTINGS_VERSION = 1


def default_settings() -> dict[str, Any]:
    return {
        "version": SETTINGS_VERSION,
        "setup_complete": False,
        "mode": "demo",
        "providers": ["demo"],
        "timezone": "UTC",
        "jira": {
            "base_url": "",
            "jql": "resolution IS EMPTY ORDER BY priority DESC, updated DESC",
            "auth_mode": "bearer",
            "email": "",
            "verify_ssl": True,
            "timeout_seconds": 30.0,
            "max_results": 500,
        },
        "github": {
            "api_url": "https://api.github.com",
            "web_url": "https://github.com",
            "repositories": [],
            "verify_ssl": True,
            "timeout_seconds": 30.0,
            "max_changes": 100,
            "max_runbooks": 100,
        },
    }


def default_secrets() -> dict[str, str]:
    return {"jira_pat": "", "jira_api_token": "", "github_token": ""}


def _clean_url(value: object, field: str, *, required: bool = True) -> str:
    text = str(value or "").strip().rstrip("/")
    if not text and not required:
        return ""
    parsed = urlparse(text)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"{field} must be an http(s) URL")
    return text


def _bounded_int(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(parsed, maximum))


def _bounded_float(value: object, default: float, minimum: float, maximum: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(parsed, maximum))


class WorkspaceSettingsStore:
    def __init__(self, data_dir: Path | None = None) -> None:
        self.data_dir = data_dir or Path(os.environ.get("THREATLINE_DATA_DIR", ".runtime"))
        self.settings_path = self.data_dir / "workspace.json"
        self.secrets_path = self.data_dir / "secrets.json"

    @property
    def configured(self) -> bool:
        return bool(self.load_settings().get("setup_complete"))

    def load_settings(self) -> dict[str, Any]:
        defaults = default_settings()
        raw = self._read_json(self.settings_path)
        if not raw:
            return defaults
        result = defaults
        for key in ("setup_complete", "mode", "providers", "timezone"):
            if key in raw:
                result[key] = raw[key]
        if isinstance(raw.get("jira"), dict):
            result["jira"].update(raw["jira"])
        if isinstance(raw.get("github"), dict):
            result["github"].update(raw["github"])
        result["version"] = SETTINGS_VERSION
        return result

    def load_secrets(self) -> dict[str, str]:
        values = default_secrets()
        raw = self._read_json(self.secrets_path)
        for key in values:
            if key in raw:
                values[key] = str(raw[key] or "")
        return values

    def prepare(self, payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
        existing_settings = self.load_settings()
        existing_secrets = self.load_secrets()
        mode = str(payload.get("mode") or "connected").strip().lower()
        if mode not in {"demo", "connected"}:
            raise ValueError("mode must be demo or connected")

        timezone_name = str(payload.get("timezone") or existing_settings.get("timezone") or "UTC").strip()
        try:
            ZoneInfo(timezone_name)
        except ZoneInfoNotFoundError as exc:
            raise ValueError("timezone must be a valid IANA timezone") from exc

        if mode == "demo":
            settings = default_settings()
            settings.update({"setup_complete": True, "mode": "demo", "providers": ["demo"], "timezone": timezone_name})
            return settings, existing_secrets

        raw_providers = payload.get("providers") or []
        if not isinstance(raw_providers, list):
            raise ValueError("providers must be a list")
        providers: list[str] = []
        for value in raw_providers:
            name = str(value).strip().lower()
            if name not in {"jira", "github"}:
                raise ValueError(f"unsupported provider: {name or 'blank'}")
            if name not in providers:
                providers.append(name)
        if not providers:
            raise ValueError("select at least one provider or choose demo mode")

        settings = default_settings()
        settings.update({"setup_complete": True, "mode": "connected", "providers": providers, "timezone": timezone_name})
        secrets = existing_secrets

        if "jira" in providers:
            raw_jira = payload.get("jira") if isinstance(payload.get("jira"), dict) else {}
            existing_jira = existing_settings.get("jira") if isinstance(existing_settings.get("jira"), dict) else {}
            auth_mode = str(raw_jira.get("auth_mode") or existing_jira.get("auth_mode") or "bearer").strip().lower()
            if auth_mode not in {"bearer", "basic"}:
                raise ValueError("Jira auth mode must be bearer or basic")
            base_url = _clean_url(raw_jira.get("base_url") or existing_jira.get("base_url"), "Jira base URL")
            jql = str(raw_jira.get("jql") or existing_jira.get("jql") or "").strip()
            if not jql:
                raise ValueError("Jira JQL is required")
            email = str(raw_jira.get("email") or existing_jira.get("email") or "").strip()
            incoming_secret = str(raw_jira.get("secret") or "").strip()
            if incoming_secret:
                if auth_mode == "bearer":
                    secrets["jira_pat"] = incoming_secret
                else:
                    secrets["jira_api_token"] = incoming_secret
            if auth_mode == "bearer" and not secrets.get("jira_pat"):
                raise ValueError("Jira personal access token is required")
            if auth_mode == "basic" and (not email or not secrets.get("jira_api_token")):
                raise ValueError("Jira Cloud email and API token are required")
            settings["jira"] = {
                "base_url": base_url,
                "jql": jql,
                "auth_mode": auth_mode,
                "email": email,
                "verify_ssl": bool(raw_jira.get("verify_ssl", existing_jira.get("verify_ssl", True))),
                "timeout_seconds": _bounded_float(raw_jira.get("timeout_seconds"), 30.0, 1.0, 300.0),
                "max_results": _bounded_int(raw_jira.get("max_results"), 500, 1, 5000),
            }

        if "github" in providers:
            raw_github = payload.get("github") if isinstance(payload.get("github"), dict) else {}
            existing_github = existing_settings.get("github") if isinstance(existing_settings.get("github"), dict) else {}
            repositories_value = raw_github.get("repositories", existing_github.get("repositories", []))
            if isinstance(repositories_value, str):
                repositories = [part.strip() for part in repositories_value.split(",") if part.strip()]
            elif isinstance(repositories_value, list):
                repositories = [str(part).strip() for part in repositories_value if str(part).strip()]
            else:
                repositories = []
            if not repositories or any("/" not in repository for repository in repositories):
                raise ValueError("GitHub repositories must contain owner/name values")
            incoming_token = str(raw_github.get("token") or "").strip()
            if incoming_token:
                secrets["github_token"] = incoming_token
            if not secrets.get("github_token"):
                raise ValueError("GitHub token is required")
            api_url = _clean_url(raw_github.get("api_url") or existing_github.get("api_url") or "https://api.github.com", "GitHub API URL")
            web_url = _clean_url(raw_github.get("web_url") or existing_github.get("web_url") or "https://github.com", "GitHub web URL")
            settings["github"] = {
                "api_url": api_url,
                "web_url": web_url,
                "repositories": repositories,
                "verify_ssl": bool(raw_github.get("verify_ssl", existing_github.get("verify_ssl", True))),
                "timeout_seconds": _bounded_float(raw_github.get("timeout_seconds"), 30.0, 1.0, 300.0),
                "max_changes": _bounded_int(raw_github.get("max_changes"), 100, 1, 1000),
                "max_runbooks": _bounded_int(raw_github.get("max_runbooks"), 100, 1, 1000),
            }

        return settings, secrets

    def save(self, settings: dict[str, Any], secrets: dict[str, str]) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._atomic_write(self.settings_path, settings, mode=0o600)
        self._atomic_write(self.secrets_path, secrets, mode=0o600)

    def public_status(self, *, managed_by_environment: bool = False) -> dict[str, Any]:
        settings = self.load_settings()
        secrets = self.load_secrets()
        jira = dict(settings.get("jira") or {})
        github = dict(settings.get("github") or {})
        return {
            "setup_complete": bool(settings.get("setup_complete")),
            "needs_setup": not bool(settings.get("setup_complete")) and not managed_by_environment,
            "managed_by_environment": managed_by_environment,
            "mode": settings.get("mode") or "demo",
            "providers": list(settings.get("providers") or ["demo"]),
            "timezone": settings.get("timezone") or "UTC",
            "jira": {
                **jira,
                "secret_configured": bool(secrets.get("jira_pat") or secrets.get("jira_api_token")),
            },
            "github": {
                **github,
                "token_configured": bool(secrets.get("github_token")),
            },
        }

    @staticmethod
    def _read_json(path: Path) -> dict[str, Any]:
        if not path.exists():
            return {}
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _atomic_write(path: Path, payload: dict[str, Any], *, mode: int) -> None:
        temp = path.with_suffix(path.suffix + ".tmp")
        temp.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
        try:
            os.chmod(temp, mode)
        except OSError:
            pass
        temp.replace(path)
        try:
            os.chmod(path, mode)
        except OSError:
            pass
