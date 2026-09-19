from __future__ import annotations

import json
import os
from datetime import date, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from threatline.attention import queue, today
from threatline.config import WorkspaceConfigStore
from threatline.context import ContextEngine
from threatline.diagnostics import build_support_bundle, support_bundle_json
from threatline.handoff import build_handoff
from threatline.investigation import build_investigation
from threatline.journal import WorkspaceJournal
from threatline.providers.factory import build_provider, build_registry, build_registry_from_env
from threatline.serialization import to_jsonable
from threatline.setup_ui import SETUP_PAGE
from threatline.ui import PAGE


def _first(query: dict[str, list[str]], key: str, default: str = "") -> str:
    values = query.get(key)
    return values[0] if values else default


def _valid_day(value: str, fallback: date) -> str:
    if not value:
        return fallback.isoformat()
    try:
        return date.fromisoformat(value).isoformat()
    except ValueError as exc:
        raise ValueError("date must use YYYY-MM-DD") from exc


def _environment_configured() -> bool:
    return bool((os.environ.get("THREATLINE_PROVIDERS") or os.environ.get("THREATLINE_PROVIDER") or "").strip())


class ThreatlineHandler(BaseHTTPRequestHandler):
    config_store = WorkspaceConfigStore()
    registry = build_registry_from_env()
    engine = ContextEngine(registry)
    journal = WorkspaceJournal()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if path == "/":
            page = SETUP_PAGE if self._setup_required() else PAGE
            self._send(page.encode(), "text/html; charset=utf-8")
            return
        if path == "/setup":
            self._send(SETUP_PAGE.encode(), "text/html; charset=utf-8")
            return
        if path == "/healthz":
            diagnostics = self.registry.diagnostics()
            unavailable = [item.name for item in diagnostics if item.health.status.value == "unavailable"]
            status = "degraded" if unavailable else "ok"
            self._json({"status": status, "providers": to_jsonable(diagnostics)})
            return
        if path == "/api/diagnostics":
            self._json(build_support_bundle(self.config_store, self.registry, self.journal))
            return
        if path == "/api/support-bundle":
            self._send(
                support_bundle_json(self.config_store, self.registry, self.journal),
                "application/json; charset=utf-8",
                headers={"Content-Disposition": 'attachment; filename="threatline-support.json"'},
            )
            return
        if path == "/api/setup":
            payload = self.config_store.public_state()
            payload["environment_configured"] = _environment_configured()
            self._json(payload)
            return
        if path == "/api/providers":
            self._json({"providers": to_jsonable(self.registry.diagnostics())})
            return
        if path == "/api/context":
            self._json(self.engine.snapshot())
            return
        if path == "/api/today":
            limit_text = _first(query, "limit", "20")
            try:
                limit = max(1, min(int(limit_text), 100))
            except ValueError:
                limit = 20
            self._json({"items": to_jsonable(today(self.registry.work_items(), limit=limit))})
            return
        if path == "/api/queue":
            values = queue(
                self.registry.work_items(),
                query=_first(query, "q"),
                priority=_first(query, "priority"),
                status=_first(query, "status"),
                ownership=_first(query, "ownership", "any"),
                sort=_first(query, "sort", "attention"),
            )
            self._json({"items": to_jsonable(values), "count": len(values)})
            return
        if path == "/api/notes":
            try:
                day = self._requested_day(query)
            except ValueError as exc:
                self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
                return
            self._json({"day": day, "notes": self.journal.notes(day)})
            return
        if path == "/api/handoff":
            try:
                day = self._requested_day(query)
            except ValueError as exc:
                self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
                return
            self._json(build_handoff(self.journal, self.registry, day))
            return
        investigation_prefix = "/api/investigations/"
        if path.startswith(investigation_prefix):
            work_item_id = unquote(path[len(investigation_prefix):])
            context = self.engine.work_item_context(work_item_id)
            if context is None:
                self._json({"error": "work item not found"}, HTTPStatus.NOT_FOUND)
            else:
                self._json(build_investigation(context))
            return
        work_prefix = "/api/work-items/"
        if path.startswith(work_prefix):
            context = self.engine.work_item_context(unquote(path[len(work_prefix):]))
            if context is None:
                self._json({"error": "work item not found"}, HTTPStatus.NOT_FOUND)
            else:
                self._json(context)
            return
        self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        try:
            payload = self._read_json()
        except ValueError as exc:
            self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        if path == "/api/setup/test":
            self._test_provider(payload)
            return
        if path == "/api/setup/workspace":
            self._save_workspace(payload)
            return
        if path == "/api/setup/activate":
            workspace_id = str(payload.get("workspace_id") or "").strip()
            try:
                workspace = self.config_store.activate(workspace_id)
                self._reload_runtime()
            except ValueError as exc:
                self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
                return
            self._json({"workspace": {"id": workspace.id, "name": workspace.name}, "state": self.config_store.public_state()})
            return
        if path == "/api/notes":
            try:
                note = self.journal.add_note(
                    str(payload.get("text") or ""),
                    work_item_id=str(payload.get("work_item_id") or "") or None,
                )
            except ValueError as exc:
                self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
                return
            self._json({"note": note}, HTTPStatus.CREATED)
            return
        if path == "/api/activity":
            kind = str(payload.get("kind") or "").strip()
            if kind != "investigation_opened":
                self._json({"error": "unsupported activity kind"}, HTTPStatus.BAD_REQUEST)
                return
            work_item_id = str(payload.get("work_item_id") or "").strip()
            if not work_item_id:
                self._json({"error": "work_item_id is required"}, HTTPStatus.BAD_REQUEST)
                return
            activity = self.journal.record_activity(
                kind,
                work_item_id=work_item_id,
                summary=str(payload.get("summary") or "Opened investigation"),
            )
            self._json({"activity": activity}, HTTPStatus.CREATED)
            return
        self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def _setup_required(self) -> bool:
        return not self.config_store.has_workspaces() and not _environment_configured()

    def _test_provider(self, payload: dict[str, object]) -> None:
        name = str(payload.get("provider") or "").strip().lower()
        settings = payload.get("config")
        secrets = payload.get("secrets")
        if not isinstance(settings, dict) or not isinstance(secrets, dict):
            self._json({"error": "config and secrets must be objects"}, HTTPStatus.BAD_REQUEST)
            return
        try:
            provider = build_provider(name, settings, secrets)
            health = provider.health()
            capabilities = tuple(sorted(provider.capabilities(), key=lambda item: item.value))
        except (TypeError, ValueError) as exc:
            self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        except Exception as exc:
            self._json({"error": str(exc)}, HTTPStatus.BAD_GATEWAY)
            return
        self._json({"provider": name, "health": to_jsonable(health), "capabilities": to_jsonable(capabilities)})

    def _save_workspace(self, payload: dict[str, object]) -> None:
        providers = payload.get("providers")
        secrets = payload.get("secrets")
        if not isinstance(providers, dict):
            self._json({"error": "providers must be an object"}, HTTPStatus.BAD_REQUEST)
            return
        if secrets is not None and not isinstance(secrets, dict):
            self._json({"error": "secrets must be an object"}, HTTPStatus.BAD_REQUEST)
            return
        try:
            workspace = self.config_store.upsert_workspace(
                workspace_id=str(payload.get("workspace_id") or ""),
                name=str(payload.get("name") or "Local workspace"),
                providers=providers,
                secrets=secrets,
                activate=bool(payload.get("activate", True)),
            )
            self._reload_runtime()
        except (TypeError, ValueError) as exc:
            self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        self._json(
            {
                "workspace": {"id": workspace.id, "name": workspace.name},
                "state": self.config_store.public_state(),
                "providers": to_jsonable(self.registry.diagnostics()),
            },
            HTTPStatus.CREATED,
        )

    def _reload_runtime(self) -> None:
        handler = type(self)
        handler.registry = build_registry(handler.config_store)
        handler.engine = ContextEngine(handler.registry)

    def _requested_day(self, query: dict[str, list[str]]) -> str:
        today_local = datetime.now(self.journal.tz).date()
        return _valid_day(_first(query, "date"), today_local)

    def _read_json(self) -> dict[str, object]:
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise ValueError("invalid content length") from exc
        if length <= 0:
            raise ValueError("JSON body is required")
        if length > 131_072:
            raise ValueError("request body is too large")
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid JSON body") from exc
        if not isinstance(payload, dict):
            raise ValueError("JSON body must be an object")
        return payload

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def _json(self, payload: object, status: HTTPStatus = HTTPStatus.OK) -> None:
        self._send(json.dumps(payload, separators=(",", ":")).encode(), "application/json", status)

    def _send(
        self,
        body: bytes,
        content_type: str,
        status: HTTPStatus = HTTPStatus.OK,
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)


def create_server(
    host: str = "127.0.0.1",
    port: int = 8080,
    *,
    journal: WorkspaceJournal | None = None,
    config_store: WorkspaceConfigStore | None = None,
) -> ThreadingHTTPServer:
    class Handler(ThreatlineHandler):
        pass

    Handler.journal = journal or WorkspaceJournal()
    Handler.config_store = config_store or WorkspaceConfigStore()
    Handler.registry = build_registry(Handler.config_store)
    Handler.engine = ContextEngine(Handler.registry)
    return ThreadingHTTPServer((host, port), Handler)
