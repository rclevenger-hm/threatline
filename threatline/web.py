from __future__ import annotations

import json
from datetime import date, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from threatline.attention import queue, today
from threatline.context import ContextEngine
from threatline.handoff import build_handoff
from threatline.investigation import build_investigation
from threatline.journal import WorkspaceJournal
from threatline.providers.factory import build_registry_from_env
from threatline.serialization import to_jsonable
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


class ThreatlineHandler(BaseHTTPRequestHandler):
    registry = build_registry_from_env()
    engine = ContextEngine(registry)
    journal = WorkspaceJournal()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if path == "/":
            self._send(PAGE.encode(), "text/html; charset=utf-8")
            return
        if path == "/healthz":
            diagnostics = self.registry.diagnostics()
            unavailable = [item.name for item in diagnostics if item.health.status.value == "unavailable"]
            status = "degraded" if unavailable else "ok"
            self._json({"status": status, "providers": to_jsonable(diagnostics)})
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

    def _send(self, body: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)


def create_server(
    host: str = "127.0.0.1",
    port: int = 8080,
    *,
    journal: WorkspaceJournal | None = None,
) -> ThreadingHTTPServer:
    class Handler(ThreatlineHandler):
        pass

    Handler.journal = journal or WorkspaceJournal()
    return ThreadingHTTPServer((host, port), Handler)
