from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse

from threatline.context import ContextEngine
from threatline.providers.demo import DemoProvider


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Threatline</title><style>:root{font-family:Inter,ui-sans-serif,system-ui,sans-serif;color:#e7e9ee;background:#101216}body{margin:0}.shell{max-width:1100px;margin:auto;padding:32px}.eyebrow{color:#8f9bb3;text-transform:uppercase;letter-spacing:.12em;font-size:12px}.hero{display:flex;justify-content:space-between;gap:24px;align-items:end}.hero h1{font-size:42px;margin:6px 0}.hero p{color:#aeb7c7;max-width:650px}.status{border:1px solid #303643;border-radius:999px;padding:8px 12px;color:#9be7b2}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;margin-top:28px}.card{background:#171a20;border:1px solid #292e38;border-radius:16px;padding:18px}.card h2{font-size:15px;color:#adb7c8;margin:0 0 12px}.item{padding:12px 0;border-top:1px solid #282d36}.item:first-of-type{border-top:0}.key{font-weight:700}.muted{color:#8f9aab;font-size:13px}.high{color:#ff9b8e}@media(max-width:720px){.grid{grid-template-columns:1fr}.hero{display:block}}</style></head><body><main class="shell"><div class="hero"><div><div class="eyebrow">Operational context workspace</div><h1>Threatline</h1><p>Connect the signals, work, changes, runbooks, meetings and decisions behind production.</p></div><div class="status">Demo provider connected</div></div><section class="grid" id="grid"></section></main><script>const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));fetch('/api/context').then(r=>r.json()).then(d=>{const sections=[['Needs attention',d.work_items],['Active alerts',d.alerts],['Recent changes',d.changes],['Decisions',d.decisions]];document.getElementById('grid').innerHTML=sections.map(([title,items])=>`<article class="card"><h2>${esc(title)}</h2>${items.length?items.map(i=>`<div class="item"><div class="key ${i.severity==='high'?'high':''}">${esc(i.id)} · ${esc(i.title||i.summary)}</div><div class="muted">${esc(i.status||i.severity||i.author||'linked context')}</div></div>`).join(''):'<div class="muted">Nothing right now.</div>'}</article>`).join('')}).catch(()=>{document.getElementById('grid').innerHTML='<article class="card">Unable to load context.</article>'});</script></body></html>"""


class ThreatlineHandler(BaseHTTPRequestHandler):
    engine = ContextEngine(DemoProvider())

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/":
            self._send(PAGE.encode(), "text/html; charset=utf-8")
            return
        if path == "/healthz":
            self._json({"status": "ok", "provider": self.engine.provider.name})
            return
        if path == "/api/context":
            self._json(self.engine.snapshot())
            return
        prefix = "/api/work-items/"
        if path.startswith(prefix):
            context = self.engine.work_item_context(unquote(path[len(prefix):]))
            if context is None:
                self._json({"error": "work item not found"}, HTTPStatus.NOT_FOUND)
            else:
                self._json(context)
            return
        self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

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


def create_server(host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), ThreatlineHandler)
