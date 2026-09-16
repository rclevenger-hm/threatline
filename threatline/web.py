from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from threatline.attention import queue, today
from threatline.context import ContextEngine
from threatline.providers.factory import build_registry_from_env
from threatline.serialization import to_jsonable


PAGE = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Threatline</title><style>
:root{font-family:Inter,ui-sans-serif,system-ui,sans-serif;color:#e7e9ee;background:#0d0f13}*{box-sizing:border-box}body{margin:0}.shell{max-width:1180px;margin:auto;padding:28px}.top{display:flex;align-items:center;justify-content:space-between;gap:20px}.brand{font-size:25px;font-weight:760;letter-spacing:-.03em}.eyebrow{color:#8490a4;font-size:12px;text-transform:uppercase;letter-spacing:.12em}.status{font-size:12px;border:1px solid #2c5d42;color:#9be7b2;border-radius:999px;padding:7px 11px}.hero{padding:42px 0 24px;border-bottom:1px solid #242a34}.hero h1{font-size:38px;margin:5px 0 8px;letter-spacing:-.04em}.hero p{color:#9fa9ba;margin:0;max-width:720px}.nav{display:flex;gap:8px;margin:22px 0}.nav button,.filters button{background:#171b22;color:#b8c0ce;border:1px solid #2b313c;border-radius:9px;padding:9px 13px;cursor:pointer}.nav button.active{background:#e9edf5;color:#11151b;border-color:#e9edf5}.filters{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 16px}.filters input,.filters select{background:#141820;color:#dfe4ec;border:1px solid #2b313c;border-radius:9px;padding:9px 11px}.summary{display:flex;justify-content:space-between;align-items:end;margin:20px 0 8px}.summary h2{margin:0;font-size:18px}.muted{color:#8d98aa;font-size:13px}.list{border:1px solid #272d37;border-radius:14px;background:#13171d;overflow:hidden}.row{display:grid;grid-template-columns:82px 1fr 155px 120px;gap:14px;padding:15px 17px;border-top:1px solid #242a33;align-items:center}.row:first-child{border-top:0}.score{font-size:12px;color:#aab4c4}.score strong{display:block;font-size:20px;color:#f0f3f7}.title{font-weight:660}.key{color:#8ca8ff;font-size:12px;margin-bottom:3px}.reason{color:#929daf;font-size:12px;margin-top:5px}.owner,.priority{color:#b5becc;font-size:13px}.priority.high,.priority.critical,.priority.highest{color:#ff9e91}.empty,.error{padding:28px;color:#949faf}.source{color:inherit;text-decoration:none}.source:hover .title{text-decoration:underline}@media(max-width:760px){.row{grid-template-columns:65px 1fr}.owner,.priority{display:none}.hero h1{font-size:31px}.shell{padding:20px}}
</style></head><body><main class="shell"><header class="top"><div><div class="eyebrow">Engineering operations</div><div class="brand">Threatline</div></div><div class="status">Local workspace</div></header><section class="hero"><div class="eyebrow">Operational context, not another vendor tab</div><h1>Know what needs attention.</h1><p>Threatline ranks active work with transparent reasons, then keeps source links and connected engineering context close to the work.</p></section><nav class="nav"><button id="todayTab" class="active">Today</button><button id="queueTab">Queue</button></nav><section id="filters" class="filters" hidden><input id="q" placeholder="Search key, title, tag"><select id="priority"><option value="">Any priority</option><option>critical</option><option>highest</option><option>high</option><option>medium</option><option>normal</option><option>low</option></select><select id="ownership"><option value="any">Any owner</option><option value="unassigned">Unassigned</option><option value="assigned">Assigned</option></select><select id="sort"><option value="attention">Attention</option><option value="updated">Recently updated</option><option value="oldest">Oldest</option><option value="priority">Priority</option></select><button id="apply">Apply</button></section><section class="summary"><div><h2 id="heading">Needs attention</h2><div id="subheading" class="muted">Deterministic ranking; every score has a reason.</div></div><div id="count" class="muted"></div></section><section id="list" class="list"><div class="empty">Loading…</div></section></main><script>
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const list=document.getElementById('list'),count=document.getElementById('count'),filters=document.getElementById('filters');let mode='today';
function row(v){const i=v.work_item||{};const reasons=(v.reasons||[]).join(' · ');const href=i.source_ref&&i.source_ref.url?i.source_ref.url:'#';return `<div class="row"><div class="score"><strong>${esc(v.score)}</strong>attention</div><a class="source" href="${esc(href)}" ${href==='#'?'':'target="_blank" rel="noreferrer"'}><div class="key">${esc(i.id)}</div><div class="title">${esc(i.title)}</div><div class="reason">${esc(reasons)}</div></a><div class="owner">${esc(i.assignee||'Unassigned')}</div><div class="priority ${esc((i.priority||'').toLowerCase())}">${esc(i.priority||'normal')}<div class="muted">${esc(i.status||'')}</div></div></div>`}
async function load(){list.innerHTML='<div class="empty">Loading…</div>';try{let url='/api/today';if(mode==='queue'){const p=new URLSearchParams();for(const id of ['q','priority','ownership','sort']){const v=document.getElementById(id).value;if(v)p.set(id,v)}url='/api/queue?'+p.toString()}const r=await fetch(url);if(!r.ok)throw new Error('request failed');const d=await r.json();const items=d.items||[];list.innerHTML=items.length?items.map(row).join(''):'<div class="empty">Nothing matches this view.</div>';count.textContent=`${items.length} item${items.length===1?'':'s'}`}catch(e){list.innerHTML='<div class="error">Unable to load work. Check provider diagnostics.</div>';count.textContent=''}}
function setMode(next){mode=next;document.getElementById('todayTab').classList.toggle('active',next==='today');document.getElementById('queueTab').classList.toggle('active',next==='queue');filters.hidden=next!=='queue';document.getElementById('heading').textContent=next==='today'?'Needs attention':'Operational queue';document.getElementById('subheading').textContent=next==='today'?'Deterministic ranking; every score has a reason.':'Filter and sort normalized work across connected providers.';load()}
document.getElementById('todayTab').onclick=()=>setMode('today');document.getElementById('queueTab').onclick=()=>setMode('queue');document.getElementById('apply').onclick=load;document.getElementById('q').addEventListener('keydown',e=>{if(e.key==='Enter')load()});load();
</script></body></html>'''


def _first(query: dict[str, list[str]], key: str, default: str = "") -> str:
    values = query.get(key)
    return values[0] if values else default


class ThreatlineHandler(BaseHTTPRequestHandler):
    registry = build_registry_from_env()
    engine = ContextEngine(registry)

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
