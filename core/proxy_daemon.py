"""
Proxy Daemon Headless para o Ecidade-DAST
Baseado em mitmproxy com captura e deduplicação automática de campanhas.
"""
import os
import sys
import time
import json
import asyncio
import threading
import re
from urllib.parse import urlparse, parse_qs
from mitmproxy import options, http
from mitmproxy.tools.dump import DumpMaster
from core.campaign import build_campaign, is_static_resource, route_signature
from core.ignore_rules import is_ignored_url, has_valid_php_parameters
from core.logging_config import get_logger

log = get_logger()

class DastCaptureAddon:
    def __init__(self, target_scope=None, on_new_route_callback=None):
        self.target_scope = target_scope or []
        self.history = []
        self._sig_index = {}
        self.lock = threading.Lock()
        self.on_new_route_callback = on_new_route_callback

    def _passes_url_filters(self, url, host, method):
        """Filtros baseados só na requisição (escopo, ignorados, params válidos)."""
        if self.target_scope:
            if not any(s.lower() in (host or "").lower() for s in self.target_scope):
                return False
        if is_ignored_url(url):
            return False
        if not has_valid_php_parameters(url, method=method):
            return False
        return True

    def _record(self, entry, has_response):
        """Registra a rota deduplicando por assinatura. Entradas vindas do
        request() entram mesmo sem resposta (lookups de iframe cancelados nunca
        disparam response()); quando a resposta chega depois, enriquece a
        entrada existente com status/headers de resposta."""
        sig = "|".join(map(str, route_signature(entry)))
        is_new = False
        cb_entry = None
        with self.lock:
            if sig in self._sig_index:
                if has_response:
                    idx = self._sig_index[sig]
                    prev = self.history[idx]
                    entry["id"] = prev.get("id", idx + 1)
                    if not entry.get("routine") and prev.get("routine"):
                        entry["routine"] = prev["routine"]
                    if not entry.get("action_file") and prev.get("action_file"):
                        entry["action_file"] = prev["action_file"]
                    self.history[idx] = entry
                return
            entry["id"] = len(self.history) + 1
            self._sig_index[sig] = len(self.history)
            self.history.append(entry)
            is_new = True
            cb_entry = entry

        if is_new and self.on_new_route_callback:
            try:
                self.on_new_route_callback(cb_entry)
            except Exception:
                pass

    def request(self, flow: http.HTTPFlow):
        # Instrumentacao opcional: loga TODA requisicao que chega ao proxy,
        # antes de qualquer filtro. Inerte sem a env var DAST_DEBUG_REQLOG.
        dbg = os.environ.get("DAST_DEBUG_REQLOG")
        if dbg:
            try:
                with open(dbg, "a", encoding="utf-8") as f:
                    f.write(f"{flow.request.method}\t{flow.request.url}\n")
            except Exception:
                pass

        # Captura a rota já no request(): assim lookups de iframe que são
        # cancelados/substituídos (abre -> busca em sequência rápida) e nunca
        # disparam response() ainda viram rotas testáveis. Para o scan ativo de
        # SQLi basta a requisição; a resposta enriquece depois, se chegar.
        req = flow.request
        if not self._passes_url_filters(req.url, req.pretty_host, req.method):
            return
        headers_dict = dict(req.headers)
        body_str = req.get_text() if req.raw_content else ""
        entry = {
            "method": req.method.upper(),
            "url": req.url,
            "path": req.path,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "request_headers": headers_dict,
            "request_body": body_str,
            "response_status": None,
            "response_headers": {},
            "routine": headers_dict.get("x-dast-routine") or headers_dict.get("X-DAST-Routine") or "",
            "action_file": headers_dict.get("x-dast-action") or headers_dict.get("X-DAST-Action") or "",
        }
        if is_static_resource(entry):
            return
        self._record(entry, has_response=False)

    def response(self, flow: http.HTTPFlow):
        req = flow.request
        res = flow.response

        # Ignora se não houver resposta
        if not res:
            return

        # Neutraliza alertas e diálogos modais síncronos (alert, confirm, prompt, onbeforeunload)
        # que travam iframes do Chrome headless antes do JS pós-carregamento rodar
        try:
            content_type = res.headers.get("content-type", "").lower()
            if "text/html" in content_type and res.text:
                dialog_neutralizer = (
                    "<script>"
                    "window.alert=function(){};"
                    "window.confirm=function(){return true;};"
                    "window.prompt=function(){return null;};"
                    "window.onbeforeunload=null;"
                    "try{if(window.top&&window.top!==window){window.top.alert=function(){};window.top.confirm=function(){return true;};}}catch(e){}"
                    "try{if(window.parent&&window.parent!==window){window.parent.alert=function(){};window.parent.confirm=function(){return true;};}}catch(e){}"
                    "</script>"
                )
                html_text = res.text
                m = re.search(r'(<head[^>]*>)', html_text, re.IGNORECASE)
                if m:
                    idx = m.end()
                    res.text = html_text[:idx] + dialog_neutralizer + html_text[idx:]
                else:
                    m = re.search(r'(<html[^>]*>)', html_text, re.IGNORECASE)
                    if m:
                        idx = m.end()
                        res.text = html_text[:idx] + dialog_neutralizer + html_text[idx:]
                    else:
                        res.text = dialog_neutralizer + html_text
        except Exception:
            pass

        # Verifica escopo se definido
        req_host = req.pretty_host.lower()
        if self.target_scope:
            in_scope = any(scope.lower() in req_host for scope in self.target_scope)
            if not in_scope:
                return

        # Filtro de arquivos/padrões ignorados configurados pelo usuário
        if is_ignored_url(req.url):
            return

        # Filtro de negócio: GET só é válido se tiver parâmetros reais após o endpoint
        if not has_valid_php_parameters(req.url, method=req.method):
            return

        # Monta entrada para o histórico
        headers_dict = dict(req.headers)
        res_headers_dict = dict(res.headers)

        body_str = req.get_text() if req.raw_content else ""

        routine_header = headers_dict.get("x-dast-routine") or headers_dict.get("X-DAST-Routine") or ""
        action_header = headers_dict.get("x-dast-action") or headers_dict.get("X-DAST-Action") or ""

        entry = {
            "method": req.method.upper(),
            "url": req.url,
            "path": req.path,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "request_headers": headers_dict,
            "request_body": body_str,
            "response_status": res.status_code,
            "response_headers": res_headers_dict,
            "routine": routine_header,
            "action_file": action_header
        }

        # Ignora recursos estáticos (.js, .css, imagens, etc.)
        if is_static_resource(entry):
            return

        self._record(entry, has_response=True)


class ProxyDaemon:
    def __init__(self, port=9507, target_scope=None, on_new_route=None):
        self.port = port
        self.target_scope = target_scope
        self.addon = DastCaptureAddon(target_scope=target_scope, on_new_route_callback=on_new_route)
        self.master = None
        self.thread = None
        self.ready_event = threading.Event()
        self.loop = None

    def start(self):
        def _run():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            try:
                async def _main():
                    opts = options.Options(listen_host="127.0.0.1", listen_port=self.port)
                    self.master = DumpMaster(opts, with_termlog=False, with_dumper=False)
                    self.master.addons.add(self.addon)
                    self.ready_event.set()
                    await self.master.run()

                self.loop.run_until_complete(_main())
            finally:
                try:
                    self.loop.close()
                except Exception:
                    pass

        self.thread = threading.Thread(target=_run, daemon=True)
        self.thread.start()
        self.ready_event.wait(timeout=5)
        log.info(f"[+] Proxy DAST iniciado em http://127.0.0.1:{self.port}")

    def stop(self):
        if self.master:
            try:
                self.master.shutdown()
            except Exception:
                pass
        if self.thread:
            self.thread.join(timeout=3)
        log.info(f"[+] Proxy DAST encerrado.")

    def export_campaign(self, output_file="logs/campaign.json", campaign_name="ecidade-dast", metadata=None):
        os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
        campaign = build_campaign(
            self.addon.history,
            name=campaign_name,
            scope=self.target_scope,
            include_static=False
        )
        if metadata:
            campaign["execution_metadata"] = metadata

        # Embute mapa de rotinas se gerado pelo crawler
        routines_map = {}
        if os.path.exists("logs/routines_map.json"):
            try:
                with open("logs/routines_map.json", "r", encoding="utf-8") as rf:
                    routines_map = json.load(rf)
            except Exception:
                pass
        if routines_map:
            campaign["routines_map"] = routines_map

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(campaign, f, indent=2, ensure_ascii=False)

        stats = campaign.get("stats", {})
        log.info(f"[+] Campanha exportada para {output_file}")
        log.info(f"    - Requisições capturadas: {stats.get('input', 0)}")
        log.info(f"    - Rotas testáveis: {stats.get('routes', 0)}")
        return campaign
