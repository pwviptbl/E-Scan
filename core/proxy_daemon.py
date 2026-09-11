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
from urllib.parse import urlparse
from mitmproxy import options, http
from mitmproxy.tools.dump import DumpMaster
from core.campaign import build_campaign, is_static_resource
from core.ignore_rules import is_ignored_url, has_valid_php_parameters

class DastCaptureAddon:
    def __init__(self, target_scope=None, on_new_route_callback=None):
        self.target_scope = target_scope or []
        self.history = []
        self.lock = threading.Lock()
        self.on_new_route_callback = on_new_route_callback

    def request(self, flow: http.HTTPFlow):
        pass

    def response(self, flow: http.HTTPFlow):
        req = flow.request
        res = flow.response

        # Ignora se não houver resposta
        if not res:
            return

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

        entry = {
            "id": len(self.history) + 1,
            "method": req.method.upper(),
            "url": req.url,
            "path": req.path,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "request_headers": headers_dict,
            "request_body": body_str,
            "response_status": res.status_code,
            "response_headers": res_headers_dict,
        }

        # Ignora recursos estáticos (.js, .css, imagens, etc.)
        if is_static_resource(entry):
            return

        with self.lock:
            self.history.append(entry)

        if self.on_new_route_callback:
            try:
                self.on_new_route_callback(entry)
            except Exception as e:
                pass


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
        print(f"[+] Proxy DAST iniciado em http://127.0.0.1:{self.port}")

    def stop(self):
        if self.master:
            try:
                self.master.shutdown()
            except Exception:
                pass
        if self.thread:
            self.thread.join(timeout=3)
        print(f"[+] Proxy DAST encerrado.")

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

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(campaign, f, indent=2, ensure_ascii=False)

        stats = campaign.get("stats", {})
        print(f"[+] Campanha exportada para {output_file}")
        print(f"    - Requisições capturadas: {stats.get('input', 0)}")
        print(f"    - Rotas testáveis: {stats.get('routes', 0)}")
        return campaign
