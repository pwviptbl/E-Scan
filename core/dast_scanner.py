"""
Motor de Varredura DAST (Ativa e Passiva) para o E-cidade
Executa testes de segurança nas rotas capturadas da campanha.
"""
import os
import re
import sys
import json
import time
import requests
from urllib.parse import urlparse, parse_qs
from core.vulnerability import Vulnerability
from scanners.sqli_module import SqlInjectionModule
from scanners.xss_module import XssModule
from scanners.lfi_module import LfiModule
from scanners.idor_module import IdorModule

class DastScanner:
    def __init__(self, types="sqli,xss", param_location="all"):
        self.enabled_types = [t.strip().lower() for t in types.split(",")]
        self.param_location = param_location.lower()
        self.modules = {}
        self.routines_map = {}
        self.ignore_params = self._load_ignore_params()

        if "sqli" in self.enabled_types:
            self.modules["SQLi"] = SqlInjectionModule()
        if "xss" in self.enabled_types:
            self.modules["XSS"] = XssModule()
        if "lfi" in self.enabled_types:
            self.modules["LFI"] = LfiModule()
        if "idor" in self.enabled_types:
            self.modules["IDOR"] = IdorModule()

        self.findings = []

    def _load_ignore_params(self):
        """Carrega lista de substrings de parâmetros a ignorar no scan ativo."""
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "ignore_params.txt")
        patterns = []
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        patterns.append(line.lower())
        return patterns

    def _is_ignored_param(self, param_name: str) -> bool:
        """Retorna True se o parâmetro deve ser ignorado no scan."""
        name_lower = param_name.lower()
        return any(pat in name_lower for pat in self.ignore_params)

    def _is_json_string(self, val):
        """Verifica se uma string representa um JSON válido (objeto ou lista)."""
        if not val or not isinstance(val, str):
            return None
        s = val.strip()
        if (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]")):
            try:
                parsed = json.loads(s)
                if isinstance(parsed, (dict, list)):
                    return parsed
            except Exception:
                pass
        return None

    def _extract_json_leaves(self, data, prefix=""):
        """Extrai recursivamente caminhos folha de um JSON (dot notation) e valores originais."""
        leaves = []
        if isinstance(data, dict):
            for k, v in data.items():
                current = f"{prefix}.{k}" if prefix else str(k)
                if isinstance(v, (dict, list)):
                    leaves.extend(self._extract_json_leaves(v, current))
                else:
                    leaves.append((current, v, str(k)))
        elif isinstance(data, list):
            for idx, item in enumerate(data):
                current = f"{prefix}.{idx}" if prefix else str(idx)
                if isinstance(item, (dict, list)):
                    leaves.extend(self._extract_json_leaves(item, current))
                else:
                    leaves.append((current, item, str(idx)))
        return leaves
    def resolve_routine(self, route):
        """Identifica com precisão a rotina, sub-rotina ou tela do E-cidade associada à requisição."""
        # 1. Metadado explícito presente na rota
        if route.get("routine"):
            return route.get("routine"), route.get("action_file", "")

        # 2. Header de rastreabilidade injetado pelo Cypress (x-dast-routine)
        headers = route.get("request_headers", {})
        for k, v in headers.items():
            if k.lower() == "x-dast-routine" and v:
                action_h = headers.get("x-dast-action") or headers.get("X-DAST-Action") or ""
                return v, action_h

        url = route.get("url", "")
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)

        action = qs.get("action", [""])[0]
        if not action:
            php_match = re.search(r"/([a-zA-Z0-9_.]+\.php)", parsed.path)
            if php_match:
                action = php_match.group(1)

        # 3. Consulta no mapa de rotinas diretamente pela action da URL
        if self.routines_map and action:
            info = self.routines_map.get(action)
            if not info and "?" in action:
                info = self.routines_map.get(action.split("?")[0])
            if not info:
                base_act = action.split("?")[0]
                info = self.routines_map.get(base_act)
            if isinstance(info, dict):
                return info.get("breadcrumb", action), action
            elif isinstance(info, str):
                return info, action

        # 4. Rastreamento inteligente via Referer para RPCs, submits e chamadas Ajax
        referer = ""
        for k, v in headers.items():
            if k.lower() == "referer" and v:
                referer = v
                break

        if referer and self.routines_map:
            ref_parsed = urlparse(referer)
            ref_qs = parse_qs(ref_parsed.query)
            ref_action = ref_qs.get("action", [""])[0]
            if not ref_action:
                ref_match = re.search(r"/([a-zA-Z0-9_.]+\.php)", ref_parsed.path)
                if ref_match:
                    ref_action = ref_match.group(1)

            if ref_action:
                ref_info = self.routines_map.get(ref_action)
                if not ref_info and "?" in ref_action:
                    ref_info = self.routines_map.get(ref_action.split("?")[0])
                if not ref_info:
                    ref_info = self.routines_map.get(ref_action.split("?")[0])

                if ref_info:
                    breadcrumb = ref_info.get("breadcrumb", ref_action) if isinstance(ref_info, dict) else ref_info
                    action_display = f"{ref_action} (RPC: {action})" if action and action != ref_action else (action or ref_action)
                    return breadcrumb, action_display

        # 5. Endpoints estruturais bem conhecidos do E-cidade
        if "extension/desktop/Menu/getModulos" in parsed.path:
            return "Menu Principal > Seleção de Módulos", ""
        if "extension/desktop/Menu/getItensMenu" in parsed.path:
            return "Menu Principal > Itens de Menu", ""
        if "extension/desktop/Menu/getAreas" in parsed.path:
            return "Menu Principal > Áreas", ""
        if "extension/desktop/desktop" in parsed.path:
            return "Desktop / Painel de Trabalho", ""
        if "v4/login" in parsed.path:
            return "Autenticação / Login", ""

        if action:
            return f"Rotina ({action})", action

        return "Geral / Infraestrutura", ""

    def scan_campaign(self, campaign_data, active_only=False):
        routes = campaign_data.get("routes", [])
        scan_label = "ATIVO (Apenas injeções)" if active_only else "COMPLETO (Ativo + Passivo)"
        print(f"\n[*] Iniciando auditoria DAST [{scan_label}] em {len(routes)} rotas testáveis...")

        # Carrega mapa de rotinas da campanha ou do disco
        self.routines_map = campaign_data.get("routines_map") or {}
        if not self.routines_map and os.path.exists("logs/routines_map.json"):
            try:
                with open("logs/routines_map.json", "r", encoding="utf-8") as f:
                    self.routines_map = json.load(f)
            except Exception:
                pass

        for idx, route in enumerate(routes, 1):
            method = route.get("method", "GET").upper()
            url = route.get("url", "")
            routine, action_file = self.resolve_routine(route)
            route["routine"] = routine
            route["action_file"] = action_file

            routine_display = f" | Rotina: {routine}" if routine else ""
            print(f"[{idx}/{len(routes)}] {method} {url}{routine_display}")

            # 1. Auditoria Passiva de Headers e Cookies (se não for active_only)
            if not active_only:
                self._passive_audit(route)

            # 2. Auditoria Ativa (Fuzzing de Parâmetros)
            self._active_audit(route)

        return self.findings

    def _passive_audit(self, route):
        headers = {k.lower(): v for k, v in route.get("response_headers", {}).items()}
        url = route.get("url", "")
        routine = route.get("routine", "Geral")
        action_file = route.get("action_file", "")

        # Cookie Security
        cookies = headers.get("set-cookie", "")
        if cookies and ("phpsessid" in cookies.lower() or "ecidadewindow" in cookies.lower()):
            if "httponly" not in cookies.lower():
                self.findings.append({
                    "title": "Cookie de Sessão sem flag HttpOnly",
                    "severity": "Média",
                    "type": "CWE-1004",
                    "url": url,
                    "method": route.get("method"),
                    "param": "Set-Cookie",
                    "routine": routine,
                    "action_file": action_file,
                    "evidence": cookies,
                    "description": "O cookie de sessão do PHP/E-cidade não possui a diretiva HttpOnly, permitindo roubo de sessão via XSS."
                })
            if "samesite" not in cookies.lower():
                self.findings.append({
                    "title": "Cookie de Sessão sem flag SameSite",
                    "severity": "Baixa",
                    "type": "CWE-1275",
                    "url": url,
                    "method": route.get("method"),
                    "param": "Set-Cookie",
                    "routine": routine,
                    "action_file": action_file,
                    "evidence": cookies,
                    "description": "Cookie de sessão desprotegido contra CSRF cross-origin."
                })

        # Anti-Clickjacking
        if "x-frame-options" not in headers and "content-security-policy" not in headers:
            self.findings.append({
                "title": "Ausência de Cabeçalho Anti-Clickjacking (X-Frame-Options/CSP)",
                "severity": "Baixa",
                "type": "CWE-1021",
                "url": url,
                "method": route.get("method"),
                "param": "Headers",
                "routine": routine,
                "action_file": action_file,
                "evidence": "X-Frame-Options e CSP ausentes",
                "description": "A aplicação não define restrições de frame-ancestors, permitindo embedding não autorizado em iframes de terceiros."
            })

    def _active_audit(self, route):
        url = route.get("url", "")
        method = route.get("method", "GET").upper()
        req_headers = route.get("request_headers", {})
        body = route.get("request_body", "")
        routine = route.get("routine", "Geral")
        action_file = route.get("action_file", "")

        request_node = {
            "id": 1,
            "method": method,
            "url": url,
            "headers": json.dumps(req_headers),
            "request_body_blob": body
        }

        # Extrai parâmetros da Query String
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        # Extrai parâmetros do Body
        body_params = {}
        if body and "application/x-www-form-urlencoded" in req_headers.get("content-type", req_headers.get("Content-Type", "")):
            body_params = parse_qs(body)
        elif body and "=" in str(body):
            body_params = parse_qs(str(body))

        # Testa parâmetros de Query
        if self.param_location in ("all", "body-query", "query"):
            for param_name, values in query_params.items():
                orig_val = values[0] if values else ""
                parsed_json = self._is_json_string(orig_val)
                if parsed_json is not None:
                    # É um container JSON na query string (ex: ?json={...})
                    leaves = self._extract_json_leaves(parsed_json)
                    for json_path, leaf_val, key_name in leaves:
                        if self._is_ignored_param(key_name):
                            print(f"   -> [Skip] Chave JSON ignorada (ignore_params): '{param_name} -> {json_path}'")
                            continue
                        inj_point = {
                            "id": 1,
                            "location": "QUERY_JSON",
                            "param_name": f"{param_name} -> {json_path}",
                            "parameter_name": f"{param_name} -> {json_path}",
                            "container_parameter": param_name,
                            "json_path": json_path,
                            "original_value": str(leaf_val) if leaf_val is not None else ""
                        }
                        self._run_modules_on_point(request_node, inj_point, routine=routine, action_file=action_file)
                else:
                    if self._is_ignored_param(param_name):
                        print(f"   -> [Skip] Parâmetro ignorado (ignore_params): '{param_name}'")
                        continue
                    inj_point = {
                        "id": 1,
                        "location": "QUERY",
                        "param_name": param_name,
                        "parameter_name": param_name,
                        "original_value": orig_val
                    }
                    self._run_modules_on_point(request_node, inj_point, routine=routine, action_file=action_file)

        # Testa parâmetros de Form Body
        if self.param_location in ("all", "body", "body-query"):
            for param_name, values in body_params.items():
                orig_val = values[0] if values else ""
                parsed_json = self._is_json_string(orig_val)
                if parsed_json is not None:
                    # É um container JSON no formulário (ex: json={...})
                    leaves = self._extract_json_leaves(parsed_json)
                    for json_path, leaf_val, key_name in leaves:
                        if self._is_ignored_param(key_name):
                            print(f"   -> [Skip] Chave JSON ignorada (ignore_params): '{param_name} -> {json_path}'")
                            continue
                        inj_point = {
                            "id": 1,
                            "location": "BODY_FORM_JSON",
                            "param_name": f"{param_name} -> {json_path}",
                            "parameter_name": f"{param_name} -> {json_path}",
                            "container_parameter": param_name,
                            "json_path": json_path,
                            "original_value": str(leaf_val) if leaf_val is not None else ""
                        }
                        self._run_modules_on_point(request_node, inj_point, routine=routine, action_file=action_file)
                else:
                    if self._is_ignored_param(param_name):
                        print(f"   -> [Skip] Parâmetro ignorado (ignore_params): '{param_name}'")
                        continue
                    inj_point = {
                        "id": 1,
                        "location": "BODY_FORM",
                        "param_name": param_name,
                        "parameter_name": param_name,
                        "original_value": orig_val
                    }
                    self._run_modules_on_point(request_node, inj_point, routine=routine, action_file=action_file)

            # Caso o body seja um JSON bruto (application/json)
            if not body_params and body:
                raw_body_str = body.decode('utf-8', errors='ignore') if isinstance(body, bytes) else str(body)
                parsed_raw_json = self._is_json_string(raw_body_str)
                if parsed_raw_json is not None:
                    leaves = self._extract_json_leaves(parsed_raw_json)
                    for json_path, leaf_val, key_name in leaves:
                        if self._is_ignored_param(key_name):
                            print(f"   -> [Skip] Chave JSON ignorada (ignore_params): 'JSON -> {json_path}'")
                            continue
                        inj_point = {
                            "id": 1,
                            "location": "BODY_JSON",
                            "param_name": f"JSON -> {json_path}",
                            "parameter_name": f"JSON -> {json_path}",
                            "json_path": json_path,
                            "original_value": str(leaf_val) if leaf_val is not None else ""
                        }
                        self._run_modules_on_point(request_node, inj_point, routine=routine, action_file=action_file)



    def _run_modules_on_point(self, request_node, inj_point, routine="Geral", action_file=""):
        print(f"   -> [Ativo] Testando {inj_point['location']}: '{inj_point['param_name']}'...")
        for mod_name, mod_instance in self.modules.items():
            try:
                vulns = mod_instance.run_test(request_node, inj_point, oast_client=None)
                if vulns:
                    for v in vulns:
                        self.findings.append({
                            "title": v.name,
                            "severity": v.severity,
                            "type": mod_name,
                            "url": request_node["url"],
                            "method": request_node["method"],
                            "param": inj_point["param_name"],
                            "routine": routine,
                            "action_file": action_file,
                            "evidence": str(v.evidence)[:300],
                            "description": v.description
                        })
                        print(f"      [!] VULNERABILIDADE DETECTADA: [{v.severity}] {v.name} em {inj_point['param_name']} (Rotina: {routine})")
            except Exception as e:
                pass

    def generate_markdown_report(self, output_path="reports/relatorio_dast.md", metadata=None):
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        meta = metadata or {}
        now = time.strftime("%Y-%m-%d %H:%M:%S")

        crit = sum(1 for f in self.findings if f["severity"].lower() == "crítica" or f["severity"].lower() == "critical")
        high = sum(1 for f in self.findings if f["severity"].lower() == "alta" or f["severity"].lower() == "high")
        med = sum(1 for f in self.findings if f["severity"].lower() == "média" or f["severity"].lower() == "medium")
        low = sum(1 for f in self.findings if f["severity"].lower() == "baixa" or f["severity"].lower() == "low")

        content = []
        content.append(f"# Relatório de Auditoria DAST - E-cidade\n")
        content.append(f"**Data da Execução:** {now}  ")
        content.append(f"**Alvo:** {meta.get('target', 'E-cidade Local')}  ")
        content.append(f"**Escopo:** {meta.get('scope', 'Geral')}  ")

        flags = meta.get("flags", {})
        if flags:
            content.append(f"\n### Parâmetros e Flags da Execução:")
            for k, v in flags.items():
                content.append(f"- **{k}:** `{v}`")

        content.append(f"\n## 1. Resumo Executivo\n")
        content.append(f"| Severidade | Quantidade |")
        content.append(f"| :--- | :--- |")
        content.append(f"| 🔴 Crítica | {crit} |")
        content.append(f"| 🟠 Alta | {high} |")
        content.append(f"| 🟡 Média | {med} |")
        content.append(f"| 🔵 Baixa | {low} |")
        content.append(f"| **Total** | **{len(self.findings)}** |\n")

        # Tabela consolidada por rotina/tela
        routine_stats = {}
        for f in self.findings:
            r = f.get("routine") or "Geral"
            act = f.get("action_file") or "-"
            key = (r, act)
            if key not in routine_stats:
                routine_stats[key] = {"crítica": 0, "alta": 0, "média": 0, "baixa": 0, "total": 0}
            sev = f.get("severity", "").lower()
            if sev in ("crítica", "critical"):
                routine_stats[key]["crítica"] += 1
            elif sev in ("alta", "high"):
                routine_stats[key]["alta"] += 1
            elif sev in ("média", "media", "medium"):
                routine_stats[key]["média"] += 1
            elif sev in ("baixa", "low"):
                routine_stats[key]["baixa"] += 1
            routine_stats[key]["total"] += 1

        if routine_stats:
            content.append(f"### 1.1 Resumo Consolidado por Rotina / Tela:")
            content.append(f"| Rotina / Tela | Arquivo (Action) | 🔴 Crítica | 🟠 Alta | 🟡 Média | 🔵 Baixa | **Total** |")
            content.append(f"| :--- | :--- | :---: | :---: | :---: | :---: | :---: |")
            for (r, act), c in sorted(routine_stats.items(), key=lambda x: x[1]["total"], reverse=True):
                content.append(f"| {r} | `{act}` | {c['crítica']} | {c['alta']} | {c['média']} | {c['baixa']} | **{c['total']}** |")
            content.append("")

        content.append(f"## 2. Detalhamento dos Achados\n")
        if not self.findings:
            content.append(f"✅ Nenhuma vulnerabilidade ativa ou passiva detectada no escopo testado.\n")
        else:
            for idx, f in enumerate(self.findings, 1):
                content.append(f"### 2.{idx} [{f['severity'].upper()}] {f['title']}")
                content.append(f"- **Rotina / Tela:** `{f.get('routine', 'Geral')}`")
                if f.get("action_file"):
                    content.append(f"- **Arquivo (Action):** `{f['action_file']}`")
                content.append(f"- **Endpoint:** `{f['method']} {f['url']}`")
                content.append(f"- **Parâmetro:** `{f['param']}`")
                content.append(f"- **Tipo/CWE:** {f['type']}")
                content.append(f"- **Descrição:** {f['description']}")
                content.append(f"- **Evidência:**\n```text\n{f['evidence']}\n```\n")

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(content))

        print(f"\n[+] Relatório DAST gerado em: {output_path}")
        return output_path

    def generate_defectdojo_report(self, output_path="reports/defectdojo_findings.json"):
        """Gera arquivo JSON compatível com o formato nativo 'Generic Findings Import' do DefectDojo."""
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        today = time.strftime("%Y-%m-%d")

        severity_map = {
            "crítica": "Critical",
            "critical": "Critical",
            "alta": "High",
            "high": "High",
            "média": "Medium",
            "media": "Medium",
            "medium": "Medium",
            "baixa": "Low",
            "low": "Low",
            "informativa": "Info",
            "info": "Info"
        }

        cwe_map = {
            "sqli": 89,
            "xss": 79,
            "lfi": 22,
            "idor": 639,
            "cwe-1004": 1004,
            "cwe-1021": 1021,
            "cwe-1275": 1275
        }

        mitigation_map = {
            89: "Valide o tipo da entrada e utilize o db_query_params.",
            79: "Aplicar encoding contextual de saída (htmlspecialchars com ENT_QUOTES | ENT_HTML5) e implementar Content-Security-Policy (CSP).",
            22: "Validar nomes de arquivos com whitelist rigorosa e utilizar basename() para impedir path traversal.",
            639: "Validar se o usuário autenticado possui autorização e controle de acesso explícito sobre o identificador do registro.",
            1004: "Configurar a flag 'HttpOnly' nos cookies de sessão (session.cookie_httponly = 1 no php.ini).",
            1021: "Implementar o cabeçalho 'X-Frame-Options: SAMEORIGIN' ou a diretiva CSP 'frame-ancestors 'self''.",
            1275: "Configurar a flag 'SameSite=Lax' ou 'SameSite=Strict' em todos os cookies de sessão."
        }

        dojo_findings = []
        for f in self.findings:
            sev = severity_map.get(f.get("severity", "").lower(), "Medium")
            vuln_type = str(f.get("type", "")).lower()
            cwe = cwe_map.get(vuln_type, 0)
            if cwe == 0:
                for k, v in cwe_map.items():
                    if k in vuln_type or k in f.get("title", "").lower():
                        cwe = v
                        break

            mitigation = mitigation_map.get(cwe, "Revisar e corrigir a validação/higienização dos parâmetros de entrada.")
            param_str = f.get("param", "")
            title_suffix = f" no parâmetro '{param_str}'" if param_str else ""

            routine_str = f.get("routine", "")
            action_str = f.get("action_file", "")
            routine_block = f"**Rotina / Tela:** `{routine_str}`\n" if routine_str else ""
            if action_str:
                routine_block += f"**Arquivo (Action):** `{action_str}`\n"

            if ".rpc.php" in f['url'].lower() or "rpc" in f['url'].lower():
                endpoint_label = f"**Endpoint (Chamada RPC):** `{f['method']} {f['url']}`\n"
            else:
                endpoint_label = f"**Endpoint:** `{f['method']} {f['url']}`\n"

            evidence_str = str(f.get("evidence", ""))
            full_description = (
                f"{f['description']}\n\n"
                f"{routine_block}"
                f"{endpoint_label}"
                f"**Parâmetro:** `{param_str}`\n\n"
                f"**Evidência / Resposta do Servidor:**\n```text\n{evidence_str}\n```"
            )

            step_1 = f"1. Acessar a rotina '{routine_str}'"
            if action_str:
                step_1 += f" (Tela/Arquivo: `{action_str}`)"
            step_1 += "."

            if ".rpc.php" in f['url'].lower() or "rpc" in f['url'].lower():
                step_2 = f"2. A rotina dispara a requisição em segundo plano ({f['method']} `{f['url']}`)."
            else:
                step_2 = f"2. Enviar requisição {f['method']} para `{f['url']}`."

            steps_reproduce = (
                f"{step_1}\n"
                f"{step_2}\n"
                f"3. Injetar payload de teste no parâmetro `{param_str}`.\n"
                f"4. Observar quebra sintática de query / comportamento diferencial no backend."
            )

            finding_dict = {
                "title": f"{f['title']}{title_suffix}",
                "date": today,
                "severity": sev,
                "description": full_description,
                "mitigation": mitigation,
                "impact": f"Possível exploração de {f['title']} comprometendo a confidencialidade e integridade da aplicação.",
                "cwe": cwe,
                "active": True,
                "verified": True,
                "false_p": False,
                "steps_to_reproduce": steps_reproduce,
                "severity_justification": f"Severidade {sev} baseada no impacto direto da falha {f['title']}.",
                "references": f"https://cwe.mitre.org/data/definitions/{cwe}.html" if cwe else ""
            }
            if action_str:
                finding_dict["file_path"] = action_str

            dojo_findings.append(finding_dict)

        data = {"findings": dojo_findings}
        with open(output_path, "w", encoding="utf-8") as out:
            json.dump(data, out, indent=2, ensure_ascii=False)

        print(f"[+] Relatório DefectDojo gerado em: {output_path}")
        return output_path
