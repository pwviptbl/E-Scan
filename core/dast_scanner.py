"""
Motor de Varredura DAST (Ativa e Passiva) para o E-cidade
Executa testes de segurança nas rotas capturadas da campanha.
"""
import os
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

        if "sqli" in self.enabled_types:
            self.modules["SQLi"] = SqlInjectionModule()
        if "xss" in self.enabled_types:
            self.modules["XSS"] = XssModule()
        if "lfi" in self.enabled_types:
            self.modules["LFI"] = LfiModule()
        if "idor" in self.enabled_types:
            self.modules["IDOR"] = IdorModule()

        self.findings = []

    def scan_campaign(self, campaign_data, active_only=False):
        routes = campaign_data.get("routes", [])
        scan_label = "ATIVO (Apenas injeções)" if active_only else "COMPLETO (Ativo + Passivo)"
        print(f"\n[*] Iniciando auditoria DAST [{scan_label}] em {len(routes)} rotas testáveis...")

        for idx, route in enumerate(routes, 1):
            method = route.get("method", "GET").upper()
            url = route.get("url", "")
            print(f"[{idx}/{len(routes)}] {method} {url}")

            # 1. Auditoria Passiva de Headers e Cookies (se não for active_only)
            if not active_only:
                self._passive_audit(route)

            # 2. Auditoria Ativa (Fuzzing de Parâmetros)
            self._active_audit(route)

        return self.findings

    def _passive_audit(self, route):
        headers = {k.lower(): v for k, v in route.get("response_headers", {}).items()}
        url = route.get("url", "")

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
                "evidence": "X-Frame-Options e CSP ausentes",
                "description": "A aplicação não define restrições de frame-ancestors, permitindo embedding não autorizado em iframes de terceiros."
            })

    def _active_audit(self, route):
        url = route.get("url", "")
        method = route.get("method", "GET").upper()
        req_headers = route.get("request_headers", {})
        body = route.get("request_body", "")

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
                inj_point = {
                    "id": 1,
                    "location": "QUERY",
                    "param_name": param_name,
                    "parameter_name": param_name,
                    "original_value": orig_val
                }
                self._run_modules_on_point(request_node, inj_point)

        # Testa parâmetros de Form Body
        if self.param_location in ("all", "body", "body-query"):
            for param_name, values in body_params.items():
                orig_val = values[0] if values else ""
                inj_point = {
                    "id": 1,
                    "location": "BODY_FORM",
                    "param_name": param_name,
                    "parameter_name": param_name,
                    "original_value": orig_val
                }
                self._run_modules_on_point(request_node, inj_point)

    def _run_modules_on_point(self, request_node, inj_point):
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
                            "evidence": str(v.evidence)[:300],
                            "description": v.description
                        })
                        print(f"      [!] VULNERABILIDADE DETECTADA: [{v.severity}] {v.name} em {inj_point['param_name']}")
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

        content.append(f"## 2. Detalhamento dos Achados\n")
        if not self.findings:
            content.append(f"✅ Nenhuma vulnerabilidade ativa ou passiva detectada no escopo testado.\n")
        else:
            for idx, f in enumerate(self.findings, 1):
                content.append(f"### 2.{idx} [{f['severity'].upper()}] {f['title']}")
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
            89: "Utilizar Prepared Statements (PDO / parameterized queries). Sanitizar e tipar estritamente todos os parâmetros de entrada.",
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

            evidence_str = str(f.get("evidence", ""))
            full_description = (
                f"{f['description']}\n\n"
                f"**Endpoint:** `{f['method']} {f['url']}`\n"
                f"**Parâmetro:** `{param_str}`\n\n"
                f"**Evidência / Resposta do Servidor:**\n```text\n{evidence_str}\n```"
            )

            dojo_findings.append({
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
                "steps_to_reproduce": f"1. Enviar requisição {f['method']} para `{f['url']}`.\n2. Injetar payload de teste no parâmetro `{param_str}`.\n3. Observar quebra sintática de query / execução na resposta.",
                "severity_justification": f"Severidade {sev} baseada no impacto direto da falha {f['title']}.",
                "references": f"https://cwe.mitre.org/data/definitions/{cwe}.html" if cwe else ""
            })

        data = {"findings": dojo_findings}
        with open(output_path, "w", encoding="utf-8") as out:
            json.dump(data, out, indent=2, ensure_ascii=False)

        print(f"[+] Relatório DefectDojo gerado em: {output_path}")
        return output_path
