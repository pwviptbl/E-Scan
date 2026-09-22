#!/usr/bin/env python3
"""
=============================================================================
 Ecidade-DAST CLI: Dynamic Application Security Testing para o E-cidade
 Orquestra Cypress Headless + Proxy mitmproxy + Scanner Ativo/Passivo
=============================================================================
"""
import os
import re
import sys
import time
import json
import shutil
from datetime import datetime
import click
import subprocess
from urllib.parse import urlparse
from core.proxy_daemon import ProxyDaemon
from core.dast_scanner import DastScanner
from core.defectdojo_client import load_dojo_config, upload_scan_to_defectdojo

@click.group()
def main():
    """CLI do Ecidade-DAST para Auditoria Dinâmica e Pipelines CI/CD."""
    pass

@main.command("run")
@click.option("--url", default="http://localhost:8085/e-cidade-php74", help="URL base do E-cidade alvo.", show_default=True)
@click.option("--area", default="TRIBUTÁRIO", help="Área do menu para auditoria.", show_default=True)
@click.option("--modulo", default=None, help="Módulo específico dentro da área.")
@click.option("--categoria", default=None, help="Categoria (Cadastros, Consultas, etc.).")
@click.option("--subcategoria", default=None, help="Subcategoria do menu.")
@click.option("--rotina", default=None, help="Rotina específica.")
@click.option("--max-routines", default=0, type=int, help="Máximo de rotinas automáticas a testar (0 = todas).", show_default=True)
@click.option("--spec", default="cypress/e2e/dast_crawler.cy.js", help="Arquivo de teste Cypress a executar.", show_default=True)
@click.option("--port", default=9507, type=int, help="Porta local do proxy de captura.", show_default=True)
@click.option("--scan-mode", type=click.Choice(["batch", "live"]), default="batch", help="Modo de auditoria: batch ou live.", show_default=True)
@click.option("--types", default="sqli,xss", help="Módulos de auditoria ativa (sqli, xss, lfi, idor).", show_default=True)
@click.option("--params", type=click.Choice(["body", "body-query", "all"]), default="all", help="Onde injetar payloads.", show_default=True)
@click.option("--active-only", is_flag=True, default=False, help="Executa apenas testes ativos (ignora checagens passivas de cookies/headers).")
@click.option("--campaign-out", default=None, help="Arquivo JSON para exportação da campanha (padrão: nome gerado por data/escopo).")
@click.option("--report", default=None, help="Arquivo Markdown para o relatório final.")
@click.option("--dojo-product", default=None, help="Nome do produto no DefectDojo.")
@click.option("--dojo-engagement", default=None, help="ID numérico ou nome do engagement no DefectDojo (padrão: config/defectdojo.json).")
@click.option("--dojo-test-id", default=None, type=int, help="ID numérico do teste no DefectDojo para reimportar/atualizar.")
@click.option("--dojo-test-title", default=None, help="Título descritivo do teste no DefectDojo.")
@click.option("--dojo-upload", is_flag=True, default=False, help="Força envio ao DefectDojo usando config/defectdojo.json.")
@click.option("--fail-on-findings", is_flag=True, default=False, help="Retorna Exit Code 1 se encontrar vulnerabilidades Críticas/Altas (CI/CD).")
def run_dast(url, area, modulo, categoria, subcategoria, rotina, max_routines, spec, port, scan_mode, types, params, active_only, campaign_out, report, dojo_product, dojo_engagement, dojo_test_id, dojo_test_title, dojo_upload, fail_on_findings):
    """Executa o ciclo completo de DAST: sobe proxy, navega com Cypress, audita e gera relatório."""
    start_time = time.time()
    now_dt = datetime.now()
    timestamp_str = now_dt.strftime("%Y%m%d_%H%M%S")
    parsed_url = urlparse(url)
    host = parsed_url.hostname or "localhost"

    # Monta Slug do Escopo para nomeação clara dos arquivos
    slug_parts = [area]
    if modulo:
        slug_parts.append(modulo)
    if categoria:
        slug_parts.append(categoria)
    if subcategoria:
        slug_parts.append(subcategoria)
    if rotina:
        slug_parts.append(rotina)

    slug = "_".join(re.sub(r'[^a-zA-Z0-9_-]', '', p.replace(' ', '_')) for p in slug_parts if p)

    # Nomes com data/hora e flags
    actual_campaign_out = campaign_out or f"logs/campaign_{slug}_{timestamp_str}.json"
    actual_report = report or f"reports/relatorio_dast_{slug}_{timestamp_str}.md"

    # Dicionário de Metadados de Execução
    execution_flags = {
        "Data / Hora": now_dt.strftime("%Y-%m-%d %H:%M:%S"),
        "URL Alvo": url,
        "Área": area,
        "Módulo": modulo or "*",
        "Categoria": categoria or "*",
        "Subcategoria": subcategoria or "*",
        "Rotina": rotina or "(automático)",
        "Limite de Rotinas": max_routines if max_routines > 0 else "ilimitado",
        "Modo de Auditoria": scan_mode.upper(),
        "Testes Ativos": types.upper(),
        "Injeção em Parâmetros": params,
        "Arquivo Campanha": actual_campaign_out,
        "Arquivo Relatório": actual_report
    }

    click.echo(click.style("=" * 75, fg="cyan"))
    click.echo(click.style(" 🚀 INICIANDO ECIDADE-DAST (HEADLESS / CI-CD) ", bold=True, fg="cyan"))
    click.echo(click.style("=" * 75, fg="cyan"))
    click.echo(f"• Data/Hora: {execution_flags['Data / Hora']}")
    click.echo(f"• Alvo: {url}")
    click.echo(f"• Escopo: {' > '.join(slug_parts)}")
    click.echo(f"• Modo de Scan: {scan_mode.upper()} | Testes Ativos: {types.upper()}")
    click.echo(f"• Arquivo Campanha: {actual_campaign_out}")
    click.echo(f"• Arquivo Relatório: {actual_report}")
    click.echo(f"• Porta Proxy: {port}")

    # 1. Inicia Proxy Daemon em Background
    scanner = DastScanner(types=types, param_location=params)

    def on_live_route(entry):
        if scan_mode == "live":
            route = {
                "method": entry["method"],
                "url": entry["url"],
                "request_headers": entry["request_headers"],
                "request_body": entry["request_body"],
                "response_headers": entry.get("response_headers", {})
            }
            if not active_only:
                scanner._passive_audit(route)
            scanner._active_audit(route)

    proxy = ProxyDaemon(port=port, target_scope=[host], on_new_route=on_live_route if scan_mode == "live" else None)
    try:
        proxy.start()
    except Exception as e:
        click.echo(click.style(f"[!] Falha ao iniciar proxy: {e}", fg="red"))
        sys.exit(1)

    # 2. Executa Cypress Headless roteado pelo Proxy
    click.echo(click.style("\n[*] Disparando Cypress Headless para navegação no E-cidade...", fg="yellow"))
    env_vars = [
        f"PROXY_PORT={port}",
        f"AREA={area}",
        f"MAX_ROUTINES={max_routines}"
    ]
    if modulo:
        env_vars.append(f"MODULO={modulo}")
    if categoria:
        env_vars.append(f"CATEGORIA={categoria}")
    if subcategoria:
        env_vars.append(f"SUBCATEGORIA={subcategoria}")
    if rotina:
        env_vars.append(f"ROTINA={rotina}")

    cypress_cmd = [
        "npx", "cypress", "run",
        "--browser", "chrome",
        "--spec", spec,
        "--config", f"baseUrl={url}",
        "--env", ",".join(env_vars)
    ]

    cypress_env = os.environ.copy()
    cypress_env["HTTP_PROXY"] = f"http://127.0.0.1:{port}"
    cypress_env["HTTPS_PROXY"] = f"http://127.0.0.1:{port}"
    cypress_env["NO_PROXY"] = "<-loopback>"

    proc = subprocess.run(cypress_cmd, env=cypress_env, cwd=os.path.dirname(os.path.abspath(__file__)))
    if proc.returncode != 0:
        click.echo(click.style("[!] Aviso: Execução do Cypress terminou com código de erro ou asserção pendente.", fg="yellow"))
    else:
        click.echo(click.style("[✓] Navegação Cypress concluída com sucesso.", fg="green"))

    # 3. Finaliza Captura e Exporta Campanha (com Metadata completa)
    campaign = proxy.export_campaign(
        output_file=actual_campaign_out,
        campaign_name=f"dast_{slug}",
        metadata=execution_flags
    )
    proxy.stop()

    # Cria cópia estável para logs/campaign_latest.json
    try:
        shutil.copyfile(actual_campaign_out, "logs/campaign_latest.json")
    except Exception:
        pass

    # 4. Auditoria Ativa e Passiva (Modo Batch)
    if scan_mode == "batch":
        scanner.scan_campaign(campaign, active_only=active_only)

    # 5. Gera Relatório Final com Metadados e Flags
    report_file = scanner.generate_markdown_report(
        output_path=actual_report,
        metadata={
            "target": url,
            "scope": " > ".join(slug_parts),
            "flags": execution_flags
        }
    )

    # Cria cópia estável para reports/relatorio_dast_latest.md
    try:
        shutil.copyfile(actual_report, "reports/relatorio_dast_latest.md")
    except Exception:
        pass

    # 6. Exporta findings para o formato nativo do DefectDojo (JSON)
    actual_dojo = f"reports/defectdojo_findings_{slug}_{timestamp_str}.json"
    scanner.generate_defectdojo_report(output_path=actual_dojo)
    try:
        shutil.copyfile(actual_dojo, "reports/defectdojo_findings_latest.json")
    except Exception:
        pass

    dojo_conf = load_dojo_config()
    should_upload = dojo_upload or bool(dojo_product) or bool(dojo_engagement) or (dojo_test_id is not None) or dojo_conf.get("auto_upload", False)
    if should_upload:
        click.echo(click.style(f"\n[*] Processando envio dos achados para o DefectDojo...", fg="cyan"))

        # Monta Título e Descrição automáticos para o Teste no DefectDojo
        scope_hierarchy = [p for p in [area, modulo, categoria, subcategoria, rotina] if p]
        scope_title = " > ".join(scope_hierarchy) if scope_hierarchy else "Auditoria Geral"
        dojo_actual_title = dojo_test_title or f"DAST - {scope_title}"

        scope_desc_lines = [
            "Auditoria de Segurança Dinâmica (DAST) automatizada E-cidade.",
            "",
            "**Escopo Executado:**",
            f"- **Área:** {area}"
        ]
        if modulo:
            scope_desc_lines.append(f"- **Módulo:** {modulo}")
        if categoria:
            scope_desc_lines.append(f"- **Categoria:** {categoria}")
        if subcategoria:
            scope_desc_lines.append(f"- **Subcategoria:** {subcategoria}")
        if rotina:
            scope_desc_lines.append(f"- **Rotina:** {rotina}")
        else:
            scope_desc_lines.append("- **Rotinas:** Todas da categoria/módulo")

        dojo_actual_desc = "\n".join(scope_desc_lines)
        dojo_tags = [p for p in [area, modulo, categoria, subcategoria] if p] + ["DAST"]

        is_eng_id = dojo_engagement and str(dojo_engagement).isdigit()
        ok, res, mode = upload_scan_to_defectdojo(
            actual_dojo,
            product_name=dojo_product,
            engagement_name=dojo_engagement if (dojo_engagement and not is_eng_id) else None,
            engagement_id=int(dojo_engagement) if is_eng_id else None,
            test_id=dojo_test_id,
            test_title=dojo_actual_title,
            test_description=dojo_actual_desc,
            tags=dojo_tags,
            config=dojo_conf
        )
        if ok:
            t_id = res.get("test_id") or res.get("test") if isinstance(res, dict) else "OK"
            t_url = res.get("test_url", "") if isinstance(res, dict) else ""
            click.echo(click.style(f"[✓] Achados enviados ao DefectDojo com sucesso!", fg="green", bold=True))
            click.echo(click.style(f"    • Modo: {mode}", fg="cyan"))
            click.echo(click.style(f"    • Test ID: {t_id}", fg="green", bold=True))
            if t_url:
                click.echo(click.style(f"    • Link direto: {t_url}", fg="bright_blue", bold=True))
        else:
            click.echo(click.style(f"[!] Falha ao enviar para o DefectDojo ({mode}): {res}", fg="yellow"))

    elapsed = round(time.time() - start_time, 2)
    click.echo(click.style(f"\n[✓] Ciclo DAST concluído em {elapsed}s.", bold=True, fg="green"))

    # 7. Avaliação de saída para CI/CD
    crit = sum(1 for f in scanner.findings if f["severity"].lower() in ("crítica", "critical", "alta", "high"))
    if fail_on_findings and crit > 0:
        click.echo(click.style(f"[FAIL] {crit} vulnerabilidades Críticas/Altas encontradas. Barrando Pipeline!", fg="red", bold=True))
        sys.exit(1)

    sys.exit(0)

@main.command("scan")
@click.option("--campaign", default="logs/campaign_latest.json", help="Arquivo JSON de campanha já capturada.", show_default=True)
@click.option("--types", default="sqli,xss", help="Módulos de auditoria ativa (sqli, xss, lfi, idor).", show_default=True)
@click.option("--params", type=click.Choice(["body", "body-query", "all"]), default="all", help="Onde injetar payloads.", show_default=True)
@click.option("--active-only", is_flag=True, default=True, help="Executa apenas testes ativos (ignora passivos de cookies/headers).", show_default=True)
@click.option("--report", default=None, help="Arquivo Markdown para o relatório final.")
@click.option("--dojo-product", default=None, help="Nome do produto no DefectDojo.")
@click.option("--dojo-engagement", default=None, help="ID numérico ou nome do engagement no DefectDojo (padrão: config/defectdojo.json).")
@click.option("--dojo-test-id", default=None, type=int, help="ID numérico do teste no DefectDojo para reimportar/atualizar.")
@click.option("--dojo-test-title", default=None, help="Título descritivo do teste no DefectDojo.")
@click.option("--dojo-upload", is_flag=True, default=False, help="Força envio ao DefectDojo usando config/defectdojo.json.")
@click.option("--fail-on-findings", is_flag=True, default=False, help="Retorna Exit Code 1 se encontrar vulnerabilidades Críticas/Altas.")
def scan_campaign_cmd(campaign, types, params, active_only, report, dojo_product, dojo_engagement, dojo_test_id, dojo_test_title, dojo_upload, fail_on_findings):
    """Executa auditoria diretamente sobre uma campanha salva, sem rodar o Cypress."""
    start_time = time.time()
    now_dt = datetime.now()
    timestamp_str = now_dt.strftime("%Y%m%d_%H%M%S")

    if not os.path.exists(campaign):
        click.echo(click.style(f"[-] Erro: Arquivo de campanha '{campaign}' não encontrado.", fg="red"))
        sys.exit(1)

    with open(campaign, "r", encoding="utf-8") as f:
        campaign_data = json.load(f)

    meta = campaign_data.get("metadata", {})
    scope_str = meta.get("Escopo", "Campanha Salva")
    target_url = meta.get("URL Alvo", "http://localhost:8085/e-cidade-php74")

    clean_scope = re.sub(r'[^a-zA-Z0-9_-]', '', scope_str.replace(' > ', '_').replace(' ', '_'))
    actual_report = report or f"reports/relatorio_dast_{clean_scope}_{timestamp_str}.md"
    actual_dojo = f"reports/defectdojo_findings_{clean_scope}_{timestamp_str}.json"

    click.echo(click.style("=" * 75, fg="yellow"))
    click.echo(click.style(" 🔍 EXECUTANDO SCAN DAST EM CAMPANHA SALVA ", bold=True, fg="yellow"))
    click.echo(click.style("=" * 75, fg="yellow"))
    click.echo(f"• Arquivo Campanha: {campaign}")
    click.echo(f"• Alvo: {target_url}")
    click.echo(f"• Escopo: {scope_str}")
    click.echo(f"• Modo Ativo Estrito: {'SIM' if active_only else 'NÃO'}")
    click.echo(f"• Módulos Ativos: {types.upper()}")
    click.echo(f"• Relatório Destino: {actual_report}")

    scanner = DastScanner(types=types, param_location=params)
    scanner.scan_campaign(campaign_data, active_only=active_only)

    report_file = scanner.generate_markdown_report(
        output_path=actual_report,
        metadata={
            "target": target_url,
            "scope": scope_str,
            "flags": {
                "Data / Hora": now_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "Campanha Fonte": campaign,
                "Auditoria": "Apenas Ativa (Injeções)" if active_only else "Completa (Ativa + Passiva)",
                "Módulos Testados": types.upper(),
                "Injeção em Parâmetros": params,
                "Arquivo Relatório": actual_report
            }
        }
    )

    try:
        shutil.copyfile(actual_report, "reports/relatorio_dast_latest.md")
    except Exception:
        pass

    # Exporta para DefectDojo
    scanner.generate_defectdojo_report(output_path=actual_dojo)
    try:
        shutil.copyfile(actual_dojo, "reports/defectdojo_findings_latest.json")
    except Exception:
        pass

    dojo_conf = load_dojo_config()
    should_upload = dojo_upload or bool(dojo_product) or bool(dojo_engagement) or (dojo_test_id is not None) or dojo_conf.get("auto_upload", False)
    if should_upload:
        click.echo(click.style(f"\n[*] Processando envio dos achados para o DefectDojo...", fg="cyan"))

        dojo_actual_title = dojo_test_title or f"DAST - {scope_str}"
        dojo_actual_desc = f"Auditoria de Segurança Dinâmica (DAST) automatizada E-cidade.\n\n**Escopo Executado:**\n- **Trilha / Escopo:** {scope_str}\n- **Campanha Fonte:** `{campaign}`"
        raw_tags = [s.strip() for s in scope_str.split(">")] + ["DAST"]
        dojo_tags = [t for t in raw_tags if t]

        is_eng_id = dojo_engagement and str(dojo_engagement).isdigit()
        ok, res, mode = upload_scan_to_defectdojo(
            actual_dojo,
            product_name=dojo_product,
            engagement_name=dojo_engagement if (dojo_engagement and not is_eng_id) else None,
            engagement_id=int(dojo_engagement) if is_eng_id else None,
            test_id=dojo_test_id,
            test_title=dojo_actual_title,
            test_description=dojo_actual_desc,
            tags=dojo_tags,
            config=dojo_conf
        )
        if ok:
            t_id = res.get("test_id") or res.get("test") if isinstance(res, dict) else "OK"
            t_url = res.get("test_url", "") if isinstance(res, dict) else ""
            click.echo(click.style(f"[✓] Achados enviados ao DefectDojo com sucesso!", fg="green", bold=True))
            click.echo(click.style(f"    • Modo: {mode}", fg="cyan"))
            click.echo(click.style(f"    • Test ID: {t_id}", fg="green", bold=True))
            if t_url:
                click.echo(click.style(f"    • Link direto: {t_url}", fg="bright_blue", bold=True))
        else:
            click.echo(click.style(f"[!] Falha ao enviar para o DefectDojo ({mode}): {res}", fg="yellow"))

    elapsed = round(time.time() - start_time, 2)
    click.echo(click.style(f"\n[✓] Auditoria concluída em {elapsed}s.", bold=True, fg="green"))

    crit = sum(1 for f in scanner.findings if f["severity"].lower() in ("crítica", "critical", "alta", "high"))
    if fail_on_findings and crit > 0:
        click.echo(click.style(f"[FAIL] {crit} vulnerabilidades Críticas/Altas encontradas. Barrando Pipeline!", fg="red", bold=True))
        sys.exit(1)

    sys.exit(0)

@main.command("dojo-import")
@click.option("--file", "findings_file", default="reports/defectdojo_findings_latest.json", help="Arquivo JSON de findings para o DefectDojo.", show_default=True)
@click.option("--product", default=None, help="Nome do produto no DefectDojo (padrão: config/defectdojo.json).")
@click.option("--engagement", default=None, help="ID numérico ou nome do engagement (padrão: config/defectdojo.json).")
@click.option("--test-id", default=None, type=int, help="ID numérico do teste no DefectDojo para reimportar/atualizar.")
@click.option("--test-title", default=None, help="Título do teste no DefectDojo.")
def dojo_import_cmd(findings_file, product, engagement, test_id, test_title):
    """Importa ou reimporta um relatório de findings JSON diretamente no DefectDojo."""
    if not os.path.exists(findings_file):
        click.echo(click.style(f"[-] Erro: Arquivo '{findings_file}' não encontrado.", fg="red"))
        sys.exit(1)

    conf = load_dojo_config()
    target_test_id = test_id if test_id is not None else conf.get("test_id")
    target_product = product or conf.get("product_name") or "E-cidade"
    target_engagement = engagement or conf.get("engagement_name") or "Auditoria DAST E-cidade"
    target_engagement_id = int(engagement) if (engagement and str(engagement).isdigit()) else conf.get("engagement_id")
    target_test_title = test_title or conf.get("test_title")

    click.echo(f"[*] Processando envio de '{findings_file}' para o DefectDojo...")
    if target_test_id:
        click.echo(f"• Modo: Reimport (Atualização do Test ID: {target_test_id})")
    else:
        click.echo(f"• Modo: Importação Inicial (Criação de Novo Teste)")
        if target_engagement_id:
            click.echo(f"• Engagement ID: {target_engagement_id}")
        else:
            click.echo(f"• Produto: {target_product}")
            click.echo(f"• Engagement: {target_engagement}")
        if target_test_title:
            click.echo(f"• Título do Teste: {target_test_title}")

    ok, res, mode = upload_scan_to_defectdojo(
        findings_file,
        product_name=target_product,
        engagement_name=target_engagement if not target_engagement_id else None,
        engagement_id=target_engagement_id,
        test_id=target_test_id,
        test_title=target_test_title,
        config=conf
    )
    if ok:
        res_test = res.get("test_id") or res.get("test") if isinstance(res, dict) else "OK"
        t_url = res.get("test_url", "") if isinstance(res, dict) else ""
        click.echo(click.style(f"[✓] Envio concluído com sucesso no DefectDojo!", fg="green", bold=True))
        click.echo(click.style(f"    • Modo: {mode}", fg="cyan"))
        click.echo(click.style(f"    • Test ID: {res_test}", fg="green", bold=True))
        if t_url:
            click.echo(click.style(f"    • Link direto: {t_url}", fg="bright_blue", bold=True))
    else:
        click.echo(click.style(f"[-] Falha no envio para o DefectDojo ({mode}): {res}", fg="red", bold=True))
        sys.exit(1)

if __name__ == "__main__":
    main()
