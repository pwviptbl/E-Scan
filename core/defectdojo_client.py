"""
Módulo de Integração com o OWASP DefectDojo.
Suporta importação inicial (import-scan) e reimportação contínua (reimport-scan).
"""
import os
import re
import json
import requests

CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "defectdojo.json")

def load_dojo_config(custom_path=None):
    """Carrega as configurações do DefectDojo a partir de arquivo JSON."""
    path = custom_path or CONFIG_PATH
    default_conf = {
        "url": os.environ.get("DEFECTDOJO_URL", "http://127.0.0.1:8080"),
        "token": os.environ.get("DEFECTDOJO_TOKEN", ""),
        "product_name": "E-cidade",
        "engagement_id": None,
        "engagement_name": "Auditoria DAST E-cidade",
        "test_id": None,
        "test_title": None,
        "auto_upload": False,
        "active": True,
        "verified": True,
        "close_old_findings": False,
        "environment": "Development"
    }

    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                dojo_data = data.get("defectdojo", data)
                default_conf.update(dojo_data)
        except Exception:
            pass

    return default_conf

def upload_scan_to_defectdojo(
    file_path,
    product_name=None,
    engagement_name=None,
    engagement_id=None,
    test_id=None,
    test_title=None,
    test_description=None,
    tags=None,
    config=None
):
    """
    Envia findings para o DefectDojo.
    - Se 'test_id' estiver configurado/fornecido, usa /api/v2/reimport-scan/ para atualizar o teste específico.
    - Se 'test_id' não for fornecido, cria um Novo Teste via /api/v2/import-scan/ dentro do engagement_id (ou engagement_name/product).
    - Aplica test_title, test_description e tags automaticamente ao teste criado.
    - Retorna status booleano, dict com dados (incluindo test_id e test_url) e modo de operação.
    """
    conf = config or load_dojo_config()

    url = (conf.get("url") or "http://127.0.0.1:8080").rstrip("/")
    token = conf.get("token") or os.environ.get("DEFECTDOJO_TOKEN", "")

    if not token:
        return False, "Token do DefectDojo não configurado (defina em config/defectdojo.json ou na variável DEFECTDOJO_TOKEN)", "Autenticação Ausente"

    prod = product_name or conf.get("product_name") or "E-cidade"
    eng_name = engagement_name or conf.get("engagement_name") or "Auditoria DAST E-cidade"
    eng_id = engagement_id if engagement_id is not None else conf.get("engagement_id")
    t_id = test_id if test_id is not None else conf.get("test_id")
    t_title = test_title or conf.get("test_title")

    active = "true" if conf.get("active", True) else "false"
    verified = "true" if conf.get("verified", True) else "false"
    close_old = "true" if conf.get("close_old_findings", False) else "false"

    headers = {"Authorization": f"Token {token}"}

    try:
        with open(file_path, "rb") as f:
            files = {"file": f}

            # CENÁRIO 1: Reimport para Teste Específico existente
            if t_id:
                endpoint = f"{url}/api/v2/reimport-scan/"
                data = {
                    "test": int(t_id),
                    "scan_type": "Generic Findings Import",
                    "active": active,
                    "verified": verified,
                    "close_old_findings": close_old
                }
                mode = f"Reimport no Teste #{t_id}"
            # CENÁRIO 2: Import Criando Novo Teste no Engagement (por ID ou por Nome)
            else:
                endpoint = f"{url}/api/v2/import-scan/"
                data = {
                    "scan_type": "Generic Findings Import",
                    "active": active,
                    "verified": verified,
                    "close_old_findings": close_old
                }

                if eng_id:
                    data["engagement"] = int(eng_id)
                    eng_label = f"Engagement #{eng_id}"
                else:
                    data["product_name"] = prod
                    data["engagement_name"] = eng_name
                    data["auto_create_context"] = "true"
                    eng_label = f"Produto '{prod}' > Engagement '{eng_name}'"

                if t_title:
                    data["test_title"] = t_title

                mode = f"Novo Teste no {eng_label} (Título: '{t_title or 'Automático'}')"

            res = requests.post(endpoint, headers=headers, data=data, files=files, timeout=60)
            if res.status_code >= 400:
                return False, f"Status {res.status_code}: {res.text}", mode

            res_data = res.json()
            created_test_id = res_data.get("test") or res_data.get("test_id") or t_id
            if created_test_id:
                res_data["test_id"] = int(created_test_id)
                res_data["test_url"] = f"{url}/test/{created_test_id}"

                # Enriquece o teste recém-criado com Descrição detalhada e Tags do Escopo
                patch_payload = {}
                if test_description:
                    patch_payload["description"] = test_description
                if tags:
                    clean_tags = []
                    for tag in tags:
                        clean_t = re.sub(r'[^a-zA-Z0-9_\-]', '_', str(tag)).strip('_')
                        if clean_t and clean_t not in clean_tags:
                            clean_tags.append(clean_t)
                    if clean_tags:
                        patch_payload["tags"] = clean_tags

                if patch_payload and not t_id:
                    try:
                        requests.patch(
                            f"{url}/api/v2/tests/{created_test_id}/",
                            headers={"Authorization": f"Token {token}", "Content-Type": "application/json"},
                            json=patch_payload,
                            timeout=30
                        )
                    except Exception:
                        pass

            return True, res_data, mode

    except Exception as e:
        return False, str(e), "Erro de Conexão"
