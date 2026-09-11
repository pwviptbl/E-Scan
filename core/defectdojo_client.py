"""
Módulo de Integração com o OWASP DefectDojo.
Suporta importação inicial (import-scan) e reimportação contínua (reimport-scan).
"""
import os
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
        "engagement_name": "Auditoria DAST E-cidade",
        "test_id": None,
        "test_title": "DAST - Auditoria Dinâmica E-cidade",
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
    test_id=None,
    test_title=None,
    config=None
):
    """
    Envia findings para o DefectDojo.
    - Se 'test_id' estiver configurado, usa /api/v2/reimport-scan/ para atualizar o teste específico.
    - Se 'test_id' não estiver configurado, usa /api/v2/import-scan/ vinculando ao produto/engagement e test_title.
    """
    conf = config or load_dojo_config()

    url = (conf.get("url") or "http://127.0.0.1:8080").rstrip("/")
    token = conf.get("token") or os.environ.get("DEFECTDOJO_TOKEN", "")

    if not token:
        return False, "Token do DefectDojo não configurado (defina em config/defectdojo.json ou na variável DEFECTDOJO_TOKEN)", "Autenticação Ausente"

    prod = product_name or conf.get("product_name") or "E-cidade"
    eng = engagement_name or conf.get("engagement_name") or "Auditoria DAST E-cidade"
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
            # CENÁRIO 2: Import no Produto / Engagement (com ou sem test_title)
            else:
                endpoint = f"{url}/api/v2/import-scan/"
                data = {
                    "product_name": prod,
                    "scan_type": "Generic Findings Import",
                    "engagement_name": eng,
                    "active": active,
                    "verified": verified,
                    "auto_create_context": "true",
                    "close_old_findings": close_old
                }
                if t_title:
                    data["test_title"] = t_title
                mode = f"Import no Produto '{prod}' > Engagement '{eng}' (Teste: '{t_title or 'Novo'}')"

            res = requests.post(endpoint, headers=headers, data=data, files=files, timeout=60)
            if res.status_code >= 400:
                return False, f"Status {res.status_code}: {res.text}", mode
            return True, res.json(), mode

    except Exception as e:
        return False, str(e), "Erro de Conexão"
