"""
Módulo de regras e filtros de URLs/arquivos ignorados no Proxy DAST.
Carrega padrões configuráveis a partir de config/ignore_patterns.txt.
"""
import os
from urllib.parse import urlparse, parse_qs

IGNORE_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "ignore_patterns.txt")

def load_ignore_patterns():
    patterns = []
    if os.path.exists(IGNORE_FILE):
        with open(IGNORE_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line.lower())
    return patterns

def is_ignored_url(url_or_entry):
    """
    Verifica se a URL deve ser descartada pelo proxy com base na lista de ignorados.

    Importante: padrões de EXTENSÃO (que começam com ".", ex: .js, .css) são
    casados apenas no FIM do PATH, nunca como substring da URL inteira. Caso
    contrário, um valor de query como funcao_js=parent.js_preenche faria a rota
    func_*.php (lookup de chave estrangeira do E-cidade) ser descartada como se
    fosse um arquivo .js estático. Padrões nomeados (ex: con4_dbhelp.RPC.php)
    continuam sendo casados como substring do path.
    """
    if isinstance(url_or_entry, dict):
        url = str(url_or_entry.get("url") or "")
    else:
        url = str(url_or_entry or "")

    path_lower = (urlparse(url).path or "").lower()
    patterns = load_ignore_patterns()

    for pat in patterns:
        if pat.startswith("."):
            if path_lower.endswith(pat):
                return True
        elif pat in path_lower:
            return True

    return False

def has_valid_php_parameters(url, method="GET"):
    """
    Valida regra de negócio do E-cidade:
    Para requisições GET, só é válido testar quando há parâmetros reais após o endpoint PHP
    ou rota de ação de janela, e não quando é apenas carregamento estático de arquivo.
    """
    if method.upper() != "GET":
        return True

    parsed = urlparse(url)
    query_params = parse_qs(parsed.query, keep_blank_values=True)

    if not query_params:
        return False

    # Se a query só tiver 'file' apontando para um .php (ex: getMenuArquivo/?file=...), é template/menu estático
    if len(query_params) == 1 and "file" in query_params:
        file_val = query_params["file"][0] if query_params["file"] else ""
        if file_val.endswith(".php") or file_val.endswith(".png") or file_val.endswith(".jpg"):
            return False

    return True
