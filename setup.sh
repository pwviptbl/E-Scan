#!/usr/bin/env bash
# =============================================================================
#  Ecidade-DAST: Script de Setup e Instalação do Ambiente Isolado
# =============================================================================
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "=================================================================="
echo " 🛠️  CONFIGURANDO AMBIENTE ISOLADO ECIDADE-DAST"
echo "=================================================================="

# 1. Checa Python 3
if ! command -v python3 &>/dev/null; then
    echo "[-] Erro: python3 não encontrado no sistema."
    exit 1
fi

# 2. Checa Node / NPM
if ! command -v npm &>/dev/null; then
    echo "[-] Erro: npm não encontrado no sistema."
    exit 1
fi

# 3. Cria Virtualenv Python se não existir
if [ ! -d ".venv" ]; then
    echo "[+] Criando virtualenv Python em .venv..."
    python3 -m venv .venv
else
    echo "[✓] Virtualenv .venv já existente."
fi

# 4. Ativa e instala dependências Python
echo "[+] Instalando dependências Python (mitmproxy, click, requests)..."
source .venv/bin/activate
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
echo "[✓] Dependências Python instaladas com sucesso."

# 5. Instala dependências Node / Cypress
echo "[+] Verificando dependências Node.js / Cypress..."
if [ ! -d "node_modules" ] || [ ! -f "node_modules/.bin/cypress" ]; then
    npm install
else
    echo "[✓] Cypress já instalado no diretório local."
fi

# 6. Cria diretórios de trabalho caso não existam
mkdir -p logs reports cypress/screenshots cypress/videos

# 7. Configuração local do DefectDojo (se não existir)
if [ ! -f "config/defectdojo.json" ] && [ -f "config/defectdojo.example.json" ]; then
    echo "[+] Criando config/defectdojo.json a partir do modelo de exemplo..."
    cp config/defectdojo.example.json config/defectdojo.json
fi

echo "=================================================================="
echo " [✓] AMBIENTE PRONTO PARA EXECUÇÃO LOCAL OU CI/CD!"
echo " Para rodar manualmente:"
echo "   source .venv/bin/activate"
echo "   python cli.py run --help"
echo " Ou use o runner direto:"
echo "   ./run.sh --area \"Configuração\" --modulo \"Configuração\" --categoria \"Cadastros\""
echo "=================================================================="
