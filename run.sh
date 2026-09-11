#!/usr/bin/env bash
# =============================================================================
#  Ecidade-DAST: Runner Wrapper que ativa o venv e executa a CLI
# =============================================================================
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

# Se o venv não existir, roda o setup primeiro
if [ ! -f ".venv/bin/activate" ]; then
    echo "[!] Ambiente .venv não encontrado. Executando setup.sh inicial..."
    ./setup.sh
fi

source .venv/bin/activate
exec python cli.py run "$@"
