"""
Configuração central de logging do Ecidade-DAST.

Separação de responsabilidades:
- A camada de apresentação do CLI (cli.py) continua usando `click.echo`.
- O motor (scanner, proxy) usa este logger para diagnóstico, com controle
  de verbosidade e registro persistente em arquivo.

Uso:
    from core.logging_config import setup_logging, get_logger
    setup_logging(verbose=True)          # uma vez, no início do comando
    log = get_logger()
    log.info("mensagem")
"""
import logging
import os
import sys

LOGGER_NAME = "ecidade_dast"
_CONFIGURED = False


def setup_logging(verbose=False, log_file="logs/dast.log"):
    """Configura o logger do motor. Idempotente: recria handlers só na 1ª vez."""
    global _CONFIGURED
    console_level = logging.DEBUG if verbose else logging.INFO
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.DEBUG)

    if _CONFIGURED:
        for h in logger.handlers:
            if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler):
                h.setLevel(console_level)
        return logger

    logger.handlers.clear()
    logger.propagate = False

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(console_level)
    console.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(console)

    try:
        os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(file_handler)
    except Exception:
        # Falha ao abrir arquivo de log não deve derrubar o scan.
        pass

    _CONFIGURED = True
    return logger


def get_logger():
    """Retorna o logger do motor (configure antes com setup_logging)."""
    return logging.getLogger(LOGGER_NAME)
