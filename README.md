# E-Scan (Ecidade-DAST Headless & CI/CD)

Ferramenta autônoma e leve de **Testes Dinâmicos de Segurança de Aplicação (DAST)** desenvolvida sob medida para a arquitetura desktop, multi-iframe e modais Prototype.js do **E-cidade**.

Orquestra **Cypress Headless** (para navegação hierárquica pelo DOM, preenchimento dinâmico de formulários e acionamento de rotinas) com um **Proxy Daemon Headless** (`mitmproxy`) e um **Scanner Ativo/Passivo** compatível com o schema do `ProxyHunter`.

---

## 🚀 Instalação e Configuração

O projeto é 100% autônomo, não depende de caminhos externos e possui um script de setup turnkey que prepara todo o ambiente isolado:

```bash
cd /home/dbseller/Modelos/ecidade-dast

# Cria o virtualenv (.venv), instala bibliotecas Python e pacotes do Cypress:
./setup.sh
```

---

## 💻 Modos de Execução

### 1. Ciclo Completo DAST: Navegação Cypress + Captura + Auditoria (`run`)

Utilize o wrapper executável `./run.sh` ou invoque `cli.py run`. O wrapper ativa o `.venv` automaticamente:

#### A. Descoberta Automática de Rotinas dentro de uma Categoria:
```bash
./run.sh \
  --url http://localhost:8085/e-cidade-php74 \
  --area "Configuração" \
  --modulo "Configuração" \
  --categoria "Cadastros" \
  --max-routines 5
```

#### B. Auditoria em uma Rotina Específica:
```bash
./run.sh \
  --url http://localhost:8085/e-cidade-php74 \
  --area "Configuração" \
  --modulo "Configuração" \
  --categoria "Cadastros" \
  --rotina "Usuário Interno"
```

#### C. Auditoria Estritamente Ativa (`--active-only`):
Ignora verificações passivas (cookies HttpOnly/SameSite, Clickjacking) e foca apenas em injeções reais (SQLi, XSS, LFI, IDOR):
```bash
./run.sh \
  --url http://localhost:8085/e-cidade-php74 \
  --area "Configuração" \
  --modulo "Configuração" \
  --categoria "Cadastros" \
  --active-only
```

---

### 2. Auditoria Direta de Campanha Salva (`scan`)

Executa o scanner DAST diretamente sobre um arquivo JSON de campanha capturada anteriormente, **sem abrir o navegador e sem iniciar o proxy**:

```bash
# Audita a última campanha capturada apenas com testes ativos:
.venv/bin/python cli.py scan --campaign logs/campaign_latest.json --active-only

# Audita uma campanha específica testando apenas SQL Injection:
.venv/bin/python cli.py scan --campaign logs/campaign_Configurao_Cadastros_20260910_104101.json --types sqli --active-only
```

---

## 🛡️ Filtros e Regras Anti-Ruído

### 1. Arquivo de Exclusões (`config/ignore_patterns.txt`)
O arquivo `config/ignore_patterns.txt` permite listar URLs, arquivos e padrões que o proxy deve descartar em tempo real:
- RPCs de interface como `con4_dbhelp.RPC.php`
- Skins e imagens dinâmicas como `skins/img.php`
- Requisições de templates de menu como `getMenuArquivo`
- Recursos estáticos (`.png`, `.jpg`, `.css`, `.js`, `.woff`, etc.)

Você pode adicionar novos arquivos ao `config/ignore_patterns.txt` linha por linha a qualquer momento.

### 2. Validação de Parâmetros Reais em Requisições GET
Requisições GET onde a query string serve apenas para indicar o arquivo a ser carregado (ex: `getMenuArquivo/?file=...`) são automaticamente ignoradas. O scanner só audita requisições GET que contenham parâmetros reais de negócio (ex: `action=...&iInstitId=...&iModuloId=...`).

---

## 🏷️ Nomenclatura dos Logs e Relatórios

Cada execução gera arquivos persistentes com **timestamp e as flags de escopo utilizadas**, preservando o histórico de auditoria:

- **Campanhas HTTP:** `logs/campaign_{Area}_{Modulo}_{Categoria}_{DataHora}.json`
  - Cópia mais recente: `logs/campaign_latest.json`
  - Armazena requisições limpas no padrão de schema do `ProxyHunter`.
  - Injeta o bloco `"execution_metadata"` com todos os parâmetros utilizados.
- **Relatórios Markdown:** `reports/relatorio_dast_{Area}_{Modulo}_{Categoria}_{DataHora}.md`
  - Cópia mais recente: `reports/relatorio_dast_latest.md`
  - Contém cabeçalho técnico com data/hora, alvo, escopo, parâmetros e tabela detalhada de vulnerabilidades com evidências e payloads.
- **Relatórios DefectDojo (JSON):** `reports/defectdojo_findings_{Area}_{Modulo}_{Categoria}_{DataHora}.json`
  - Cópia mais recente: `reports/defectdojo_findings_latest.json`
  - Formato nativo compatível com o scanner **Generic Findings Import** do OWASP DefectDojo.

---

## 🎯 Integração com OWASP DefectDojo

O Ecidade-DAST exporta nativamente todos os achados para o formato **Generic Findings Import** do DefectDojo (incluindo severidade, CWE, mitigação, endpoints, parâmetros e evidências de erro/injeção).

### 1. Envio Automático no Final do Scan (`--dojo-product`)
Adicione `--dojo-product "<NomeDoProduto>"` para publicar os achados diretamente na API do DefectDojo:

```bash
./run.sh \
  --url http://localhost:8085/e-cidade-php74 \
  --area "Configuração" \
  --modulo "Configuração" \
  --categoria "Cadastros" \
  --types sqli \
  --active-only \
  --dojo-product "E-cidade"
```

### 2. Importação Manual ou em Pipelines (`dojo-import`)
Para enviar qualquer relatório de achados JSON existente diretamente para um produto do DefectDojo:

```bash
.venv/bin/python cli.py dojo-import \
  --file reports/defectdojo_findings_latest.json \
  --product "E-cidade" \
  --engagement "Auditoria DAST E-cidade"
```

---

## ⚙️ Tabela Completa de Parâmetros da CLI

### Comando `run` (Navegação + Auditoria)
| Flag | Descrição | Padrão |
| :--- | :--- | :--- |
| `--url` | URL base do E-cidade | `http://localhost:8085/e-cidade-php74` |
| `--area` | Área do menu principal (ex: Configuração, Tributário) | `TRIBUTÁRIO` |
| `--modulo` | Módulo específico | `None` (primeiro módulo) |
| `--categoria` | Categoria do menu (ex: Cadastros, Consultas) | `None` |
| `--subcategoria` | Subcategoria de agrupamento | `None` |
| `--rotina` | Rotina específica (se omitido, descobre automático) | `None` |
| `--max-routines` | Limite de rotinas na descoberta automática (0 = todas) | `0` (todas) |
| `--active-only` | Executa apenas testes ativos (ignora passivos) | `False` |
| `--scan-mode` | Modo de auditoria (`batch` ou `live`) | `batch` |
| `--types` | Módulos ativos separados por vírgula (`sqli,xss,lfi,idor`) | `sqli,xss` |
| `--params` | Onde injetar payloads (`body`, `body-query`, `all`) | `all` |
| `--port` | Porta local do Proxy Daemon | `9507` |
| `--campaign-out` | Caminho do arquivo JSON de campanha | `None` (auto-gerado) |
| `--report` | Caminho do relatório Markdown final | `None` (auto-gerado) |
| `--dojo-upload` | Força envio ao DefectDojo usando `config/defectdojo.json` | `False` |
| `--dojo-test-id` | ID numérico do teste no DefectDojo para reimportar/atualizar | `None` (usa config) |
| `--dojo-test-title` | Título descritivo do teste no DefectDojo | `None` (usa config) |
| `--dojo-product` | Nome do produto no DefectDojo | `None` (usa config) |
| `--fail-on-findings` | Retorna Exit Code 1 se encontrar falhas Altas/Críticas (CI/CD) | `False` |

### Comando `scan` (Auditoria Direta de Campanha Salva)
| Flag | Descrição | Padrão |
| :--- | :--- | :--- |
| `--campaign` | Arquivo JSON da campanha a auditar | `logs/campaign_latest.json` |
| `--types` | Módulos ativos separados por vírgula (`sqli,xss,lfi,idor`) | `sqli,xss` |
| `--params` | Onde injetar payloads (`body`, `body-query`, `all`) | `all` |
| `--active-only` | Executa apenas testes ativos (ignora passivos) | `True` |
| `--report` | Caminho do relatório Markdown de saída | `None` (auto-gerado) |
| `--dojo-upload` | Força envio ao DefectDojo usando `config/defectdojo.json` | `False` |
| `--dojo-test-id` | ID numérico do teste no DefectDojo para reimportar/atualizar | `None` (usa config) |
| `--dojo-test-title` | Título descritivo do teste no DefectDojo | `None` (usa config) |
| `--dojo-product` | Nome do produto no DefectDojo | `None` (usa config) |
| `--fail-on-findings` | Retorna Exit Code 1 se encontrar falhas Altas/Críticas (CI/CD) | `False` |

### Comando `dojo-import` (Upload / Reimport Manual para DefectDojo)
| Flag | Descrição | Padrão |
| :--- | :--- | :--- |
| `--file` | Arquivo JSON formatado para o DefectDojo | `reports/defectdojo_findings_latest.json` |
| `--test-id` | ID do Teste para **Reimportar/Atualizar** | `None` (lê de `config/defectdojo.json`) |
| `--test-title` | Título do Teste para vincular na importação | `None` (lê de `config/defectdojo.json`) |
| `--product` | Nome do produto no DefectDojo | `None` (lê de `config/defectdojo.json`) |
| `--engagement` | Nome do engagement | `None` (lê de `config/defectdojo.json`) |

---

## ⚙️ Configuração Centralizada do DefectDojo (`config/defectdojo.json`)

Copie o arquivo de exemplo `config/defectdojo.example.json` para `config/defectdojo.json` e configure a URL, credenciais e o teste de destino:

```json
{
  "defectdojo": {
    "url": "http://127.0.0.1:8080",
    "token": "SEU_TOKEN_DEFECTDOJO_AQUI",
    "product_name": "E-cidade",
    "engagement_name": "Auditoria DAST E-cidade",
    "test_id": null,
    "test_title": "DAST - Auditoria Dinâmica E-cidade",
    "auto_upload": false,
    "active": true,
    "verified": true,
    "close_old_findings": false,
    "environment": "Development"
  }
}
```

### Como funciona o envio para o Teste:
1. **Reimportar em Teste Existente (`test_id`)**:
   - Se `test_id` estiver preenchido (ex: `79`), o DAST utiliza o endpoint `/api/v2/reimport-scan/`.
   - O DefectDojo atualiza as vulnerabilidades existentes, fecha as mitigadas e deduplica sem poluir o histórico.
2. **Criar ou Vincular por Título (`test_title`)**:
   - Se `test_id` for `null`, o DAST utiliza `/api/v2/import-scan/` criando/vinculando um teste com o título definido em `test_title` no Produto e Engagement informados.
3. **Upload Automático (`auto_upload: true`)**:
   - Se ativado, qualquer execução do `./run.sh` enviará automaticamente o relatório ao DefectDojo no final da auditoria.

