"""
Testes unitários para core.request_rebuilder.

Cobrem a reconstrução de requisições em cada tipo de ponto de injeção,
sem tráfego de rede (apenas PreparedRequest). O caso multipart existe
especificamente para proteger contra a regressão do `re` não importado,
que fazia o ramo BODY_FORM/multipart quebrar silenciosamente.

Execute com:
    .venv/bin/python -m unittest discover -s tests
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.request_rebuilder import rebuild_attack_request


def make_node(method="GET", url="http://alvo/x.php", headers=None, body=""):
    return {
        "id": 1,
        "method": method,
        "url": url,
        "headers": json.dumps(headers or {}),
        "request_body_blob": body,
    }


class TestRebuildQuery(unittest.TestCase):
    def test_query_param_injected(self):
        node = make_node(url="http://alvo/x.php?id=10&ok=1")
        point = {"id": 1, "location": "QUERY", "parameter_name": "id", "original_value": "10"}
        prepared = rebuild_attack_request(node, point, "10'")
        self.assertIn("id=10%27", prepared.url)
        self.assertIn("ok=1", prepared.url)

    def test_query_json_leaf_injected(self):
        node = make_node(url='http://alvo/x.php?json={"a":"1","b":"2"}')
        point = {
            "id": 1,
            "location": "QUERY_JSON",
            "parameter_name": "json -> a",
            "container_parameter": "json",
            "json_path": "a",
            "original_value": "1",
        }
        prepared = rebuild_attack_request(node, point, "PWN")
        self.assertIn("PWN", prepared.url)


class TestRebuildBodyForm(unittest.TestCase):
    def test_urlencoded_body_injected(self):
        node = make_node(
            method="POST",
            url="http://alvo/x.php",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body="nome=abc&idade=30",
        )
        point = {"id": 1, "location": "BODY_FORM", "parameter_name": "nome", "original_value": "abc"}
        prepared = rebuild_attack_request(node, point, "abc'")
        self.assertIn(b"nome=abc%27", prepared.body if isinstance(prepared.body, bytes) else prepared.body.encode())

    def test_multipart_body_does_not_crash_and_injects(self):
        """Regressão: ramo multipart usava re.search sem `import re`."""
        boundary = "----pxhBoundary"
        body = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="nome"\r\n\r\n'
            "abc\r\n"
            f"--{boundary}--\r\n"
        )
        node = make_node(
            method="POST",
            url="http://alvo/x.php",
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            body=body,
        )
        point = {"id": 1, "location": "BODY_FORM", "parameter_name": "nome", "original_value": "abc"}
        prepared = rebuild_attack_request(node, point, "PWN")
        out = prepared.body if isinstance(prepared.body, str) else prepared.body.decode("utf-8", "ignore")
        self.assertIn("PWN", out)


class TestRebuildBodyJson(unittest.TestCase):
    def test_json_body_leaf_injected(self):
        node = make_node(
            method="POST",
            url="http://alvo/x.php",
            headers={"Content-Type": "application/json"},
            body='{"filtro": {"nome": "abc"}}',
        )
        point = {
            "id": 1,
            "location": "BODY_JSON",
            "parameter_name": "filtro.nome",
            "json_path": "filtro.nome",
            "original_value": "abc",
        }
        prepared = rebuild_attack_request(node, point, "PWN")
        out = prepared.body if isinstance(prepared.body, str) else prepared.body.decode("utf-8", "ignore")
        self.assertIn("PWN", out)


if __name__ == "__main__":
    unittest.main()
