import re
from typing import List, Any
import requests
from core.request_rebuilder import rebuild_attack_request
from core.vulnerability import Vulnerability
from scanners.IScanModule import IScanModule, RequestNode, InjectionPoint

OASTClient = Any

class XssModule(IScanModule):
    """Detecta XSS refletido (HTML body, Script breakout e atributos) com validacao contextual."""

    MARKER = "PXH_XSS_TEST"

    def run_test(
        self,
        request_node: RequestNode,
        injection_point: InjectionPoint,
        oast_client: OASTClient
    ) -> List[Vulnerability]:
        if injection_point['location'] not in {'QUERY', 'BODY_FORM', 'BODY_JSON'}:
            return []

        session = requests.Session()
        session.verify = False
        session.timeout = 5

        # Payloads cobrindo:
        # 1. Breakout de tag <script> (vital para rotinas E-cidade dentro de blocos JS)
        # 2. Contexto HTML padrao
        # 3. Breakout de atributos de tag HTML
        test_payloads = [
            f"</script><svg/onload=alert(1)>{self.MARKER}",
            f"<svg/onload=alert(1)>{self.MARKER}",
            f"\"><svg/onload=alert(1)>{self.MARKER}"
        ]

        for payload in test_payloads:
            try:
                request_to_send = rebuild_attack_request(request_node, injection_point, payload)
                response = session.send(request_to_send, timeout=session.timeout, allow_redirects=False)
                res_text = response.text or ""

                if self.MARKER in res_text:
                    idx = res_text.find(self.MARKER)
                    snippet = res_text[max(0, idx - 70):min(len(res_text), idx + len(self.MARKER) + 50)]

                    # Valida se os caracteres essenciais da tag (<, >) foram refletidos sem sanitizacao HTML
                    # Se foram convertidos para &lt; ou &gt;, nao e executavel
                    if ("<svg" in snippet or "</script>" in snippet) and ("&lt;svg" not in snippet):
                        return [
                            Vulnerability(
                                name="Cross-Site Scripting (Reflected)",
                                severity="Medium",
                                description=(
                                    "XSS refletido detectado por reflexão desprotegida de tags HTML/Script no response. "
                                    f"Parâmetro '{injection_point['parameter_name']}'."
                                ),
                                evidence=f"Payload: {payload}\nSnippet Refletido:\n{snippet.strip()}",
                                request_node_id=request_node['id'],
                                injection_point_id=injection_point['id']
                            )
                        ]
            except requests.exceptions.RequestException:
                pass
            except Exception:
                pass

        return []
