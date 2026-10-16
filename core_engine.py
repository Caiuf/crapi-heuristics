import time
from typing import Optional
from zscore_detector import ZScoreVolumetricDetector
from payload_detector import PayloadAnomalyDetector

class APIHeuristicEngine:
    def __init__(self):
        self.volumetric_engine = ZScoreVolumetricDetector(
            window_size=10,
            threshold=3.5,
            general_hard_cap=80,
            auth_hard_cap=15,
            bola_unique_uri_cap=20
        )
        self.payload_engine = PayloadAnomalyDetector(
            max_bytes=32768,
            max_depth=8,
            score_threshold=4
        )

    def inspect_request(
        self,
        ip: str,
        current_req_count: Optional[int],
        payload_str: str,
        endpoint: str = "/identity/api/v2/user/profile",
        endpoint_type: str = "profile",
        unique_uris_count: int = 1,
        headers: Optional[dict[str, str]] = None,
        enable_volumetric: bool = True,
        enable_payload: bool = True
    ) -> dict:
        start_ns = time.perf_counter_ns()

        if enable_volumetric:
            vol_res = self.volumetric_engine.analyze_traffic(
                ip=ip,
                current_req_count=current_req_count,
                endpoint=endpoint,
                unique_uris_count=unique_uris_count
            )
            if vol_res["is_anomalous"]:
                end_ns = time.perf_counter_ns()
                return self._build_response(False, "Volumétrica/Comportamental", vol_res["reason"], start_ns, end_ns)

        if enable_payload:
            pay_res = self.payload_engine.analyze_payload(
                payload_str=payload_str,
                endpoint_type=endpoint_type,
                uri_and_query=endpoint,
                headers=headers
            )
            if pay_res["is_anomalous"]:
                end_ns = time.perf_counter_ns()
                return self._build_response(False, "Payload/Semântica", pay_res["reason"], start_ns, end_ns)

        end_ns = time.perf_counter_ns()
        return self._build_response(True, "N/A", "Requisição Legítima", start_ns, end_ns)

    @staticmethod
    def _build_response(is_allowed: bool, blocked_by: str, reason: str, start_ns: int, end_ns: int) -> dict:
        latency_ms = (end_ns - start_ns) / 1_000_000.0
        return {
            "is_allowed": is_allowed,
            "blocked_by_module": blocked_by,
            "reason": reason,
            "latency_ms": round(latency_ms, 4)
        }


if __name__ == "__main__":
    engine = APIHeuristicEngine()
    print("\n--- Iniciando Firewall Heurístico Refatorado (Bateria de Validação) ---")

    test_cases = [
        (
            "TESTE 1 - Tráfego Normal (Com texto contendo palavra 'select' legítima)",
            "192.168.1.10", 5,
            '{"name": "João Silva", "email": "joao@empresa.com", "age": 28}',
            "/identity/api/v2/user/profile", "profile", 1
        ),
        (
            "TESTE 2 - Ataque XSS Aninhado (Sub-objeto JSON que antes passava invisível)",
            "192.168.1.15", 8,
            '{"name": "Teste", "email": "teste@teste.com", "metadata": {"bio": "<script>alert(1)</script>"}}',
            "/identity/api/v2/user/profile", "profile", 1
        ),
        (
            "TESTE 3 - Ataque Volumétrico em IP Inédito (Cold Start Brute Force - 150 req/min)",
            "192.168.1.20", 150,
            '{"name": "Admin", "email": "admin@empresa.com"}',
            "/identity/api/auth/login", "profile", 1
        ),
        (
            "TESTE 4 - SQL Injection por Tautologia (' OR 1=1) em campo válido",
            "192.168.1.25", 4,
            '{"name": "Admin\' OR 1=1 --", "email": "admin@banco.com"}',
            "/identity/api/v2/user/profile", "profile", 1
        ),
        (
            "TESTE 5 - Mass Assignment (OWASP API3: Injeção de campo 'role': 'admin')",
            "192.168.1.30", 3,
            '{"name": "Caio", "email": "caio@empresa.com", "role": "admin"}',
            "/identity/api/v2/user/profile", "profile", 1
        ),
        (
            "TESTE 6 - Enumeração BOLA/IDOR (OWASP API1: 35 IDs distintos em 1 min)",
            "192.168.1.40", 35,
            '{"name": "User", "email": "user@empresa.com"}',
            "/workshop/api/merchant/orders/1035", "profile", 35
        ),
    ]

    for title, ip, req_count, payload, endpoint, ep_type, unique_uris in test_cases:
        res = engine.inspect_request(ip, req_count, payload, endpoint, ep_type, unique_uris)
        status = "ALLOW" if res["is_allowed"] else "DROP"
        print(f"[{title}]\n  -> Status: {status} | Módulo: {res['blocked_by_module']} | Tempo: {res['latency_ms']} ms\n  -> Motivo: {res['reason']}\n")