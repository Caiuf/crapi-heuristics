import json
import time
import random
import urllib.request
import urllib.error
import pandas as pd
from pathlib import Path
from core_engine import APIHeuristicEngine

class CrAPILiveTestbed:
    def __init__(self, base_url: str = "http://localhost:8888"):
        self.base_url = base_url.rstrip("/")
        self.engine = APIHeuristicEngine()
        self.jwt_token = None

        # Registra um schema flexível para os endpoints reais da crAPI no detector de payload
        self.engine.payload_engine.schemas["crapi_generic"] = {
            "type": "object",
            "properties": {
                "name": {"type": "string", "minLength": 1, "maxLength": 250},
                "email": {"type": "string", "format": "email", "maxLength": 120},
                "password": {"type": "string", "minLength": 1, "maxLength": 120},
                "number": {"type": "string", "maxLength": 30},
                "coupon_code": {"type": "string", "maxLength": 250}
            },
            "additionalProperties": False
        }
        from jsonschema import Draft202012Validator, FormatChecker
        self.engine.payload_engine.validators["crapi_generic"] = Draft202012Validator(
            self.engine.payload_engine.schemas["crapi_generic"],
            format_checker=FormatChecker()
        )

    def check_crapi_online(self) -> bool:
        try:
            req = urllib.request.Request(f"{self.base_url}/identity/api/auth/login", method="OPTIONS")
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                return resp.status < 500
        except urllib.error.HTTPError as e:
            return e.code < 500
        except Exception:
            return False

    def authenticate_test_user(self) -> bool:
        """Cria um usuário real na crAPI e obtém o token JWT para chamadas autenticadas."""
        email = "auditor.tcc@crapi.local"
        password = "TccPassword@2026"
        signup_payload = json.dumps({
            "name": "Auditor TCC",
            "email": email,
            "number": "61999990000",
            "password": password
        }).encode("utf-8")

        # 1. Tenta cadastrar (ignora se já existir)
        try:
            req = urllib.request.Request(
                f"{self.base_url}/identity/api/auth/signup",
                data=signup_payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            urllib.request.urlopen(req, timeout=4.0)
        except Exception:
            pass

        # 2. Faz login para obter o JWT
        login_payload = json.dumps({"email": email, "password": password}).encode("utf-8")
        try:
            req = urllib.request.Request(
                f"{self.base_url}/identity/api/auth/login",
                data=login_payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                self.jwt_token = body.get("token")
                return self.jwt_token is not None
        except Exception as e:
            print(f"[Aviso] Não foi possível obter JWT automático ({e}). Rodando sem token Bearer.")
            return False

    def send_through_heuristic_gateway(
        self,
        ip: str,
        method: str,
        endpoint: str,
        payload_str: str,
        req_count: int,
        unique_uris: int
    ) -> dict:
        headers = {"Content-Type": "application/json", "User-Agent": "TCC-Bench/1.0"}
        if self.jwt_token:
            headers["Authorization"] = f"Bearer {self.jwt_token}"

        # 1. Passa pelo Motor Heurístico (Inline WAF)
        verdict = self.engine.inspect_request(
            ip=ip,
            current_req_count=req_count,
            payload_str=payload_str,
            endpoint=endpoint,
            endpoint_type="crapi_generic",
            unique_uris_count=unique_uris,
            headers=headers
        )

        # Se o motor bloqueou (DROP), nem gasta rede/CPU do container da crAPI!
        if not verdict["is_allowed"]:
            return {
                "firewall_Action": "DROP (403 Forbidden)",
                "blocked_by": verdict["blocked_by_module"],
                "reason": verdict["reason"],
                "firewall_latency_ms": verdict["latency_ms"],
                "crapi_http_status": "BLOCKED_INLINE",
                "crapi_latency_ms": 0.0
            }

        # 2. Se permitido (ALLOW), encaminha via rede HTTP para o Docker da crAPI
        start_crapi = time.perf_counter_ns()
        http_status = 0
        try:
            data_bytes = payload_str.encode("utf-8") if payload_str and method in ("POST", "PUT") else None
            req = urllib.request.Request(
                url=f"{self.base_url}{endpoint}",
                data=data_bytes,
                headers=headers,
                method=method
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                http_status = resp.status
        except urllib.error.HTTPError as e:
            http_status = e.code
        except Exception:
            http_status = -1
        end_crapi = time.perf_counter_ns()

        crapi_ms = round((end_crapi - start_crapi) / 1_000_000.0, 3)
        return {
            "firewall_Action": "ALLOW",
            "blocked_by": "N/A",
            "reason": "Requisição Legítima",
            "firewall_latency_ms": verdict["latency_ms"],
            "crapi_http_status": http_status,
            "crapi_latency_ms": crapi_ms
        }


if __name__ == "__main__":
    testbed = CrAPILiveTestbed("http://localhost:8888")
    online = testbed.check_crapi_online()
    print(f"Status do Container OWASP crAPI (localhost:8888): {'ONLINE' if online else 'OFFLINE'}")

    if online:
        auth_ok = testbed.authenticate_test_user()
        print(f"Autenticação JWT na crAPI: {'SUCESSO' if auth_ok else 'FALHOU / NÃO AUTENTICADO'}")
    else:
        print("Dica: Suba a crAPI com 'docker compose up -d' para medir a latência HTTP real do container.\n")

    # Carrega 20 payloads reais do payload_full.csv (10 normais e 10 ataques reais)
    real_samples = []
    if Path("payload_full.csv").exists():
        df_pub = pd.read_csv("payload_full.csv")
        norms = df_pub[df_pub["label"] == "norm"].sample(10, random_state=7)
        anoms = df_pub[df_pub["label"] == "anom"].sample(10, random_state=7)
        for _, r in pd.concat([norms, anoms]).iterrows():
            is_atk = r["label"] == "anom"
            real_samples.append((
                "Atk_Public_" + str(r["attack_type"]) if is_atk else "Normal_Public_CSIC",
                "10.20.0.5",
                "POST",
                "/community/api/v2/coupon/validate-coupon",
                json.dumps({"coupon_code": str(r["payload"])[:240]}),
                8,
                2
            ))

    # Adiciona casos específicos de rotas reais da crAPI (Login Brute Force e BOLA em /workshop/api/shop/orders)
    real_samples.extend([
        ("Normal_Dashboard_GET", "10.20.0.5", "GET", "/identity/api/v2/user/dashboard", "", 9, 2),
        ("Atk_BruteForce_Login", "192.168.50.99", "POST", "/identity/api/auth/login", '{"email":"admin@crapi.local","password":"123"}', 65, 1),
        ("Atk_BOLA_Orders_Enum", "172.16.88.10", "GET", "/workshop/api/shop/orders/42", "", 30, 28)
    ])

    results = []
    for category, ip, method, ep, body, req_c, uniq_u in real_samples:
        res = testbed.send_through_heuristic_gateway(ip, method, ep, body, req_c, uniq_u)
        res["category"] = category
        res["endpoint"] = ep
        results.append(res)

    res_df = pd.DataFrame(results)[
        ["category", "endpoint", "firewall_Action", "crapi_http_status", "firewall_latency_ms", "crapi_latency_ms", "reason"]
    ]
    print("\n=== RESULTADO DO TESTE INTEGRADO COM ROTAS DA OWASP crAPI ===")
    print(res_df.to_string(index=False))