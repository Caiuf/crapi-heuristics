import json
import random
import pandas as pd
from datetime import datetime, timedelta

def generate_labeled_crapi_dataset(seed: int = 42) -> pd.DataFrame:
    """
    Gera um dataset balanceado e realista inspirado nas rotas da OWASP crAPI,
    contendo rótulos ground-truth (y_true: 0 = Normal, 1 = Anômalo) e categorias.
    """
    random.seed(seed)
    records = []
    base_time = datetime(2026, 10, 14, 10, 0, 0)

    # 1. Tráfego Legítimo Basal (850 requisições distribuídas em IPs normais)
    normal_ips = [f"10.0.0.{i}" for i in range(1, 18)]
    for idx in range(850):
        ip = normal_ips[idx % len(normal_ips)]
        req_count = random.randint(6, 14)  # Comportamento estável (~10 req/min)
        payload = json.dumps({
            "name": f"Usuario {idx}",
            "email": f"user{idx}@crapi.local",
            "age": random.randint(20, 65)
        })
        records.append({
            "timestamp": base_time + timedelta(seconds=idx * 2),
            "ip": ip,
            "endpoint": "/identity/api/v2/user/profile",
            "endpoint_type": "profile",
            "req_count": req_count,
            "unique_uris": random.randint(1, 4),
            "headers": {"User-Agent": "Mozilla/5.0 (X11; Fedora; Linux x86_64)"},
            "payload": payload,
            "y_true": 0,
            "category": "Normal_Basal"
        })

    # 2. Tráfego Legítimo "Hard Negatives" (50 requisições com palavras "select", "update", "#" em contexto inofensivo)
    hard_negative_notes = [
        "Please select the best mechanic for my car maintenance",
        "I want to update my contact address in the system",
        "Order #1042 was delivered on time",
        "My vehicle mileage is > 50000 km",
        "Contact support from Monday to Friday"
    ]
    for idx in range(50):
        ip = normal_ips[idx % len(normal_ips)]
        payload = json.dumps({
            "name": "Cliente Oficina",
            "email": f"cliente{idx}@crapi.local",
            "age": 34,
            "metadata": {"comment": random.choice(hard_negative_notes)}
        })
        records.append({
            "timestamp": base_time + timedelta(minutes=30, seconds=idx),
            "ip": ip,
            "endpoint": "/identity/api/v2/user/profile",
            "endpoint_type": "profile",
            "req_count": random.randint(8, 12),
            "unique_uris": 2,
            "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
            "payload": payload,
            "y_true": 0,
            "category": "Normal_Hard_Negative"
        })

    # 3. Ataque Volumétrico 1: Pico Dinâmico (Z-Score) em IPs que já possuem histórico normal (20 amostras)
    for idx in range(20):
        ip = normal_ips[idx % len(normal_ips)]
        records.append({
            "timestamp": base_time + timedelta(minutes=35, seconds=idx),
            "ip": ip,
            "endpoint": "/identity/api/v2/user/dashboard",
            "endpoint_type": "profile",
            "req_count": random.randint(45, 75),  # Abaixo do Hard Cap geral (80), mas muito acima da mediana (~10)!
            "unique_uris": 3,
            "headers": {"User-Agent": "Python-urllib/3.12"},
            "payload": '{"name": "User", "email": "user@crapi.local", "age": 30}',
            "y_true": 1,
            "category": "Atk_Volumetric_ZScore"
        })

    # 4. Ataque Volumétrico 2: Brute Force Cold Start em IPs Inéditos no Login (20 amostras)
    for idx in range(20):
        records.append({
            "timestamp": base_time + timedelta(minutes=36, seconds=idx),
            "ip": f"192.168.99.{idx + 10}",
            "endpoint": "/identity/api/auth/login",
            "endpoint_type": "profile",
            "req_count": random.randint(30, 150),  # Excede o auth_hard_cap (15)
            "unique_uris": 1,
            "headers": {"User-Agent": "Hydra/9.5"},
            "payload": '{"name": "Admin", "email": "admin@crapi.local"}',
            "y_true": 1,
            "category": "Atk_Volumetric_BruteForce"
        })

    # 5. Ataque Comportamental: Enumeração BOLA / IDOR (15 amostras)
    for idx in range(15):
        records.append({
            "timestamp": base_time + timedelta(minutes=37, seconds=idx),
            "ip": f"172.16.0.{idx + 5}",
            "endpoint": f"/workshop/api/merchant/orders/{1000 + idx}",
            "endpoint_type": "profile",
            "req_count": 35,
            "unique_uris": random.randint(25, 60),  # Excede bola_unique_uri_cap (20)
            "headers": {"User-Agent": "BurpSuite-Intruder"},
            "payload": '{"name": "Scraper", "email": "scraper@crapi.local"}',
            "y_true": 1,
            "category": "Atk_Behavioral_BOLA"
        })

    # 6. Ataque Estrutural: Violação de JSON Schema e Mass Assignment (15 amostras)
    schema_attacks = [
        '{"name": "Hacker", "email": "hacker@crapi.local", "role": "admin"}',
        '{"name": "Hacker", "email": "email_invalido_sem_arroba", "age": 25}',
        '{"name": "Hacker", "email": "h@crapi.local", "age": "vinte_e_cinco"}',
        '{"name": "Hacker", "email": "h@crapi.local", "age": 999}',
        '{"malformed_json": "missing_closing_brace"'
    ]
    for idx in range(15):
        records.append({
            "timestamp": base_time + timedelta(minutes=38, seconds=idx),
            "ip": normal_ips[idx % len(normal_ips)],
            "endpoint": "/identity/api/v2/user/profile",
            "endpoint_type": "profile",
            "req_count": 9,
            "unique_uris": 1,
            "headers": {"User-Agent": "curl/8.5.0"},
            "payload": schema_attacks[idx % len(schema_attacks)],
            "y_true": 1,
            "category": "Atk_Payload_Schema_MassAssign"
        })

    # 7. Ataques Semânticos/Léxicos em Payload, URI e Headers (30 amostras: SQLi, XSS, Path Traversal, Ofuscação)
    lexical_attacks = [
        ('{"name": "admin\' OR 1=1 --", "email": "a@crapi.local"}', "/identity/api/v2/user/profile", {"User-Agent": "Mozilla/5.0"}),
        ('{"name": "User", "email": "a@crapi.local", "metadata": {"bio": "<script>fetch(\'http://evil.com\')</script>"}}', "/identity/api/v2/user/profile", {"User-Agent": "Mozilla/5.0"}),
        ('{"name": "UNION SELECT username, password FROM users--", "email": "a@crapi.local"}', "/identity/api/v2/user/profile", {"User-Agent": "sqlmap/1.8"}),
        ('{"name": "Teste", "email": "a@crapi.local"}', "/community/api/v2/coupon?file=../../../../etc/passwd", {"User-Agent": "Mozilla/5.0"}),
        ('{"name": "Teste", "email": "a@crapi.local"}', "/identity/api/v2/user/profile", {"User-Agent": "() { :; }; /bin/bash -c 'cat /etc/shadow'"}),
        ('{"name": "%3Csvg%20onload%3Dalert(1)%3E", "email": "a@crapi.local"}', "/identity/api/v2/user/profile", {"User-Agent": "Mozilla/5.0"})
    ]
    for idx in range(30):
        pay, ep, hdr = lexical_attacks[idx % len(lexical_attacks)]
        records.append({
            "timestamp": base_time + timedelta(minutes=39, seconds=idx),
            "ip": normal_ips[idx % len(normal_ips)],
            "endpoint": ep,
            "endpoint_type": "profile",
            "req_count": 10,
            "unique_uris": 2,
            "headers": hdr,
            "payload": pay,
            "y_true": 1,
            "category": "Atk_Payload_Lexical_Injection"
        })

    return pd.DataFrame(records)

if __name__ == "__main__":
    df = generate_labeled_crapi_dataset()
    print(f"Total de Requisições Geradas: {len(df)}")
    print("\nDistribuição por Categoria:")
    print(df["category"].value_counts())