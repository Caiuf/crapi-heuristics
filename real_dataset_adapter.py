import csv
import json
import random
import urllib.request
import urllib.error
import pandas as pd
from datetime import datetime, timedelta
from pathlib import Path
from benchmark_evaluator import evaluate_mode

def build_hybrid_real_dataset(
    csv_path: str = "payload_full.csv",
    sample_size: int = 2000,
    send_to_live_crapi: bool = False,
    crapi_base_url: str = "http://localhost:8888"
) -> pd.DataFrame:
    """
    Lê amostras reais do dataset público HttpParamsDataset (CSIC 2010 + sqlmap + FuzzDB)
    e monta um dataset completo de API REST no formato das rotas da OWASP crAPI.
    Se send_to_live_crapi=True, envia requisições HTTP reais contra o container Docker da crAPI.
    """
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(
            f"Arquivo '{csv_path}' não encontrado. Baixe antes com:\n"
            "curl -L -o payload_full.csv https://raw.githubusercontent.com/Morzeux/HttpParamsDataset/master/payload_full.csv"
        )

    raw_df = pd.read_csv(path)
    # Colunas originais do payload_full.csv: 'payload', 'length', 'attack_type', 'label'
    normal_rows = raw_df[raw_df["label"] == "norm"].sample(n=int(sample_size * 0.8), random_state=42)
    attack_rows = raw_df[raw_df["label"] == "anom"].sample(n=int(sample_size * 0.2), random_state=42)

    combined = pd.concat([normal_rows, attack_rows]).sample(frac=1.0, random_state=42).reset_index(drop=True)

    records = []
    base_time = datetime(2026, 11, 9, 14, 0, 0)
    normal_ips = [f"10.10.0.{i}" for i in range(1, 25)]

    for idx, row in combined.iterrows():
        raw_param = str(row["payload"])
        is_attack = 1 if row["label"] == "anom" else 0
        attack_subtype = str(row["attack_type"])

        ip = normal_ips[idx % len(normal_ips)]
        endpoint = "/identity/api/v2/user/profile"
        req_count = random.randint(6, 14)
        unique_uris = random.randint(1, 4)

        # Constrói o JSON REST com o valor real extraído do dataset público CSIC/HttpParams
        payload_json = json.dumps({
            "name": raw_param[:250],
            "email": f"user{idx}@crapi.local",
            "age": random.randint(20, 60)
        })

        http_status = 200
        if send_to_live_crapi:
            # Dispara a requisição HTTP real contra o container Docker da crAPI
            req = urllib.request.Request(
                url=f"{crapi_base_url}{endpoint}",
                data=payload_json.encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "TCC-Benchmark-Client/1.0"},
                method="POST"
            )
            try:
                with urllib.request.urlopen(req, timeout=1.5) as resp:
                    http_status = resp.status
            except urllib.error.HTTPError as e:
                http_status = e.code
            except Exception:
                http_status = 0

        records.append({
            "timestamp": base_time + timedelta(seconds=idx),
            "ip": ip,
            "endpoint": endpoint,
            "endpoint_type": "profile",
            "req_count": req_count,
            "unique_uris": unique_uris,
            "headers": {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"},
            "payload": payload_json,
            "http_status": http_status,
            "y_true": is_attack,
            "category": f"Real_Public_{attack_subtype}"
        })

    out_df = pd.DataFrame(records)
    out_df.to_csv("crapi_real_public_dataset.csv", index=False, quoting=csv.QUOTE_ALL)
    return out_df


if __name__ == "__main__":
    print("Carregando e adaptando amostras reais do HttpParamsDataset (CSIC 2010 / sqlmap / FuzzDB)...")
    real_df = build_hybrid_real_dataset(sample_size=1000, send_to_live_crapi=False)
    print(f"Dataset salvo em 'crapi_real_public_dataset.csv' ({len(real_df)} requisições reais).\n")

    print("--- Avaliando Motor Heurístico no Dataset Público Real ---")
    metrics = evaluate_mode(real_df, mode="full")
    for k, v in metrics.items():
        if k != "y_pred":
            print(f"{k}: {v}")

    real_df["y_pred"] = metrics["y_pred"]
    fn_df = real_df[(real_df["y_true"] == 1) & (real_df["y_pred"] == 0)]
    print(f"\n--- Análise Qualitativa dos Falsos Negativos (Total: {len(fn_df)}) ---")
    for idx, r in fn_df.iterrows():
        print(f"[FN #{idx}] Categoria: {r['category']} | Payload: {r['payload']}")