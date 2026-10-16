import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score
from mock_generator import generate_labeled_crapi_dataset
from core_engine import APIHeuristicEngine

def evaluate_mode(df: pd.DataFrame, mode: str = "full") -> dict:
    """
    Executa a bateria de avaliação sob 3 modos para o Estudo de Ablação:
    - 'volumetric_only': Apenas 1ª Barreira (Hard Cap + BOLA + Modified Z-Score)
    - 'payload_only': Apenas 2ª Barreira (JSON Schema + Regex Scoring + Entropia)
    - 'full': Pipeline completo integrado (Fail-Fast)
    """
    engine = APIHeuristicEngine()
    y_true = df["y_true"].to_numpy()
    y_pred = []
    latencies_ms = []
    reasons = []

    for _, row in df.iterrows():
        if mode == "volumetric_only":
            res = engine.inspect_request(
                ip=row["ip"],
                current_req_count=row["req_count"],
                payload_str="",  # Ignora payload
                endpoint=row["endpoint"],
                endpoint_type="none",
                unique_uris_count=row["unique_uris"],
                headers=None
            )
        elif mode == "payload_only":
            res = engine.inspect_request(
                ip=row["ip"],
                current_req_count=1,  # Volume fixo normal para isolar a camada de payload
                payload_str=row["payload"],
                endpoint=row["endpoint"],
                endpoint_type=row["endpoint_type"],
                unique_uris_count=1,
                headers=row["headers"]
            )
        else:
            res = engine.inspect_request(
                ip=row["ip"],
                current_req_count=row["req_count"],
                payload_str=row["payload"],
                endpoint=row["endpoint"],
                endpoint_type=row["endpoint_type"],
                unique_uris_count=row["unique_uris"],
                headers=row["headers"]
            )

        is_blocked = 0 if res["is_allowed"] else 1
        y_pred.append(is_blocked)
        latencies_ms.append(res["latency_ms"])
        reasons.append(res["reason"])

    y_pred_arr = np.asarray(y_pred)
    lat_arr = np.asarray(latencies_ms)

    # Extração rigorosa da Matriz de Confusão
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred_arr, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    precision = precision_score(y_true, y_pred_arr, zero_division=0)
    recall = recall_score(y_true, y_pred_arr, zero_division=0)
    f1 = f1_score(y_true, y_pred_arr, zero_division=0)

    total_time_sec = np.sum(lat_arr) / 1000.0
    throughput_rps = len(df) / total_time_sec if total_time_sec > 0 else 0.0

    return {
        "mode": mode,
        "TP": int(tp),
        "TN": int(tn),
        "FP": int(fp),
        "FN": int(fn),
        "FPR (%)": round(fpr * 100, 2),
        "Precision (%)": round(precision * 100, 2),
        "Recall (%)": round(recall * 100, 2),
        "F1-Score (%)": round(f1 * 100, 2),
        "Lat_Mean (ms)": round(float(np.mean(lat_arr)), 4),
        "Lat_P50 (ms)": round(float(np.percentile(lat_arr, 50)), 4),
        "Lat_P95 (ms)": round(float(np.percentile(lat_arr, 95)), 4),
        "Lat_P99 (ms)": round(float(np.percentile(lat_arr, 99)), 4),
        "Throughput (RPS)": int(round(throughput_rps, 0)),
        "y_pred": y_pred_arr
    }

if __name__ == "__main__":
    print("Gerando Dataset Rotulado da crAPI (1.000 requisições)...")
    dataset_df = generate_labeled_crapi_dataset()

    print("\n======================================================================")
    print("1. ESTUDO DE ABLAÇÃO (COMPARATIVO DE CAMADAS HEURÍSTICAS)")
    print("======================================================================")
    ablation_results = []
    for m in ["volumetric_only", "payload_only", "full"]:
        metrics = evaluate_mode(dataset_df, mode=m)
        ablation_results.append({k: v for k, v in metrics.items() if k != "y_pred"})

    ablation_df = pd.DataFrame(ablation_results)
    print(ablation_df.to_string(index=False))

    print("\n======================================================================")
    print("2. DESEMPENHO DETALHADO POR CATEGORIA (MOTOR COMPLETO)")
    print("======================================================================")
    full_eval = evaluate_mode(dataset_df, mode="full")
    dataset_df["y_pred"] = full_eval["y_pred"]

    category_summary = dataset_df.groupby("category").agg(
        Total=("y_true", "count"),
        Bloqueados=("y_pred", "sum"),
        Permitidos=("y_pred", lambda x: (x == 0).sum())
    ).reset_index()
    category_summary["Taxa_Acerto (%)"] = np.where(
        category_summary["category"].str.startswith("Normal"),
        round((category_summary["Permitidos"] / category_summary["Total"]) * 100, 2),
        round((category_summary["Bloqueados"] / category_summary["Total"]) * 100, 2)
    )
    print(category_summary.to_string(index=False))