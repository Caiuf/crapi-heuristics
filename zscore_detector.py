import numpy as np
from collections import deque
from datetime import datetime, timedelta
from typing import Optional

class ZScoreVolumetricDetector:
    def __init__(
        self,
        window_size: int = 12,
        min_warmup_samples: int = 6,
        threshold: float = 3.5,
        min_mad: float = 2.5,
        min_spike_delta: int = 12,
        general_hard_cap: int = 80,
        auth_hard_cap: int = 15,
        bola_unique_uri_cap: int = 20
    ):
        """
        window_size: Quantidade de janelas de 1 minuto no histórico por IP.
        min_warmup_samples: Amostras mínimas para estabilizar a Mediana/MAD antes de ativar o bloqueio dinâmico.
        threshold: Limiar do Modified Z-Score (3.5).
        min_mad: Piso mínimo de dispersão (MAD Floor) para evitar falsos positivos em tráfego de baixa volumetria.
        min_spike_delta: Aumento mínimo absoluto (req/min acima da mediana) para caracterizar pico anômalo.
        general_hard_cap: Teto absoluto (Hard Limit) de req/min para endpoints comuns.
        auth_hard_cap: Teto absoluto estrito para rotas críticas (/login, /auth, /otp).
        bola_unique_uri_cap: Máximo de URIs/IDs distintos acessados pelo mesmo IP em 1 minuto (BOLA/IDOR).
        """
        self.window_size = window_size
        self.min_warmup_samples = min_warmup_samples
        self.threshold = threshold
        self.min_mad = min_mad
        self.min_spike_delta = min_spike_delta
        self.general_hard_cap = general_hard_cap
        self.auth_hard_cap = auth_hard_cap
        self.bola_unique_uri_cap = bola_unique_uri_cap

        self.history: dict[str, deque[int]] = {}
        self.realtime_timestamps: dict[str, deque[datetime]] = {}
        self.realtime_uris: dict[str, dict[str, datetime]] = {}

    def _is_sensitive_endpoint(self, endpoint: str) -> bool:
        sensitive_keywords = ("/login", "/auth", "/token", "/otp", "/password", "/signup")
        return any(kw in endpoint.lower() for kw in sensitive_keywords)

    def register_and_count_streaming(self, ip: str, timestamp: datetime, endpoint: str) -> tuple[int, int]:
        if ip not in self.realtime_timestamps:
            self.realtime_timestamps[ip] = deque()
            self.realtime_uris[ip] = {}

        cutoff = timestamp - timedelta(seconds=60)

        ts_deque = self.realtime_timestamps[ip]
        while ts_deque and ts_deque[0] < cutoff:
            ts_deque.popleft()
        ts_deque.append(timestamp)

        uri_map = self.realtime_uris[ip]
        expired_uris = [u for u, t in uri_map.items() if t < cutoff]
        for u in expired_uris:
            del uri_map[u]
        uri_map[endpoint] = timestamp

        return len(ts_deque), len(uri_map)

    def analyze_traffic(
        self,
        ip: str,
        current_req_count: Optional[int] = None,
        endpoint: str = "/",
        timestamp: Optional[datetime] = None,
        unique_uris_count: int = 1
    ) -> dict:
        if current_req_count is None:
            ts = timestamp or datetime.now()
            current_req_count, unique_uris_count = self.register_and_count_streaming(ip, ts, endpoint)

        if ip not in self.history:
            self.history[ip] = deque(maxlen=self.window_size)

        # SUBCAMADA V1: Hard Limit Estático (Ativo desde a 1ª requisição - evita Cold Start Poisoning)
        hard_cap = self.auth_hard_cap if self._is_sensitive_endpoint(endpoint) else self.general_hard_cap
        if current_req_count > hard_cap:
            return {
                "is_anomalous": True,
                "z_score": float("inf"),
                "reason": f"Hard Cap Excedido: {current_req_count} req/min > limite estático ({hard_cap}) para '{endpoint}'"
            }

        # SUBCAMADA V2: Heurística Comportamental para BOLA/IDOR
        if unique_uris_count > self.bola_unique_uri_cap:
            return {
                "is_anomalous": True,
                "z_score": float("inf"),
                "reason": f"Possível Enumeração BOLA/IDOR: {unique_uris_count} recursos distintos acessados em 1 min (limite: {self.bola_unique_uri_cap})"
            }

        # SUBCAMADA V3: Modified Z-Score Calibrado com MAD Floor e Delta Mínimo
        ip_history = self.history[ip]
        if len(ip_history) < self.min_warmup_samples:
            ip_history.append(current_req_count)
            return {
                "is_anomalous": False,
                "z_score": 0.0,
                "reason": f"Baseline em formação ({len(ip_history)}/{self.min_warmup_samples} amostras dentro do Hard Cap)"
            }

        arr = np.asarray(ip_history, dtype=np.float64)
        median = float(np.median(arr))
        raw_mad = float(np.median(np.abs(arr - median)))

        # Aplica o Piso de Dispersão (MAD Floor) para evitar divisão por variância residual em contagens discretas
        effective_mad = max(raw_mad, self.min_mad)
        delta = current_req_count - median
        modified_z_score = 0.6745 * delta / effective_mad

        # Só considera anomalia dinâmica se superar o Z-Score limiar E o delta mínimo absoluto de requisições
        is_anomalous = bool(modified_z_score > self.threshold and delta >= self.min_spike_delta)

        # Atualiza a janela deslizante apenas com tráfego normal validado
        if not is_anomalous:
            ip_history.append(current_req_count)

        return {
            "is_anomalous": is_anomalous,
            "z_score": round(modified_z_score, 2),
            "reason": (
                f"Modified Z-Score {modified_z_score:.2f} excedeu limiar {self.threshold} "
                f"(Atual={current_req_count}, Mediana={median:.1f}, MAD_Efetivo={effective_mad:.1f})"
                if is_anomalous else "Normal"
            )
        }