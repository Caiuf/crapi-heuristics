import html
import json
import math
import re
import urllib.parse
from collections import Counter
from typing import Any, Iterator, Optional
from jsonschema import Draft202012Validator, FormatChecker

class PayloadAnomalyDetector:
    def __init__(self, max_bytes: int = 32768, max_depth: int = 8, score_threshold: int = 4):
        self.max_bytes = max_bytes
        self.max_depth = max_depth
        self.score_threshold = score_threshold

        # 1. Esquemas Estritos (JSON Schema Draft 2020-12) com FormatChecker e bloqueio de Mass Assignment
        self.schemas = {
            "profile": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "minLength": 1, "maxLength": 50},
                    "email": {"type": "string", "format": "email", "maxLength": 100},
                    "age": {"type": "integer", "minimum": 18, "maximum": 120},
                    "metadata": {"type": "object"}  # Permite testar objetos aninhados
                },
                "required": ["name", "email"],
                "additionalProperties": False  # Mitiga OWASP API3:2023 (Mass Assignment)
            }
        }
        # Pré-compila os validadores com FormatChecker ativo (corrige o bug do format: "email")
        self.validators = {
            name: Draft202012Validator(schema, format_checker=FormatChecker())
            for name, schema in self.schemas.items()
        }

        # 2. Regras Heurísticas Ponderadas (inspiradas no OWASP ModSecurity CRS Anomaly Scoring)
        self.weighted_rules = [
            (
                "sql_tautology",
                re.compile(r"(?i)(?:['\"`;]|--|\b)\s*(?:or|and)\s+(?:['\"]?\w+['\"]?\s*[=<>!]+|\btrue\b|\d+\s*=\s*\d+)"),
                4
            ),
            (
                "sql_stacked_or_union",
                re.compile(r"(?i)(?:\bunion\s+(?:all\s+)?select\b|;\s*(?:drop|delete|update|insert|shutdown|declare)\b|--\s+|/\*.*?\*/)"),
                4
            ),
            (
                "sql_dml_keywords",
                re.compile(r"(?i)\b(?:select\s+.+\s+from|insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+table|waitfor\s+delay|sleep\s*\(\s*\d+\s*\))\b"),
                3
            ),
            (
                "xss_attack",
                re.compile(r"(?i)(?:<\s*script\b|javascript\s*:|on(?:error|load|mouseover|focus|click|submit)\s*=|<\s*(?:iframe|svg|img|body|object|embed)\b[^>]*>)"),
                4
            ),
            (
                "path_traversal",
                re.compile(r"(?i)(?:\.\./|\.\.\\|/etc/passwd|/etc/shadow|c:\\windows\\|boot\.ini)"),
                4
            ),
            (
                "command_or_nosql_injection",
                re.compile(r"(?i)(?:\$(?:gt|lt|ne|nin|where|regex)\b|(?:;|\|\||&&)\s*(?:cat|ls|whoami|id|wget|curl|nc|bash|sh)\b)"),
                4
            )
        ]

    @staticmethod
    def _normalize(value: str) -> str:
        """Decodifica múltiplas camadas de URL encoding e entidades HTML para impedir evasão por ofuscação."""
        decoded = value
        for _ in range(2):
            decoded = urllib.parse.unquote_plus(decoded)
        return html.unescape(decoded).replace("\x00", "")

    def _extract_strings_recursive(self, obj: Any, depth: int = 0, path: str = "body") -> Iterator[tuple[str, str]]:
        """Percorre recursivamente dicionários e listas aninhadas com proteção contra JSON Bomb (max_depth)."""
        if depth > self.max_depth:
            raise ValueError(f"Profundidade máxima de JSON excedida (> {self.max_depth})")
        if isinstance(obj, dict):
            for k, v in obj.items():
                yield f"{path}.{k}(key)", str(k)
                yield from self._extract_strings_recursive(v, depth + 1, f"{path}.{k}")
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                yield from self._extract_strings_recursive(item, depth + 1, f"{path}[{idx}]")
        elif isinstance(obj, str):
            yield path, obj

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        """Calcula a Entropia de Shannon em bits por caractere para detectar payloads ofuscados/fuzzing."""
        if len(s) < 16:
            return 0.0
        counts = Counter(s)
        length = len(s)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())

    @staticmethod
    def _special_char_ratio(s: str) -> float:
        """Mede a densidade de metacaracteres de injeção na string."""
        if len(s) < 6:
            return 0.0
        specials = sum(1 for ch in s if ch in "'\";--/*<>()%=&$#{}\\[]|`")
        return specials / len(s)

    def analyze_payload(
        self,
        payload_str: Optional[str],
        endpoint_type: str = "profile",
        uri_and_query: str = "",
        headers: Optional[dict[str, str]] = None
    ) -> dict:
        # CAMADA P0: Verificação Volumétrica de Payload (Tamanho em Bytes)
        raw_body = payload_str or ""
        if len(raw_body.encode("utf-8")) > self.max_bytes:
            return {"is_anomalous": True, "score": 10, "reason": f"Tamanho de Payload Excedido (> {self.max_bytes} bytes)"}

        payload_dict = {}
        if raw_body.strip():
            try:
                payload_dict = json.loads(raw_body)
            except json.JSONDecodeError:
                return {"is_anomalous": True, "score": 10, "reason": "JSON Malformado"}

            # CAMADA P1: Validação Estrutural Estrita (JSON Schema + FormatChecker + Anti-Mass Assignment)
            if endpoint_type in self.validators:
                validator = self.validators[endpoint_type]
                errors = list(validator.iter_errors(payload_dict))
                if errors:
                    first_err = errors[0]
                    return {
                        "is_anomalous": True,
                        "score": 10,
                        "reason": f"Falha de Esquema JSON: {first_err.message}"
                    }

        # CAMADA P2: Inspeção Profunda (Recursiva no Body + URI/Query + Headers) com Anomaly Scoring
        total_score = 0
        reasons = []

        try:
            inspection_targets: list[tuple[str, str]] = []
            if uri_and_query:
                inspection_targets.append(("uri", uri_and_query))
            if headers:
                for hk, hv in headers.items():
                    inspection_targets.append((f"header.{hk}", str(hv)))
            if payload_dict:
                inspection_targets.extend(self._extract_strings_recursive(payload_dict))

            for location, raw_val in inspection_targets:
                norm_val = self._normalize(raw_val)

                # 2.1 Avaliação de Assinaturas Ponderadas
                for rule_name, regex, weight in self.weighted_rules:
                    if regex.search(norm_val):
                        total_score += weight
                        reasons.append(f"{rule_name}(+{weight}) em '{location}'")

                # 2.2 Avaliação Estatística Léxica (Entropia de Shannon e Densidade de Metacaracteres)
                entropy = self._shannon_entropy(norm_val)
                if entropy > 4.6:
                    total_score += 2
                    reasons.append(f"alta_entropia={entropy:.2f}(+2) em '{location}'")

                spec_ratio = self._special_char_ratio(norm_val)
                if spec_ratio > 0.25:
                    total_score += 2
                    reasons.append(f"densidade_metachar={spec_ratio:.2f}(+2) em '{location}'")

                # Fail-Fast assim que o score atingir o limiar de bloqueio
                if total_score >= self.score_threshold:
                    return {
                        "is_anomalous": True,
                        "score": total_score,
                        "reason": f"Anomaly Score {total_score} >= {self.score_threshold}: " + "; ".join(reasons)
                    }

        except ValueError as e:
            return {"is_anomalous": True, "score": 10, "reason": str(e)}

        return {
            "is_anomalous": False,
            "score": total_score,
            "reason": "Payload Estrutural e Semanticamente Válido"
        }