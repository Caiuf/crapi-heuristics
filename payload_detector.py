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

        # Regex para reconhecer tokens JWT legítimos no header Authorization e não penalizar sua entropia criptográfica
        self.jwt_bearer_pattern = re.compile(
            r"^Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$"
        )

        # 1. Esquemas Estritos (JSON Schema Draft 2020-12)
        self.schemas = {
            "profile": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "minLength": 1, "maxLength": 250},
                    "email": {"type": "string", "format": "email", "maxLength": 100},
                    "age": {"type": "integer", "minimum": 18, "maximum": 120},
                    "metadata": {"type": "object"}
                },
                "required": ["name", "email"],
                "additionalProperties": False
            }
        }
        self.validators = {
            name: Draft202012Validator(schema, format_checker=FormatChecker())
            for name, schema in self.schemas.items()
        }

        # 2. Regras Heurísticas Ponderadas (Calibradas para OWASP CRS + sqlmap / FuzzDB)
        self.weighted_rules = [
            (
                "sql_tautology_or_logic",
                re.compile(
                    r"(?i)(?:['\"`;\)]|--|\b)\s*(?:or|and|having|rlike)\s+"
                    r"(?:\(?['\"]?\w+['\"]?\s*[=<>!]+|\btrue\b|\bfalse\b|\d+\s*=\s*\d+|\(\s*select\b)"
                ),
                4
            ),
            (
                "sql_stacked_union_comment",
                re.compile(
                    r"(?i)(?:\bunion\s+(?:all\s+)?select\b|;\s*(?:drop|delete|update|insert|shutdown|declare|waitfor|select)\b|"
                    r"--(?:\s|$)|/\*.*?\*/|#\s*$)"
                ),
                4
            ),
            (
                "sql_dml_and_probing",
                re.compile(
                    r"(?i)\b(?:select\s+[^;]{1,200}?\s+from|insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+(?:table|database)|"
                    r"order\s+by\s+\d+|group\s+by\s+\d+|information_schema|pg_sleep|waitfor\s+delay|"
                    r"sleep\s*\(\s*\d+|benchmark\s*\(|extractvalue\s*\(|updatexml\s*\(|"
                    r"case\s+when\b|char\s*\(\s*\d+|concat\s*\(|cast\s*\([^;()]{1,120}?\s+as\s+|convert\s*\()\b"
                ),
                4
            ),
            (
                "sql_hex_or_quotes_probe",
                re.compile(r"(?i)(?:0x[0-9a-f]{6,}|['\"`]\s*(?:;|\)|\bunion\b|\bselect\b|\band\b|\bor\b|--|/\*))"),
                4
            ),
            (
                "xss_attack",
                re.compile(
                    r"(?i)(?:<\s*script\b|javascript\s*:|vbscript\s*:|data\s*:\s*text/html|"
                    r"on(?:error|load|mouseover|focus|click|submit|toggle|auxclick)\s*=|"
                    r"<\s*(?:iframe|svg|img|body|object|embed|style|meta|link|video|audio)\b|"
                    r"\balert\s*\(|\bprompt\s*\(|\bconfirm\s*\(|document\.(?:cookie|domain|location|write)|window\.location)"
                ),
                4
            ),
            (
                "path_traversal_lfi",
                re.compile(
                    r"(?i)(?:\.\./|\.\.\\|%2e%2e|/etc/passwd|/etc/shadow|/etc/hosts|/proc/self/|"
                    r"c:\\windows|win\.ini|boot\.ini|php://|file://)"
                ),
                4
            ),
            (
                "command_or_nosql_injection",
                re.compile(
                    r"(?i)(?:\$(?:gt|lt|gte|lte|ne|nin|where|regex|exists)\b|"
                    r"(?:;|\|\||&&|\||`|\$\()\s*(?:cat|ls|whoami|id|wget|curl|nc|bash|sh|ping|nslookup|dir|type)\b|"
                    r"\(\)\s*\{\s*:;\s*\})"
                ),
                4
            )
        ]

    @staticmethod
    def _normalize(value: str) -> str:
        decoded = value
        for _ in range(2):
            decoded = urllib.parse.unquote_plus(decoded)
        return html.unescape(decoded).replace("\x00", "")

    def _extract_strings_recursive(self, obj: Any, depth: int = 0, path: str = "body") -> Iterator[tuple[str, str]]:
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
        if len(s) < 16:
            return 0.0
        counts = Counter(s)
        length = len(s)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())

    @staticmethod
    def _special_char_ratio(s: str) -> float:
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
        raw_body = payload_str or ""
        if len(raw_body.encode("utf-8")) > self.max_bytes:
            return {"is_anomalous": True, "score": 10, "reason": f"Tamanho de Payload Excedido (> {self.max_bytes} bytes)"}

        payload_dict = {}
        if raw_body.strip():
            try:
                payload_dict = json.loads(raw_body)
            except json.JSONDecodeError:
                return {"is_anomalous": True, "score": 10, "reason": "JSON Malformado"}

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
                # Verifica se é um header Authorization com formato estrito de Bearer JWT
                is_valid_jwt_header = (
                    location.lower() == "header.authorization"
                    and bool(self.jwt_bearer_pattern.match(raw_val.strip()))
                )

                norm_val = self._normalize(raw_val)

                # 2.1 Avaliação de Assinaturas Ponderadas (Aplica-se a tudo, inclusive headers)
                for rule_name, regex, weight in self.weighted_rules:
                    if regex.search(norm_val):
                        total_score += weight
                        reasons.append(f"{rule_name}(+{weight}) em '{location}'")

                # 2.2 Avaliação Estatística Léxica (Ignora apenas tokens JWT estruturalmente válidos)
                if not is_valid_jwt_header:
                    entropy = self._shannon_entropy(norm_val)
                    if entropy > 4.6:
                        total_score += 2
                        reasons.append(f"alta_entropia={entropy:.2f}(+2) em '{location}'")

                    spec_ratio = self._special_char_ratio(norm_val)
                    if spec_ratio > 0.25:
                        total_score += 2
                        reasons.append(f"densidade_metachar={spec_ratio:.2f}(+2) em '{location}'")

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