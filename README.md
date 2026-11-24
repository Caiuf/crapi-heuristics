# Sistema Heurístico para Detecção de Anomalias Volumétricas e de Payload em APIs REST

Motor determinístico de inspeção *inline* (estilo WAF/API Gateway) escrito em Python para detecção de anomalias volumétricas, comportamentais e de payload em APIs REST, avaliado contra rotas da **OWASP crAPI** (*Completely Ridiculous API*) e o dataset público **HttpParamsDataset (CSIC 2010 / sqlmap / FuzzDB)**.

O projeto prioriza **explicabilidade algorítmica**, **determinismo** e **latência sub-milissegundo**, dispensando modelos de *Machine Learning* do tipo caixa-preta.

---

## Arquitetura do Pipeline (*Fail-Fast*)

As requisições passam por duas barreiras sequenciais em funil (`APIHeuristicEngine`), interrompendo o processamento na camada computacionalmente mais barata assim que uma violação é detectada:

### 1ª Barreira — Módulo Volumétrico e Comportamental (`zscore_detector.py`)
* **Subcamada V1 (*Hard Cap* Estático):** Aplica limites imediatos desde a primeira requisição (`15 req/min` para endpoints sensíveis como `/login`, `/auth`, `/token`, `/otp`, `/password`, `/signup` e `80 req/min` para demais rotas), mitigando *Brute Force* e *Cold Start Poisoning*.
* **Subcamada V2 (Cardinalidade de URIs — BOLA/IDOR):** Monitora o número de URIs/IDs distintos acessados por um mesmo IP em janela deslizante de 60 segundos (limite padrão: `20`), mitigando enumeração de objetos (*OWASP API1*).
* **Subcamada V3 (*Modified Z-Score* com Piso MAD):** Mantém janela deslizante (`window_size=12`, *warm-up* de `6` amostras) por IP usando Mediana e Desvio Absoluto Mediano (MAD) com piso de dispersão (`min_mad=2.5`) e delta mínimo absoluto (`min_spike_delta=12`), evitando falsos positivos em tráfego de baixa volumetria:

$$
M_i = \frac{0.6745 \cdot (x_i - \tilde{X})}{\max(\text{MAD}, \text{min\textunderscore mad})}
$$

### 2ª Barreira — Módulo Estrutural, Léxico e de Entropia (`payload_detector.py`)
* **Limites Estruturais:** Bloqueio por tamanho máximo (`max_bytes=32768`) e profundidade máxima de aninhamento JSON (`max_depth=8`).
* **JSON Schema Estrito (Draft 2020-12):** Validação de tipos, formatos (`FormatChecker`) e proibição de campos não declarados (`additionalProperties: False`), mitigando *Mass Assignment* (*OWASP API3*).
* **Normalização Canônica e Travessia Recursiva:** Extrai strings de URI, cabeçalhos HTTP e objetos/listas JSON aninhados, aplicando decodificação URL em 2 níveis, `html.unescape` e remoção de *null bytes*.
* **Assinaturas Ponderadas e Estatística Léxica (*Anomaly Scoring*):**
  * Regras regex para SQLi (tautologias, `UNION`, *stacked queries*, funções de *probing* do `sqlmap`), XSS, *Path Traversal/LFI*, *Command Injection* e *NoSQL Injection*.
  * **Entropia de Shannon** (`> 4.6`, +2 pts) e **Densidade de Metacaracteres** (`> 0.25`, +2 pts), com isenção automática para cabeçalhos `Authorization: Bearer <JWT>` estruturalmente válidos.
  * Bloqueio ao atingir `score_threshold >= 4`.

---

## Estrutura do Repositório

| Arquivo | Descrição |
| :--- | :--- |
| `core_engine.py` | Orquestrador do pipeline *Fail-Fast* (`APIHeuristicEngine`) com medição de latência via `time.perf_counter_ns()` e bateria rápida de testes. |
| `zscore_detector.py` | Implementação da 1ª Barreira (`ZScoreVolumetricDetector`): *Hard Cap*, detecção BOLA/IDOR e *Modified Z-Score* com piso MAD. |
| `payload_detector.py` | Implementação da 2ª Barreira (`PayloadAnomalyDetector`): JSON Schema, travessia recursiva, normalização, regex ponderado e entropia. |
| `mock_generator.py` | Gerador determinístico (`seed=42`) de dataset sintético rotulado (1.000 requisições: 850 normais, 50 *Hard Negatives* e 100 ataques em 5 categorias). |
| `benchmark_evaluator.py` | Avaliador de estudo de ablação (`volumetric_only`, `payload_only`, `full`) com Matriz de Confusão, FPR, Precision, Recall, F1-Score, latência (média/P50/P95/P99) e Throughput (RPS). |
| `real_dataset_adapter.py` | Adaptador do dataset público `payload_full.csv` (HttpParamsDataset / CSIC 2010) para payloads REST da crAPI e análise qualitativa de Falsos Negativos. |
| `crapi_live_testbed.py` | *Testbed* integrado que atua como gateway *inline* à frente de uma instância Docker da OWASP crAPI (`localhost:8888`), com autenticação JWT automática. |
| `plot_generator.py` | Script para geração de gráficos em 300 DPI (estudo de ablação, evolução da calibração e matrizes de confusão). |

---

## Pré-requisitos e Instalação

* **Python 3.10+**
* **Docker / Docker Compose** (opcional — necessário apenas para o *testbed* ao vivo em `crapi_live_testbed.py`)

```bash
# 1. Clone o repositório
git clone <URL_DO_REPOSITORIO>
cd <NOME_DO_REPOSITORIO>

# 2. Crie e ative um ambiente virtual
python3 -m venv .venv
source .venv/bin/activate

# 3. Instale as dependências
pip install numpy pandas scikit-learn matplotlib "jsonschema[format-nongpl]"
