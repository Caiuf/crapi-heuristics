# Sistema Heurístico de Detecção de Anomalias em APIs REST

Protótipo de engenharia desenvolvido no âmbito do Trabalho de Conclusão de Curso (TCC) em Engenharia de Computação, sob o tema:  
**"Desenvolvimento e avaliação de um sistema heurístico para detecção de anomalias volumétricas e de payload em APIs REST utilizando Python"**.

O projeto implementa uma arquitetura de proteção e inspeção *inline* com estratégia *Fail-Fast*, concebida para mitigar ameaças do **OWASP API Security Top 10** em ambientes como a plataforma de testes **OWASP crAPI**. O sistema combina limites estáticos, análise estatística robusta (*Modified Z-Score* com MAD), verificação de cardinalidade para prevenção de BOLA/IDOR, validação estrutural de esquemas JSON, pontuação cumulativa de regras léxicas (*Anomaly Scoring*) e análise de Entropia de Shannon.

---

## 🏛️ Arquitetura do Motor de Inspeção

O tráfego de rede é processado através de um funil hierárquico com avaliação de curto-circuito, no qual as verificações computacionalmente mais leves precedem a inspeção profunda de conteúdo:

1. **Barreira 1: Inspeção Volumétrica e Comportamental** (`zscore_detector.py`)
   - **Camada V1 (Hard Limit Estático):** Tetos rígidos de requisições por minuto parametrizados por endpoint (rotas sensíveis como `/login` vs. rotas comuns), prevenindo ataques imediatos de força bruta e envenenamento de baseline no arranque (*Cold Start Poisoning*).
   - **Camada V2 (Cardinalidade de Recursos / BOLA):** Monitorização de identificadores únicos acedidos pelo mesmo endereço IP num intervalo temporal, detetando explorações de *Broken Object Level Authorization* (OWASP API1).
   - **Camada V3 (Modified Z-Score via Mediana e MAD):** Identificação de picos volumétricos anómalos recorrendo ao Desvio Absoluto Mediano (*Median Absolute Deviation*) com piso de dispersão (*MAD Floor*) e limiar delta mínimo, prevenindo ataques lentos de envenenamento (*Slow-Rate Poisoning*).

2. **Barreira 2: Inspeção Estrutural e Semântica de Payload** (`payload_detector.py`)
   - **Camada P0 (Volumetria do Payload):** Verificação de limites máximos em bytes para o corpo da requisição.
   - **Camada P1 (Validação Estrutural Estrita):** Validação de esquemas JSON via *Draft 2020-12*, com ativação obrigatória de validadores de formato (`FormatChecker`) e bloqueio rigoroso de propriedades não mapeadas (`additionalProperties: False` contra *Mass Assignment* / OWASP API3).
   - **Camada P2 (Inspeção Léxica e Estatística com Anomaly Scoring):**
     - Normalização canónica prévia contra evasão (descodificação de camadas de URL encoding e entidades HTML).
     - Varredura recursiva de dicionários e listas JSON aninhadas, além de parâmetros de query na URI e cabeçalhos HTTP.
     - Padrões regex ponderados (tautologias SQL, stacked queries, vetores XSS, injeções de comandos e NoSQL).
     - Entropia de Shannon ($H > 4.6$) para deteção de payloads ofuscados/cifrados.
     - Densidade de metacaracteres de injeção (`special_char_ratio`).

---

## 📁 Estrutura do Repositório

```text
.
├── zscore_detector.py      # Motor estatístico e comportamental (Hard Cap, MAD, BOLA)
├── payload_detector.py     # Motor de validação de payload (Schema, Regex, Entropia)
├── core_engine.py          # Roteador central com lógica Fail-Fast e telemetria de latência
├── mock_generator.py       # Gerador sintético de tráfego rotulado baseado na OWASP crAPI
├── benchmark_evaluator.py  # Script de avaliação científica (Matriz de Confusão, Ablação e Percentis)
└── README.md
```
