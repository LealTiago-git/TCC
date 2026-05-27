# TCC — Sistema de Defesa Contra Acessos Anômalos com Agentes de IA

Sistema híbrido de defesa de banco de dados que combina **endpoints HTTP intencionalmente vulneráveis** (Postgres + MongoDB) com **agentes LLM autônomos** (tool-calling) que detectam ataques reais e executam ações defensivas em tempo real.

> **Aviso:** o servidor é INTENCIONALMENTE vulnerável (SQLi, NoSQLi, brute-force expostos). Roda apenas em `127.0.0.1` atrás de Docker isolado. Nunca exponha à internet.

## Resumo executivo

Protótipo acadêmico em Python que demonstra:
- Ataques **reais** (não simulados) contra Postgres e MongoDB via HTTP
- Defesa autônoma por LLMs (qwen2.5, gemma3) com function-calling
- Métricas de eficácia: tempo até bloqueio, taxa de sucesso, cobertura
- Benchmark comparativo Postgres vs MongoDB (4 workloads)
- Dashboard Streamlit com 7 abas em tempo real

### Palavras-chave
- LLM agentes autônomos com tool-calling
- SQL Injection / NoSQL Injection reais
- Defesa em camadas (enforcement + detecção)
- Postgres vs MongoDB benchmark
- Auditoria + resposta a incidentes

## Arquitetura

```
┌────────────────┐
│  attacker.py   │ → HTTP requests reais (SQLi, NoSQLi, brute, DDoS, exfil, privesc)
└───────┬────────┘
        │
        ▼
┌────────────────┐     ┌──────────────┐
│   server.py    │────►│  Postgres    │  (Docker :5432) - alvo SQLi
│  Flask :8000   │     │  tcc_target  │
│                │────►│              │
│  Vulnerável!   │     └──────────────┘
│                │     ┌──────────────┐
│                │────►│  MongoDB     │  (Docker :27017) - alvo NoSQLi
│                │     │  tcc_target  │
└───────┬────────┘     └──────────────┘
        │
        ▼ append
┌────────────────┐                    ┌──────────────────────┐
│  access_logs   │◄────── poll ───────│  agent_loop.py       │
│  (SQLite)      │                    │  LLM tool-calling    │
└───────┬────────┘                    │  qwen2.5 / gemma3    │
        ▲                             └──────────┬───────────┘
        │ enforce 403                            │ tool calls
        │                                        ▼
┌────────────────┐                    ┌──────────────────────┐
│  blocked_ips   │◄───────────────────│  block_ip()          │
│  locked_users  │◄───────────────────│  lock_user()         │
│  security_alerts│◄──────────────────│  flag_for_audit()    │
└────────────────┘                    └──────────────────────┘
        ▲
        │ read
┌────────────────┐
│  dashboard.py  │ Streamlit :8501 — 7 abas
└────────────────┘
```

## Componentes principais (módulos novos em **negrito**)

| Módulo | Função |
|---|---|
| **`server.py`** | Flask HTTP server com endpoints vulneráveis (`/pg/login`, `/pg/search`, `/pg/query`, `/mongo/login`, `/mongo/find`). Enforcement de `blocked_ips` + `locked_users` antes da query. |
| **`db_backends.py`** | Conexões Postgres + MongoDB com queries f-string (SQLi) e filtros JSON crus (NoSQLi). |
| **`attacker.py`** | Cliente Python que dispara 6 modos de ataque HTTP reais via `requests`. |
| **`agent_loop.py`** | Loop autônomo: polla `access_logs` → LLM com tool-calling → executa `block_ip`/`lock_user`/`flag_for_audit`. Suporta Ollama nativo + JSON-fallback para modelos sem tool-calling. |
| **`benchmark.py`** | Mede latência Postgres vs MongoDB em 4 workloads (login, search_eq, search_like, full_scan). |
| **`metrics.py`** | Calcula `time_to_block_ms`, `attack_success_rate`, `coverage_pct`, distribuição de tools. |
| `dashboard.py` | Streamlit, 7 abas (logs, alertas, anomalias, resposta defensiva, performance IA, agente IA ao vivo, benchmark). |
| `database.py` | Schema SQLite + seed (tabelas: `access_logs`, `ai_actions`, `blocked_ips`, `locked_users`, `benchmark_runs`, etc.). |
| `cli.py` | CLI legado (`init-db`, `simulate`, `attack`, `monitor`, etc.) — sistema antigo gateway+anomaly continua funcional para demos sem Docker. |

## Endpoints vulneráveis

| Método | Path | Vulnerabilidade |
|---|---|---|
| POST | `/pg/login` | SQLi clássico (f-string em username/password) |
| GET | `/pg/search?table=&q=` | SQLi via UNION + table name injection |
| POST | `/pg/query` | SQL bruto (pior caso, demo exfiltração total) |
| POST | `/mongo/login` | NoSQLi via `$ne`, `$gt`, `$where` |
| POST | `/mongo/find` | Filtro JSON passa direto ao `db.find()` |
| GET | `/health` | Status PG+Mongo |
| GET | `/status` | Contadores SQLite (logs/blocked/locked) |

## Ferramentas expostas ao LLM (function-calling)

| Tool | Args | Efeito |
|---|---|---|
| `block_ip` | `ip, reason, ttl_seconds` | INSERT em `blocked_ips`. Server passa a retornar 403 pra esse IP. |
| `lock_user` | `username, reason` | INSERT em `locked_users`. Server retorna 403 pra esse user. |
| `flag_for_audit` | `log_id, severity, reason` | Cria alerta em `security_alerts` (sem bloquear). |
| `no_action` | `reason` | Explicitamente nada a fazer. |

## Pré-requisitos

| Item | Versão mínima | Como instalar |
|---|---|---|
| Python | 3.10+ | python.org |
| Docker Desktop | 4.42+ | docker.com |
| WSL | 2.4.13 (não 2.5+) | <https://github.com/microsoft/WSL/releases/tag/2.4.13> |
| Ollama | qualquer | ollama.com |
| Modelo `qwen2.5` | — | `ollama pull qwen2.5` |
| Modelo `gemma3` | opcional | `ollama pull gemma3` |

> **Importante:** WSL 2.5+ incompatível com Docker Desktop ≤ 4.75. Crash com sockets `dockerInference` e `engine.sock`. Use WSL 2.4.13 ou Docker Desktop 4.76+.

## Setup (1 vez)

```powershell
# 1. PATH do Docker
$env:PATH = "C:\Program Files\Docker\Docker\resources\bin;$env:PATH"

# 2. Deps Python
pip install -r requirements.txt

# 3. Subir containers
docker compose up -d

# 4. SQLite schema
python -m access_defense.cli init-db

# 5. Modelo LLM
ollama pull qwen2.5
```

## Demo rápida (script orquestrador)

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run_full_demo.ps1
```

Flags: `-Model qwen2.5|gemma3`, `-SkipDocker`, `-AttackMode sqli|nosqli|brute-force|ddos|exfil|privesc|full`.

## Demo manual (4 terminais)

**Terminal 1 — Server vulnerável**
```powershell
$env:PATH = "C:\Program Files\Docker\Docker\resources\bin;$env:PATH"
python -m access_defense.server --port 8000
```

**Terminal 2 — Agente IA**
```powershell
$env:AGENT_PROVIDER = "ollama"
$env:OLLAMA_NATIVE_URL = "http://localhost:11434"
python -m access_defense.agent_loop --model qwen2.5 --batch 15 --interval 3
```

**Terminal 3 — Dashboard**
```powershell
python -m streamlit run access_defense/dashboard.py
# http://localhost:8501
```

**Terminal 4 — Atacante**
```powershell
python -m access_defense.attacker --mode full
# OU modos individuais:
python -m access_defense.attacker --mode sqli
python -m access_defense.attacker --mode nosqli
python -m access_defense.attacker --mode brute-force --rounds 50
python -m access_defense.attacker --mode ddos --requests 500 --concurrency 50
python -m access_defense.attacker --mode exfil
python -m access_defense.attacker --mode privesc
```

## Modos de ataque

### SQL Injection (`sqli`)
```python
{"username": "admin' --", "password": "qualquer"}
{"username": "' OR '1'='1", "password": "' OR '1'='1"}
"' UNION SELECT id, username, password, role, NULL FROM users --"
```

### NoSQL Injection (`nosqli`)
```python
{"username": {"$ne": None}, "password": {"$ne": None}}
{"collection": "users", "filter": {"$where": "true"}}
```

### Brute Force, DDoS, Exfiltration, Privilege Escalation
Detalhes em `GUIA_USO.md` seção 6.

## Métricas e benchmark

```powershell
# Métricas de defesa
python -m access_defense.metrics
python -m access_defense.metrics --json

# Benchmark PG vs Mongo (200 iterações × 4 workloads × 2 backends)
python -m access_defense.benchmark --iterations 200
```

## Resultados experimentais (sessão de teste)

### Comparação de modelos LLM

| Aspecto | qwen2.5 | gemma3 |
|---|---|---|
| Total ações | 43 | 21 |
| `block_ip` | 5 | 2 |
| `flag_for_audit` | 31 | 19 |
| `lock_user` | 7 | **0** |
| Suporte tool-calling | ✅ nativo | ❌ JSON fallback |
| Estabilidade | Constante | Trava após ~5 batches |
| Gap médio entre ações | 20.8s | 12.5s |

**Conclusão**: Tool-calling nativo > JSON fallback. qwen2.5 detecta mais classes de ataque (incluindo brute-force via `lock_user`).

### Benchmark Postgres vs MongoDB (200 iterações cada)

| Workload | Postgres avg | Mongo avg | Postgres p95 | Mongo p95 |
|---|---|---|---|---|
| login | 0.414 ms | 0.669 ms | 0.467 ms | 0.762 ms |
| search_eq | 0.386 ms | 0.691 ms | 0.432 ms | 0.801 ms |
| search_like | 0.368 ms | 0.714 ms | 0.394 ms | 0.837 ms |
| full_scan | 0.366 ms | 0.694 ms | 0.407 ms | 0.816 ms |

**Conclusão**: Postgres ~2× mais rápido que Mongo nas 4 workloads (dataset pequeno, índices SQL otimizados).

### Métricas de defesa (rodada qwen2.5)

| Métrica | Valor |
|---|---|
| Total requests | 291 |
| Maliciosas detectadas | 48 |
| Bloqueadas pré-execução | 9 |
| Ações IA totais | 57 |
| IPs bloqueados | 1 (cobertura 100%) |
| Tempo até bloqueio | 138s (latência LLM batch) |

## Estrutura de arquivos

```
TCC/
├── access_defense/
│   ├── __init__.py
│   ├── agents.py             # Cliente LLM legado (gateway antigo)
│   ├── agent_loop.py         # NOVO: agente IA autônomo tool-calling
│   ├── anomaly.py            # Regras determinísticas (legado)
│   ├── attacker.py           # NOVO: cliente HTTP atacante
│   ├── attacks.py            # Simulador legado (atinge gateway)
│   ├── benchmark.py          # NOVO: bench PG vs Mongo
│   ├── cli.py                # CLI legado (init-db, simulate, etc.)
│   ├── dashboard.py          # Streamlit (7 abas)
│   ├── database.py           # Schema SQLite + seed
│   ├── db_backends.py        # NOVO: conexões PG + Mongo vulneráveis
│   ├── defender.py           # Monitor legado
│   ├── gateway.py            # Gateway legado (rules + RBAC)
│   ├── metrics.py            # NOVO: métricas de defesa
│   ├── security.py           # PBKDF2 hash
│   └── server.py             # NOVO: Flask server vulnerável
├── scripts/
│   ├── init_postgres.sql     # Seed Postgres
│   ├── init_mongo.js         # Seed Mongo
│   ├── run_full_demo.ps1     # Orquestrador completo
│   ├── run_hydra.sh          # Wrapper hydra (brute force)
│   └── run_sqlmap.sh         # Wrapper sqlmap (SQLi)
├── .claude/
│   └── launch.json           # Dev server configs
├── docker-compose.yml        # PG + Mongo containers
├── requirements.txt          # Deps Python
├── access_control.db         # SQLite local
├── README.md                 # Este arquivo
├── GUIA_USO.md               # Guia detalhado de uso (18 seções)
├── USANDO_HTTP.md            # Guia do fluxo HTTP
├── USANDO_DASHBOARD.md       # Guia da dashboard
└── USANDO_IA_LOCAL.md        # Setup Ollama
```

## Schema SQLite (tabelas relevantes)

| Tabela | Conteúdo |
|---|---|
| `access_logs` | Toda request HTTP (user, IP, op, table, payload, success, rows_returned) |
| `security_alerts` | Alertas (regras OU `flag_for_audit` do agente) |
| `blocked_ips` | IPs bloqueados pelo agente (com TTL opcional) |
| `locked_users` | Usuários travados pelo agente |
| `ai_actions` | Histórico de tool-calls do LLM (id, session, model, tool, args, applied, error) |
| `ai_agent_logs` | Timing de chamadas LLM (legado) |
| `benchmark_runs` | Resultados PG vs Mongo |
| `users`, `permissions`, `clientes`, `transacoes`, `salarios` | Dados legado (sistema gateway antigo) |

## Cenários de demonstração

### A — Atacante sem agente (baseline)
Mostra impacto sem defesa. Esperado: `attack_success_rate_pct` ~90-100%.

### B — Atacante com qwen2.5
Mostra defesa autônoma. Esperado: IP bloqueado após 1-2 batches do LLM, taxa de sucesso cai.

### C — Comparação qwen2.5 vs gemma3
Roda mesmo ataque com cada modelo. Compara `ai_actions_by_tool` e cobertura.

### D — Benchmark PG vs Mongo isolado
Compara latência por workload. Visualiza na aba ⚡ do dashboard.

Detalhes em `GUIA_USO.md` seções 12 e 17.

## Troubleshooting

| Erro | Causa | Fix |
|---|---|---|
| `docker: command not found` | PATH | `$env:PATH = "C:\Program Files\Docker\Docker\resources\bin;$env:PATH"` |
| `failed to connect to docker API at npipe://...` | Docker daemon down | Abrir Docker Desktop pela GUI |
| `Inference manager / Secrets Engine: cannot be accessed` | WSL 2.5+ incompat | Downgrade WSL para 2.4.13 |
| `KeyError 'severity'` no dashboard | Schema antigo | `python -m access_defense.cli init-db` |
| Agente IA não produz ações | Modelo sem tool-calling | Use qwen2.5 ou llama3.1 (gemma3 usa JSON fallback) |

Detalhes em `GUIA_USO.md` seção 14.

## Limpeza

```powershell
# Reset estado defensivo
python -m access_defense.cli reset-defense

# Reset SQLite total
Remove-Item access_control.db -Force
python -m access_defense.cli init-db

# Parar containers
docker compose down

# Wipe total (apaga volumes Docker — perde seed PG+Mongo)
docker compose down -v
```

## Documentação adicional

- **`GUIA_USO.md`** — guia completo de uso (18 seções, mais detalhado)
- **`USANDO_HTTP.md`** — fluxo HTTP/Docker
- **`USANDO_DASHBOARD.md`** — uso do dashboard
- **`USANDO_IA_LOCAL.md`** — setup Ollama

## Avisos de segurança

- Servidor INTENCIONALMENTE vulnerável. Localhost apenas.
- Credenciais Postgres/Mongo hardcoded (`app/app_pwd`) no `docker-compose.yml`.
- Containers bindam em `0.0.0.0` — qualquer um na rede local pode acessar. Para isolar, mude para `127.0.0.1:5432:5432` no compose.
- Nunca commitar `ChavesOpenrouter.txt` (já no `.gitignore`).

---

**Desenvolvido para**: Trabalho de Conclusão de Curso
**Metodologia**: Agentes LLM autônomos + ataques reais + benchmark relacional vs NoSQL
**Última atualização**: Maio 2026
