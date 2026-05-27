# Fluxo HTTP Real — Guia Rápido

Setup ponta-a-ponta para rodar o sistema com **DBs reais (Postgres + Mongo)**,
**servidor vulnerável Flask**, **atacante HTTP** e **agente IA autônomo**.

## Pré-requisitos

1. **Docker Desktop** instalado e rodando (Windows/macOS/Linux)
2. **Python 3.10+**
3. **Ollama** instalado + modelo com tool-calling: `ollama pull qwen2.5`
4. `pip install -r requirements.txt`

## Componentes

| Processo | Porta | Comando |
|---|---|---|
| Postgres | 5432 | `docker compose up -d` |
| MongoDB | 27017 | `docker compose up -d` |
| Server vulnerável | 8000 | `python -m access_defense.server` |
| Agente IA | — | `python -m access_defense.agent_loop --model qwen2.5` |
| Atacante | — | `python -m access_defense.attacker --mode full` |
| Dashboard | 8501 | `python -m streamlit run access_defense/dashboard.py` |
| Ollama | 11434 | `ollama serve` (geralmente automático) |

## Setup mínimo (1 vez)

```powershell
# 1. Containers
docker compose up -d

# 2. Schema SQLite (logs locais)
python -m access_defense.cli init-db

# 3. Modelo LLM com tool-calling
ollama pull qwen2.5
```

## Demo rápida

```powershell
# Tudo de uma vez
powershell -ExecutionPolicy Bypass -File scripts/run_full_demo.ps1
```

## Demo manual (4 terminais)

**Terminal 1 — Server vulnerável**
```powershell
python -m access_defense.server --port 8000
```

**Terminal 2 — Agente IA**
```powershell
$env:AGENT_PROVIDER="ollama"
$env:OLLAMA_OPENAI_BASE_URL="http://localhost:11434/v1"
$env:OLLAMA_API_KEY="ollama"
python -m access_defense.agent_loop --model qwen2.5 --interval 3
```

**Terminal 3 — Dashboard**
```powershell
python -m streamlit run access_defense/dashboard.py
```

**Terminal 4 — Atacante**
```powershell
# Tudo
python -m access_defense.attacker --mode full

# Modos individuais
python -m access_defense.attacker --mode sqli
python -m access_defense.attacker --mode nosqli
python -m access_defense.attacker --mode brute-force --rounds 50
python -m access_defense.attacker --mode ddos --requests 500 --concurrency 50
python -m access_defense.attacker --mode exfil
python -m access_defense.attacker --mode privesc
```

## Métricas

```powershell
# Texto formatado
python -m access_defense.metrics

# JSON pra parse
python -m access_defense.metrics --json
```

Saída mostra:
- `time_to_block_ms` — latência entre 1ª req maliciosa e 1º `block_ip` aplicado
- `attack_success_rate_pct` — % de ataques que retornaram dados
- `coverage_pct` — % de IPs atacantes que foram bloqueados
- `ai_actions_by_tool` — quantas vezes cada tool foi chamada

## Benchmark Postgres vs Mongo

```powershell
# Todos workloads, 100 iterações cada
python -m access_defense.benchmark --iterations 100

# Workload específico
python -m access_defense.benchmark --workload search_like --iterations 500

# Backend específico
python -m access_defense.benchmark --backend postgres --iterations 1000
```

Workloads: `login`, `search_eq`, `search_like`, `full_scan`.
Resultados persistidos em `benchmark_runs` e visíveis na aba **⚡ Benchmark** do dashboard.

## Ferramentas externas (sqlmap, hydra)

```bash
# sqlmap automatizado contra /pg/search e /pg/login
bash scripts/run_sqlmap.sh

# hydra brute-force contra /pg/login
bash scripts/run_hydra.sh
```

## Endpoints vulneráveis

| Método | Path | Vulnerabilidade |
|---|---|---|
| POST | `/pg/login` | SQLi clássico (string-concat em `username`/`password`) |
| GET | `/pg/search?table=&q=` | SQLi via UNION + table name injection |
| POST | `/pg/query` | SQL bruto (pior caso, demo de exfiltração) |
| POST | `/mongo/login` | NoSQLi via `$ne`, `$gt`, `$where` |
| POST | `/mongo/find` | NoSQLi: filtro JSON passa direto pro `find()` |
| GET | `/health` | Status PG+Mongo |
| GET | `/status` | Contadores SQLite (logs/blocked/locked) |

**Enforcement** (executa **antes** de cada query):
- `blocked_ips`: 403 se IP do request estiver bloqueado
- `locked_users`: 403 se username do payload estiver travado

## Ferramentas expostas ao LLM (function-calling)

| Tool | Args | Efeito |
|---|---|---|
| `block_ip` | `ip, reason, ttl_seconds` | Insere em `blocked_ips`. Server passa a retornar 403 pra esse IP. |
| `lock_user` | `username, reason` | Insere em `locked_users`. Server passa a retornar 403 pra esse user. |
| `flag_for_audit` | `log_id, severity, reason` | Cria alerta em `security_alerts` sem bloquear. |
| `no_action` | `reason` | Explicitamente nada a fazer. |

## Schema SQLite (relevante)

- `access_logs` — toda request HTTP loggada
- `blocked_ips` — bloqueios ativos
- `locked_users` — usuários travados
- `ai_actions` — histórico de tool-calls do LLM
- `security_alerts` — alertas (regras OU agente)
- `benchmark_runs` — resultados de bench
- `ai_agent_logs` — timing de chamadas LLM (legado, do gateway antigo)

## Limpeza

```powershell
# Resetar estado defensivo (manter logs)
python -m access_defense.cli reset-defense

# Wipe completo
docker compose down -v
Remove-Item access_control.db -Force
python -m access_defense.cli init-db
```

## Notas para o TCC

- **Aviso de segurança**: O servidor é INTENCIONALMENTE vulnerável. Só rodar em
  localhost / rede isolada. Nunca expor à internet.
- **Modelo recomendado**: `qwen2.5` ou `llama3.1` (suportam tool-calling nativo).
  `gemma3` precisa de fallback JSON-no-content (já implementado).
- **Comparação experimental**: rode demo 2× — uma com agente ativo, outra com
  agente parado. Compare `attack_success_rate_pct` e `time_to_block_ms`.
- **Benchmark p/ pesquisa**: a aba ⚡ do dashboard mostra Postgres vs Mongo
  lado-a-lado por workload, util pra justificar escolha de stack no TCC.
