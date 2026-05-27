# Guia de Uso — TCC Sistema de Defesa Contra Acessos Anômalos

Guia detalhado para rodar o projeto end-to-end no estado atual.

---

## 1. Visão Geral da Stack

```
┌────────────────┐
│  attacker.py   │  Script Python que dispara ataques HTTP reais
└───────┬────────┘
        │ HTTP
        ▼
┌────────────────┐     ┌──────────────┐
│   server.py    │────►│  Postgres    │  (Docker, porta 5432)
│  Flask :8000   │     │  tcc_target  │
│                │────►│              │
│   Vulnerável!  │     └──────────────┘
│                │     ┌──────────────┐
│                │────►│  MongoDB     │  (Docker, porta 27017)
│                │     │  tcc_target  │
│                │     └──────────────┘
└───────┬────────┘
        │ append
        ▼
┌────────────────┐                    ┌──────────────────────┐
│  access_logs   │◄───── poll ────────│  agent_loop.py       │
│  (SQLite)      │                    │  LLM tool-calling    │
└───────┬────────┘                    │  (gemma3 ou qwen2.5) │
        ▲                             └──────────┬───────────┘
        │ enforce 403                            │ tool calls
        │                                        ▼
┌────────────────┐                    ┌──────────────────────┐
│  blocked_ips   │◄───────────────────│  block_ip            │
│  locked_users  │◄───────────────────│  lock_user           │
│  security_alerts│◄──────────────────│  flag_for_audit      │
└────────────────┘                    └──────────────────────┘
        ▲
        │ read
        │
┌────────────────┐
│  dashboard.py  │  Streamlit :8501 — 7 abas
└────────────────┘
```

**Componentes**:
- **2 bancos alvo**: Postgres + MongoDB (Docker)
- **1 servidor HTTP vulnerável**: Flask em :8000 com endpoints intencionalmente inseguros
- **1 atacante**: script Python que faz SQLi, NoSQLi, brute-force, DDoS, exfiltração, privesc
- **1 agente IA**: LLM (gemma3 ou qwen2.5) com tool-calling autônomo
- **1 dashboard**: Streamlit em :8501, 7 abas (logs, alertas, anomalias, resposta, performance IA, agente IA ao vivo, benchmark)
- **1 SQLite local**: `access_control.db` armazena logs/alertas/ações/benchmarks

---

## 2. Pré-requisitos (verifique antes)

| Item | Verificação | Como instalar |
|---|---|---|
| Python 3.10+ | `python --version` | python.org |
| Docker Desktop | `docker --version` | docker.com/products/docker-desktop |
| Ollama | `ollama --version` | ollama.com |
| Modelo gemma3 | `ollama list \| grep gemma3` | `ollama pull gemma3` |
| Modelo qwen2.5 | `ollama list \| grep qwen2.5` | `ollama pull qwen2.5` |

**Importante (Windows)**: Docker executável fica em `C:\Program Files\Docker\Docker\resources\bin\`. Se `docker` não estiver no PATH, abra Docker Desktop pela GUI (basta isso para o daemon subir) — esses comandos PowerShell do guia já funcionarão.

---

## 3. Setup Inicial (1× só)

Abra PowerShell na raiz do projeto (`C:\Users\tiago\Documents\TCC`):

```powershell
# 1. Adicionar Docker ao PATH desta sessão (se necessário)
$env:PATH = "C:\Program Files\Docker\Docker\resources\bin;$env:PATH"

# 2. Instalar dependências Python
pip install -r requirements.txt

# 3. Subir containers Postgres + Mongo
docker compose up -d

# 4. Aguardar containers ficarem prontos
Start-Sleep -Seconds 8

# 5. Verificar containers UP
docker compose ps

# 6. Inicializar SQLite local (logs/alertas/ações)
python -m access_defense.cli init-db
```

**Output esperado**:
```
tcc_postgres  running  Up 8 seconds  0.0.0.0:5432->5432/tcp
tcc_mongo     running  Up 8 seconds  0.0.0.0:27017->27017/tcp
Banco inicializado em: C:\Users\tiago\Documents\TCC\access_control.db
```

---

## 4. Demo Rápida (script orquestrador)

Para rodar tudo de uma vez:

```powershell
$env:PATH = "C:\Program Files\Docker\Docker\resources\bin;$env:PATH"
powershell -ExecutionPolicy Bypass -File scripts/run_full_demo.ps1
```

Flags úteis:
```powershell
# Trocar modelo
powershell -ExecutionPolicy Bypass -File scripts/run_full_demo.ps1 -Model gemma3

# Pular Docker (se já estiver up)
powershell -ExecutionPolicy Bypass -File scripts/run_full_demo.ps1 -SkipDocker

# Modo ataque específico
powershell -ExecutionPolicy Bypass -File scripts/run_full_demo.ps1 -AttackMode sqli
```

---

## 5. Demo Manual (4 terminais separados)

Use este modo para enxergar logs ao vivo de cada componente.

### Terminal 1 — Servidor vulnerável

```powershell
$env:PATH = "C:\Program Files\Docker\Docker\resources\bin;$env:PATH"
python -m access_defense.server --port 8000
```

Sai algo como:
```
[server] Postgres+Mongo health: {'postgres': True, 'mongo': True, 'errors': {}}
[server] Escutando em http://127.0.0.1:8000
* Running on http://127.0.0.1:8000
```

**Teste manual** (em outro terminal):
```powershell
curl http://localhost:8000/health
curl http://localhost:8000/status
```

### Terminal 2 — Agente IA

Use **qwen2.5** (recomendado, tool-calling nativo, mais rápido):
```powershell
$env:AGENT_PROVIDER = "ollama"
$env:OLLAMA_NATIVE_URL = "http://localhost:11434"
$env:OLLAMA_API_KEY = "ollama"

python -m access_defense.agent_loop --model qwen2.5 --batch 15 --interval 3
```

OU **gemma3** (mais lento, sem tool-calling nativo, usa JSON fallback):
```powershell
$env:AGENT_PROVIDER = "ollama"
$env:OLLAMA_NATIVE_URL = "http://localhost:11434"
python -m access_defense.agent_loop --model gemma3 --batch 8 --interval 4
```

Output em loop:
```
[agent] sessao=9c9abc8d modelo=qwen2.5 batch=15
[agent] iniciando do log_id=0
[agent] batch=15 ultimo_id=15 tools=3
  -> block_ip({'ip': '127.0.0.1', 'reason': 'SQLi'}) applied=True err=None
  -> flag_for_audit({'log_id': 12, 'severity': 'high'}) applied=True err=None
```

### Terminal 3 — Dashboard

```powershell
python -m streamlit run access_defense/dashboard.py
```

Abre automaticamente http://localhost:8501. Mostra 7 abas:

| Aba | O que mostra |
|---|---|
| 📝 Logs de Acesso | Todo request HTTP loggado |
| ⚠️ Alertas | security_alerts (flagged pelo agente) |
| 📊 Anomalias | Distribuição de scores |
| 🛡️ Resposta Defensiva | incident_response_logs (sistema antigo) |
| 🤖 Performance IA | Latência LLM por modelo |
| 🧠 **Agente IA ao vivo** | Tool-calls do agent_loop, blocked_ips, locked_users |
| ⚡ **Benchmark PG vs Mongo** | Comparação de latência por workload |

### Terminal 4 — Atacante

```powershell
# Tudo (sqli + nosqli + brute + ddos + exfil + privesc)
python -m access_defense.attacker --target http://localhost:8000 --mode full

# Modos individuais
python -m access_defense.attacker --mode sqli
python -m access_defense.attacker --mode nosqli
python -m access_defense.attacker --mode brute-force --rounds 50
python -m access_defense.attacker --mode ddos --requests 500 --concurrency 50
python -m access_defense.attacker --mode exfil
python -m access_defense.attacker --mode privesc
```

Cada modo imprime JSON com `requests_sent`, `successful_breaches`, `blocked_by_defense`, `errors`, `samples`, `duration_s`.

---

## 6. Modos de Ataque Detalhados

### 6.1 SQL Injection (`sqli`)

Payloads de auth bypass + UNION + DROP:
```python
{"username": "admin' --", "password": "qualquer"}
{"username": "' OR '1'='1", "password": "' OR '1'='1"}
"' UNION SELECT id, username, password, role, NULL FROM users --"
```

**Esperado sem defesa**: retorna 5 users com password em plaintext.

### 6.2 NoSQL Injection (`nosqli`)

Payloads com operadores Mongo:
```python
{"username": {"$ne": None}, "password": {"$ne": None}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"collection": "users", "filter": {"$where": "true"}}
```

**Esperado sem defesa**: bypassa login + dump da collection.

### 6.3 Brute Force (`brute-force`)

Tenta N senhas comuns contra `/pg/login` com user fixo.

**Esperado sem defesa**: `admin123` está na lista → autentica.

### 6.4 DDoS (`ddos`)

ThreadPool com N requests concorrentes contra `/pg/search`.

Padrão: 200 requests, 20 workers.

### 6.5 Exfiltração (`exfil`)

POST direto em `/pg/query` com SQL bruto:
```sql
SELECT username, password, role FROM users
SELECT * FROM salarios
SELECT table_name FROM information_schema.tables WHERE table_schema='public'
```

### 6.6 Privilege Escalation (`privesc`)

User comum (`joao`) tenta acessar tabela sensível (`salarios`).

---

## 7. Endpoints do Servidor

| Método | Path | Body/Query | Vulnerabilidade |
|---|---|---|---|
| POST | `/pg/login` | `{"username":..., "password":...}` | SQLi f-string |
| GET | `/pg/search` | `?table=&q=` | SQLi via UNION + table injection |
| POST | `/pg/query` | `{"sql":...}` | SQL bruto (worst case) |
| POST | `/mongo/login` | `{"username":..., "password":...}` | NoSQLi operators |
| POST | `/mongo/find` | `{"collection":..., "filter":{...}}` | Filtro passa direto |
| GET | `/health` | — | Status PG+Mongo |
| GET | `/status` | — | Contadores SQLite |

**Enforcement** (sempre antes da query):
1. Checa `blocked_ips`. Se IP bloqueado → 403.
2. Checa `locked_users`. Se username travado → 403.

---

## 8. Comandos do Agente IA

### Argumentos

```
--model       MODEL    gemma3, qwen2.5, llama3.1, etc.
--batch       N        Eventos por chamada LLM (padrão 15)
--interval    SEGUNDOS Tempo entre polls (padrão 3)
--once                 Processa 1 batch e sai
--from-start           Começa do log_id=0 (reprocessa tudo)
```

### Ferramentas expostas ao LLM

```
block_ip(ip, reason, ttl_seconds)
  → INSERT em blocked_ips. Server retorna 403 pra esse IP.

lock_user(username, reason)
  → INSERT em locked_users. Server retorna 403 pra esse user.

flag_for_audit(log_id, severity, reason)
  → INSERT em security_alerts (status=open). Não bloqueia.

no_action(reason)
  → Explicitamente nada a fazer.
```

### Variáveis de ambiente

```powershell
$env:AGENT_PROVIDER = "ollama"       # ou "openrouter"
$env:OLLAMA_NATIVE_URL = "http://localhost:11434"   # endpoint Ollama nativo
$env:OLLAMA_API_KEY = "ollama"       # qualquer string
$env:OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
$env:OPENROUTER_API_KEY = "sk-or-..."
```

### Modelo suportado vs JSON fallback

| Modelo | Tool-calling nativo | Modo usado | Latência média |
|---|---|---|---|
| qwen2.5 | ✅ | Tools API | ~5s/batch |
| llama3.1 | ✅ | Tools API | ~6s/batch |
| mistral | ✅ | Tools API | ~5s/batch |
| gemma3 | ❌ | JSON format | ~30s/batch |
| gemma2 | ❌ | JSON format | ~25s/batch |

Lista hardcoded em `agent_loop.py:NO_TOOLS_MODELS`.

---

## 9. Benchmark Postgres vs MongoDB

```powershell
# Todas workloads, 200 iterações cada, ambos backends
python -m access_defense.benchmark --iterations 200

# Workload específico
python -m access_defense.benchmark --workload search_like --iterations 500

# Backend único
python -m access_defense.benchmark --backend postgres --iterations 1000
```

### Workloads

| Nome | Postgres | Mongo |
|---|---|---|
| `login` | `WHERE username=%s AND password=%s` | `find_one({username, password})` |
| `search_eq` | `WHERE nome=%s` | `find({nome: ...})` |
| `search_like` | `WHERE nome LIKE 'A%'` | `find({nome: {$regex: '^A'}})` |
| `full_scan` | `SELECT * FROM clientes` | `find({})` |

Resultados persistidos em `benchmark_runs` + visíveis na aba **⚡ Benchmark** do dashboard.

---

## 10. Métricas de Defesa

```powershell
# Texto formatado
python -m access_defense.metrics

# JSON pra parse
python -m access_defense.metrics --json

# Filtrar por sessão específica do agente
python -m access_defense.metrics --session 9c9abc8d
```

Output mostra:
- `total_requests` — todos os logs
- `malicious_requests` — detectado pela heurística (tokens SQLi/NoSQLi)
- `blocked_by_defense` — requests bloqueados pelo enforcement
- `attack_success_count` — atacante conseguiu rows > 0
- `attack_success_rate_pct` — % de sucesso do atacante
- `ai_actions_by_tool` — dict de quantas chamadas por tool
- `time_to_block_ms` — latência entre 1ª req maliciosa e 1º block_ip
- `coverage_pct` — % de IPs atacantes bloqueados

---

## 11. Inspecionar Banco Manualmente

```powershell
# Quick stats
python -c "import sqlite3; c=sqlite3.connect('access_control.db'); [print(t, c.execute(f'SELECT COUNT(*) FROM {t}').fetchone()[0]) for t in ['access_logs','ai_actions','blocked_ips','locked_users','security_alerts','benchmark_runs']]"

# Últimas ações IA
python -c "import sqlite3; c=sqlite3.connect('access_control.db'); [print(r) for r in c.execute('SELECT agent_name, tool_name, substr(arguments,1,80), applied FROM ai_actions ORDER BY id DESC LIMIT 10')]"

# IPs bloqueados ativos
python -c "import sqlite3; c=sqlite3.connect('access_control.db'); [print(r) for r in c.execute('SELECT * FROM blocked_ips')]"
```

### Tabelas (SQLite local)

| Tabela | O que guarda |
|---|---|
| `access_logs` | Toda request HTTP (user, ip, op, table, payload, success, rows) |
| `security_alerts` | Alertas (criados por regras OU pelo flag_for_audit) |
| `blocked_ips` | IPs bloqueados pelo agente (com TTL opcional) |
| `locked_users` | Usuários travados pelo agente |
| `ai_actions` | Histórico de tool-calls do LLM |
| `ai_agent_logs` | Timing de chamadas LLM (legado, do gateway antigo) |
| `incident_response_logs` | Ações do defender (legado) |
| `benchmark_runs` | Resultados de bench PG vs Mongo |
| `users`, `permissions`, `clientes`, `transacoes`, `salarios` | Sistema legado (não usado pelo HTTP server) |

---

## 12. Cenários de Demonstração

### Cenário A — "Atacante sem agente"

Mostra impacto sem defesa.

```powershell
# Reset enforcement
python -c "import sqlite3; c=sqlite3.connect('access_control.db'); c.execute('DELETE FROM blocked_ips'); c.execute('DELETE FROM locked_users'); c.commit()"

# Sem agente rodando
python -m access_defense.attacker --mode full

# Ver dano
python -m access_defense.metrics
```

Esperado: `attack_success_rate_pct` alto (~90-100%).

### Cenário B — "Atacante com qwen2.5"

```powershell
# Terminal 1
python -m access_defense.agent_loop --model qwen2.5 --batch 15 --interval 3

# Terminal 2 (aguardar ~5s pro agente carregar)
python -m access_defense.attacker --mode full
Start-Sleep 30   # deixar agente processar
python -m access_defense.metrics
```

Esperado: IP bloqueado após 1-2 batches, `blocked_by_defense` cresce, `attack_success_rate_pct` cai conforme atacante prossegue.

### Cenário C — "Comparação gemma3 vs qwen2.5"

```powershell
# Rodar Cenário B com qwen2.5, salvar metrics como JSON
python -m access_defense.metrics --json > metrics_qwen.json

# Reset
python -c "import sqlite3; c=sqlite3.connect('access_control.db'); [c.execute(f'DELETE FROM {t}') for t in ['ai_actions','blocked_ips','locked_users','access_logs','security_alerts']]; c.commit()"

# Rodar Cenário B com gemma3
python -m access_defense.agent_loop --model gemma3 --batch 8 --interval 4
python -m access_defense.attacker --mode full
python -m access_defense.metrics --json > metrics_gemma.json

# Comparar
python -c "import json; a=json.load(open('metrics_qwen.json')); b=json.load(open('metrics_gemma.json')); print('qwen:', a['ai_actions_by_tool'], 'gemma:', b['ai_actions_by_tool'])"
```

### Cenário D — "Benchmark PG vs Mongo isolado"

```powershell
# Garantir DBs limpos (opcional)
docker compose down -v
docker compose up -d
Start-Sleep 10

# Rodar bench grande
python -m access_defense.benchmark --iterations 1000

# Visualizar no dashboard, aba ⚡ Benchmark
```

---

## 13. Ferramentas Externas (sqlmap + hydra)

Não vêm com o projeto. Instalar manualmente:
- sqlmap: `pip install sqlmap` ou clone do repo
- hydra: `choco install hydra` (Windows) ou `apt install hydra` (Linux)

```bash
# WSL ou Git Bash
bash scripts/run_sqlmap.sh
bash scripts/run_hydra.sh
```

Os scripts apontam para `http://localhost:8000` por padrão.

---

## 14. Troubleshooting

### "Docker daemon not running"
- Abra Docker Desktop pela GUI. Aguarde ícone na bandeja ficar verde.

### "Connection refused" no Postgres/Mongo
```powershell
docker compose ps
docker compose logs postgres
docker compose logs mongo
```
Se containers down: `docker compose up -d`.

### "ollama: command not found"
- Ollama instalado mas não no PATH. Use endpoint HTTP direto: `curl http://localhost:11434/api/tags`. Se responde, OK.

### Agente IA não produz ações
- Verifique: `curl http://localhost:11434/api/ps` (deve listar modelo)
- Pull modelo: `ollama pull qwen2.5`
- Teste tools API: `curl http://localhost:11434/api/chat -d '{"model":"qwen2.5","stream":false,"messages":[{"role":"user","content":"hi"}]}'`

### `KeyError: 'severity'` ou similar no dashboard
- Schema desatualizado. Roda: `python -m access_defense.cli init-db` para criar novas tabelas.

### Dashboard mostra vazio
- Aguarde: agente IA processa em batches (1 batch = ~5-30s dependendo do modelo).
- Dispare ataques primeiro para gerar dados.

---

## 15. Limpeza

### Reset estado defensivo (manter logs)
```powershell
python -m access_defense.cli reset-defense
python -c "import sqlite3; c=sqlite3.connect('access_control.db'); c.execute('DELETE FROM locked_users'); c.commit()"
```

### Reset SQLite completo
```powershell
Remove-Item access_control.db -Force
python -m access_defense.cli init-db
```

### Parar containers
```powershell
docker compose down
```

### Wipe total (CUIDADO — apaga tudo, incluindo volumes Docker)

> **AVISO**: O comando abaixo apaga permanentemente os dados dos containers Postgres e MongoDB. Use só se quiser começar do zero.

```powershell
docker compose down -v
Remove-Item access_control.db -Force
python -m access_defense.cli init-db
```

---

## 16. Estrutura de Arquivos

```
TCC/
├── access_defense/
│   ├── __init__.py
│   ├── agents.py             # Cliente LLM legado (gateway antigo)
│   ├── agent_loop.py         # NOVO: Agente IA autônomo tool-calling
│   ├── anomaly.py            # Regras determinísticas (legado)
│   ├── attacker.py           # NOVO: Cliente HTTP atacante
│   ├── attacks.py            # Simulador legado (atinge gateway)
│   ├── benchmark.py          # NOVO: Bench PG vs Mongo
│   ├── cli.py                # CLI principal (init-db, simulate, etc.)
│   ├── dashboard.py          # Streamlit (7 abas)
│   ├── database.py           # Schema SQLite + seed
│   ├── db_backends.py        # NOVO: Conexões PG + Mongo vulneráveis
│   ├── defender.py           # Monitor legado
│   ├── gateway.py            # Gateway legado (rules + RBAC)
│   ├── metrics.py            # NOVO: Métricas de defesa
│   ├── security.py           # PBKDF2 hash
│   └── server.py             # NOVO: Flask server vulnerável
├── scripts/
│   ├── init_postgres.sql     # Seed Postgres
│   ├── init_mongo.js         # Seed Mongo
│   ├── run_full_demo.ps1     # Orquestrador completo
│   ├── run_hydra.sh          # Wrapper hydra (brute force)
│   └── run_sqlmap.sh         # Wrapper sqlmap (SQLi)
├── docker-compose.yml        # PG + Mongo containers
├── requirements.txt          # Deps Python
├── access_control.db         # SQLite local (logs/ações)
├── README.md                 # Docs do sistema legado
├── USANDO_HTTP.md            # Guia do novo fluxo HTTP
├── USANDO_DASHBOARD.md       # Guia da dashboard antiga
├── USANDO_IA_LOCAL.md        # Setup Ollama
└── GUIA_USO.md               # Este arquivo
```

---

## 17. Sequência Recomendada para o TCC

Para gravar/demonstrar no TCC, esta sequência cobre tudo em ~10 minutos:

1. **Setup** (terminal único, 1 min):
   ```powershell
   $env:PATH = "C:\Program Files\Docker\Docker\resources\bin;$env:PATH"
   docker compose up -d
   Start-Sleep 8
   python -m access_defense.cli init-db
   ```

2. **Subir dashboard** (terminal 1, deixar aberto):
   ```powershell
   python -m streamlit run access_defense/dashboard.py
   ```

3. **Subir server** (terminal 2):
   ```powershell
   python -m access_defense.server --port 8000
   ```

4. **Mostrar ataque SEM defesa** (terminal 3):
   ```powershell
   python -m access_defense.attacker --mode sqli
   ```
   → Mostrar no dashboard aba "Logs": SQLi rolou.

5. **Subir agente qwen2.5** (terminal 4):
   ```powershell
   $env:AGENT_PROVIDER = "ollama"
   $env:OLLAMA_NATIVE_URL = "http://localhost:11434"
   python -m access_defense.agent_loop --model qwen2.5 --batch 15 --interval 3
   ```

6. **Repetir ataque COM defesa** (terminal 3):
   ```powershell
   python -m access_defense.attacker --mode full
   ```
   → Aguardar 30s. Mostrar dashboard aba "Agente IA ao vivo": IP bloqueado, tool calls aparecendo.

7. **Métricas finais** (terminal 3):
   ```powershell
   python -m access_defense.metrics
   ```

8. **Benchmark PG vs Mongo** (terminal 3):
   ```powershell
   python -m access_defense.benchmark --iterations 200
   ```
   → Mostrar dashboard aba "Benchmark": Postgres ~2× mais rápido.

9. **Comparação qwen vs gemma** (opcional):
   - Parar agente qwen
   - Reset: `python -m access_defense.cli reset-defense`
   - Subir gemma3
   - Repetir ataque
   - Comparar metrics

---

## 18. Aviso de Segurança

**O servidor é INTENCIONALMENTE vulnerável.** Endpoints aceitam SQLi e NoSQLi reais. Os DBs Postgres e Mongo expostos via Docker têm credenciais hardcoded (`app/app_pwd`).

**Nunca rode:**
- Em rede pública (binding `0.0.0.0` em IP externo)
- Em servidor de produção
- Com dados reais

**Sempre rode:**
- Em localhost (`127.0.0.1`)
- Atrás de firewall
- Em VM/container isolado
- Com dados de teste apenas

Os containers Docker bindam em `0.0.0.0:5432` e `0.0.0.0:27017` — qualquer um na sua rede local pode acessar. Para isolar, mude para `127.0.0.1:5432:5432` no `docker-compose.yml`.
