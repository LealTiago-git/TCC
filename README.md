# TCC — Sistema de Defesa Contra Acessos Anômalos com Agentes de IA

Protótipo acadêmico que expõe um banco de dados **intencionalmente vulnerável** a ataques HTTP reais (SQL Injection, NoSQL Injection, brute-force, DDoS, exfiltração, escalada de privilégio) e usa **agentes LLM autônomos** (qwen2.5, gemma3) para detectar esses ataques e executar respostas defensivas em tempo real — bloquear IP, travar usuário, registrar alerta.

> ⚠️ **Aviso de segurança:** o servidor é vulnerável de propósito. Roda apenas em `127.0.0.1` atrás de containers Docker isolados. **Nunca exponha à internet.**

---

# Como o Projeto Funciona (Visão Geral)

## A ideia

Um atacante dispara ataques reais contra um servidor HTTP. Cada requisição é registrada. Um agente de IA observa esse registro continuamente, identifica padrões maliciosos e age sozinho para conter o atacante. Um painel mostra tudo acontecendo ao vivo.

## Fluxo de ponta a ponta

```
┌──────────────┐
│ attacker.py  │  dispara ataques HTTP reais
└──────┬───────┘
       │ HTTP
       ▼
┌──────────────┐      ┌──────────────┐
│  server.py   │─────►│  Postgres    │  (Docker :5432)  ← alvo SQLi
│ Flask :8000  │      └──────────────┘
│ VULNERÁVEL   │      ┌──────────────┐
│              │─────►│  MongoDB     │  (Docker :27017) ← alvo NoSQLi
└──────┬───────┘      └──────────────┘
       │ grava cada request
       ▼
┌──────────────┐  poll   ┌──────────────────────┐
│ access_logs  │◄────────│  agent_loop.py       │
│  (SQLite)    │         │  LLM tool-calling    │
└──────┬───────┘         │  qwen2.5 / gemma3    │
       ▲ 403             └──────────┬───────────┘
       │                            │ tool calls
       │                            ▼
┌─────────────────┐      ┌──────────────────────┐
│ blocked_ips     │◄─────│ block_ip()           │
│ locked_users    │◄─────│ lock_user()          │
│ security_alerts │◄─────│ flag_for_audit()     │
└─────────────────┘      └──────────────────────┘
       ▲ lê
       │
┌──────────────┐
│ dashboard.py │  Streamlit :8501 — 5 abas ao vivo
└──────────────┘
```

## Os 6 componentes

| Componente | Papel |
|---|---|
| **Bancos-alvo** | Postgres + MongoDB em Docker, com dados-isca (usuários, clientes, salários) |
| **Servidor vulnerável** (`server.py`) | API Flask com endpoints que aceitam SQLi/NoSQLi de verdade. Loga cada acesso. |
| **Atacante** (`attacker.py`) | Script Python que faz requisições maliciosas reais via HTTP |
| **Agente IA** (`agent_loop.py`) | LLM que lê os logs, classifica ataques e chama ferramentas de defesa |
| **Camada de enforcement** | Middleware do servidor que bloqueia IPs/usuários marcados pela IA (HTTP 403) |
| **Dashboard** (`dashboard.py`) | Painel Streamlit que mostra logs, defesa ativa, análise e benchmark |

## O ciclo de defesa

1. Atacante manda payload malicioso → servidor executa e **loga**.
2. Agente IA pega o log no próximo ciclo (poll a cada N segundos).
3. LLM classifica o ataque e decide a ação via *tool-calling*.
4. Ferramenta grava em `blocked_ips` / `locked_users`.
5. Próxima requisição daquele IP/usuário recebe **403 antes de chegar ao banco**.
6. Dashboard reflete tudo em tempo real.

## Princípio do TCC

**Defesa autônoma por LLM com tool-calling.** O modelo não só *explica* o ataque — ele **age** (bloqueia, trava, alerta). O projeto compara dois modelos (qwen2.5 vs gemma3) e dois bancos (Postgres vs MongoDB).

---

# Funcionamento Profundo

## 2.1 Os bancos de dados (como são tratados)

Há **dois tipos** de banco, com papéis diferentes:

### Bancos-alvo (Postgres + MongoDB) — onde o ataque acontece

Rodam em Docker (`docker-compose.yml`), populados pelos seeds `scripts/init_postgres.sql` e `scripts/init_mongo.js`. Mesma estrutura de dados nos dois, de propósito, para comparar SQL vs NoSQL:

- `users` (username, **password em texto puro** — cenário de DB legado), `clientes`, `transacoes`, `salarios`.

O acesso é feito por `db_backends.py`, que é **intencionalmente inseguro**:

```python
# Postgres — f-string crua, vulnerável a SQLi clássico
sql = f"SELECT id, username, role FROM users WHERE username='{username}' AND password='{password}'"
```

```python
# Mongo — filtro JSON do cliente passa direto pro find(), vulnerável a operadores
db.users.find_one({"username": username, "password": password})
# username = {"$ne": null} → bypassa autenticação
```

Dois helpers centralizam execução + medição de tempo + captura de erro:
- `_run_pg(sql, swallow_no_rows=False)` — roda SQL e devolve `QueryResult`. `swallow_no_rows=True` permite DDL (ex.: `DROP`) sem quebrar.
- `_run_mongo(filter_doc, fetch_fn)` — roda a query Mongo via closure, **fecha o client no `finally`** (evita vazar conexão).

Ambos retornam o mesmo `QueryResult(backend, success, rows, duration_ms, error, raw_query)` — uniforme para o benchmark comparar os dois bancos.

### Banco de controle (SQLite — `access_control.db`)

Não é alvo. É o "cérebro" do sistema, criado por `database.py → init_db()`. Tabelas relevantes:

| Tabela | Conteúdo |
|---|---|
| `access_logs` | Toda requisição HTTP (user, IP, operação, tabela, payload, sucesso, linhas retornadas) |
| `blocked_ips` | IPs em quarentena (com TTL opcional) — lido pelo enforcement |
| `locked_users` | Usuários travados pela IA |
| `ai_actions` | Histórico de cada *tool call* do LLM (modelo, ferramenta, argumentos, aplicado, erro) |
| `security_alerts` | Alertas (de regras ou de `flag_for_audit`) |
| `benchmark_runs` | Resultados de latência Postgres vs Mongo |

## 2.2 O servidor vulnerável (`server.py`)

Flask na porta 8000. Cada endpoint: recebe payload → chama o backend vulnerável → **loga em `access_logs`** → devolve JSON com resultado e tempo.

| Método | Rota | Vulnerabilidade |
|---|---|---|
| POST | `/pg/login` | SQLi clássico (f-string em username/password) |
| GET | `/pg/search?table=&q=` | SQLi via UNION + injeção no nome da tabela |
| POST | `/pg/query` | SQL bruto — pior caso, demonstra exfiltração total |
| POST | `/mongo/login` | NoSQLi via `$ne`, `$gt`, `$where` |
| POST | `/mongo/find` | Filtro JSON do cliente passa direto pro `find()` |
| GET | `/health` | Status de Postgres + Mongo |
| GET | `/status` | Contadores do SQLite (logs / bloqueados / travados) |

**Enforcement** — decorator `enforce_block` roda **antes** de qualquer query:
1. IP está em `blocked_ips` (e dentro do TTL)? → `403 {"error": "ip blocked"}`.
2. Username do payload está em `locked_users`? → `403 {"error": "user locked"}`.

É assim que a decisão da IA vira efeito real: o servidor consulta as tabelas que a IA escreve.

## 2.3 Como os ataques são feitos (`attacker.py`)

Cliente HTTP que dispara **requisições reais** via `requests`. 6 modos:

| Modo | Alvo | Como ataca |
|---|---|---|
| `sqli` | `/pg/login`, `/pg/search` | Payloads de auth-bypass + UNION + DROP |
| `nosqli` | `/mongo/login`, `/mongo/find` | Operadores Mongo (`$ne`, `$gt`, `$where`) |
| `brute-force` | `/pg/login` | Lista de senhas comuns contra `admin` |
| `ddos` | `/pg/search` | ThreadPool com N requisições concorrentes |
| `exfil` | `/pg/query` | SQL bruto dumpando `users`/`salarios`/`information_schema` |
| `privesc` | `/pg/search` | User comum (`joao`) tentando ler `salarios` |
| `full` | todos | Roda os 6 em sequência |

Payloads reais embutidos:

```python
# SQLi login (auth bypass)
{"username": "admin' --", "password": "qualquer"}
{"username": "' OR '1'='1", "password": "' OR '1'='1"}

# SQLi search (vaza tabela users via UNION)
"' UNION SELECT id, username, password, role, NULL FROM users --"

# NoSQLi login (ignora a senha)
{"username": {"$ne": None}, "password": {"$ne": None}}

# Exfiltração (SQL bruto)
"SELECT username, password, role FROM users"
```

Cada modo produz um `AttackReport`: `requests_sent`, `successful_breaches` (atacante obteve dados), `blocked_by_defense` (recebeu 403), `errors`, `duration_s`.

**Ferramentas externas opcionais:** `scripts/run_sqlmap.sh` (sqlmap real contra `/pg/*`) e `scripts/run_hydra.sh` (hydra brute-force) — para validação com ferramentas de pentest consagradas.

## 2.4 Como as IAs atuam (`agent_loop.py`)

Loop autônomo:

1. **Poll** — busca eventos novos em `access_logs` (`id > last_seen`), **pulando** quem já está em `blocked_ips`/`locked_users` (não desperdiça chamada de LLM com tráfego já contido).
2. **Batch** — agrupa até N eventos e envia ao LLM.
3. **Tool-calling** — o LLM responde com chamadas de ferramenta.
4. **Executor** — aplica cada chamada (grava em `blocked_ips`/`locked_users`/`security_alerts`) e registra em `ai_actions`.

### Ferramentas disponíveis ao LLM

| Ferramenta | Argumentos | Efeito |
|---|---|---|
| `block_ip` | `ip, reason, ttl_seconds` | Insere em `blocked_ips`. Servidor passa a dar 403 a esse IP. |
| `lock_user` | `username, reason` | Insere em `locked_users`. Login daquele usuário sempre falha. |
| `flag_for_audit` | `log_id, severity, reason` | Cria alerta em `security_alerts` **sem** bloquear. |
| `no_action` | `reason` | Tráfego legítimo — nada a fazer. |

### Taxonomia que o agente usa

O prompt força o modelo a classificar cada evento em uma categoria exata (em vez de descrições genéricas) e começar o `reason` com ela:

`sql_injection` · `nosql_injection` · `brute_force` · `ddos` · `buffer_overflow` · `privilege_escalation` · `exfiltration` · `benign`

Regras de ação embutidas no prompt: injeção/exfil/ddos/overflow → `block_ip`; brute-force → `lock_user`; privesc → `lock_user` + `flag_for_audit`; incerto → `flag_for_audit`; tudo benigno → `no_action`. Instrução explícita: **se o IP já foi bloqueado num batch anterior, usar `no_action`** (não re-bloquear).

### Dois caminhos de provider

- **Ollama nativo** (`/api/chat`) — usado por padrão. Modelos com tool-calling nativo (qwen2.5, llama3.1) recebem as `tools` diretamente.
- **Fallback JSON** — modelos sem tool-calling nativo (gemma3) recebem instrução para responder um array JSON; o parser `extract_tool_calls` aceita tanto `message.tool_calls` (nativo) quanto JSON cru no `content`.
- **OpenRouter** — suportado via `AGENT_PROVIDER=openrouter` para rodar na nuvem.

### Comparação observada (qwen2.5 vs gemma3)

| | qwen2.5 | gemma3 |
|---|---|---|
| Tool-calling | nativo | fallback JSON |
| Cobertura | usa `block_ip` + `lock_user` + `flag` | quase só `flag` (raramente bloqueia, nunca trava) |
| Estabilidade | constante | trava após ~5 batches |

**Conclusão:** tool-calling nativo é materialmente mais confiável para defesa autônoma.

## 2.5 Benchmark Postgres vs MongoDB (`benchmark.py`)

Roda 4 workloads equivalentes em cada banco, mede `avg/min/max/p95` ms e grava em `benchmark_runs`:

| Workload | Postgres | Mongo |
|---|---|---|
| `login` | `WHERE username=%s AND password=%s` | `find_one({username, password})` |
| `search_eq` | `WHERE nome=%s` | `find({nome})` |
| `search_like` | `WHERE nome LIKE 'A%'` | `find({nome: {$regex: '^A'}})` |
| `full_scan` | `SELECT *` | `find({})` |

Resultado típico (200 iterações): **Postgres ~2× mais rápido** no dataset semeado.

## 2.6 Métricas de defesa (`metrics.py`)

Calcula a eficácia da IA contra os ataques:
- `time_to_block_ms` — latência entre o 1º request malicioso de um IP e o 1º `block_ip` aplicado.
- `attack_success_rate_pct` — % de ataques que ainda retornaram dados.
- `coverage_pct` — % de IPs atacantes que foram bloqueados.
- Distribuição de ações por ferramenta e por modelo.

## 2.7 O dashboard (`dashboard.py`)

Streamlit na porta 8501, lê só o SQLite. 5 abas:

| Aba | Mostra |
|---|---|
| 🏠 Visão Geral | KPIs (requests, bloqueios, ações da IA, taxa de bloqueio) |
| 📝 Acessos HTTP | Cada requisição + categoria de ataque inferida + filtros |
| 🛡️ Defesa Ativa | Tool-calls da IA, IPs bloqueados, usuários travados |
| 📊 Análise de Ataques | Categoria × resultado, taxa de bloqueio, timeline |
| ⚡ Benchmark | Postgres vs Mongo, latência média e p95 por workload |

Helper `categorize(payload)` (regex) classifica cada acesso na mesma taxonomia do agente, para a aba de análise cruzar "categoria × bloqueado vs vazado".

## 2.8 Os scripts

| Script | Função |
|---|---|
| `scripts/init_postgres.sql` | Cria e popula tabelas no Postgres (executado pelo Docker no boot) |
| `scripts/init_mongo.js` | Cria e popula coleções no Mongo (executado pelo Docker no boot) |
| `scripts/run_full_demo.ps1` | Orquestrador: detecta/sobe Docker, inicia servidor + agente + dashboard, dispara atacante, mede métricas. Loga cada processo em `logs/`. |
| `scripts/run_sqlmap.sh` | sqlmap real contra os endpoints `/pg/*` |
| `scripts/run_hydra.sh` | hydra brute-force contra `/pg/login` |

---

# Guia de Uso

## 3.1 Pré-requisitos

| Item | Versão | Instalação |
|---|---|---|
| Python | 3.10+ | python.org |
| Docker Desktop | 4.42+ | docker.com |
| WSL (Windows) | **2.4.13** (não 2.5+) | [release 2.4.13](https://github.com/microsoft/WSL/releases/tag/2.4.13) |
| Ollama | qualquer | ollama.com |
| Modelo `qwen2.5` | — | `ollama pull qwen2.5` |
| Modelo `gemma3` | opcional | `ollama pull gemma3` |

> WSL 2.5+ quebra o Docker Desktop ≤ 4.75 (sockets `dockerInference`/`engine.sock` órfãos — issue docker/for-win#14804). Use WSL 2.4.13 **ou** Docker Desktop 4.76+.

## 3.2 Setup inicial (uma vez)

```powershell
# 1. Docker no PATH desta sessão (se necessário)
$env:PATH = "C:\Program Files\Docker\Docker\resources\bin;$env:PATH"

# 2. Dependências Python
pip install -r requirements.txt

# 3. Subir os bancos-alvo
docker compose up -d

# 4. Criar o schema SQLite de controle
python -m access_defense.cli init-db

# 5. Baixar o modelo LLM
ollama pull qwen2.5
```

## 3.3 Demo automática (um comando)

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run_full_demo.ps1
```

Flags: `-Model qwen2.5|gemma3`, `-SkipDocker`, `-SkipDashboard`, `-AttackMode sqli|nosqli|brute-force|ddos|exfil|privesc|full`.

O script sobe tudo, ataca, espera o agente processar e imprime as métricas. Logs em `logs/server.log`, `logs/agent.log`, `logs/dashboard.log`.

## 3.4 Demo manual (4 terminais)

**Terminal 1 — servidor vulnerável**
```powershell
$env:PATH = "C:\Program Files\Docker\Docker\resources\bin;$env:PATH"
python -m access_defense.server --port 8000
```

**Terminal 2 — agente IA**
```powershell
$env:AGENT_PROVIDER = "ollama"
$env:OLLAMA_NATIVE_URL = "http://localhost:11434"
python -m access_defense.agent_loop --model qwen2.5 --batch 15 --interval 3
```

**Terminal 3 — dashboard**
```powershell
python -m streamlit run access_defense/dashboard.py
# abre http://localhost:8501
```

**Terminal 4 — atacante**
```powershell
python -m access_defense.attacker --mode full
# ou modos individuais:
python -m access_defense.attacker --mode sqli
python -m access_defense.attacker --mode nosqli
python -m access_defense.attacker --mode brute-force --rounds 50
python -m access_defense.attacker --mode ddos --requests 500 --concurrency 50
python -m access_defense.attacker --mode exfil
python -m access_defense.attacker --mode privesc
```

## 3.5 Benchmark e métricas

```powershell
# Postgres vs Mongo (4 workloads × 2 backends)
python -m access_defense.benchmark --iterations 200

# Métricas de defesa
python -m access_defense.metrics            # texto
python -m access_defense.metrics --json     # JSON
```

## 3.6 Cenários de demonstração

**A — Sem agente (baseline):** rode só o atacante. `attack_success_rate_pct` fica alto (~90-100%).

**B — Com agente:** suba o agente, depois ataque. O IP é bloqueado após 1-2 batches; as requisições seguintes recebem 403.

**C — qwen2.5 vs gemma3:** rode o cenário B com cada modelo e compare `ai_actions` e cobertura.

## 3.7 Limpeza

```powershell
python -m access_defense.cli reset-defense   # limpa blocked_ips + estado
docker compose down                          # para os containers
docker compose down -v                        # apaga também os volumes (perde seed)
```

## 3.8 Deploy do dashboard (grátis, para apresentação)

O dashboard sozinho (só lê SQLite) pode ir para a **Streamlit Community Cloud** (grátis, sem cartão):

1. `share.streamlit.io` → login com GitHub → autorize o repo.
2. **Create app** → Repository: `LealTiago-git/TCC` · Main file: `access_defense/dashboard.py`.
3. Advanced settings → **Python 3.11**.
4. Deploy.

O dashboard usa `access_control.db` localmente e cai no snapshot commitado `demo_data.db` quando o banco vivo não existe (caso da nuvem). Custo de manutenção: zero.

## 3.9 Solução de problemas

| Erro | Causa | Correção |
|---|---|---|
| `docker: command not found` | PATH | `$env:PATH = "C:\Program Files\Docker\Docker\resources\bin;$env:PATH"` |
| `failed to connect ... npipe` | Daemon parado | Abrir Docker Desktop |
| `Secrets Engine ... cannot be accessed` | WSL 2.5+ incompatível | WSL 2.4.13 ou Docker 4.76+ |
| `ModuleNotFoundError: access_defense` | CWD errado | Rode da raiz do projeto |
| Agente só produz `flag_for_audit` | Modelo sem tool-calling | Use qwen2.5 (gemma3 cai no fallback JSON) |

---

**Desenvolvido para:** Trabalho de Conclusão de Curso
**Stack:** Flask · Postgres · MongoDB · Ollama (qwen2.5, gemma3) · Streamlit
**Repositório:** <https://github.com/LealTiago-git/TCC>
