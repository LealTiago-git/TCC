# TCC - Sistema de Defesa Contra Acessos Anômalos a Banco de Dados

## Resumo Executivo

Protótipo acadêmico em Python que implementa um **sistema de controle de acesso com detecção de anomalias em tempo real** para bancos de dados SQLite. O sistema utiliza uma abordagem **determinística com suporte a inteligência artificial** para análise de eventos de segurança, permitindo avaliar a eficácia de técnicas de detecção de intrusões e resposta a incidentes.

### Palavras-chave
- Detecção de Anomalias em Banco de Dados
- Controle de Acesso Baseado em Função (RBAC)
- Auditoria em Tempo Real
- Agentes de IA para Resposta a Incidentes
- Simulação Controlada de Ataques

## O que o Sistema Faz

O protótipo implementa um **gateway controlado de acesso** que funciona como intermediário obrigatório para todas as operações no banco de dados. Suas funções principais são:

### 1. **Controle de Acesso (Authentication & Authorization)**
- Autentica usuários contra senhas protegidas com PBKDF2-SHA256
- Autoriza operações através de matriz RBAC (Role-Based Access Control)
- Valida permissões antes de executar qualquer query no banco

### 2. **Auditoria Completa de Operações**
- Registra **cada acesso** com: usuário, IP, hora, tabela, operação, resultado
- Mantém histórico de IPs por usuário para detecção de anomalias
- Rastreia tentativas negadas e motivos da negação

### 3. **Detecção de Anomalias em Tempo Real**
- Calcula **score de anomalia** (0-100) para cada acesso usando regras determinísticas
- Classifica severidade: `normal`, `low`, `medium`, `high`, `critical`
- Detecta 9+ padrões de ataque diferentes (SQL injection, DDoS, brute-force, etc.)

### 4. **Geração de Alertas**
- Cria alertas automáticos para acessos com score >= 35 (medium severity)
- Persiste alertas em banco para análise posterior
- Opcionalmente envia alertas para agentes de IA para análise contextual

### 5. **Resposta a Incidentes**
- Monitor defensivo que executa playbooks de contenção automática
- Isola IPs de origem de ataques
- Ativa rate-limiting defensivo em caso de DDoS
- Simula shutdown defensivo em cenários críticos

## Arquitetura e Estrutura do Código

```
access_defense/
├── __init__.py              # Exporta módulos públicos
├── database.py              # Esquema SQLite, inicialização, dados de demo
├── security.py              # Hash de senhas (PBKDF2-SHA256)
├── anomaly.py               # Mecanismo de detecção de anomalias (9+ regras)
├── gateway.py               # Gateway de controle de acesso (Auth + Authz)
├── agents.py                # Interface com LLMs (Ollama/OpenRouter)
├── defender.py              # Monitor defensivo e resposta a incidentes
├── cli.py                   # Interface de linha de comando (CLI)
└── dashboard.py             # Dashboard interativa (Streamlit)
```

### Módulos Principais

#### `database.py`
- **Função**: Gerencia schema SQLite e dados iniciais
- **Tabelas criadas**:
  - `users`: usuários com senhas hasheadas
  - `permissions`: matriz RBAC (role + table + operation)
  - `clientes`, `transacoes`, `salarios`: dados de negócio
  - `access_logs`: auditoria completa de acessos
  - `security_alerts`: alertas de anomalias detectadas
  - `user_ip_history`: histórico de IPs por usuário
  - `ai_agent_logs`: timing e resultados das análises de IA
  - `incident_response_logs`: histórico de ações defensivas
- **Parâmetros**: Caminho do banco, opção de seed com dados demo

#### `security.py`
- **Função**: Proteção de senhas
- **Algoritmo**: PBKDF2-SHA256 com 260k iterações
- **Operações**: `hash_password()`, `verify_password()`

#### `anomaly.py`
- **Função**: Mecanismo de detecção de anomalias
- **Entrada**: Evento de acesso + sinais recentes (IP history, denied attempts)
- **Processamento**: Calcula score (0-100) aplicando 18+ regras de negócio
- **Saída**: Score + severidade + lista de motivos
- **Regras detectadas**:
  - Acesso fora do horário comercial (07:00-20:00)
  - Acesso a tabelas sensíveis (ex: salarios)
  - Credenciais inválidas
  - IP novo para usuário
  - Múltiplas negações recentes
  - Volume alto de acessos (janela 10 min)
  - Operações destrutivas (DELETE)
  - Leitura em massa (>100 linhas)
  - Padrões de SQL injection
  - Padrões de DDoS
  - Entrada excessivamente grande
  - Tentativa de escalada de privilégio

#### `gateway.py`
- **Função**: Ponto único de controle para todas as operações
- **Fluxo de execução**:
  1. Autentica usuário contra hash de senha
  2. Autoriza operação contra matriz RBAC
  3. Se autorizado: executa query e coleta dados
  4. Registra acesso em `access_logs`
  5. Coleta sinais recentes do usuário/IP
  6. Calcula anomaly score via `anomaly.py`
  7. Se score >= 35: cria alerta em `security_alerts`
  8. Se IA ativada: envia para revisão de agentes
  9. Retorna `AccessResponse` com resultado
- **Métodos públicos**:
  - `read_table()`: SELECT com controle de acesso
  - `insert_transaction()`: INSERT com validação
  - `delete_transaction()`: DELETE com restrições

#### `agents.py`
- **Função**: Interface com modelos de IA para análise de segurança
- **Provedores suportados**:
  - Ollama (local): `http://localhost:11434/v1`
  - OpenRouter (cloud): `https://openrouter.ai/api/v1`
- **Entrada**: Evento de acesso anômalo ou alerta de segurança
- **Processamento**: Envia para LLM com prompt defensivo estruturado
- **Saída**: Análise em JSON com chaves: `risco`, `acao`, `justificativa`, `evidencias`
- **Modelos testados**:
  - Gemma 3 (Google) - via Ollama
  - Qwen 2.5 (Alibaba) - via Ollama
- **Medição**: Captura timing completo de cada interação com IA

#### `defender.py`
- **Função**: Monitor defensivo que responde a alertas
- **Fluxo**:
  1. Monitora `security_alerts` com status `open`
  2. Para cada alerta: classifica tipo de ataque
  3. Se IA ativada: solicita análise contextual
  4. Monta plano de resposta (7-10 passos)
  5. Executa ações de contenção:
     - Bloqueia IP de origem no gateway
     - Ativa rate-limiting (max 10 req/min por IP)
     - Se crítico: simula shutdown defensivo
  6. Registra tudo em `incident_response_logs`
- **Playbooks**: Customizados por tipo de ataque (injection, ddos, brute-force, etc.)

#### `cli.py`
- **Função**: Interface de linha de comando para demonstração
- **Comandos principais**:
  - `init-db`: Cria/atualiza schema e seed de dados
  - `simulate`: Cenários normais + anômalos para teste
  - `attack`: Simula 5 tipos de ataque controlado
  - `monitor`: Deixa em alerta observando novos alertas
  - `access`: Executa acesso único manual
  - `show-logs`, `show-alerts`, `show-ai-results`: Relatórios
- **Parâmetros**:
  - `--ai off|gemma3|qwen2.5|both`: Seleção de IA
  - `--mode injection|ddos|brute-force|buffer-overflow|privilege-escalation`: Tipo de ataque
  - `--once`: Executa uma única vez (útil em testes)

#### `dashboard.py`
- **Função**: Visualização interativa do sistema em tempo real
- **Framework**: Streamlit (web app Python nativo)
- **Abas disponíveis**:
  - **KPIs**: 6 métricas principais (acessos, alertas, IPs bloqueados, etc)
  - **Logs de Acesso**: Tabela filtrável com gráficos de operações e timeline
  - **Alertas**: Distribuição por severidade, status, timeline
  - **Anomalias**: Histograma, box plot, scatter plot de scores
  - **Resposta Defensiva**: Ações executadas, tipos, timeline
  - **Performance de IA**: Timing e taxa de sucesso (Gemma 3 vs Qwen 2.5)
- **Comando**: `streamlit run access_defense/dashboard.py`
- **Acesso**: http://localhost:8501 (automaticamente no navegador)

## Como Rodar - Guia Completo

### Prerequisitos
- Python 3.10+
- SQLite 3.35+
- Ollama (local) OU OpenRouter API key (cloud)

### Inicialização Básica

```powershell
# 1. Preparar ambiente (execute UMA VEZ)
python -m access_defense.cli init-db

# 2. Testar sem IA (funciona offline)
python -m access_defense.cli simulate --ai off
```

### Cenário 1: Teste com IA Local (RECOMENDADO)

**Terminal 1** - Deixe o Ollama rodando:
```powershell
# Iniciar Ollama (manter aberto)
C:\Users\{seu_usuario}\AppData\Local\Programs\Ollama\ollama.exe
```

**Terminal 2** - Configure e execute simulação:
```powershell
$env:AGENT_PROVIDER="ollama"
$env:OLLAMA_OPENAI_BASE_URL="http://localhost:11434/v1"
$env:OLLAMA_API_KEY="ollama"
$env:GEMMA_MODEL="gemma3"
$env:QWEN_MODEL="qwen2.5"

# Teste com Gemma 3
python -m access_defense.cli simulate --ai gemma3

# OU teste com Qwen 2.5
python -m access_defense.cli simulate --ai qwen2.5

# OU teste ambas sequencialmente
python -m access_defense.cli simulate --ai both
```

### Cenário 2: Monitor em Tempo Real + Ataques Controlados

**Terminal 1** - Monitor aguardando alertas:
```powershell
$env:AGENT_PROVIDER="ollama"
$env:OLLAMA_OPENAI_BASE_URL="http://localhost:11434/v1"
$env:OLLAMA_API_KEY="ollama"
$env:GEMMA_MODEL="gemma3"
$env:QWEN_MODEL="qwen2.5"

# Deixar monitor ativo
python -m access_defense.cli monitor --ai gemma3
```

**Terminal 2** - Gere ataques controlados:
```powershell
$env:AGENT_PROVIDER="ollama"
$env:OLLAMA_OPENAI_BASE_URL="http://localhost:11434/v1"
$env:OLLAMA_API_KEY="ollama"
$env:GEMMA_MODEL="gemma3"
$env:QWEN_MODEL="qwen2.5"

# Execute ataques um a um
python -m access_defense.cli attack --mode injection
python -m access_defense.cli attack --mode ddos
python -m access_defense.cli attack --mode brute-force
python -m access_defense.cli attack --mode buffer-overflow
python -m access_defense.cli attack --mode privilege-escalation
```

**O que observar**: O Terminal 1 detectará em tempo real os alertas gerados pelo Terminal 2.

### Cenário 3: Teste Isolado de Acesso Manual

```powershell
# Usuário analyst lendo tabela de clientes
python -m access_defense.cli access \
  --username analista \
  --password analista123 \
  --table clientes \
  --ip 10.0.0.12
```

### Comandos de Consulta/Relatórios

```powershell
# Ver logs de acesso (últimas 20 entradas)
python -m access_defense.cli show-logs

# Ver alertas de segurança gerados
python -m access_defense.cli show-alerts

# Ver histórico de respostas do monitor
python -m access_defense.cli show-responses

# Ver estatísticas de performance das IAs
python -m access_defense.cli show-ai-results

# Filtrar por agente específico
python -m access_defense.cli show-ai-results --agent gemma3

# Ver todas as sessões
python -m access_defense.cli show-ai-results --all-sessions
```

### Dashboard Interativa

Visualize em **tempo real** todos os eventos, alertas e métricas do sistema com a dashboard Streamlit:

```powershell
# Instalar dependências (execute UMA VEZ)
pip install -r requirements.txt

# Opção 1: Executar direto
streamlit run access_defense/dashboard.py

# Opção 2: Usar script helper
powershell -ExecutionPolicy Bypass -File run_dashboard.ps1
```

**O que você vê na dashboard:**
- 📊 KPIs em destaque (acessos, alertas, IPs bloqueados, score médio)
- 📝 **Aba 1 - Logs**: Histórico de acessos com filtros por usuário e severidade
- ⚠️ **Aba 2 - Alertas**: Timeline e distribuição de eventos de segurança
- 📈 **Aba 3 - Anomalias**: Distribuição de scores, box plots, scatter plots
- 🛡️ **Aba 4 - Resposta Defensiva**: Ações executadas (bloqueios, rate-limiting)
- 🤖 **Aba 5 - Performance de IA**: Comparação Gemma 3 vs Qwen 2.5 (timing, taxa de sucesso)

**Exemplo: Monitorar em tempo real**

Terminal 1 - Dashboard:
```powershell
streamlit run access_defense/dashboard.py
# Abre em http://localhost:8501
```

Terminal 2 - Simule eventos:
```powershell
$env:AGENT_PROVIDER="ollama"
$env:OLLAMA_OPENAI_BASE_URL="http://localhost:11434/v1"
$env:OLLAMA_API_KEY="ollama"

python -m access_defense.cli simulate --ai gemma3
```

✨ **A dashboard atualiza em tempo real enquanto você executa comandos!**

Para documentação completa: Ver [USANDO_DASHBOARD.md](USANDO_DASHBOARD.md)

### Limpeza/Reset

```powershell
# Limpar estado defensivo (depois de bloqueios)
python -m access_defense.cli reset-defense

# Recomeçar do zero
Remove-Item access_control.db -Force
python -m access_defense.cli init-db
```

## Usuários de Demonstração e Permissões

### Usuários

| Usuário | Senha | Papel | Descrição |
|---------|-------|-------|-----------|
| `admin` | `admin123` | Administrator | Acesso total a todas as operações |
| `analista` | `analista123` | Analyst | Leitura de negócio + escrita limitada |
| `auditor` | `auditor123` | Auditor | Leitura apenas (incluindo tabelas sensíveis) |

### Matriz de Autorização (RBAC)

| Perfil | Tabela | SELECT | INSERT | DELETE |
|--------|--------|--------|--------|--------|
| admin | clientes | ✓ | ✓ | ✗ |
| admin | transacoes | ✓ | ✓ | ✓ |
| admin | salarios | ✓ | ✓ | ✗ |
| analyst | clientes | ✓ | ✗ | ✗ |
| analyst | transacoes | ✓ | ✓ | ✗ |
| auditor | clientes | ✓ | ✗ | ✗ |
| auditor | transacoes | ✓ | ✗ | ✗ |
| auditor | salarios | ✓ | ✗ | ✗ |

### Dados de Exemplo

**Tabela: clientes**
- 5 clientes de exemplo com riscos variados

**Tabela: transacoes**
- 5 transações com valores entre R$77,90 e R$15.400,00

**Tabela: salarios** (sensível)
- 3 colaboradores: R$6.400 a R$9.100
- Restrita a admin + auditor (read-only)

**Tabela: user_ip_history**
- Histórico pré-preenchido com IPs conhecidos por usuário

## Ataques Controlados Simulados

O sistema não ataca **rede externa, sistema operacional ou serviços de terceiros**. Em vez disso, simula **eventos anômalos locais** para teste:

### 1. SQL Injection
```
Executa acessos a tabelas com nomes maliciosos:
  - "clientes' OR '1'='1"
  - "clientes; DROP TABLE users; --"
  - "clientes UNION SELECT senha FROM users"
```
**Detecção**: Score +30 por padrões SQL, resultado bloqueado

### 2. DDoS (Distributed Denial of Service)
```
Gera 30 requisições rápidas de um mesmo IP novo
```
**Detecção**: Volume alto (+20 pontos) + novo IP (+20) + score cumulativo

### 3. Brute-Force
```
Tenta login múltiplas vezes com senhas inválidas
```
**Detecção**: Múltiplas negações recentes (+25), IP novo (+20)

### 4. Buffer Overflow
```
Envia table_name com 512 caracteres + user-agent com 1024 chars
```
**Detecção**: Entrada excessiva (+35), padrão de buffer-overflow (+35)

### 5. Privilege Escalation
```
Usuário 'analyst' tenta:
  - Ler tabela 'salarios' (restrita)
  - Deletar transação (operação não permitida)
```
**Detecção**: Permissão negada (+35), escalada de privilégio (+30)

## Metodologia de Detecção de Anomalias

### Modelo de Pontuação (Anomaly Score)

O sistema utiliza uma **abordagem baseada em regras determinísticas** para calcular um score de anomalia de 0 a 100. Este design permite:

✓ **Reproduzibilidade**: Mesma entrada sempre gera mesmo score  
✓ **Auditabilidade**: Cada regra é rastreável  
✓ **Interpretabilidade**: Cada decisão tem justificativas claras  

### Matriz de Regras

| Regra | Categoria | Score | Descrição |
|-------|-----------|-------|-----------|
| Hora fora comercial | Temporal | +20 | Acesso 20:00-07:00 |
| Tabela sensível | Autorização | +30 | Tentativa de acessar tabelas restritas |
| Acesso negado | Autenticação | +35 | Falha de credenciais/permissão |
| IP novo | Comportamento | +20 | Novo IP para usuário conhecido |
| Múltiplas negações | Padrão | +25 | ≥3 negações nos últimos 10 min |
| Volume alto | Padrão | +20 | ≥20 acessos nos últimos 10 min |
| Operação destrutiva | Criticidade | +20 | DELETE por perfil não-admin |
| Leitura em massa | Volume | +35 | ≥100 linhas retornadas |
| SQL injection | Assinatura | +30 | Tokens: `'`, `--`, `;`, `UNION`, `DROP` |
| DDoS signature | Assinatura | +25 | Muitos acessos rápidos + user-agent suspeito |
| Buffer overflow | Assinatura | +35 | Entrada >256 chars ou table name >64 chars |
| Escalada privilegio | Assinatura | +30 | User-agent com "privilege-escalation" |

**Score final**: Min(soma de regras ativadas, 100)

### Severidade

```
Score 0-14   → normal      (sem alerta)
Score 15-34  → low         (alerta informativo)
Score 35-59  → medium      (alerta com investigação)
Score 60-84  → high        (alerta crítico)
Score 85-100 → critical    (alerta severo + resposta automática)
```

### Integração com IA (Opcional)

Quando IA está ativada:

1. **Filtro determinístico** calcula anomaly score
2. Se score >= 35 (medium+), alerta é criado
3. **Agente IA recebe**: Evento + contexto + histórico
4. **IA analisa** em JSON estruturado:
   ```json
   {
     "risco": "Tentativa de SQL injection",
     "acao": "Bloquear IP + auditar account",
     "justificativa": "Padrões SQL detectados em table_name",
     "evidencias": ["tokens: UNION, DROP detectados", "score: 65"]
   }
   ```
5. **Timing capturado**: Início, fim, duração em ms
6. **Resultado persistido** em `ai_agent_logs`

**Importante**: IA apenas *explica* e *recomenda*. As decisões finais de bloqueio continuam sendo baseadas em regras determinísticas, garantindo auditabilidade.

## Sinais de Anomalia Detectados

O sistema monitora **9 categorias de anomalias**:

### 1. Temporal
- Acesso fora do horário comercial (07:00-20:00)

### 2. Autorização
- Tentativa de acessar tabela sensível (ex: `salarios`)
- Operação não autorizada para o perfil

### 3. Autenticação
- Credenciais inválidas
- Usuário desabilitado

### 4. Comportamento do Usuário
- IP novo para usuário conhecido
- Múltiplas negações em janela curta
- Volume anormalmente alto de acessos

### 5. Padrões de Volume
- Leitura em massa (>100 linhas)
- Muitos acessos muito rapidamente (DDoS)

### 6. Assinaturas de Ataque
- **SQL Injection**: Tokens `'`, `--`, `;`, `UNION`, `OR`, `DROP`, `SLEEP(`
- **DDoS**: User-agent suspeito + volume alto
- **Brute-force**: Múltiplas tentativas de login com senha errada
- **Buffer overflow**: Entrada excessivamente grande (>256 chars)
- **Escalada de privilégio**: Perfil baixo tentando operação alta

### 7. User-Agent Automatizado
- Detecta: `curl`, `python-requests`, `sqlmap`, `scanner`, `bot`

### 8. Operações Destrutivas
- DELETE executado por perfil não-administrativo

### 9. Eventos de Simulação
- Identifica ataques controlados para análise

## Agentes de IA para Análise de Segurança

### Arquitectura de Decisão

```
┌─────────────────┐
│  Acesso ao BD   │
└────────┬────────┘
         │
         ▼
┌──────────────────────┐
│ Regras Determinísticas│  ◄─ Sempre executado
│ (Score 0-100)        │     Auditável, reproduzível
└────────┬─────────────┘
         │
    Score >= 35?
    │         
    ├─── SIM ──▶ Criar alerta
    │           
    └─── NÃO ──▶ Registrar como normal
    
    Se alerta criado E IA ativada:
    ▼
┌────────────────────────┐
│  Enviar para Agente IA │  ◄─ Opcional
│  (Gemma 3 ou Qwen 2.5) │     Fornece contexto
└────────┬───────────────┘     Recomendações
         │
         ▼
┌────────────────────────┐
│  Retornar análise      │
│  em JSON estruturado   │
└────────┬───────────────┘
         │
         ▼
┌────────────────────────┐
│  Persistir em BD       │
│  + Timing              │
└────────────────────────┘
```

### Fluxo de Análise por IA

#### 1. **Filtragem (Determinística)**
```python
if anomaly_score >= 35:  # medium, high, ou critical
    send_to_ai(access_event)
else:
    return  # Sem alerta, sem IA
```

#### 2. **Prompt do Agente**
```
Você é um agente defensivo de segurança de banco de dados.
Analise APENAS sinais de auditoria e recomende uma ação defensiva.
Não gere instruções ofensivas, exploração, evasão ou código malicioso.
Responda em JSON com as chaves: risco, acao, justificativa, evidencias.

Contexto:
{
  "usuario": "admin",
  "tabela_acessada": "salarios",
  "operacao": "READ",
  "ip_origem": "203.0.113.99",
  "hora": "02:15",
  "score_anomalia": 80,
  "motivos": ["acesso fora do horário comercial", "tabela sensível acessada", "IP novo..."],
  "historico_usuario": {...}
}
```

#### 3. **Resposta Esperada**
```json
{
  "risco": "Acesso a dados sensíveis fora do horário comercial de um IP novo",
  "acao": "Investigar login de emergência; validar 2FA; auditar histórico",
  "justificativa": "Múltiplos indicadores de comportamento anômalo",
  "evidencias": [
    "score_anomalia: 80 (critical)",
    "hora: 02:15 (fora comercial)",
    "ip_novo: 203.0.113.99",
    "tabela_sensível: salarios"
  ]
}
```

#### 4. **Persistência e Auditoria**
Cada interação é registrada em `ai_agent_logs`:
- `agent_name`: "gemma3" ou "qwen2.5"
- `started_at`, `finished_at`, `duration_ms`: Timing completo
- `session_id`: Agrupa múltiplas análises
- `success`: Verdadeiro/Falso
- `error`: Mensagem de erro se falhou
- `result`: Resposta em JSON

### Modelos Suportados

#### Gemma 3 (Google)
- **Via**: Ollama local ou OpenRouter
- **Modelo**: `gemma3`
- **Características**: Rápido, eficiente, bom para contextos estruturados

#### Qwen 2.5 (Alibaba)  
- **Via**: Ollama local ou OpenRouter
- **Modelo**: `qwen2.5`
- **Características**: Multilíngue, forte em análise contextual

### Configuração de Provedores

#### Ollama (Local - Recomendado para TCC)

```powershell
# Iniciar Ollama
C:\Users\{username}\AppData\Local\Programs\Ollama\ollama.exe

# Em outro terminal
$env:AGENT_PROVIDER="ollama"
$env:OLLAMA_OPENAI_BASE_URL="http://localhost:11434/v1"
$env:OLLAMA_API_KEY="ollama"
```

**Vantagens**:
- Sem custos por API
- Sem conectividade requerida
- Dados permanecem locais
- Ideal para pesquisa acadêmica

#### OpenRouter (Cloud)

```powershell
$env:AGENT_PROVIDER="openrouter"
$env:OPENROUTER_BASE_URL="https://openrouter.ai/api/v1"
$env:OPENROUTER_API_KEY="sk-or-..."
```

**Vantagens**:
- Acesso a múltiplos modelos
- Sem instalação local
- Escalável

### Métricas de Performance Capturadas

O sistema mede:

1. **Latência**: Tempo total de análise (ms)
2. **Sucesso**: Taxa de respostas bem-sucedidas
3. **Erros**: Timeout, conexão recusada, etc.
4. **Agregação por sessão**: Média, min, max
5. **Comparação entre modelos**: Qual é mais rápido?

Executar:
```powershell
python -m access_defense.cli show-ai-results
```

Para ver tabelas com:
- Estatísticas gerais por modelo
- Resultados por caso
- Comparação Gemma 3 vs Qwen 2.5

O comando antigo `--agents` ainda funciona por compatibilidade, mas equivale a `--ai both`. Para experimentos mais claros, prefira `--ai gemma3` ou `--ai qwen2.5`.

## Logs e Auditoria

### Tabelas de Persistência

#### `access_logs` - Auditoria Completa
```sql
CREATE TABLE access_logs (
  id INTEGER PRIMARY KEY,
  created_at TEXT,              -- Timestamp ISO-8601
  username TEXT,                -- Usuário
  role TEXT,                    -- Perfil (admin, analyst, auditor)
  ip_address TEXT,              -- IP de origem
  user_agent TEXT,              -- Navegador/cliente
  operation TEXT,               -- READ, WRITE, DELETE
  table_name TEXT,              -- Tabela acessada
  record_filter TEXT,           -- WHERE clause (se delete)
  rows_returned INTEGER,        -- Linhas afetadas
  success BOOLEAN,              -- Acesso permitido?
  denial_reason TEXT,           -- Motivo da negação
  anomaly_score INTEGER,        -- Score 0-100
  anomaly_severity TEXT,        -- normal/low/medium/high/critical
  anomaly_reasons TEXT          -- Lista de motivos em JSON
);
```

#### `security_alerts` - Alertas de Anomalia
```sql
CREATE TABLE security_alerts (
  id INTEGER PRIMARY KEY,
  access_log_id INTEGER,        -- FK para access_logs
  severity TEXT,                -- Severidade do alerta
  created_at TEXT,
  status TEXT,                  -- open, investigating, contained, resolved
  details TEXT                  -- JSON com detalhes
);
```

#### `ai_agent_logs` - Performance de IA
```sql
CREATE TABLE ai_agent_logs (
  id INTEGER PRIMARY KEY,
  session_id TEXT,              -- Agrupa análises de uma execução
  agent_name TEXT,              -- gemma3 ou qwen2.5
  access_log_id INTEGER,        -- FK para access_logs
  started_at TEXT,
  finished_at TEXT,
  duration_ms INTEGER,          -- Tempo em milissegundos
  session_case_number INTEGER,  -- Ordem na sessão
  session_average_duration_ms INTEGER, -- Média acumulada
  success BOOLEAN,
  error TEXT,                   -- Mensagem de erro
  result TEXT                   -- Resposta em JSON
);
```

#### `incident_response_logs` - Ações Defensivas
```sql
CREATE TABLE incident_response_logs (
  id INTEGER PRIMARY KEY,
  monitor_session_id TEXT,
  alert_id INTEGER,
  access_log_id INTEGER,
  agent_name TEXT,              -- Nome da IA ou "rules-fallback"
  attack_type TEXT,             -- injection, ddos, brute-force, etc.
  ai_message TEXT,              -- Explicação estruturada
  planned_steps TEXT,           -- JSON com passos
  executed_actions TEXT,        -- JSON com ações executadas
  service_status_after TEXT,    -- active, rate_limited, shutdown
  shutdown_requested BOOLEAN,
  created_at TEXT
);
```

### Consultas Úteis para Análise

```powershell
# Ver acesso mais anômalo
python -m access_defense.cli show-logs | grep -i critical

# Ver histórico de um usuário
python -m access_defense.cli show-logs | grep admin

# Ver alertas não resolvidos
python -m access_defense.cli show-alerts | grep open

# Ver performance média de Gemma 3
python -m access_defense.cli show-ai-results --agent gemma3
```

## Interpretação de Resultados

### Output de `simulate`

```
IA defensiva: gemma3

Cenarios executados:
log | cenario                                   | acesso    | score | nivel    |
1   | Leitura normal do analista                | permitido | 0     | normal   |
2   | Analista tentando acessar tabela sensivel | bloqueado | 65    | high     |
3   | Admin em horario incomum por IP novo      | permitido | 80    | high     |

Alertas gerados:
alerta | log | nivel    | resumo                    | resultado
3      | 3   | high     | Acesso anomalo score 80   | acesso fora do horario...
2      | 2   | high     | Acesso anomalo score 65   | tabela sensivel acessada...
```

**Interpretação**:
- Log 1: Acesso normal, sem anomalia (score 0)
- Log 2: Bloqueado, score 65 (high), causa: tabela sensível
- Log 3: Permitido mas anômalo (score 80), IA deve investigar

### Output de `show-ai-results`

```
Medias das IAs:
agent       | total | media | minimo | maximo
gemma3      | 1200  | 600   | 450    | 800
qwen2.5     | 900   | 450   | 380    | 600

Resultados por caso - gemma3:
case | usuario | operacao | duration_ms | resultado
1    | admin   | READ     | 600         | success: "risco alto"
2    | analyst | WRITE    | 800         | error: "timeout"
3    | auditor | DELETE   | 450         | success: "ação recomendada"
```

**Interpretação**:
- Qwen 2.5 é ~30% mais rápido que Gemma 3
- Gemma 3 teve timeout em uma análise (error)
- Variação de 450-800ms = latência aceitável para análise offline

## Parâmetros Ajustáveis

### Em `anomaly.py`

```python
# Threshold de hora comercial
BUSINESS_HOURS_START = 7      # 07:00
BUSINESS_HOURS_END = 20       # 20:00

# Janelas de tempo para sinais
DENIAL_WINDOW_MINUTES = 10    # Múltiplas negações em 10 min?
ACCESS_VOLUME_WINDOW_MINUTES = 10
RECENT_IP_THRESHOLD_DAYS = 30  # IP novo se >30 dias sem ver

# Thresholds de volume
HIGH_ACCESS_VOLUME_THRESHOLD = 20  # >20 acessos = alto
HIGH_ROW_RETURN_THRESHOLD = 100    # >100 linhas = leitura em massa
```

### Em `gateway.py`

```python
# Timeout de chamada a IA
AGENT_TIMEOUT_SECONDS = 45

# Janela deslizante para cálculos
TIME_WINDOW_MINUTES = 10
```

## Referências Acadêmicas

### Princípios de Design

1. **Determinstic + AI Hybrid**: Combina regras auditáveis com análise contextual de IA
2. **RBAC (Role-Based Access Control)**: Modelo de autorização padrão em segurança
3. **Defense in Depth**: Múltiplas camadas (autenticação → autorização → auditoria → detecção)
4. **Anomaly Detection**: Abordagem baseada em desvio de comportamento esperado

### Técnicas Implementadas

- **Signature-based Detection**: Identificação de padrões conhecidos (SQL injection, etc.)
- **Behavior-based Detection**: Desvios de padrão normal (novo IP, volume alto, etc.)
- **Context-aware Analysis**: Integração com IA para análise semântica
- **Real-time Monitoring**: Processamento imediato de eventos

### Padrões de Ataque Simulados

- **OWASP Top 10**: SQL Injection, Brute Force
- **Escalação de Privilégio**: Privilege Escalation
- **Negação de Serviço**: DDoS
- **Buffer Overflow**: Entrada excessiva
- **Abuso de Autorização**: Acesso a dados sensíveis

## Arquivos de Configuração

### Setup Scripts

- `setup_local_ai.ps1`: Configura Ollama local
- `run_with_local_ai.ps1`: Facilita rodar com IA

### Documentação Adicional

- `USANDO_IA_LOCAL.md`: Guia detalhado de troubleshooting para Ollama

## Notas Importantes para Avaliação

### Reproduzibilidade
✓ Todas as decisões são determinísticas e auditáveis  
✓ Mesmas entradas sempre geram mesmos alertas  
✓ Útil para demonstração e avaliação acadêmica

### Escalabilidade
⚠ Protótipo otimizado para demonstração, não para produção  
⚠ SQLite adequado para ~1000 acessos/dia  
⚠ Para produção: migrar para PostgreSQL + cache distribuído

### Limitações Conhecidas
- IA é **opcional** - sistema funciona 100% sem ela
- Ataques são **simulados localmente** - não afetam rede externa
- Banco é **em memória ou local** - apropriado para laboratório
- Perfis de usuário são **pré-definidos** - não há auto-provisioning

---

**Desenvolvido para**: Trabalho de Conclusão de Curso  
**Metodologia**: Detecção de Anomalias + Resposta a Incidentes  
**Última atualização**: Maio de 2026
