# Dashboard Streamlit - Instruções de Uso

## O que é a Dashboard?

A **dashboard interativa** mostra em tempo real:
- 📝 **Logs de Acesso**: Histórico completo de operações no banco de dados
- ⚠️ **Alertas**: Eventos de segurança acionados pelo sistema
- 📊 **Anomalias**: Análise visual de scores e padrões detectados
- 🛡️ **Resposta Defensiva**: Ações de contenção automatizadas executadas
- 🤖 **Performance de IA**: Timing e taxa de sucesso dos modelos LLM

## Instalação de Dependências

```powershell
# Navegar para o diretório do projeto
cd c:\Users\tiago\Documents\TCC

# Instalar dependências
pip install -r requirements.txt

# Ou instalar apenas as necessárias para dashboard:
pip install streamlit plotly pandas openai click rich
```

## Executar a Dashboard

### Forma 1: Comando direto (recomendado)

```powershell
streamlit run access_defense/dashboard.py
```

A dashboard abrirá automaticamente em: http://localhost:8501

### Forma 2: Com configurações customizadas

```powershell
streamlit run access_defense/dashboard.py \
    --logger.level=info \
    --client.toolbarMode=minimal
```

### Forma 3: Em background com output redirectionado

```powershell
Start-Process -NoNewWindow -RedirectStandardOutput "streamlit.log" `
    streamlit run access_defense/dashboard.py
```

## Fluxo de Uso Recomendado

### Cenário 1: Apenas Dashboard (offline)

```powershell
# Terminal 1 - Inicialize banco com dados
python -m access_defense.cli init-db

# Terminal 2 - Abra a dashboard
streamlit run access_defense/dashboard.py

# Visualizar dados de teste
```

### Cenário 2: Com Sistema Rodando

**Terminal 1** - Dashboard:
```powershell
streamlit run access_defense/dashboard.py
```

**Terminal 2** - Sistema em simulação:
```powershell
$env:AGENT_PROVIDER="ollama"
$env:OLLAMA_OPENAI_BASE_URL="http://localhost:11434/v1"
$env:OLLAMA_API_KEY="ollama"

python -m access_defense.cli simulate --ai gemma3
```

A dashboard **atualizará em tempo real** enquanto você executa comandos.

### Cenário 3: Monitor Defensivo + Dashboard

**Terminal 1** - Dashboard:
```powershell
streamlit run access_defense/dashboard.py
```

**Terminal 2** - Monitor ativo:
```powershell
$env:AGENT_PROVIDER="ollama"
$env:OLLAMA_OPENAI_BASE_URL="http://localhost:11434/v1"
$env:OLLAMA_API_KEY="ollama"

python -m access_defense.cli monitor --ai gemma3
```

**Terminal 3** - Gere ataques:
```powershell
$env:AGENT_PROVIDER="ollama"
$env:OLLAMA_OPENAI_BASE_URL="http://localhost:11434/v1"
$env:OLLAMA_API_KEY="ollama"

python -m access_defense.cli attack --mode injection
python -m access_defense.cli attack --mode ddos
```

**Observe** na dashboard:
- Novos alertas aparecem em tempo real
- Gráficos atualizam com os eventos
- Resposta defensiva é registrada na aba correspondente

## Funcionalidades da Dashboard

### 1. Visão Geral (Home)
- **6 KPIs principais**: Acessos totais, alertas, críticos, usuários, IPs bloqueados, score médio
- **Status em destaque** para identificação rápida de problemas

### 2. Aba 1: Logs de Acesso
- 📋 Tabela filtrável de todos os acessos registrados
- 🔍 Filtros por:
  - Usuário específico
  - Severidades de anomalia
  - Limite de registros (10-500)
- 📊 Gráficos:
  - Operações por tipo (pizza)
  - Acessos por usuário (barras)
  - Timeline de acessos por severidade (linha)

### 3. Aba 2: Alertas
- 📋 Tabela de alertas de segurança
- 🎚️ Filtro por status (open, closed, resolved)
- 📊 Gráficos:
  - Distribuição por severidade
  - Status dos alertas (pizza)
  - Timeline de alertas (linha)

### 4. Aba 3: Anomalias
- 📈 Histograma de distribuição de scores (0-100)
- 📊 Box plot: Score por severidade (visualizar outliers)
- 🔍 Scatter: Anomalias ao longo do dia (hora vs score)
- 📑 Estatísticas: Max, média, min, quantidade alertável

### 5. Aba 4: Resposta Defensiva
- 📋 Histórico de ações executadas
- 🥧 Tipo de ações (IP blocking, rate-limiting, etc)
- 📊 Status das respostas (sucesso/falha)
- 📈 Timeline de ações defensivas

### 6. Aba 5: Performance de IA
- 📋 Logs de execução de agentes
- 📊 Distribuição de tempo de resposta por modelo
- 📈 Taxa de sucesso por modelo (%)
- 🔄 Comparação: Gemma 3 vs Qwen 2.5

## Atualização de Dados

### Automática
- Streamlit carrega dados do banco a cada render
- Clique no botão **"🔄 Atualizar"** para forçar recarregamento

### Manual
- Mude os filtros para refrescar a aba
- Reabra a dashboard se os dados não atualizarem

## Troubleshooting

### Problema: "Banco de dados não encontrado"

**Solução:**
```powershell
python -m access_defense.cli init-db
streamlit run access_defense/dashboard.py
```

### Problema: Dashboard carregando lentamente

**Causa**: Muitos registros no banco

**Solução**: Reduza o limite de registros no filtro (ex: 50 ao invés de 500)

### Problema: Gráficos não aparecem

**Solução**: Verifique se há dados no banco

```powershell
python -m access_defense.cli show-logs
```

### Problema: "Module not found: streamlit"

**Solução**: Instale as dependências

```powershell
pip install -r requirements.txt
```

### Problema: Porta 8501 já em uso

**Solução**: Use outra porta

```powershell
streamlit run access_defense/dashboard.py --server.port=8502
```

## Exemplos de Uso

### Investigar Pico de Anomalias

1. Abra a aba **"Anomalias"**
2. Procure por um pico no gráfico de timeline
3. Note a hora e o tipo de severidade
4. Vá para **"Logs de Acesso"** e:
   - Filtre por essa severidade
   - Procure logs próximos àquele horário
5. Clique em **"Alertas"** para ver qual alerta foi gerado

### Avaliar Eficácia de Resposta Defensiva

1. Abra **"Resposta Defensiva"**
2. Verifique o histórico de ações
3. Compare com alertas na aba **"Alertas"**:
   - Se alerta gerou resposta → sistema está funcionando
   - Se alerta não gerou resposta → verificar configuração

### Comparar Performance de Modelos de IA

1. Execute simulação com `--ai gemma3`
2. Vá para **"Performance de IA"**
3. Note tempo e taxa de sucesso
4. Execute novamente com `--ai qwen2.5`
5. Compare os gráficos de timing e sucesso

## Customização

### Adicionar Novo Gráfico

Edite `access_defense/dashboard.py`:

```python
# Exemplo: Gráfico de acessos por tabela
table_counts = logs_df["table_name"].value_counts()
fig_tables = px.bar(
    x=table_counts.index,
    y=table_counts.values,
    title="Acessos por Tabela",
    labels={"x": "Tabela", "y": "Quantidade"}
)
st.plotly_chart(fig_tables, use_container_width=True)
```

### Mudar Cores

Edite a seção de CSS:

```python
st.markdown("""
<style>
    .metric-card {
        background-color: #seu_codigo_hex;
    }
</style>
""", unsafe_allow_html=True)
```

### Adicionar Novo Filtro

```python
custom_filter = st.selectbox(
    "Seu filtro:",
    ["Opção 1", "Opção 2", "Opção 3"]
)

# Depois use na query:
if custom_filter != "Todos":
    df = df[df["sua_coluna"] == custom_filter]
```

## Performance

- **Base pequena** (<1000 registros): Carregamento instantâneo
- **Base média** (1000-10000): <1 segundo
- **Base grande** (>10000): Reduza o limite de registros ou use filtros mais específicos

## Requisitos de Sistema

- **RAM**: Mínimo 512 MB, recomendado 2 GB
- **Processador**: Qualquer processador moderno (2010+)
- **Navegador**: Chrome, Firefox, Safari, Edge (qualquer moderno)
- **Python**: 3.10+
- **Conexão**: Localhost (sem requerimento de internet)

---

**Pronto!** Agora você tem uma dashboard profissional para visualizar e analisar o sistema de defesa.
