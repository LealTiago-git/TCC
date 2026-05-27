"""
Dashboard Streamlit para Sistema de Defesa Contra Acessos Anômalos

Módulo: dashboard.py
Propósito: Interface interativa para visualização em tempo real de:
  - Logs de acesso ao banco de dados
  - Alertas de segurança acionados
  - Análise de anomalias detectadas
  - Resposta defensiva automatizada
  - Estatísticas de performance

Componentes principais:
  - Página inicial: Status do sistema
  - Aba 1: Histórico de acessos com filtros por usuário, IP, severidade
  - Aba 2: Alertas de segurança com timeline e análise de agrupamento
  - Aba 3: Métricas de detecção (distribuição de scores, padrões)
  - Aba 4: Resposta defensiva (playbooks, bloqueios, rate-limiting)
  - Aba 5: Performance de IA (timing de Gemma 3 vs Qwen 2.5)

Dependências:
  - streamlit: Framework para dashboards interativas
  - pandas: Manipulação de dados
  - plotly: Gráficos interativos
  - sqlite3: Acesso ao banco de dados
  - datetime: Manipulação de timestamps

Instruções de uso:
  $ streamlit run access_defense/dashboard.py

"""

import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
import sqlite3
from pathlib import Path

# ============================================================================
# CONSTANTES
# ============================================================================

SEVERITY_LABELS = ["normal", "low", "medium", "high", "critical"]
SEVERITY_BINS = [-1, 14, 34, 59, 84, 100]
SEVERITY_COLORS = {
    "normal": "#74c0fc",
    "low": "#69db7c",
    "medium": "#ffd43b",
    "high": "#ff922b",
    "critical": "#ff6b6b",
}

# ============================================================================
# CONFIGURAÇÃO INICIAL DA PÁGINA
# ============================================================================

st.set_page_config(
    page_title="TCC - Dashboard de Segurança",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# CSS customizado para melhor visual
st.markdown("""
<style>
    .metric-card {
        background-color: #f0f2f6;
        padding: 20px;
        border-radius: 10px;
        text-align: center;
    }
    .status-critical {
        background-color: #ff6b6b;
        color: white;
        padding: 10px;
        border-radius: 5px;
    }
    .status-high {
        background-color: #ff922b;
        color: white;
        padding: 10px;
        border-radius: 5px;
    }
    .status-medium {
        background-color: #ffd43b;
        color: black;
        padding: 10px;
        border-radius: 5px;
    }
    .status-low {
        background-color: #69db7c;
        color: black;
        padding: 10px;
        border-radius: 5px;
    }
    .status-normal {
        background-color: #74c0fc;
        color: black;
        padding: 10px;
        border-radius: 5px;
    }
</style>
""", unsafe_allow_html=True)

# ============================================================================
# FUNÇÕES AUXILIARES
# ============================================================================


def get_database_connection():
    """
    Estabelece conexão com o banco de dados SQLite.
    
    Retorna:
        sqlite3.Connection: Conexão com row_factory para acesso tipo dict
    """
    db_path = Path(__file__).parent.parent / "access_control.db"
    if not db_path.exists():
        st.error(f"❌ Banco de dados não encontrado em {db_path}")
        st.info("Execute: python -m access_defense.cli init-db")
        st.stop()
    
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def get_access_logs(conn, limit=100, username_filter=None, severity_filter=None):
    """
    Recupera histórico de logs de acesso com filtros opcionais.
    
    Parâmetros:
        conn (sqlite3.Connection): Conexão com banco
        limit (int): Número máximo de registros a retornar
        username_filter (str, optional): Filtrar por nome de usuário
        severity_filter (list, optional): Filtrar por severidades (normal, low, medium, high, critical)
    
    Retorna:
        pd.DataFrame: Logs formatados com colunas: created_at, usuario, ip, tabela, 
                      operacao, anomaly_score, severity
    """
    query = "SELECT * FROM access_logs ORDER BY created_at DESC LIMIT ?"
    params = [limit]
    
    conn_obj = conn.cursor()
    results = conn_obj.execute(query, params).fetchall()
    
    if not results:
        return pd.DataFrame()
    
    df = pd.DataFrame([dict(r) for r in results])

    # Derivar severity a partir de anomaly_score (schema só tem score)
    if 'severity' not in df.columns:
        score = df['anomaly_score'].fillna(0).astype(int)
        df['severity'] = pd.cut(
            score,
            bins=SEVERITY_BINS,
            labels=SEVERITY_LABELS,
        ).astype(str)

    # Aplicar filtros
    if username_filter:
        df = df[df['username'] == username_filter]

    if severity_filter:
        df = df[df['severity'].isin(severity_filter)]

    return df


def get_security_alerts(conn, status_filter=None, limit=50):
    """
    Recupera alertas de segurança gerados pelo sistema.
    
    Parâmetros:
        conn (sqlite3.Connection): Conexão com banco
        status_filter (str, optional): Filtrar por status (open, closed, resolved)
        limit (int): Número máximo de registros
    
    Retorna:
        pd.DataFrame: Alertas com colunas: id, created_at, access_log_id, severity,
                      status, source, summary, verdict
    """
    query = "SELECT * FROM security_alerts ORDER BY created_at DESC LIMIT ?"
    params = [limit]
    
    results = conn.cursor().execute(query, params).fetchall()
    
    if not results:
        return pd.DataFrame()
    
    df = pd.DataFrame([dict(r) for r in results])
    
    if status_filter:
        df = df[df['status'] == status_filter]
    
    return df


def get_incident_responses(conn, limit=50):
    """
    Recupera histórico de ações defensivas tomadas pelo sistema.
    
    Parâmetros:
        conn (sqlite3.Connection): Conexão com banco
        limit (int): Número máximo de registros
    
    Retorna:
        pd.DataFrame: Respostas com colunas: id, created_at, monitor_session_id,
                      alert_id, access_log_id, agent_name, attack_type, severity,
                      ai_message, planned_steps, executed_actions,
                      service_status_after, shutdown_requested
    """
    query = "SELECT * FROM incident_response_logs ORDER BY created_at DESC LIMIT ?"
    params = [limit]
    
    results = conn.cursor().execute(query, params).fetchall()
    
    if not results:
        return pd.DataFrame()
    
    return pd.DataFrame([dict(r) for r in results])


def get_ai_agent_logs(conn):
    """
    Recupera dados de performance dos agentes de IA.
    
    Parâmetros:
        conn (sqlite3.Connection): Conexão com banco
    
    Retorna:
        pd.DataFrame: Logs de IA com colunas: id, created_at, session_id,
                      access_log_id, agent_name, model, provider_url, started_at,
                      finished_at, duration_ms, session_case_number,
                      session_total_duration_ms, session_average_duration_ms,
                      success, error, result
    """
    query = "SELECT * FROM ai_agent_logs ORDER BY created_at DESC LIMIT 100"
    results = conn.cursor().execute(query).fetchall()
    
    if not results:
        return pd.DataFrame()
    
    return pd.DataFrame([dict(r) for r in results])


def get_summary_stats(conn):
    """
    Calcula estatísticas resumidas do sistema.
    
    Parâmetros:
        conn (sqlite3.Connection): Conexão com banco
    
    Retorna:
        dict: Estatísticas com chaves: total_accesses, open_alerts, critical_count,
              unique_users, blocked_ips, avg_anomaly_score
    """
    cursor = conn.cursor()
    
    # Total de acessos
    total_accesses = cursor.execute(
        "SELECT COUNT(*) as count FROM access_logs"
    ).fetchone()["count"]
    
    # Alertas abertos
    open_alerts = cursor.execute(
        "SELECT COUNT(*) as count FROM security_alerts WHERE status='open'"
    ).fetchone()["count"]
    
    # Alertas críticos
    critical_count = cursor.execute(
        "SELECT COUNT(*) as count FROM security_alerts WHERE severity='critical'"
    ).fetchone()["count"]
    
    # Usuários únicos
    unique_users = cursor.execute(
        "SELECT COUNT(DISTINCT username) as count FROM access_logs"
    ).fetchone()["count"]
    
    # IPs bloqueados (ativos: sem expiração ou com expiração no futuro)
    blocked_ips = cursor.execute(
        """
        SELECT COUNT(*) as count FROM blocked_ips 
        WHERE expires_at IS NULL OR expires_at > datetime('now')
        """
    ).fetchone()["count"]
    
    # Score médio de anomalia
    avg_anomaly = cursor.execute(
        "SELECT AVG(anomaly_score) as avg FROM access_logs WHERE anomaly_score > 0"
    ).fetchone()["avg"]
    
    return {
        "total_accesses": total_accesses,
        "open_alerts": open_alerts,
        "critical_count": critical_count,
        "unique_users": unique_users,
        "blocked_ips": blocked_ips,
        "avg_anomaly_score": round(avg_anomaly or 0, 1),
    }


# ============================================================================
# LAYOUT PRINCIPAL
# ============================================================================

# Título e descrição
col1, col2 = st.columns([0.8, 0.2])
with col1:
    st.title("🛡️ TCC - Dashboard de Segurança em Banco de Dados")
    st.markdown("**Sistema de Defesa Contra Acessos Anômalos**")

with col2:
    if st.button("🔄 Atualizar", help="Recarregar dados do banco"):
        st.rerun()

# ============================================================================
# PÁGINA 1: VISÃO GERAL (HOME)
# ============================================================================

# Conectar ao banco e obter dados
try:
    conn = get_database_connection()
    stats = get_summary_stats(conn)
except Exception as e:
    st.error(f"❌ Erro ao conectar ao banco: {e}")
    st.stop()

# Exibir KPIs em cards
st.markdown("### 📊 Resumo do Sistema")
col1, col2, col3, col4, col5, col6 = st.columns(6)

with col1:
    st.metric("📝 Acessos Totais", stats["total_accesses"],
              help="Total de operações registradas")

with col2:
    st.metric("⚠️ Alertas Abertos", stats["open_alerts"],
              help="Alertas de segurança pendentes")

with col3:
    st.metric("🔴 Críticos", stats["critical_count"],
              help="Alertas de severidade crítica")

with col4:
    st.metric("👥 Usuários", stats["unique_users"],
              help="Usuários únicos no sistema")

with col5:
    st.metric("🚫 IPs Bloqueados", stats["blocked_ips"],
              help="Endereços IP em quarentena")

with col6:
    st.metric("📈 Score Médio", f"{stats['avg_anomaly_score']}/100",
              help="Anomalia média detectada")

st.divider()

# ============================================================================
# ABAS PRINCIPAIS
# ============================================================================

tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
    "📝 Logs de Acesso",
    "⚠️ Alertas",
    "📊 Anomalias",
    "🛡️ Resposta Defensiva",
    "🤖 Performance de IA",
    "🧠 Agente IA (ao vivo)",
    "⚡ Benchmark PG vs Mongo"
])

# ========== TAB 1: LOGS DE ACESSO ==========
with tab1:
    st.markdown("### Histórico de Acessos ao Banco de Dados")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        username_filter = st.selectbox(
            "Filtrar por Usuário:",
            ["Todos"] + [row[0] for row in conn.cursor().execute(
                "SELECT DISTINCT username FROM access_logs ORDER BY username"
            ).fetchall()]
        )
    
    with col2:
        severity_filter = st.multiselect(
            "Filtrar por Severidade:",
            SEVERITY_LABELS,
            default=["high", "critical"],
        )
    
    with col3:
        log_limit = st.number_input(
            "Quantidade de registros:",
            min_value=10, max_value=500, value=50
        )
    
    # Recuperar logs com filtros
    username_val = None if username_filter == "Todos" else username_filter
    logs_df = get_access_logs(
        conn,
        limit=log_limit,
        username_filter=username_val,
        severity_filter=severity_filter if severity_filter else None
    )
    
    if not logs_df.empty:
        # Exibir tabela com formatação
        display_df = logs_df[[
            "created_at", "username", "ip_address", "table_name", 
            "operation", "anomaly_score", "severity"
        ]].copy()
        
        st.dataframe(
            display_df.sort_values("created_at", ascending=False),
            use_container_width=True,
            height=400
        )
        
        # Gráfico: Distribuição de operações por tipo
        col1, col2 = st.columns(2)
        
        with col1:
            operation_counts = logs_df["operation"].value_counts()
            fig_ops = px.pie(
                values=operation_counts.values,
                names=operation_counts.index,
                title="Operações por Tipo",
                color_discrete_sequence=px.colors.qualitative.Set2
            )
            st.plotly_chart(fig_ops, use_container_width=True)
        
        with col2:
            # Gráfico: Acessos por usuário
            user_counts = logs_df["username"].value_counts()
            fig_users = px.bar(
                x=user_counts.index,
                y=user_counts.values,
                title="Acessos por Usuário",
                labels={"x": "Usuário", "y": "Quantidade"},
                color=user_counts.values,
                color_continuous_scale="Blues"
            )
            st.plotly_chart(fig_users, use_container_width=True)
        
        # Gráfico: Timeline de acessos por severidade
        logs_df["created_at"] = pd.to_datetime(logs_df["created_at"])
        hourly_counts = logs_df.groupby(
            [pd.Grouper(key="created_at", freq="1h"), "severity"]
        ).size().reset_index(name="count")
        
        fig_timeline = px.line(
            hourly_counts,
            x="created_at",
            y="count",
            color="severity",
            title="Timeline de Acessos por Severidade",
            labels={"created_at": "Hora", "count": "Quantidade de Acessos"}
        )
        st.plotly_chart(fig_timeline, use_container_width=True)
    
    else:
        st.info("ℹ️ Nenhum log encontrado com os filtros selecionados")

# ========== TAB 2: ALERTAS ==========
with tab2:
    st.markdown("### Alertas de Segurança")
    
    col1, col2 = st.columns(2)
    with col1:
        status_filter = st.selectbox(
            "Status do Alerta:",
            ["Todos", "open", "closed", "resolved"]
        )
    
    with col2:
        alert_limit = st.number_input(
            "Registros a mostrar:",
            min_value=10, max_value=200, value=50
        )
    
    status_val = None if status_filter == "Todos" else status_filter
    alerts_df = get_security_alerts(conn, status_filter=status_val, limit=alert_limit)
    
    if not alerts_df.empty:
        # Tabela de alertas
        st.dataframe(
            alerts_df[[
                "id", "severity", "created_at", "status"
            ]].sort_values("created_at", ascending=False),
            use_container_width=True,
            height=300
        )
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Distribuição de severidades
            severity_counts = alerts_df["severity"].value_counts()
            fig_sev = px.bar(
                x=severity_counts.index,
                y=severity_counts.values,
                title="Alertas por Severidade",
                labels={"x": "Severidade", "y": "Quantidade"},
                color=severity_counts.index,
                color_discrete_map=SEVERITY_COLORS,
            )
            st.plotly_chart(fig_sev, use_container_width=True)
        
        with col2:
            # Status dos alertas
            status_counts = alerts_df["status"].value_counts()
            fig_status = px.pie(
                values=status_counts.values,
                names=status_counts.index,
                title="Distribuição de Status",
                color_discrete_sequence=px.colors.qualitative.Set2
            )
            st.plotly_chart(fig_status, use_container_width=True)
        
        # Timeline de alertas
        alerts_df["created_at"] = pd.to_datetime(alerts_df["created_at"])
        hourly_alerts = alerts_df.groupby(
            pd.Grouper(key="created_at", freq="6h")
        ).size().reset_index(name="count")
        
        fig_alert_timeline = px.line(
            hourly_alerts,
            x="created_at",
            y="count",
            title="Timeline de Alertas",
            markers=True,
            labels={"created_at": "Hora", "count": "Quantidade"}
        )
        st.plotly_chart(fig_alert_timeline, use_container_width=True)
    
    else:
        st.info("ℹ️ Nenhum alerta registrado")

# ========== TAB 3: ANOMALIAS ==========
with tab3:
    st.markdown("### Análise de Anomalias Detectadas")
    
    logs_df = get_access_logs(conn, limit=200)
    
    if not logs_df.empty:
        # Distribuição de scores de anomalia
        col1, col2 = st.columns(2)
        
        with col1:
            # Histograma de scores
            fig_hist = px.histogram(
                logs_df,
                x="anomaly_score",
                nbins=20,
                title="Distribuição de Scores de Anomalia",
                labels={"anomaly_score": "Score (0-100)", "count": "Frequência"},
                color_discrete_sequence=["#ff922b"]
            )
            st.plotly_chart(fig_hist, use_container_width=True)
        
        with col2:
            # Box plot por severidade
            fig_box = px.box(
                logs_df,
                x="severity",
                y="anomaly_score",
                title="Score por Severidade",
                category_orders={"severity": SEVERITY_LABELS},
                color="severity",
                color_discrete_map=SEVERITY_COLORS,
            )
            st.plotly_chart(fig_box, use_container_width=True)
        
        # Scatter: Score vs Hora
        logs_df["hour"] = pd.to_datetime(logs_df["created_at"]).dt.hour
        fig_scatter = px.scatter(
            logs_df,
            x="hour",
            y="anomaly_score",
            color="severity",
            size="anomaly_score",
            title="Anomalias ao Longo do Dia",
            labels={"hour": "Hora do Dia", "anomaly_score": "Score"},
            color_discrete_map=SEVERITY_COLORS,
        )
        st.plotly_chart(fig_scatter, use_container_width=True)
        
        # Métricas de anomalia
        st.markdown("#### Estatísticas de Anomalia")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Score Máximo",
                f"{logs_df['anomaly_score'].max()}/100",
                help="Maior anomalia detectada"
            )
        
        with col2:
            st.metric(
                "Score Médio",
                f"{logs_df['anomaly_score'].mean():.1f}/100",
                help="Anomalia média"
            )
        
        with col3:
            st.metric(
                "Score Mínimo",
                f"{logs_df['anomaly_score'].min()}/100",
                help="Menor anomalia detectada"
            )
        
        with col4:
            anomalies_count = len(logs_df[logs_df["anomaly_score"] >= 35])
            st.metric(
                "Alertáveis (≥35)",
                anomalies_count,
                help="Eventos que geraram alertas"
            )
    
    else:
        st.info("ℹ️ Nenhum dado de anomalia disponível")

# ========== TAB 4: RESPOSTA DEFENSIVA ==========
with tab4:
    st.markdown("### Resposta Defensiva Automatizada")
    
    responses_df = get_incident_responses(conn)
    
    if not responses_df.empty:
        # Tabela de respostas
        st.dataframe(
            responses_df[[
                "id", "attack_type", "agent_name", "service_status_after", "created_at"
            ]].sort_values("created_at", ascending=False),
            use_container_width=True,
            height=300
        )
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Tipo de ações executadas
            action_counts = responses_df["attack_type"].value_counts()
            fig_actions = px.pie(
                values=action_counts.values,
                names=action_counts.index,
                title="Ações Executadas",
                color_discrete_sequence=px.colors.qualitative.Set3
            )
            st.plotly_chart(fig_actions, use_container_width=True)

        with col2:
            # Status das respostas
            status_counts = responses_df["service_status_after"].value_counts()
            fig_resp_status = px.bar(
                x=status_counts.index,
                y=status_counts.values,
                title="Status das Respostas",
                labels={"x": "Status", "y": "Quantidade"},
                color=status_counts.index,
                color_discrete_sequence=px.colors.qualitative.Set1
            )
            st.plotly_chart(fig_resp_status, use_container_width=True)
        
        # Timeline de ações defensivas
        responses_df["created_at"] = pd.to_datetime(responses_df["created_at"])
        defense_timeline = responses_df.groupby(
            [pd.Grouper(key="created_at", freq="6h"), "attack_type"]
        ).size().reset_index(name="count")

        fig_defense = px.line(
            defense_timeline,
            x="created_at",
            y="count",
            color="attack_type",
            title="Timeline de Ações Defensivas",
            markers=True,
            labels={"created_at": "Hora", "count": "Quantidade"}
        )
        st.plotly_chart(fig_defense, use_container_width=True)
    
    else:
        st.info("ℹ️ Nenhuma ação defensiva registrada")

# ========== TAB 5: PERFORMANCE DE IA ==========
with tab5:
    st.markdown("### Performance de Agentes de IA")
    
    ai_logs_df = get_ai_agent_logs(conn)
    
    if not ai_logs_df.empty:
        # Tabela de execuções
        display_ai = ai_logs_df[[
            "agent_name", "duration_ms", "success", "created_at"
        ]].copy()
        
        st.dataframe(
            display_ai.sort_values("created_at", ascending=False),
            use_container_width=True,
            height=300
        )
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Tempo de resposta por modelo
            fig_timing = px.box(
                ai_logs_df,
                x="agent_name",
                y="duration_ms",
                title="Distribuição de Tempo de Resposta",
                labels={"agent_name": "Modelo", "duration_ms": "Tempo (ms)"},
                color="agent_name"
            )
            st.plotly_chart(fig_timing, use_container_width=True)
        
        with col2:
            # Taxa de sucesso por modelo
            success_rate = ai_logs_df.groupby("agent_name")["success"].apply(
                lambda x: (x.sum() / len(x) * 100)
            ).reset_index()
            success_rate.columns = ["agent_name", "success_rate"]
            
            fig_success = px.bar(
                success_rate,
                x="agent_name",
                y="success_rate",
                title="Taxa de Sucesso por Modelo (%)",
                labels={"agent_name": "Modelo", "success_rate": "Taxa (%)"},
                color="agent_name",
                range_y=[0, 100]
            )
            st.plotly_chart(fig_success, use_container_width=True)
        
        # Comparação de modelos
        st.markdown("#### Comparação de Performance")
        comparison = ai_logs_df.groupby("agent_name").agg({
            "duration_ms": ["mean", "min", "max", "count"],
            "success": lambda x: f"{(x.sum()/len(x)*100):.1f}%"
        }).round(1)
        
        st.dataframe(comparison, use_container_width=True)
    
    else:
        st.info("ℹ️ Nenhuma execução de IA registrada")

# ========== TAB 6: AGENTE IA AO VIVO ==========
with tab6:
    st.markdown("### Agente IA Autônomo — Decisões em Tempo Real")
    st.caption(
        "Tool-calls executados pelo `agent_loop.py`. Cada linha é uma ação "
        "decidida pelo LLM via function-calling."
    )

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        n_actions = conn.execute(
            "SELECT COUNT(*) AS c FROM ai_actions"
        ).fetchone()["c"]
        st.metric("🧠 Ações totais", n_actions)
    with col2:
        n_applied = conn.execute(
            "SELECT COUNT(*) AS c FROM ai_actions WHERE applied=1"
        ).fetchone()["c"]
        st.metric("✅ Aplicadas", n_applied)
    with col3:
        n_blocked = conn.execute(
            "SELECT COUNT(*) AS c FROM blocked_ips"
        ).fetchone()["c"]
        st.metric("🚫 IPs bloqueados", n_blocked)
    with col4:
        try:
            n_locked = conn.execute(
                "SELECT COUNT(*) AS c FROM locked_users"
            ).fetchone()["c"]
        except sqlite3.OperationalError:
            n_locked = 0
        st.metric("🔒 Usuários travados", n_locked)

    st.markdown("#### Histórico de tool-calls")
    actions_rows = conn.execute(
        """
        SELECT id, created_at, agent_name, tool_name, arguments,
               applied, error, reason
        FROM ai_actions
        ORDER BY id DESC
        LIMIT 200
        """
    ).fetchall()
    if actions_rows:
        actions_df = pd.DataFrame([dict(r) for r in actions_rows])
        st.dataframe(actions_df, use_container_width=True, height=300)

        colA, colB = st.columns(2)
        with colA:
            tool_counts = actions_df["tool_name"].value_counts()
            fig_tools = px.pie(
                values=tool_counts.values,
                names=tool_counts.index,
                title="Distribuição de Tool Calls",
                color_discrete_sequence=px.colors.qualitative.Bold,
            )
            st.plotly_chart(fig_tools, use_container_width=True)
        with colB:
            agent_counts = actions_df["agent_name"].value_counts()
            fig_agents = px.bar(
                x=agent_counts.index,
                y=agent_counts.values,
                title="Ações por Modelo",
                labels={"x": "Modelo", "y": "Quantidade"},
                color=agent_counts.index,
            )
            st.plotly_chart(fig_agents, use_container_width=True)

        actions_df["created_at"] = pd.to_datetime(actions_df["created_at"])
        timeline = actions_df.groupby(
            [pd.Grouper(key="created_at", freq="1min"), "tool_name"]
        ).size().reset_index(name="count")
        fig_tl = px.line(
            timeline,
            x="created_at",
            y="count",
            color="tool_name",
            title="Timeline de Ações do Agente",
            markers=True,
        )
        st.plotly_chart(fig_tl, use_container_width=True)
    else:
        st.info("ℹ️ Nenhuma ação do agente registrada. Rode `python -m access_defense.agent_loop`.")

    st.markdown("#### IPs bloqueados (estado atual)")
    blocked_rows = conn.execute(
        "SELECT ip_address, reason, created_at, expires_at FROM blocked_ips ORDER BY created_at DESC LIMIT 100"
    ).fetchall()
    if blocked_rows:
        st.dataframe(
            pd.DataFrame([dict(r) for r in blocked_rows]),
            use_container_width=True,
            height=200,
        )
    else:
        st.caption("Nenhum IP bloqueado.")

    st.markdown("#### Usuários travados (estado atual)")
    try:
        locked_rows = conn.execute(
            "SELECT username, reason, created_at, expires_at FROM locked_users ORDER BY created_at DESC LIMIT 100"
        ).fetchall()
    except sqlite3.OperationalError:
        locked_rows = []
    if locked_rows:
        st.dataframe(
            pd.DataFrame([dict(r) for r in locked_rows]),
            use_container_width=True,
            height=200,
        )
    else:
        st.caption("Nenhum usuário travado.")

# ========== TAB 7: BENCHMARK POSTGRES vs MONGO ==========
with tab7:
    st.markdown("### Benchmark de Desempenho — Postgres vs MongoDB")
    st.caption(
        "Resultados de `python -m access_defense.benchmark`. Compara latência "
        "média e p95 por workload."
    )

    bench_rows = conn.execute(
        """
        SELECT id, created_at, run_id, backend, workload, iterations,
               avg_ms, min_ms, max_ms, p95_ms, error_count, notes
        FROM benchmark_runs
        ORDER BY id DESC
        LIMIT 500
        """
    ).fetchall()

    if not bench_rows:
        st.info(
            "ℹ️ Nenhum benchmark rodado. Execute: "
            "`python -m access_defense.benchmark --iterations 100`"
        )
    else:
        bench_df = pd.DataFrame([dict(r) for r in bench_rows])

        # Filtros
        col1, col2 = st.columns(2)
        with col1:
            run_options = ["Todos"] + sorted(bench_df["run_id"].unique().tolist(), reverse=True)
            selected_run = st.selectbox("Run ID:", run_options)
        with col2:
            workloads = sorted(bench_df["workload"].unique().tolist())
            selected_workloads = st.multiselect(
                "Workloads:", workloads, default=workloads
            )

        view = bench_df.copy()
        if selected_run != "Todos":
            view = view[view["run_id"] == selected_run]
        if selected_workloads:
            view = view[view["workload"].isin(selected_workloads)]

        st.dataframe(view, use_container_width=True, height=300)

        if not view.empty:
            colA, colB = st.columns(2)
            with colA:
                fig_avg = px.bar(
                    view,
                    x="workload",
                    y="avg_ms",
                    color="backend",
                    barmode="group",
                    title="Latência Média (ms) por Workload",
                    labels={"avg_ms": "ms", "workload": "Workload"},
                    color_discrete_map={
                        "postgres": "#336791",
                        "mongo": "#47A248",
                    },
                )
                st.plotly_chart(fig_avg, use_container_width=True)
            with colB:
                fig_p95 = px.bar(
                    view,
                    x="workload",
                    y="p95_ms",
                    color="backend",
                    barmode="group",
                    title="Latência p95 (ms) por Workload",
                    labels={"p95_ms": "ms", "workload": "Workload"},
                    color_discrete_map={
                        "postgres": "#336791",
                        "mongo": "#47A248",
                    },
                )
                st.plotly_chart(fig_p95, use_container_width=True)

            # Tabela resumo head-to-head
            st.markdown("#### Head-to-head (último run de cada workload)")
            latest_per = (
                bench_df.sort_values("id", ascending=False)
                .drop_duplicates(subset=["backend", "workload"])
            )
            pivot_avg = latest_per.pivot(
                index="workload", columns="backend", values="avg_ms"
            )
            if "postgres" in pivot_avg.columns and "mongo" in pivot_avg.columns:
                pivot_avg["mongo_vs_pg_pct"] = (
                    (pivot_avg["mongo"] - pivot_avg["postgres"])
                    / pivot_avg["postgres"] * 100
                ).round(1)
            st.dataframe(pivot_avg, use_container_width=True)

# ============================================================================
# RODAPÉ
# ============================================================================

st.divider()

col1, col2, col3 = st.columns([0.33, 0.34, 0.33])

with col1:
    st.markdown("### 📚 Documentação")
    st.markdown("[README completo](https://github.com)")

with col2:
    st.markdown("### ⚙️ Atualização")
    last_update = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.caption(f"Última atualização: {last_update}")

with col3:
    st.markdown("### 🎓 TCC - 2026")
    st.caption("Sistema de Defesa Contra Acessos Anômalos")

# Fechar conexão
conn.close()
