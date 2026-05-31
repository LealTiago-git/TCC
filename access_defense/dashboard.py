"""Dashboard Streamlit — Sistema de Defesa Contra Acessos Anômalos.

5 abas focadas no fluxo atual (server.py + agent_loop.py):
  1. Visão Geral — KPIs principais + estado do sistema
  2. Acessos HTTP — logs do servidor com categoria de ataque
  3. Defesa Ativa — IPs bloqueados, usuários travados, ações da IA
  4. Análise de Ataques — distribuição por categoria + timeline + eficácia
  5. Benchmark PG vs Mongo — comparação de performance dos backends

Execute:
  python -m streamlit run access_defense/dashboard.py
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

# ============================================================================
# CONFIGURAÇÃO
# ============================================================================

st.set_page_config(
    page_title="TCC — Defesa Anti-Anomalias",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# Paleta única para categorias de ataque
ATTACK_COLORS = {
    "sql_injection":        "#e63946",  # vermelho
    "nosql_injection":      "#f3722c",  # laranja
    "brute_force":          "#f9c74f",  # amarelo
    "ddos":                 "#9c27b0",  # roxo
    "buffer_overflow":      "#577590",  # azul-acinzentado
    "privilege_escalation": "#f72585",  # rosa
    "exfiltration":         "#7209b7",  # roxo escuro
    "benign":               "#90be6d",  # verde
    "outro":                "#adb5bd",  # cinza
}


# ============================================================================
# CONEXÃO E HELPERS
# ============================================================================


@st.cache_resource
def get_db_path():
    """Usa o banco vivo localmente; cai no snapshot demo no deploy (cloud).

    `access_control.db` é gitignored — em produção (Streamlit Cloud) ele não
    existe, então usamos `demo_data.db` commitado para a demonstração do TCC.
    """
    root = Path(__file__).parent.parent
    live = root / "access_control.db"
    demo = root / "demo_data.db"
    return live if live.exists() else demo


def connect():
    """Connection nova por request — evita conflitos com escritas concorrentes."""
    db = get_db_path()
    if not db.exists():
        st.error(
            "Banco SQLite não encontrado. Localmente rode "
            "`python -m access_defense.cli init-db`; no deploy, garanta que "
            "`demo_data.db` esteja commitado."
        )
        st.stop()
    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row
    return conn


def fetch_df(query: str, params: tuple = ()) -> pd.DataFrame:
    with connect() as conn:
        rows = conn.execute(query, params).fetchall()
    return pd.DataFrame([dict(r) for r in rows]) if rows else pd.DataFrame()


# ----------------------------------------------------------------------------
# Detecção de categoria de ataque (heurística — espelha agent_loop.SYSTEM_PROMPT)
# ----------------------------------------------------------------------------

CATEGORY_PATTERNS = [
    ("sql_injection",        re.compile(r"(union\s+select|or\s+1=1|--|drop\s+table|information_schema|;\s*select)", re.I)),
    ("nosql_injection",      re.compile(r"(\$ne|\$gt|\$where|\$regex|\$exists)", re.I)),
    ("buffer_overflow",      re.compile(r".{256,}", re.S)),
    ("exfiltration",         re.compile(r"select\s+.*password|select\s+.*from\s+users\b", re.I)),
    ("privilege_escalation", re.compile(r"\bsalarios\b", re.I)),
]


def categorize(payload: str) -> str:
    """Classifica payload em uma categoria de ataque. 'benign' se nenhuma bate."""
    if not payload:
        return "benign"
    for name, pat in CATEGORY_PATTERNS:
        if pat.search(payload):
            return name
    return "benign"


def categorize_logs(df: pd.DataFrame) -> pd.DataFrame:
    """Adiciona coluna 'categoria' ao DataFrame de access_logs."""
    if df.empty:
        return df
    df = df.copy()
    df["categoria"] = df["record_filter"].fillna("").apply(categorize)
    return df


# ----------------------------------------------------------------------------
# KPIs
# ----------------------------------------------------------------------------


def get_kpis() -> dict:
    with connect() as conn:
        def count(sql, params=()):
            try:
                return conn.execute(sql, params).fetchone()[0]
            except sqlite3.OperationalError:
                return 0

        return {
            "total_requests": count("SELECT COUNT(*) FROM access_logs"),
            "blocked_403":    count("SELECT COUNT(*) FROM access_logs WHERE denial_reason LIKE 'ip_blocked%' OR denial_reason LIKE 'user_locked%'"),
            "ips_blocked":    count("SELECT COUNT(*) FROM blocked_ips WHERE expires_at IS NULL OR expires_at > ?", (datetime.utcnow().isoformat(),)),
            "users_locked":   count("SELECT COUNT(*) FROM locked_users"),
            "agent_actions":  count("SELECT COUNT(*) FROM ai_actions"),
            "agent_models":   conn.execute("SELECT COUNT(DISTINCT agent_name) FROM ai_actions").fetchone()[0],
            "benchmark_runs": count("SELECT COUNT(*) FROM benchmark_runs"),
        }


# ============================================================================
# LAYOUT PRINCIPAL
# ============================================================================

st.title("🛡️ Dashboard de Defesa Contra Acessos Anômalos")
st.caption(
    "Monitoramento em tempo real de ataques HTTP a Postgres + MongoDB com "
    "resposta autônoma de agentes LLM (qwen2.5, gemma3). "
    "Os dados são atualizados a cada recarga da página."
)

col_refresh, col_info = st.columns([1, 5])
with col_refresh:
    if st.button("🔄 Atualizar dados", use_container_width=True):
        st.cache_resource.clear()
        st.rerun()
with col_info:
    st.caption(f"Última leitura: **{datetime.now().strftime('%H:%M:%S')}**  •  Banco: `{get_db_path().name}`")

kpis = get_kpis()

st.divider()


tab_home, tab_logs, tab_defense, tab_attacks, tab_bench = st.tabs([
    "🏠 Visão Geral",
    "📝 Acessos HTTP",
    "🛡️ Defesa Ativa",
    "📊 Análise de Ataques",
    "⚡ Benchmark PG vs Mongo",
])


# ============================================================================
# TAB 1: VISÃO GERAL
# ============================================================================

with tab_home:
    st.markdown("### Visão geral do sistema")
    st.caption(
        "KPIs agregados de toda a sessão. Cada cartão mostra um número-chave; "
        "passe o mouse sobre o ⓘ para ver o que ele significa."
    )

    c1, c2, c3, c4 = st.columns(4)
    c1.metric(
        "Requests HTTP recebidos",
        f"{kpis['total_requests']:,}",
        help="Total de chamadas ao servidor vulnerável desde o último reset.",
    )
    c2.metric(
        "Bloqueados pré-execução",
        f"{kpis['blocked_403']:,}",
        help="Requests que receberam HTTP 403 porque o IP/usuário já estava na lista negra do agente.",
    )
    c3.metric(
        "IPs bloqueados (ativos)",
        f"{kpis['ips_blocked']:,}",
        help="IPs em quarentena agora — ainda dentro do TTL definido pela IA.",
    )
    c4.metric(
        "Usuários travados",
        f"{kpis['users_locked']:,}",
        help="Contas em lock_user — login sempre falha enquanto a entrada existir.",
    )

    c5, c6, c7, c8 = st.columns(4)
    c5.metric(
        "Ações totais do agente IA",
        f"{kpis['agent_actions']:,}",
        help="Quantas vezes o LLM chamou uma das tools (block_ip, lock_user, flag, no_action).",
    )
    c6.metric(
        "Modelos LLM usados",
        f"{kpis['agent_models']}",
        help="Quantos modelos distintos já contribuíram (ex.: qwen2.5 + gemma3 = 2).",
    )
    c7.metric(
        "Runs de benchmark",
        f"{kpis['benchmark_runs']}",
        help="Quantas medições de latência Postgres × Mongo estão salvas em benchmark_runs.",
    )
    if kpis["total_requests"] > 0:
        block_pct = kpis["blocked_403"] / kpis["total_requests"] * 100
    else:
        block_pct = 0
    c8.metric(
        "Taxa de bloqueio",
        f"{block_pct:.1f}%",
        help="Bloqueados / total. Sobe à medida que o agente identifica atacantes e a lista negra cresce.",
    )

    st.divider()

    st.markdown("#### Como ler esta dashboard")
    st.info(
        "**📝 Acessos HTTP** lista cada requisição com a categoria de ataque inferida pelo payload. "
        "**🛡️ Defesa Ativa** mostra o estado atual da quarentena e o que a IA decidiu. "
        "**📊 Análise de Ataques** agrega por categoria e mostra a eficácia da defesa. "
        "**⚡ Benchmark** compara Postgres vs MongoDB nas mesmas consultas — para justificar a escolha de stack no TCC."
    )


# ============================================================================
# TAB 2: ACESSOS HTTP
# ============================================================================

with tab_logs:
    st.markdown("### Histórico de requisições HTTP")
    st.caption(
        "Cada linha = uma chamada ao `server.py`. A coluna **categoria** é "
        "inferida pelo payload (mesma taxonomia que o agente usa)."
    )

    df_all = fetch_df("""
        SELECT id, created_at, username, ip_address, operation,
               table_name, record_filter, rows_returned, success, denial_reason
        FROM access_logs
        ORDER BY id DESC
        LIMIT 1000
    """)

    if df_all.empty:
        st.info("Nenhum acesso registrado ainda. Rode o `attacker.py` para gerar tráfego.")
    else:
        df_all = categorize_logs(df_all)

        col_a, col_b, col_c = st.columns([2, 2, 1])
        with col_a:
            usuarios = ["Todos"] + sorted(df_all["username"].dropna().unique().tolist())
            user_filter = st.selectbox("Filtrar por usuário:", usuarios)
        with col_b:
            cats = ["Todas"] + sorted(df_all["categoria"].unique().tolist())
            cat_filter = st.selectbox("Filtrar por categoria de ataque:", cats)
        with col_c:
            only_blocked = st.checkbox("Só bloqueados (403)")

        view = df_all
        if user_filter != "Todos":
            view = view[view["username"] == user_filter]
        if cat_filter != "Todas":
            view = view[view["categoria"] == cat_filter]
        if only_blocked:
            view = view[view["denial_reason"].fillna("").str.startswith(("ip_blocked", "user_locked"))]

        # Tabela legível (renomeia colunas)
        readable = view[[
            "id", "created_at", "username", "ip_address", "operation",
            "table_name", "categoria", "rows_returned", "success", "denial_reason",
        ]].rename(columns={
            "id": "Log #",
            "created_at": "Quando",
            "username": "Usuário",
            "ip_address": "IP",
            "operation": "Operação",
            "table_name": "Tabela",
            "categoria": "Categoria",
            "rows_returned": "Linhas",
            "success": "Sucesso",
            "denial_reason": "Motivo da negação",
        })

        st.dataframe(readable, use_container_width=True, height=420, hide_index=True)
        st.caption(f"Mostrando **{len(view)}** de **{len(df_all)}** acessos registrados.")

        st.divider()

        col1, col2 = st.columns(2)
        with col1:
            st.markdown("#### Distribuição por categoria")
            cat_counts = view["categoria"].value_counts().reset_index()
            cat_counts.columns = ["Categoria", "Quantidade"]
            fig = px.bar(
                cat_counts,
                x="Categoria", y="Quantidade",
                color="Categoria",
                color_discrete_map=ATTACK_COLORS,
                text="Quantidade",
            )
            fig.update_traces(textposition="outside")
            fig.update_layout(showlegend=False, height=320, margin=dict(t=10, b=10))
            st.plotly_chart(fig, use_container_width=True)
            st.caption(
                "Quantas requisições foram classificadas em cada categoria de ataque. "
                "Barras altas indicam padrões repetidos."
            )

        with col2:
            st.markdown("#### Operações HTTP")
            op_counts = view["operation"].value_counts().reset_index()
            op_counts.columns = ["Operação", "Quantidade"]
            fig = px.pie(
                op_counts,
                values="Quantidade", names="Operação",
                hole=0.4,
                color_discrete_sequence=px.colors.qualitative.Set2,
            )
            fig.update_layout(height=320, margin=dict(t=10, b=10))
            st.plotly_chart(fig, use_container_width=True)
            st.caption(
                "LOGIN = `/pg/login` ou `/mongo/login`. SEARCH = `/pg/search`. "
                "RAW_SQL = `/pg/query` (pior caso, exfiltração)."
            )


# ============================================================================
# TAB 3: DEFESA ATIVA
# ============================================================================

with tab_defense:
    st.markdown("### Estado da defesa autônoma")
    st.caption(
        "Decisões tomadas pelo agente LLM e quem está em quarentena agora. "
        "A IA chama `block_ip`, `lock_user`, `flag_for_audit` ou `no_action` "
        "para cada batch de eventos suspeitos."
    )

    df_actions = fetch_df("""
        SELECT id, created_at, agent_name, tool_name, arguments, reason, applied, error
        FROM ai_actions
        ORDER BY id DESC
        LIMIT 500
    """)

    if df_actions.empty:
        st.info("Nenhuma ação do agente ainda. Rode `python -m access_defense.agent_loop --model qwen2.5`.")
    else:
        # Extrai categoria do reason
        df_actions["categoria"] = df_actions["reason"].fillna("").str.extract(r"^(\w+)")[0].fillna("outro")

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Ações totais", len(df_actions))
        c2.metric("block_ip", int((df_actions["tool_name"] == "block_ip").sum()))
        c3.metric("lock_user", int((df_actions["tool_name"] == "lock_user").sum()))
        c4.metric("flag_for_audit", int((df_actions["tool_name"] == "flag_for_audit").sum()))

        st.divider()

        col1, col2 = st.columns(2)
        with col1:
            st.markdown("#### Ferramentas chamadas pela IA")
            tool_counts = df_actions["tool_name"].value_counts().reset_index()
            tool_counts.columns = ["Ferramenta", "Quantidade"]
            fig = px.bar(
                tool_counts,
                x="Ferramenta", y="Quantidade",
                text="Quantidade",
                color="Ferramenta",
                color_discrete_sequence=px.colors.qualitative.Bold,
            )
            fig.update_traces(textposition="outside")
            fig.update_layout(showlegend=False, height=320, margin=dict(t=10, b=10))
            st.plotly_chart(fig, use_container_width=True)
            st.caption(
                "Mostra quantas vezes cada ferramenta foi acionada. "
                "block_ip e lock_user travam o atacante; flag_for_audit só registra para investigação."
            )

        with col2:
            st.markdown("#### Ações por modelo LLM")
            model_counts = df_actions["agent_name"].value_counts().reset_index()
            model_counts.columns = ["Modelo", "Quantidade"]
            fig = px.bar(
                model_counts,
                x="Modelo", y="Quantidade",
                text="Quantidade",
                color="Modelo",
                color_discrete_sequence=px.colors.qualitative.Set1,
            )
            fig.update_traces(textposition="outside")
            fig.update_layout(showlegend=False, height=320, margin=dict(t=10, b=10))
            st.plotly_chart(fig, use_container_width=True)
            st.caption(
                "Comparação entre modelos. Diferenças refletem capacidade de tool-calling: "
                "qwen2.5 suporta nativo, gemma3 usa fallback JSON e tende a agir menos."
            )

        st.markdown("#### Histórico recente de ações")
        recent = df_actions.head(50)[["id", "created_at", "agent_name", "tool_name", "reason", "applied", "error"]].rename(columns={
            "id": "Ação #",
            "created_at": "Quando",
            "agent_name": "Modelo",
            "tool_name": "Ferramenta",
            "reason": "Motivo (categoria + evidência)",
            "applied": "Aplicada",
            "error": "Erro",
        })
        st.dataframe(recent, use_container_width=True, height=320, hide_index=True)
        st.caption(
            "Últimas 50 decisões. **Aplicada=1** significa que a tool foi executada com sucesso. "
            "O **Motivo** começa com a categoria do ataque (sql_injection, brute_force, etc.)."
        )

    st.divider()

    st.markdown("#### Quarentena atual")
    col_ip, col_user = st.columns(2)

    with col_ip:
        st.markdown("**🚫 IPs bloqueados**")
        df_ips = fetch_df("SELECT ip_address, reason, created_at, expires_at FROM blocked_ips ORDER BY created_at DESC")
        if df_ips.empty:
            st.caption("Nenhum IP em quarentena.")
        else:
            df_ips.columns = ["IP", "Motivo", "Bloqueado em", "Expira em"]
            st.dataframe(df_ips, use_container_width=True, hide_index=True, height=200)

    with col_user:
        st.markdown("**🔒 Usuários travados**")
        df_users = fetch_df("SELECT username, reason, created_at, expires_at FROM locked_users ORDER BY created_at DESC")
        if df_users.empty:
            st.caption("Nenhum usuário travado.")
        else:
            df_users.columns = ["Usuário", "Motivo", "Travado em", "Expira em"]
            st.dataframe(df_users, use_container_width=True, hide_index=True, height=200)

    st.caption(
        "Estas listas alimentam o middleware do `server.py`. "
        "Qualquer request com IP/usuário aqui recebe HTTP 403 antes de a query ser executada."
    )


# ============================================================================
# TAB 4: ANÁLISE DE ATAQUES
# ============================================================================

with tab_attacks:
    st.markdown("### Análise dos ataques registrados")
    st.caption(
        "Visão analítica: que tipos de ataque foram detectados, quando aconteceram, "
        "e qual a taxa de sucesso/bloqueio de cada categoria."
    )

    df_logs = fetch_df("""
        SELECT id, created_at, ip_address, operation, record_filter,
               rows_returned, success, denial_reason
        FROM access_logs
        ORDER BY id ASC
    """)

    if df_logs.empty:
        st.info("Sem dados ainda. Gere tráfego com `attacker.py`.")
    else:
        df_logs = categorize_logs(df_logs)
        df_logs["is_blocked"] = df_logs["denial_reason"].fillna("").str.startswith(("ip_blocked", "user_locked"))
        df_logs["is_malicious"] = df_logs["categoria"] != "benign"
        df_logs["created_at"] = pd.to_datetime(df_logs["created_at"], errors="coerce")

        # KPIs analíticos
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total de acessos", len(df_logs))
        c2.metric("Maliciosos", int(df_logs["is_malicious"].sum()),
                  help="Requests cuja categoria não é 'benign'.")
        c3.metric("Bloqueados", int(df_logs["is_blocked"].sum()),
                  help="Requests com HTTP 403 (IP ou usuário em quarentena).")
        success_attacks = int(df_logs[df_logs["is_malicious"] & (df_logs["success"] == 1)].shape[0])
        c4.metric("Ataques bem-sucedidos", success_attacks,
                  help="Maliciosos que ainda assim retornaram resultado (atacante passou).")

        st.divider()

        st.markdown("#### Categoria de ataque × resultado")
        agg = df_logs[df_logs["is_malicious"]].groupby("categoria").agg(
            total=("id", "count"),
            sucesso_ataque=("success", lambda s: int((s == 1).sum())),
            bloqueado=("is_blocked", lambda s: int(s.sum())),
        ).reset_index()
        if not agg.empty:
            agg["taxa_bloqueio_%"] = (agg["bloqueado"] / agg["total"] * 100).round(1)
            agg = agg.rename(columns={
                "categoria": "Categoria",
                "total": "Total",
                "sucesso_ataque": "Atacante conseguiu dados",
                "bloqueado": "Bloqueado (403)",
                "taxa_bloqueio_%": "Taxa de bloqueio (%)",
            })
            st.dataframe(agg, use_container_width=True, hide_index=True)
            st.caption(
                "**Total**: quantos ataques desta categoria chegaram ao servidor. "
                "**Atacante conseguiu dados**: a query rodou e retornou resultado. "
                "**Bloqueado**: defesa interceptou antes da query. "
                "Quanto maior a **Taxa de bloqueio**, mais efetiva foi a IA contra essa categoria."
            )

            fig = px.bar(
                agg.melt(id_vars=["Categoria"], value_vars=["Atacante conseguiu dados", "Bloqueado (403)"]),
                x="Categoria", y="value", color="variable",
                barmode="group",
                labels={"value": "Quantidade", "variable": "Resultado"},
                color_discrete_map={"Atacante conseguiu dados": "#e63946", "Bloqueado (403)": "#2a9d8f"},
            )
            fig.update_layout(height=380, margin=dict(t=10, b=10), legend_title_text="")
            st.plotly_chart(fig, use_container_width=True)
            st.caption(
                "Comparação lado a lado: **vermelho** = atacante passou, **verde** = defesa bloqueou. "
                "Categorias onde verde >> vermelho indicam defesa madura; o oposto pede atenção."
            )

        st.divider()

        st.markdown("#### Linha do tempo dos ataques")
        timeline = df_logs[df_logs["is_malicious"]].set_index("created_at").resample("1min").size().reset_index()
        timeline.columns = ["Quando", "Ataques por minuto"]
        if not timeline.empty:
            fig = px.line(
                timeline, x="Quando", y="Ataques por minuto",
                markers=True,
            )
            fig.update_layout(height=320, margin=dict(t=10, b=10))
            st.plotly_chart(fig, use_container_width=True)
            st.caption(
                "Volume de requests maliciosos por minuto. "
                "Picos correspondem a rodadas de `attacker.py`. "
                "Períodos planos depois de um pico = defesa funcionando (IPs já bloqueados não geram mais logs)."
            )


# ============================================================================
# TAB 5: BENCHMARK POSTGRES vs MONGO
# ============================================================================

with tab_bench:
    st.markdown("### Benchmark de performance: Postgres × MongoDB")
    st.caption(
        "Comparação direta da latência de cada backend nas mesmas workloads. "
        "Resultados gerados por `python -m access_defense.benchmark`."
    )

    df_bench = fetch_df("""
        SELECT id, created_at, run_id, backend, workload, iterations,
               avg_ms, min_ms, max_ms, p95_ms, error_count, notes
        FROM benchmark_runs
        ORDER BY id DESC
    """)

    if df_bench.empty:
        st.info("Nenhum benchmark rodado. Execute: `python -m access_defense.benchmark --iterations 200`")
    else:
        # Filtro de run
        run_options = ["Mais recente de cada workload"] + sorted(df_bench["run_id"].unique().tolist(), reverse=True)
        chosen = st.selectbox("Selecionar run:", run_options)

        if chosen == "Mais recente de cada workload":
            view = (
                df_bench.sort_values("id", ascending=False)
                .drop_duplicates(subset=["backend", "workload"])
            )
        else:
            view = df_bench[df_bench["run_id"] == chosen]

        # Pivot legível
        pivot = view.pivot_table(
            index="workload",
            columns="backend",
            values=["avg_ms", "p95_ms"],
        ).round(3)
        if not pivot.empty:
            # Multi-index → flatten
            pivot.columns = [f"{m} ({b})" for m, b in pivot.columns]
            pivot = pivot.reset_index().rename(columns={"workload": "Workload"})

            # Adiciona coluna comparativa
            try:
                pivot["Mongo / Postgres (avg)"] = (pivot["avg_ms (mongo)"] / pivot["avg_ms (postgres)"]).round(2)
            except KeyError:
                pass

            st.dataframe(pivot, use_container_width=True, hide_index=True)
            st.caption(
                "**avg_ms** = latência média por consulta. "
                "**p95_ms** = 95% das consultas levaram até esse tempo. "
                "**Mongo / Postgres** = razão; valor 2.0 significa Mongo é 2× mais lento."
            )

        st.divider()

        col_a, col_b = st.columns(2)
        with col_a:
            st.markdown("#### Latência média (avg) por workload")
            fig = px.bar(
                view,
                x="workload", y="avg_ms",
                color="backend",
                barmode="group",
                text="avg_ms",
                color_discrete_map={"postgres": "#336791", "mongo": "#47A248"},
                labels={"workload": "Workload", "avg_ms": "ms"},
            )
            fig.update_traces(textposition="outside")
            fig.update_layout(height=380, margin=dict(t=10, b=10), legend_title_text="")
            st.plotly_chart(fig, use_container_width=True)
            st.caption(
                "Barras menores = backend mais rápido na média. "
                "Postgres costuma ganhar em buscas indexadas; Mongo pode brilhar em documentos aninhados."
            )

        with col_b:
            st.markdown("#### Latência p95 (cauda) por workload")
            fig = px.bar(
                view,
                x="workload", y="p95_ms",
                color="backend",
                barmode="group",
                text="p95_ms",
                color_discrete_map={"postgres": "#336791", "mongo": "#47A248"},
                labels={"workload": "Workload", "p95_ms": "ms"},
            )
            fig.update_traces(textposition="outside")
            fig.update_layout(height=380, margin=dict(t=10, b=10), legend_title_text="")
            st.plotly_chart(fig, use_container_width=True)
            st.caption(
                "p95 mostra o pior caso entre 95% das consultas. "
                "Um p95 muito maior que o avg revela cauda longa (alguns requests bem lentos)."
            )


# ============================================================================
# RODAPÉ
# ============================================================================

st.divider()
st.caption(
    "🎓 **TCC — Sistema de Defesa Contra Acessos Anômalos**  •  "
    "Stack: Flask + Postgres + MongoDB + Ollama (qwen2.5, gemma3)  •  "
    "Repositório: <https://github.com/LealTiago-git/TCC>"
)
