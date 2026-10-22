"""Dashboard Streamlit — Sistema de Defesa Contra Acessos Anômalos.

Overhaul conciso: 4 abas que contam a história de ponta a ponta.
  1. Visão Geral           — KPIs + o gráfico-tese (ataque bloqueado vs vazado)
  2. Ataques & Defesa      — logs, ações da IA, quarentena, categoria × resultado
  3. Comparação de Modelos — qwen2.5 × llama3.1 (lê results/battery_results.csv)
  4. Benchmark PG × Mongo  — latência dos backends

Lê o SQLite de controle (access_control.db; cai em demo_data.db na nuvem) e o
CSV da bateria. Execute:
  python -m streamlit run access_defense/dashboard.py
"""
from __future__ import annotations

import re
import sqlite3
from datetime import datetime
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

st.set_page_config(page_title="TCC — Defesa Anti-Anomalias", page_icon="🛡️",
                   layout="wide", initial_sidebar_state="collapsed")

# Paletas únicas (reuso em todo o app)
ATTACK_COLORS = {
    "sql_injection": "#e63946", "nosql_injection": "#f3722c", "brute_force": "#f9c74f",
    "ddos": "#9c27b0", "buffer_overflow": "#577590", "privilege_escalation": "#f72585",
    "exfiltration": "#7209b7", "benign": "#90be6d", "outro": "#adb5bd",
}
MODEL_COLORS = {"qwen2.5": "#4361ee", "llama3.1": "#f72585", "gemma3": "#43aa8b"}
OK_RED, OK_GREEN = "#e63946", "#2a9d8f"


# ============================================================================
# DADOS
# ============================================================================

@st.cache_resource
def get_db_path() -> Path:
    root = Path(__file__).parent.parent
    live, demo = root / "access_control.db", root / "demo_data.db"
    return live if live.exists() else demo

def _conn():
    db = get_db_path()
    if not db.exists():
        st.error("Banco SQLite não encontrado. Rode `python -m access_defense.cli init-db`.")
        st.stop()
    c = sqlite3.connect(str(db)); c.row_factory = sqlite3.Row
    return c

def q(sql: str, params: tuple = ()) -> pd.DataFrame:
    try:
        with _conn() as c:
            rows = c.execute(sql, params).fetchall()
    except sqlite3.OperationalError:
        return pd.DataFrame()
    return pd.DataFrame([dict(r) for r in rows]) if rows else pd.DataFrame()

def scalar(sql: str, params: tuple = ()) -> int:
    df = q(sql, params)
    return int(df.iloc[0, 0]) if not df.empty else 0

CATEGORY_PATTERNS = [
    ("sql_injection", re.compile(r"(union\s+select|or\s+1=1|--|drop\s+table|information_schema|;\s*select)", re.I)),
    ("nosql_injection", re.compile(r"(\$ne|\$gt|\$where|\$regex|\$exists)", re.I)),
    ("buffer_overflow", re.compile(r".{256,}", re.S)),
    ("exfiltration", re.compile(r"select\s+.*password|select\s+.*from\s+users\b", re.I)),
    ("privilege_escalation", re.compile(r"\bsalarios\b", re.I)),
]

def categorize(payload: str) -> str:
    if not payload:
        return "benign"
    for name, pat in CATEGORY_PATTERNS:
        if pat.search(payload):
            return name
    return "benign"

def with_category(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df
    df = df.copy()
    df["categoria"] = df["record_filter"].fillna("").apply(categorize)
    df["is_blocked"] = df["denial_reason"].fillna("").str.startswith(("ip_blocked", "user_locked"))
    df["is_malicious"] = df["categoria"] != "benign"
    return df

@st.cache_data(ttl=10)
def load_battery() -> pd.DataFrame:
    path = Path(__file__).parent.parent / "results" / "battery_results.csv"
    if not path.exists():
        return pd.DataFrame()
    df = pd.read_csv(path)
    for col in ("breaches", "events", "category_ok", "acted", "latency_s"):
        if col in df:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    return df


# ============================================================================
# CABEÇALHO
# ============================================================================

st.title("🛡️ Defesa Contra Acessos Anômalos")
left, right = st.columns([3, 1])
left.caption("Ataques HTTP reais a Postgres + MongoDB; agentes LLM (qwen2.5, llama3.1) "
             "detectam e respondem em tempo real — bloqueiam IP, travam usuário, alertam.")
with right:
    if st.button("🔄 Atualizar", use_container_width=True):
        st.cache_resource.clear(); st.cache_data.clear(); st.rerun()
    st.caption(f"{datetime.now():%H:%M:%S} · `{get_db_path().name}`")

tab_overview, tab_defense, tab_models, tab_bench = st.tabs(
    ["🏠 Visão Geral", "⚔️ Ataques & Defesa", "🤖 Comparação de Modelos", "⚡ Benchmark"])


# ============================================================================
# 1. VISÃO GERAL
# ============================================================================

with tab_overview:
    total = scalar("SELECT COUNT(*) FROM access_logs")
    blocked = scalar("SELECT COUNT(*) FROM access_logs WHERE denial_reason LIKE 'ip_blocked%' OR denial_reason LIKE 'user_locked%'")
    ips = scalar("SELECT COUNT(*) FROM blocked_ips WHERE expires_at IS NULL OR expires_at > ?", (datetime.utcnow().isoformat(),))
    users = scalar("SELECT COUNT(*) FROM locked_users")
    actions = scalar("SELECT COUNT(*) FROM ai_actions")
    block_pct = (blocked / total * 100) if total else 0

    c = st.columns(5)
    c[0].metric("Requests HTTP", f"{total:,}")
    c[1].metric("Bloqueados (403)", f"{blocked:,}", help="IP/usuário já em quarentena → 403 antes da query.")
    c[2].metric("IPs bloqueados", f"{ips:,}")
    c[3].metric("Ações da IA", f"{actions:,}")
    c[4].metric("Taxa de bloqueio", f"{block_pct:.0f}%")

    st.divider()
    st.subheader("Ataque bloqueado vs. vazado, por categoria")
    logs = with_category(q("SELECT ip_address, record_filter, success, denial_reason FROM access_logs"))
    mal = logs[logs["is_malicious"]] if not logs.empty else logs
    if mal.empty:
        st.info("Sem tráfego malicioso ainda. Rode `attacker.py` para gerar ataques.")
    else:
        agg = mal.groupby("categoria").apply(
            lambda g: pd.Series({
                "Vazou (atacante obteve dados)": int(((g["success"] == 1) & (g["denial_reason"].isna() | ~g["is_blocked"])).sum()),
                "Bloqueado (403)": int(g["is_blocked"].sum()),
            }), include_groups=False).reset_index()
        m = agg.melt(id_vars="categoria", var_name="Resultado", value_name="Quantidade")
        fig = px.bar(m, x="categoria", y="Quantidade", color="Resultado", barmode="group",
                     color_discrete_map={"Vazou (atacante obteve dados)": OK_RED, "Bloqueado (403)": OK_GREEN})
        fig.update_layout(height=360, margin=dict(t=10, b=10), xaxis_title="", legend_title_text="")
        st.plotly_chart(fig, use_container_width=True)
        st.caption("Verde ≫ vermelho = defesa madura naquela categoria. A defesa atua **antes** da query.")


# ============================================================================
# 2. ATAQUES & DEFESA
# ============================================================================

with tab_defense:
    logs = with_category(q("""SELECT id, created_at, username, ip_address, operation, table_name,
                                     record_filter, rows_returned, success, denial_reason
                              FROM access_logs ORDER BY id DESC LIMIT 1000"""))
    if logs.empty:
        st.info("Nenhum acesso registrado. Rode `attacker.py`.")
    else:
        f1, f2, f3 = st.columns([2, 2, 1])
        user_f = f1.selectbox("Usuário", ["Todos"] + sorted(logs["username"].dropna().unique()))
        cat_f = f2.selectbox("Categoria", ["Todas"] + sorted(logs["categoria"].unique()))
        only_b = f3.checkbox("Só 403")
        view = logs
        if user_f != "Todos": view = view[view["username"] == user_f]
        if cat_f != "Todas": view = view[view["categoria"] == cat_f]
        if only_b: view = view[view["is_blocked"]]

        st.dataframe(
            view[["id", "created_at", "username", "ip_address", "operation", "categoria",
                  "rows_returned", "success", "denial_reason"]].rename(columns={
                "id": "Log", "created_at": "Quando", "username": "Usuário", "ip_address": "IP",
                "operation": "Op", "categoria": "Categoria", "rows_returned": "Linhas",
                "success": "OK", "denial_reason": "Negação"}),
            use_container_width=True, height=300, hide_index=True)
        st.caption(f"{len(view)} de {len(logs)} acessos. Categoria inferida do payload (mesma taxonomia do agente).")

        st.divider()
        st.subheader("O que a IA decidiu")
        acts = q("""SELECT agent_name, tool_name, reason, applied, created_at
                    FROM ai_actions ORDER BY id DESC LIMIT 500""")
        if acts.empty:
            st.info("Nenhuma ação do agente. Rode `python -m access_defense.agent_loop --model qwen2.5`.")
        else:
            k = st.columns(4)
            k[0].metric("Ações", len(acts))
            for i, t in enumerate(("block_ip", "lock_user", "flag_for_audit")):
                k[i + 1].metric(t, int((acts["tool_name"] == t).sum()))
            cc = st.columns(2)
            tc = acts["tool_name"].value_counts().reset_index()
            tc.columns = ["Ferramenta", "N"]
            fig = px.bar(tc, x="Ferramenta", y="N", color="Ferramenta", text="N",
                         color_discrete_sequence=px.colors.qualitative.Bold)
            fig.update_layout(height=280, margin=dict(t=10, b=10), showlegend=False)
            cc[0].plotly_chart(fig, use_container_width=True)
            mc = acts["agent_name"].value_counts().reset_index()
            mc.columns = ["Modelo", "N"]
            fig = px.bar(mc, x="Modelo", y="N", color="Modelo", text="N",
                         color_discrete_map=MODEL_COLORS)
            fig.update_layout(height=280, margin=dict(t=10, b=10), showlegend=False)
            cc[1].plotly_chart(fig, use_container_width=True)
            st.dataframe(
                acts.head(30)[["created_at", "agent_name", "tool_name", "reason", "applied"]].rename(columns={
                    "created_at": "Quando", "agent_name": "Modelo", "tool_name": "Ferramenta",
                    "reason": "Motivo", "applied": "Aplicada"}),
                use_container_width=True, height=240, hide_index=True)

        st.divider()
        qi, qu = st.columns(2)
        with qi:
            st.subheader("🚫 IPs em quarentena")
            dfi = q("SELECT ip_address, reason, expires_at FROM blocked_ips ORDER BY created_at DESC")
            st.dataframe(dfi, use_container_width=True, hide_index=True, height=180) if not dfi.empty else st.caption("Nenhum.")
        with qu:
            st.subheader("🔒 Usuários travados")
            dfu = q("SELECT username, reason, expires_at FROM locked_users ORDER BY created_at DESC")
            st.dataframe(dfu, use_container_width=True, hide_index=True, height=180) if not dfu.empty else st.caption("Nenhum.")

        st.divider()
        st.subheader("Linha do tempo dos ataques")
        tl = with_category(q("SELECT created_at, record_filter, denial_reason, success FROM access_logs ORDER BY id ASC"))
        tl = tl[tl["is_malicious"]].copy() if not tl.empty else tl
        if not tl.empty:
            tl["created_at"] = pd.to_datetime(tl["created_at"], errors="coerce")
            series = tl.set_index("created_at").resample("1min").size().reset_index()
            series.columns = ["Quando", "Ataques/min"]
            fig = px.line(series, x="Quando", y="Ataques/min", markers=True)
            fig.update_layout(height=260, margin=dict(t=10, b=10))
            st.plotly_chart(fig, use_container_width=True)


# ============================================================================
# 3. COMPARAÇÃO DE MODELOS (battery CSV)
# ============================================================================

with tab_models:
    bat = load_battery()
    if bat.empty:
        st.info("Sem dados de bateria. Gere com `python -m access_defense.battery --runs 10` "
                "(grava em `results/battery_results.csv`).")
    else:
        runs = bat["run_id"].nunique()
        st.caption(f"{len(bat)} medições · {runs} sessões (run_id) · acurácia = categoria inferida == esperada.")

        summ = bat.groupby("model").agg(
            acuracia=("category_ok", "mean"), acao=("acted", "mean"),
            latencia=("latency_s", "mean"), n=("category_ok", "size")).reset_index()
        summ["acuracia"] *= 100; summ["acao"] *= 100

        cols = st.columns(len(summ))
        for i, r in summ.iterrows():
            with cols[i]:
                st.markdown(f"### {r['model']}")
                st.metric("Acurácia de categoria", f"{r['acuracia']:.0f}%")
                st.metric("Agiu (block/lock)", f"{r['acao']:.0f}%")
                st.metric("Latência média", f"{r['latencia']:.1f} s")

        st.divider()
        g = bat.groupby(["model", "attack"]).agg(
            cat_ok=("category_ok", "mean"), acted=("acted", "mean"),
            lat=("latency_s", "mean")).reset_index()
        g["cat_ok"] *= 100; g["acted"] *= 100

        c1, c2 = st.columns(2)
        with c1:
            st.subheader("Acurácia de categoria (%) por ataque")
            fig = px.bar(g, x="attack", y="cat_ok", color="model", barmode="group",
                         color_discrete_map=MODEL_COLORS, text=g["cat_ok"].round(0))
            fig.update_layout(height=320, margin=dict(t=10, b=10), xaxis_title="",
                              yaxis_title="%", legend_title_text="")
            st.plotly_chart(fig, use_container_width=True)
        with c2:
            st.subheader("Agiu (%) por ataque")
            fig = px.bar(g, x="attack", y="acted", color="model", barmode="group",
                         color_discrete_map=MODEL_COLORS, text=g["acted"].round(0))
            fig.update_layout(height=320, margin=dict(t=10, b=10), xaxis_title="",
                              yaxis_title="%", legend_title_text="")
            st.plotly_chart(fig, use_container_width=True)

        st.subheader("Latência média (s) por ataque")
        fig = px.bar(g, x="attack", y="lat", color="model", barmode="group",
                     color_discrete_map=MODEL_COLORS, text=g["lat"].round(1))
        fig.update_layout(height=300, margin=dict(t=10, b=10), xaxis_title="",
                          yaxis_title="s", legend_title_text="")
        st.plotly_chart(fig, use_container_width=True)
        st.caption("Trade-off central: precisão (acurácia alta) vs. recall (age em quase tudo) vs. latência.")


# ============================================================================
# 4. BENCHMARK PG × MONGO
# ============================================================================

with tab_bench:
    b = q("""SELECT run_id, backend, workload, avg_ms, p95_ms
             FROM benchmark_runs ORDER BY id DESC""")
    if b.empty:
        st.info("Nenhum benchmark. Rode `python -m access_defense.benchmark --iterations 200`.")
    else:
        opts = ["Mais recente por workload"] + sorted(b["run_id"].unique(), reverse=True)
        chosen = st.selectbox("Run", opts)
        view = (b.drop_duplicates(subset=["backend", "workload"]) if chosen == opts[0]
                else b[b["run_id"] == chosen])
        c1, c2 = st.columns(2)
        for col, metric, title in ((c1, "avg_ms", "Latência média (ms)"), (c2, "p95_ms", "Latência p95 (ms)")):
            fig = px.bar(view, x="workload", y=metric, color="backend", barmode="group",
                         text=view[metric].round(1),
                         color_discrete_map={"postgres": "#336791", "mongo": "#47A248"})
            fig.update_layout(height=340, margin=dict(t=10, b=10), xaxis_title="", legend_title_text="")
            col.subheader(title); col.plotly_chart(fig, use_container_width=True)
        st.caption("Barras menores = backend mais rápido. p95 revela a cauda (requests lentos).")


st.divider()
st.caption("🎓 TCC — Defesa Contra Acessos Anômalos · Flask · Postgres · MongoDB · Ollama · Streamlit")
