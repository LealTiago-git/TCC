"""Agente autônomo de defesa baseado em LLM com tool-calling.

Loop:
  1. Polla access_logs por eventos novos (id > last_seen).
  2. Agrupa em batch (até N eventos) e envia ao LLM via OpenAI-compatible API.
  3. LLM recebe o batch + a lista de ferramentas e responde com tool_calls JSON.
  4. Executor aplica cada tool_call (escreve em blocked_ips / locked_users /
     ai_actions) e persiste o resultado.

Ferramentas expostas ao LLM:
  - block_ip(ip, reason, ttl_seconds)
  - lock_user(username, reason)
  - flag_for_audit(log_id, severity, reason)
  - no_action(reason)

Provedores:
  - Ollama local (default)
  - OpenRouter cloud

Uso:
  python -m access_defense.agent_loop --model gemma3 --interval 3
  python -m access_defense.agent_loop --model qwen2.5 --batch 25 --once
"""

from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from .database import DEFAULT_DB_PATH, get_connection, init_db, utc_now


# ============================================================================
# TOOL SPECS (formato OpenAI function-calling)
# ============================================================================


TOOLS_SPEC = [
    {
        "type": "function",
        "function": {
            "name": "block_ip",
            "description": (
                "Bloqueia um endereco IP de fazer novas requisicoes ao servidor. "
                "Use para SQL injection, NoSQL injection, DDoS, ou qualquer ataque "
                "vindo de um IP unico identificavel."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "IP a bloquear, ex 127.0.0.1"},
                    "reason": {"type": "string", "description": "Justificativa curta"},
                    "ttl_seconds": {
                        "type": "integer",
                        "description": "Duracao do bloqueio em segundos. 0 = permanente.",
                        "default": 3600,
                    },
                },
                "required": ["ip", "reason"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lock_user",
            "description": (
                "Bloqueia uma conta de usuario impedindo qualquer login. "
                "Use para brute force bem-sucedido, credenciais vazadas, "
                "ou escalada de privilegio."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "username": {"type": "string"},
                    "reason": {"type": "string"},
                },
                "required": ["username", "reason"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "flag_for_audit",
            "description": (
                "Marca um evento para revisao humana sem bloquear nada. "
                "Use quando o sinal e suspeito mas nao conclusivo."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "log_id": {"type": "integer"},
                    "severity": {
                        "type": "string",
                        "enum": ["low", "medium", "high", "critical"],
                    },
                    "reason": {"type": "string"},
                },
                "required": ["log_id", "severity", "reason"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "no_action",
            "description": (
                "Nenhum dos eventos do batch requer acao. Use quando todo o "
                "trafego parece legitimo."
            ),
            "parameters": {
                "type": "object",
                "properties": {"reason": {"type": "string"}},
                "required": ["reason"],
            },
        },
    },
]


SYSTEM_PROMPT = (
    "Voce e um agente autonomo de defesa de banco de dados. "
    "Recebe um batch de eventos de acesso recentes (logs em JSON). "
    "Para cada padrao malicioso identificado, chame UMA das ferramentas: "
    "block_ip, lock_user, flag_for_audit, no_action. "
    "Pode chamar varias ferramentas no mesmo turno. "
    "Indicadores de ataque a procurar: "
    "tokens SQL injection (UNION, OR 1=1, --, DROP), "
    "operadores NoSQL no payload ($ne, $gt, $where), "
    "varias tentativas de login negadas do mesmo IP, "
    "volume anormal de requests, "
    "acessos a tabelas sensiveis (salarios) por usuario sem permissao, "
    "raw SQL exfiltrando users/passwords. "
    "Seja conservador: prefira flag_for_audit a block quando incerto. "
    "Responda usando tool_calls; nao escreva texto explicativo extra."
)


# ============================================================================
# CONFIG
# ============================================================================


@dataclass
class AgentConfig:
    model: str
    base_url: str
    api_key: str
    batch_size: int
    interval_s: int
    session_id: str
    timeout_s: int = 60


def build_config(model: str, batch: int, interval: int) -> AgentConfig:
    provider = os.getenv("AGENT_PROVIDER", "ollama").strip().lower()
    if provider == "openrouter":
        base = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
        key = os.getenv("OPENROUTER_API_KEY", "")
    else:
        # Para Ollama, usamos a API nativa /api/chat (suporta tools melhor que /v1)
        base = os.getenv("OLLAMA_NATIVE_URL", "http://localhost:11434")
        key = os.getenv("OLLAMA_API_KEY", "ollama")
    return AgentConfig(
        model=model,
        base_url=base,
        api_key=key,
        batch_size=batch,
        interval_s=interval,
        session_id=uuid4().hex,
    )


# Modelos que NÃO suportam tool-calling nativo — usar prompt JSON fallback.
NO_TOOLS_MODELS = {"gemma3", "gemma3:latest", "gemma2", "llama2", "phi"}


def model_supports_tools(model: str) -> bool:
    base = model.lower().split(":")[0]
    return base not in {m.split(":")[0] for m in NO_TOOLS_MODELS}


# ============================================================================
# FETCH EVENTOS
# ============================================================================


def fetch_new_events(last_seen_id: int, limit: int) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, created_at, username, role, ip_address, user_agent,
                   operation, table_name, record_filter, rows_returned,
                   success, denial_reason
            FROM access_logs
            WHERE id > ?
            ORDER BY id ASC
            LIMIT ?
            """,
            (last_seen_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def last_log_id() -> int:
    with get_connection() as conn:
        row = conn.execute("SELECT COALESCE(MAX(id), 0) AS m FROM access_logs").fetchone()
    return int(row["m"])


# ============================================================================
# CHAMADA AO LLM
# ============================================================================


JSON_FALLBACK_INSTRUCTION = (
    "\n\nVoce DEVE responder APENAS com um array JSON valido (sem markdown, sem texto extra). "
    "Cada item representa uma chamada de ferramenta com este formato exato:\n"
    '[{"tool": "block_ip", "args": {"ip": "1.2.3.4", "reason": "SQLi", "ttl_seconds": 3600}}, '
    '{"tool": "no_action", "args": {"reason": "trafego ok"}}]\n'
    "Ferramentas disponiveis: block_ip(ip, reason, ttl_seconds), lock_user(username, reason), "
    "flag_for_audit(log_id, severity, reason), no_action(reason)."
)


def call_llm(cfg: AgentConfig, events: list[dict[str, Any]]) -> dict[str, Any]:
    """Chama LLM via Ollama /api/chat (nativo) ou OpenRouter /chat/completions."""
    is_ollama = "11434" in cfg.base_url or "ollama" in cfg.base_url.lower()
    user_content = (
        "Analise este batch de eventos de acesso e tome as acoes necessarias:\n"
        + json.dumps(events, ensure_ascii=False, indent=2, default=str)
    )

    if is_ollama:
        return _call_ollama_native(cfg, user_content)
    return _call_openai_compat(cfg, user_content)


def _call_ollama_native(cfg: AgentConfig, user_content: str) -> dict[str, Any]:
    """Usa /api/chat do Ollama. Suporta tools nativamente para modelos compatíveis."""
    supports_tools = model_supports_tools(cfg.model)
    system_prompt = SYSTEM_PROMPT if supports_tools else SYSTEM_PROMPT + JSON_FALLBACK_INSTRUCTION

    body: dict[str, Any] = {
        "model": cfg.model,
        "stream": False,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
        "options": {"temperature": 0.1},
    }
    if supports_tools:
        body["tools"] = TOOLS_SPEC
    else:
        body["format"] = "json"

    url = cfg.base_url.rstrip("/") + "/api/chat"
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=cfg.timeout_s) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _call_openai_compat(cfg: AgentConfig, user_content: str) -> dict[str, Any]:
    """Fallback para OpenRouter ou OpenAI-compatible."""
    body = {
        "model": cfg.model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
        "tools": TOOLS_SPEC,
        "tool_choice": "auto",
        "temperature": 0.1,
    }
    url = cfg.base_url.rstrip("/") + "/chat/completions"
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {cfg.api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=cfg.timeout_s) as resp:
        return json.loads(resp.read().decode("utf-8"))


def extract_tool_calls(llm_response: dict[str, Any]) -> list[dict[str, Any]]:
    """Suporta:
       - Ollama native: top-level `message.tool_calls`
       - OpenAI compat: `choices[0].message.tool_calls`
       - Fallback texto JSON em content
    """
    # Ollama native format
    msg = llm_response.get("message")
    if not msg:
        # OpenAI format
        try:
            msg = llm_response["choices"][0]["message"]
        except (KeyError, IndexError):
            return []

    tool_calls = msg.get("tool_calls") or []
    parsed: list[dict[str, Any]] = []
    for tc in tool_calls:
        fn = tc.get("function", {})
        name = fn.get("name", "")
        args_raw = fn.get("arguments", "{}")
        if isinstance(args_raw, str):
            try:
                args = json.loads(args_raw)
            except json.JSONDecodeError:
                args = {}
        else:
            args = args_raw or {}
        parsed.append({"tool": name, "args": args})

    if parsed:
        return parsed

    # Fallback: modelos sem tool support retornam JSON puro em content
    content = msg.get("content") or ""
    if not content:
        return []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        # tentar extrair primeiro array JSON do texto
        import re
        match = re.search(r"\[\s*\{.*\}\s*\]", content, re.DOTALL)
        if not match:
            return []
        try:
            data = json.loads(match.group(0))
        except json.JSONDecodeError:
            return []

    if isinstance(data, list):
        return [{"tool": d.get("tool"), "args": d.get("args", {})} for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        # Pode ser {"tool":..., "args":...} ou {"actions":[...]}
        if "tool" in data:
            return [{"tool": data["tool"], "args": data.get("args", {})}]
        if "actions" in data and isinstance(data["actions"], list):
            return [{"tool": d.get("tool"), "args": d.get("args", {})} for d in data["actions"] if isinstance(d, dict)]
    return []


# ============================================================================
# EXECUTOR DAS TOOLS
# ============================================================================


def execute_block_ip(args: dict[str, Any]) -> tuple[bool, str | None]:
    ip = str(args.get("ip", "")).strip()
    reason = str(args.get("reason", "agent decision"))
    ttl = int(args.get("ttl_seconds", 3600) or 0)
    if not ip:
        return False, "ip vazio"
    expires_at = (
        (datetime.now(timezone.utc) + timedelta(seconds=ttl)).replace(microsecond=0).isoformat()
        if ttl > 0 else None
    )
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO blocked_ips (ip_address, reason, source_alert_id, created_at, expires_at)
            VALUES (?, ?, NULL, ?, ?)
            ON CONFLICT(ip_address) DO UPDATE SET
                reason=excluded.reason,
                created_at=excluded.created_at,
                expires_at=excluded.expires_at
            """,
            (ip, reason, utc_now(), expires_at),
        )
        conn.commit()
    return True, None


def execute_lock_user(args: dict[str, Any]) -> tuple[bool, str | None]:
    username = str(args.get("username", "")).strip()
    reason = str(args.get("reason", "agent decision"))
    if not username:
        return False, "username vazio"
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO locked_users (username, reason, source_log_id, created_at, expires_at)
            VALUES (?, ?, NULL, ?, NULL)
            ON CONFLICT(username) DO UPDATE SET
                reason=excluded.reason,
                created_at=excluded.created_at
            """,
            (username, reason, utc_now()),
        )
        conn.commit()
    return True, None


def execute_flag_for_audit(args: dict[str, Any]) -> tuple[bool, str | None]:
    log_id = int(args.get("log_id", 0) or 0)
    severity = str(args.get("severity", "medium"))
    reason = str(args.get("reason", "agent flag"))
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO security_alerts (created_at, access_log_id, severity, status, source, summary, verdict)
            VALUES (?, ?, ?, 'open', 'agent', ?, ?)
            """,
            (utc_now(), log_id or None, severity, reason[:200], reason),
        )
        conn.commit()
    return True, None


def execute_no_action(args: dict[str, Any]) -> tuple[bool, str | None]:
    return True, None


EXECUTORS = {
    "block_ip": execute_block_ip,
    "lock_user": execute_lock_user,
    "flag_for_audit": execute_flag_for_audit,
    "no_action": execute_no_action,
}


def record_action(cfg: AgentConfig, tool: str, args: dict, applied: bool, error: str | None):
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO ai_actions (
                created_at, session_id, agent_name, tool_name, arguments,
                target_log_id, reason, applied, error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utc_now(),
                cfg.session_id,
                cfg.model,
                tool,
                json.dumps(args, ensure_ascii=False),
                int(args.get("log_id", 0)) or None,
                str(args.get("reason", ""))[:500],
                int(applied),
                error,
            ),
        )
        conn.commit()


# ============================================================================
# LOOP PRINCIPAL
# ============================================================================


def run_loop(cfg: AgentConfig, *, once: bool = False, start_from: int | None = None) -> None:
    last_id = start_from if start_from is not None else last_log_id()
    print(f"[agent] sessao={cfg.session_id[:8]} modelo={cfg.model} batch={cfg.batch_size}")
    print(f"[agent] iniciando do log_id={last_id}")
    while True:
        events = fetch_new_events(last_id, cfg.batch_size)
        if events:
            last_id = max(e["id"] for e in events)
            try:
                llm_resp = call_llm(cfg, events)
                tool_calls = extract_tool_calls(llm_resp)
                print(f"[agent] batch={len(events)} ultimo_id={last_id} tools={len(tool_calls)}")
                for call in tool_calls:
                    tool = call.get("tool")
                    args = call.get("args", {}) or {}
                    fn = EXECUTORS.get(tool)
                    if not fn:
                        record_action(cfg, tool or "unknown", args, False, "tool desconhecida")
                        continue
                    ok, err = fn(args)
                    record_action(cfg, tool, args, ok, err)
                    print(f"  -> {tool}({args}) applied={ok} err={err}")
            except urllib.error.URLError as exc:
                print(f"[agent] erro LLM: {exc}")
            except Exception as exc:
                print(f"[agent] erro inesperado: {exc}")
        if once:
            return
        time.sleep(cfg.interval_s)


# ============================================================================
# CLI
# ============================================================================


def main():
    parser = argparse.ArgumentParser(description="Agente IA autonomo do TCC.")
    parser.add_argument("--model", default="gemma3", help="gemma3, qwen2.5, etc.")
    parser.add_argument("--batch", type=int, default=15, help="Eventos por batch")
    parser.add_argument("--interval", type=int, default=3, help="Segundos entre polls")
    parser.add_argument("--once", action="store_true", help="Processa um batch e sai")
    parser.add_argument("--from-start", action="store_true", help="Comeca do log_id=0")
    args = parser.parse_args()

    init_db(DEFAULT_DB_PATH, seed=False)
    cfg = build_config(args.model, args.batch, args.interval)
    run_loop(cfg, once=args.once, start_from=0 if args.from_start else None)


if __name__ == "__main__":
    main()
