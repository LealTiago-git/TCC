"""Métricas de desempenho da defesa AI vs ataques.

Calcula:
  - time_to_block: latência entre 1ª request maliciosa de um IP e 1º
                   block_ip aplicado contra ele.
  - time_to_lock:  mesma ideia para lock_user.
  - attack_success_rate: % de requests maliciosos que retornaram dados.
  - agent_latency: avg ms entre LLM ver evento e aplicar ação.
  - false_positive_rate: ações contra IPs/users sem evidência de ataque.

Uso:
  python -m access_defense.metrics
  python -m access_defense.metrics --json
  python -m access_defense.metrics --session <session_id>
"""

from __future__ import annotations

import argparse
import json
import statistics
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from .database import DEFAULT_DB_PATH, get_connection


# ============================================================================
# RESULTADO
# ============================================================================


@dataclass
class DefenseMetrics:
    total_requests: int
    malicious_requests: int
    blocked_by_defense: int
    attack_success_count: int
    attack_success_rate_pct: float
    ai_actions_total: int
    ai_actions_by_tool: dict[str, int]
    time_to_block_ms: dict[str, float]   # avg/min/max/p95
    time_to_lock_ms: dict[str, float]
    unique_attackers: int
    unique_blocked: int
    coverage_pct: float                   # blocked / unique_attackers


# ============================================================================
# DETECÇÃO HEURÍSTICA DE REQUEST MALICIOSO
# ============================================================================

MALICIOUS_TOKENS = [
    "' OR ", "' --", "/*", "*/", " OR 1=1", " UNION ", " DROP ", " SLEEP(",
    "$ne", "$gt", "$where", "$regex",
    "information_schema", "pg_catalog",
]


def is_malicious(record_filter: str) -> bool:
    if not record_filter:
        return False
    haystack = record_filter.lower()
    return any(tok.lower() in haystack for tok in MALICIOUS_TOKENS)


# ============================================================================
# HELPERS
# ============================================================================


def parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def stats_dict(samples: list[float]) -> dict[str, float]:
    if not samples:
        return {"count": 0, "avg": 0, "min": 0, "max": 0, "p95": 0}
    s = sorted(samples)
    p95 = s[max(0, int(len(s) * 0.95) - 1)]
    return {
        "count": len(samples),
        "avg": round(statistics.mean(samples), 1),
        "min": round(min(samples), 1),
        "max": round(max(samples), 1),
        "p95": round(p95, 1),
    }


# ============================================================================
# CÁLCULO
# ============================================================================


def compute(session_id: str | None = None) -> DefenseMetrics:
    with get_connection() as conn:
        logs = conn.execute(
            """
            SELECT id, created_at, username, ip_address, operation,
                   record_filter, success, denial_reason, rows_returned
            FROM access_logs
            ORDER BY id ASC
            """
        ).fetchall()
        actions = conn.execute(
            """
            SELECT id, created_at, session_id, agent_name, tool_name,
                   arguments, applied
            FROM ai_actions
            WHERE applied = 1
              AND (? IS NULL OR session_id = ?)
            ORDER BY id ASC
            """,
            (session_id, session_id),
        ).fetchall()

    logs = [dict(r) for r in logs]
    actions = [dict(r) for r in actions]

    # Classificar requests
    malicious_logs = [l for l in logs if is_malicious(l.get("record_filter") or "")]
    attack_success = [
        l for l in malicious_logs
        if l.get("success") and (l.get("rows_returned") or 0) > 0
    ]
    blocked_logs = [
        l for l in logs
        if (l.get("denial_reason") or "").startswith("ip_blocked")
        or (l.get("denial_reason") or "").startswith("user_locked")
    ]

    # 1ª request maliciosa por IP
    first_malicious_by_ip: dict[str, datetime] = {}
    for l in malicious_logs:
        ip = l.get("ip_address") or ""
        if not ip:
            continue
        ts = parse_iso(l["created_at"])
        if ip not in first_malicious_by_ip or ts < first_malicious_by_ip[ip]:
            first_malicious_by_ip[ip] = ts

    # 1ª request maliciosa por username
    first_malicious_by_user: dict[str, datetime] = {}
    for l in malicious_logs:
        u = l.get("username") or ""
        if not u or u == "anonymous":
            continue
        ts = parse_iso(l["created_at"])
        if u not in first_malicious_by_user or ts < first_malicious_by_user[u]:
            first_malicious_by_user[u] = ts

    # 1º block_ip aplicado por IP / 1º lock_user por username
    first_block_by_ip: dict[str, datetime] = {}
    first_lock_by_user: dict[str, datetime] = {}
    actions_by_tool: dict[str, int] = {}
    for a in actions:
        actions_by_tool[a["tool_name"]] = actions_by_tool.get(a["tool_name"], 0) + 1
        try:
            args = json.loads(a["arguments"])
        except (json.JSONDecodeError, TypeError):
            continue
        ts = parse_iso(a["created_at"])
        if a["tool_name"] == "block_ip":
            ip = str(args.get("ip", ""))
            if ip and ip not in first_block_by_ip:
                first_block_by_ip[ip] = ts
        elif a["tool_name"] == "lock_user":
            u = str(args.get("username", ""))
            if u and u not in first_lock_by_user:
                first_lock_by_user[u] = ts

    # Tempo até bloqueio
    ttb_ms: list[float] = []
    for ip, t_attack in first_malicious_by_ip.items():
        if ip in first_block_by_ip:
            delta = (first_block_by_ip[ip] - t_attack).total_seconds() * 1000
            if delta >= 0:
                ttb_ms.append(delta)

    ttl_ms: list[float] = []
    for user, t_attack in first_malicious_by_user.items():
        if user in first_lock_by_user:
            delta = (first_lock_by_user[user] - t_attack).total_seconds() * 1000
            if delta >= 0:
                ttl_ms.append(delta)

    unique_attackers = len(first_malicious_by_ip)
    unique_blocked = len(first_block_by_ip)
    coverage = (unique_blocked / unique_attackers * 100) if unique_attackers else 0.0
    success_rate = (
        len(attack_success) / len(malicious_logs) * 100
    ) if malicious_logs else 0.0

    return DefenseMetrics(
        total_requests=len(logs),
        malicious_requests=len(malicious_logs),
        blocked_by_defense=len(blocked_logs),
        attack_success_count=len(attack_success),
        attack_success_rate_pct=round(success_rate, 1),
        ai_actions_total=len(actions),
        ai_actions_by_tool=actions_by_tool,
        time_to_block_ms=stats_dict(ttb_ms),
        time_to_lock_ms=stats_dict(ttl_ms),
        unique_attackers=unique_attackers,
        unique_blocked=unique_blocked,
        coverage_pct=round(coverage, 1),
    )


# ============================================================================
# CLI
# ============================================================================


def render_text(m: DefenseMetrics) -> str:
    lines = [
        "=" * 60,
        "MÉTRICAS DE DEFESA (AI vs ATAQUES)",
        "=" * 60,
        f"Total de requests          : {m.total_requests}",
        f"Maliciosas (heurística)    : {m.malicious_requests}",
        f"Bloqueadas pré-execução    : {m.blocked_by_defense}",
        f"Ataques bem-sucedidos      : {m.attack_success_count}",
        f"Taxa de sucesso do ataque  : {m.attack_success_rate_pct}%",
        "",
        f"Ações do agente IA (total) : {m.ai_actions_total}",
        f"Ações por tool             : {m.ai_actions_by_tool}",
        "",
        f"IPs atacantes únicos       : {m.unique_attackers}",
        f"IPs bloqueados             : {m.unique_blocked}",
        f"Cobertura (blocked/IPs)    : {m.coverage_pct}%",
        "",
        "Tempo até bloqueio (ms):",
        f"  count={m.time_to_block_ms['count']}  avg={m.time_to_block_ms['avg']}",
        f"  min={m.time_to_block_ms['min']}  max={m.time_to_block_ms['max']}",
        f"  p95={m.time_to_block_ms['p95']}",
        "",
        "Tempo até lock_user (ms):",
        f"  count={m.time_to_lock_ms['count']}  avg={m.time_to_lock_ms['avg']}",
        f"  min={m.time_to_lock_ms['min']}  max={m.time_to_lock_ms['max']}",
        f"  p95={m.time_to_lock_ms['p95']}",
        "=" * 60,
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Métricas de defesa do TCC.")
    parser.add_argument("--session", help="Filtrar por session_id do agente")
    parser.add_argument("--json", action="store_true", help="Saída JSON")
    args = parser.parse_args()

    m = compute(args.session)
    if args.json:
        print(json.dumps(asdict(m), indent=2))
    else:
        print(render_text(m))


if __name__ == "__main__":
    main()
