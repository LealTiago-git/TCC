"""Bateria de testes: compara modelos LLM (qwen2.5, llama3.1) contra cada tipo
de ataque em cada backend. Cada execucao ANEXA os resultados a um CSV unico
(results/battery_results.csv) com run_id + timestamp, acumulando todo o estudo.

Reusa agent_loop + attacker internos. Roda do host contra o server :8000 (Docker).
Pre-requisitos: lab Docker no ar (server:8000) e Ollama no host com os modelos.

Uso:
  python -m access_defense.battery
  python -m access_defense.battery --models qwen2.5 llama3.1 --csv results/battery_results.csv
  python -m access_defense.battery --selftest   # so valida o append do CSV (sem Docker/LLM)
"""
from __future__ import annotations

import argparse
import csv
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from . import agent_loop as al, attacker as atk
from .database import get_connection

DEFAULT_CSV = Path("results/battery_results.csv")
DEFAULT_TARGET = "http://localhost:8000"

# (nome, backend, categoria_esperada, fn(target)->AttackReport)
ATTACKS = [
    ("sqli",        "postgres", "sql_injection",        lambda t: atk.attack_sqli(t)),
    ("nosqli",      "mongo",    "nosql_injection",      lambda t: atk.attack_nosqli(t)),
    ("brute-force", "postgres", "brute_force",          lambda t: atk.attack_brute_force(t, rounds=10)),
    ("ddos",        "postgres", "ddos",                 lambda t: atk.attack_ddos(t, total_requests=25, concurrency=10)),
    ("exfil",       "postgres", "exfiltration",         lambda t: atk.attack_exfil(t)),
    ("privesc",     "postgres", "privilege_escalation", lambda t: atk.attack_privesc(t)),
]

FIELDS = ["run_id", "timestamp", "model", "attack", "db", "breaches", "events",
          "ai_category", "expected_category", "category_ok", "acted", "tools", "latency_s"]

# ponytail: timeout alto porque llama3.1 (4.9GB) estoura o default de 60s em CPU.
LLM_TIMEOUT_S = 300


def _clear_enforcement() -> None:
    with get_connection() as c:
        c.execute("DELETE FROM blocked_ips")
        c.execute("DELETE FROM locked_users")
        c.commit()


def _max_log_id() -> int:
    with get_connection() as c:
        return c.execute("SELECT COALESCE(MAX(id),0) FROM access_logs").fetchone()[0]


def _taxonomy(reason: str) -> str:
    r = (reason or "").lower()
    for cat in ("sql_injection", "nosql_injection", "brute_force", "ddos",
                "buffer_overflow", "privilege_escalation", "exfiltration", "benign"):
        if r.startswith(cat):
            return cat
    return (reason.split(":")[0][:18] if reason else "-")


def append_rows(csv_path: Path, rows: list[dict]) -> None:
    """Anexa linhas ao CSV; escreve o header so quando o arquivo e novo."""
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    new = not csv_path.exists() or csv_path.stat().st_size == 0
    with csv_path.open("a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if new:
            w.writeheader()
        for row in rows:
            w.writerow(row)


def run_battery(models: list[str], target: str, csv_path: Path) -> list[dict]:
    run_id = uuid4().hex[:8]
    ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    rows: list[dict] = []
    for model in models:
        cfg = al.build_config(model, batch=120, interval=1)
        cfg.timeout_s = LLM_TIMEOUT_S
        for name, backend, expected, fn in ATTACKS:
            _clear_enforcement()
            start = _max_log_id()
            t0 = time.perf_counter()
            rep = fn(target)
            events = al.fetch_new_events(start, 120)
            tools, reason0 = [], ""
            if events:
                try:
                    resp = al.call_llm(cfg, events)
                    for call in al.extract_tool_calls(resp):
                        tool = call.get("tool")
                        args = call.get("args", {}) or {}
                        ex = al.EXECUTORS.get(tool)
                        ok, err = (ex(args) if ex else (False, "tool desconhecida"))
                        al.record_action(cfg, tool, args, ok, err)
                        tools.append(tool)
                        if not reason0:
                            reason0 = str(args.get("reason", ""))
                except Exception as e:  # noqa: BLE001 - registra o erro na linha
                    reason0 = f"ERRO: {type(e).__name__}: {e}"
            cat = _taxonomy(reason0)
            rows.append({
                "run_id": run_id, "timestamp": ts, "model": model, "attack": name,
                "db": backend, "breaches": rep.successful_breaches, "events": len(events),
                "ai_category": cat, "expected_category": expected,
                "category_ok": int(cat == expected),
                "acted": int(any(t in ("block_ip", "lock_user") for t in tools)),
                "tools": ",".join(tools) or "-",
                "latency_s": round(time.perf_counter() - t0, 1),
            })
            print(rows[-1], flush=True)
    append_rows(csv_path, rows)
    _clear_enforcement()
    print(f"\nrun_id={run_id}: {len(rows)} linhas anexadas em {csv_path}")
    return rows


def _selftest() -> None:
    import tempfile
    p = Path(tempfile.mkdtemp()) / "t.csv"
    r = {k: "x" for k in FIELDS}
    append_rows(p, [r]); append_rows(p, [r, r])
    lines = p.read_text(encoding="utf-8").strip().splitlines()
    assert lines[0] == ",".join(FIELDS), "header errado"
    assert len(lines) == 1 + 3, f"esperava 1 header + 3 dados, veio {len(lines)}"
    print("selftest OK: header unico, append acumula")


def main() -> None:
    ap = argparse.ArgumentParser(description="Bateria LLM vs ataques, com CSV acumulativo.")
    ap.add_argument("--models", nargs="+", default=["qwen2.5", "llama3.1"])
    ap.add_argument("--target", default=DEFAULT_TARGET)
    ap.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    ap.add_argument("--runs", type=int, default=1, help="Quantas sessoes de bateria (cada uma = 1 run_id).")
    ap.add_argument("--selftest", action="store_true", help="valida o append do CSV e sai")
    args = ap.parse_args()
    if args.selftest:
        _selftest()
        return
    for i in range(args.runs):
        print(f"\n===== SESSAO {i + 1}/{args.runs} =====", flush=True)
        run_battery(args.models, args.target, args.csv)


if __name__ == "__main__":
    main()
