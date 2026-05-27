"""Benchmark de desempenho Postgres vs MongoDB.

Roda workloads equivalentes em cada backend, mede latência por iteração,
calcula avg/min/max/p95 e persiste em benchmark_runs.

Workloads:
  - login         — find_one por username+password
  - search_eq     — busca por igualdade (nome='Ana Souza')
  - search_like   — busca por prefixo/regex (nome começa com 'A')
  - full_scan     — varre tabela inteira

Uso:
  python -m access_defense.benchmark --iterations 100
  python -m access_defense.benchmark --workload search_like --iterations 500
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
from dataclasses import dataclass
from typing import Callable
from uuid import uuid4

from .database import DEFAULT_DB_PATH, get_connection, init_db, utc_now
from .db_backends import (
    mongo_client,
    MONGO_DB_NAME,
    pg_connect,
)


# ============================================================================
# RESULTADO
# ============================================================================


@dataclass
class BenchResult:
    backend: str
    workload: str
    iterations: int
    avg_ms: float
    min_ms: float
    max_ms: float
    p95_ms: float
    error_count: int
    notes: str = ""


# ============================================================================
# WORKLOADS POSTGRES
# ============================================================================


def pg_login(cur) -> None:
    cur.execute(
        "SELECT id, username, role FROM users WHERE username=%s AND password=%s",
        ("admin", "admin123"),
    )
    cur.fetchall()


def pg_search_eq(cur) -> None:
    cur.execute("SELECT * FROM clientes WHERE nome = %s", ("Ana Souza",))
    cur.fetchall()


def pg_search_like(cur) -> None:
    cur.execute("SELECT * FROM clientes WHERE nome LIKE %s", ("A%",))
    cur.fetchall()


def pg_full_scan(cur) -> None:
    cur.execute("SELECT * FROM clientes")
    cur.fetchall()


PG_WORKLOADS: dict[str, Callable] = {
    "login": pg_login,
    "search_eq": pg_search_eq,
    "search_like": pg_search_like,
    "full_scan": pg_full_scan,
}


# ============================================================================
# WORKLOADS MONGO
# ============================================================================


def mongo_login(db) -> None:
    db.users.find_one({"username": "admin", "password": "admin123"})


def mongo_search_eq(db) -> None:
    list(db.clientes.find({"nome": "Ana Souza"}))


def mongo_search_like(db) -> None:
    list(db.clientes.find({"nome": {"$regex": "^A"}}))


def mongo_full_scan(db) -> None:
    list(db.clientes.find({}))


MONGO_WORKLOADS: dict[str, Callable] = {
    "login": mongo_login,
    "search_eq": mongo_search_eq,
    "search_like": mongo_search_like,
    "full_scan": mongo_full_scan,
}


# ============================================================================
# EXECUÇÃO
# ============================================================================


def bench_postgres(workload: str, iterations: int) -> BenchResult:
    fn = PG_WORKLOADS[workload]
    durations: list[float] = []
    errors = 0
    try:
        conn = pg_connect()
        cur = conn.cursor()
    except Exception as exc:
        return BenchResult(
            backend="postgres",
            workload=workload,
            iterations=0,
            avg_ms=0, min_ms=0, max_ms=0, p95_ms=0,
            error_count=iterations,
            notes=f"connect_error: {exc}",
        )
    try:
        for _ in range(iterations):
            t0 = time.perf_counter()
            try:
                fn(cur)
            except Exception:
                errors += 1
                continue
            durations.append((time.perf_counter() - t0) * 1000)
    finally:
        cur.close()
        conn.close()
    return _summarize("postgres", workload, durations, errors)


def bench_mongo(workload: str, iterations: int) -> BenchResult:
    fn = MONGO_WORKLOADS[workload]
    durations: list[float] = []
    errors = 0
    try:
        client = mongo_client()
        db = client[MONGO_DB_NAME]
        client.admin.command("ping")
    except Exception as exc:
        return BenchResult(
            backend="mongo",
            workload=workload,
            iterations=0,
            avg_ms=0, min_ms=0, max_ms=0, p95_ms=0,
            error_count=iterations,
            notes=f"connect_error: {exc}",
        )
    try:
        for _ in range(iterations):
            t0 = time.perf_counter()
            try:
                fn(db)
            except Exception:
                errors += 1
                continue
            durations.append((time.perf_counter() - t0) * 1000)
    finally:
        client.close()
    return _summarize("mongo", workload, durations, errors)


def _summarize(backend: str, workload: str, durations: list[float], errors: int) -> BenchResult:
    if not durations:
        return BenchResult(
            backend=backend, workload=workload, iterations=0,
            avg_ms=0, min_ms=0, max_ms=0, p95_ms=0,
            error_count=errors,
        )
    sorted_d = sorted(durations)
    p95_idx = max(0, int(len(sorted_d) * 0.95) - 1)
    return BenchResult(
        backend=backend,
        workload=workload,
        iterations=len(durations),
        avg_ms=round(statistics.mean(durations), 3),
        min_ms=round(min(durations), 3),
        max_ms=round(max(durations), 3),
        p95_ms=round(sorted_d[p95_idx], 3),
        error_count=errors,
    )


# ============================================================================
# PERSIST
# ============================================================================


def persist(run_id: str, result: BenchResult) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO benchmark_runs (
                created_at, run_id, backend, workload, iterations,
                avg_ms, min_ms, max_ms, p95_ms, error_count, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utc_now(), run_id, result.backend, result.workload,
                result.iterations, result.avg_ms, result.min_ms,
                result.max_ms, result.p95_ms, result.error_count,
                result.notes,
            ),
        )
        conn.commit()


# ============================================================================
# CLI
# ============================================================================


def main():
    parser = argparse.ArgumentParser(description="Benchmark Postgres vs Mongo")
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument(
        "--workload",
        choices=list(PG_WORKLOADS.keys()) + ["all"],
        default="all",
    )
    parser.add_argument(
        "--backend",
        choices=["postgres", "mongo", "both"],
        default="both",
    )
    args = parser.parse_args()

    init_db(DEFAULT_DB_PATH, seed=False)
    run_id = uuid4().hex[:12]
    workloads = list(PG_WORKLOADS.keys()) if args.workload == "all" else [args.workload]
    backends = ["postgres", "mongo"] if args.backend == "both" else [args.backend]

    results = []
    for workload in workloads:
        for backend in backends:
            print(f"[bench] {backend} {workload} x{args.iterations}...")
            if backend == "postgres":
                r = bench_postgres(workload, args.iterations)
            else:
                r = bench_mongo(workload, args.iterations)
            persist(run_id, r)
            results.append(r.__dict__)
            print(f"  avg={r.avg_ms}ms p95={r.p95_ms}ms errors={r.error_count}")

    print()
    print(json.dumps({"run_id": run_id, "results": results}, indent=2))


if __name__ == "__main__":
    main()
