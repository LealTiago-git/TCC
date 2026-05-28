"""Backends de banco de dados vulneráveis para alvo de ataques reais.

Postgres: usa f-string em SQL (SQLi real).
Mongo: aceita filtro JSON cru ($where, $ne, $gt) — NoSQL injection.

ATENÇÃO: código intencionalmente inseguro. Apenas para experimentos do TCC
em localhost atrás de containers Docker isolados.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any

import psycopg2
import psycopg2.extras
import pymongo


# ============================================================================
# CONFIG
# ============================================================================

POSTGRES_DSN = os.getenv(
    "POSTGRES_DSN",
    "host=localhost port=5432 dbname=tcc_target user=app password=app_pwd",
)

MONGO_URI = os.getenv(
    "MONGO_URI",
    "mongodb://app:app_pwd@localhost:27017/?authSource=admin",
)
MONGO_DB_NAME = os.getenv("MONGO_DB", "tcc_target")


# ============================================================================
# RESULTADO COMUM
# ============================================================================


@dataclass
class QueryResult:
    """Resultado uniforme de qualquer backend, com métricas para benchmark."""

    backend: str
    success: bool
    rows: list[dict[str, Any]]
    duration_ms: int
    error: str | None = None
    raw_query: str = ""


# ============================================================================
# POSTGRES (vulnerável — string-concat)
# ============================================================================


def pg_connect() -> psycopg2.extensions.connection:
    return psycopg2.connect(POSTGRES_DSN)


def _run_pg(sql: str, *, swallow_no_rows: bool = False) -> QueryResult:
    """Execute raw SQL on Postgres and wrap the result with timing + error capture."""
    start = time.perf_counter()
    try:
        with pg_connect() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql)
                try:
                    rows = cur.fetchall()
                except psycopg2.ProgrammingError:
                    if not swallow_no_rows:
                        raise
                    rows = []
        return QueryResult(
            backend="postgres", success=True,
            rows=[dict(r) for r in rows],
            duration_ms=_ms(start), raw_query=sql,
        )
    except Exception as exc:
        return QueryResult(
            backend="postgres", success=False, rows=[],
            duration_ms=_ms(start), error=str(exc), raw_query=sql,
        )


def pg_login_vulnerable(username: str, password: str) -> QueryResult:
    """SELECT com f-string. Vulnerável a SQLi clássico (admin' --, ' OR '1'='1)."""
    sql = (
        f"SELECT id, username, role FROM users "
        f"WHERE username='{username}' AND password='{password}'"
    )
    return _run_pg(sql)


def pg_search_vulnerable(table: str, term: str) -> QueryResult:
    """SELECT genérico em qualquer tabela com termo bruto no LIKE. SQLi via UNION."""
    return _run_pg(f"SELECT * FROM {table} WHERE nome LIKE '%{term}%'")


def pg_raw(sql: str) -> QueryResult:
    """Executa SQL bruto. Pior caso possível — usado para mostrar exfiltração."""
    return _run_pg(sql, swallow_no_rows=True)


# ============================================================================
# MONGO (vulnerável — aceita operadores no filtro)
# ============================================================================


def mongo_client() -> pymongo.MongoClient:
    return pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)


def _run_mongo(filter_doc: Any, fetch_fn) -> QueryResult:
    """Execute a Mongo query through fetch_fn(db) and wrap timing + errors."""
    raw = str(filter_doc)
    start = time.perf_counter()
    try:
        client = mongo_client()
        try:
            rows = fetch_fn(client[MONGO_DB_NAME])
        finally:
            client.close()
        return QueryResult(
            backend="mongo", success=True, rows=rows,
            duration_ms=_ms(start), raw_query=raw,
        )
    except Exception as exc:
        return QueryResult(
            backend="mongo", success=False, rows=[],
            duration_ms=_ms(start), error=str(exc), raw_query=raw,
        )


def mongo_login_vulnerable(username: Any, password: Any) -> QueryResult:
    """find_one direto com filtro do payload. Vulnerável a {"$ne": null} bypass."""
    filter_doc = {"username": username, "password": password}

    def fetch(db):
        result = db.users.find_one(filter_doc, {"_id": 0})
        return [result] if result else []

    return _run_mongo(filter_doc, fetch)


def mongo_search_vulnerable(collection: str, filter_doc: dict[str, Any]) -> QueryResult:
    """find genérico com filtro vindo do cliente. Aceita $where, $regex, $gt, etc."""

    def fetch(db):
        return list(db[collection].find(filter_doc, {"_id": 0}).limit(500))

    return _run_mongo(filter_doc, fetch)


# ============================================================================
# HEALTH CHECK
# ============================================================================


def health() -> dict[str, Any]:
    out = {"postgres": False, "mongo": False, "errors": {}}
    try:
        with pg_connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
        out["postgres"] = True
    except Exception as exc:
        out["errors"]["postgres"] = str(exc)
    try:
        client = mongo_client()
        client.admin.command("ping")
        out["mongo"] = True
    except Exception as exc:
        out["errors"]["mongo"] = str(exc)
    return out


def _ms(started: float) -> int:
    return max(0, round((time.perf_counter() - started) * 1000))
