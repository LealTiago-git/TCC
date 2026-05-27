"""Servidor HTTP Flask intencionalmente vulnerável.

Endpoints expõem Postgres + MongoDB a ataques reais (SQLi, NoSQLi,
brute-force, DDoS). Cada requisição é registrada em SQLite local
(access_logs) para o agente de IA consumir.

Camada de enforcement (antes da query):
  - blocked_ips: bloqueia IPs marcados pelo agente
  - locked_users: bloqueia usernames marcados pelo agente

Uso:
  python -m access_defense.server
  python -m access_defense.server --port 8000 --host 127.0.0.1
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request

from .database import DEFAULT_DB_PATH, get_connection, init_db, utc_now
from .db_backends import (
    health,
    mongo_login_vulnerable,
    mongo_search_vulnerable,
    pg_login_vulnerable,
    pg_raw,
    pg_search_vulnerable,
)


app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


# ============================================================================
# ENFORCEMENT
# ============================================================================


def is_ip_blocked(ip: str) -> tuple[bool, str | None]:
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT reason FROM blocked_ips
            WHERE ip_address = ?
              AND (expires_at IS NULL OR expires_at > ?)
            LIMIT 1
            """,
            (ip, utc_now()),
        ).fetchone()
    return (bool(row), row["reason"] if row else None)


def is_user_locked(username: str) -> tuple[bool, str | None]:
    with get_connection() as conn:
        # locked_users criada por init_db se schema for atualizado;
        # fallback: tabela não existe ainda → trata como não bloqueado.
        try:
            row = conn.execute(
                "SELECT reason FROM locked_users WHERE username = ? LIMIT 1",
                (username,),
            ).fetchone()
            return (bool(row), row["reason"] if row else None)
        except sqlite3.OperationalError:
            return (False, None)


# ============================================================================
# LOGGING DE REQUEST
# ============================================================================


def log_request(
    *,
    username: str | None,
    operation: str,
    table_name: str,
    payload: Any,
    rows_returned: int,
    success: bool,
    denial_reason: str | None,
    backend: str,
    duration_ms: int,
) -> int:
    """Persiste cada request em access_logs. Retorna access_log_id."""
    payload_str = json.dumps(payload, default=str, ensure_ascii=False)[:4000]
    record_filter = f"backend={backend} duration_ms={duration_ms} payload={payload_str}"
    with get_connection() as conn:
        cur = conn.execute(
            """
            INSERT INTO access_logs (
                created_at, username, role, ip_address, user_agent,
                operation, table_name, record_filter, rows_returned,
                success, denial_reason, anomaly_score, anomaly_reasons
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utc_now(),
                username or "anonymous",
                "external",
                request.remote_addr or "unknown",
                request.headers.get("User-Agent", "")[:255],
                operation,
                table_name,
                record_filter,
                rows_returned,
                int(success),
                denial_reason,
                0,
                json.dumps([]),
            ),
        )
        conn.commit()
        return cur.lastrowid


# ============================================================================
# DECORADOR: bloqueio antes da query
# ============================================================================


def enforce_block(username_field: str | None = None):
    """Verifica blocked_ips e locked_users antes de processar o request."""

    def deco(fn):
        def wrapper(*args, **kwargs):
            ip = request.remote_addr or "unknown"
            blocked, ip_reason = is_ip_blocked(ip)
            if blocked:
                log_request(
                    username=None,
                    operation="BLOCKED",
                    table_name=fn.__name__,
                    payload={"ip": ip},
                    rows_returned=0,
                    success=False,
                    denial_reason=f"ip_blocked:{ip_reason}",
                    backend="enforcement",
                    duration_ms=0,
                )
                return jsonify({"error": "ip blocked", "reason": ip_reason}), 403

            if username_field:
                body = request.get_json(silent=True) or {}
                uname = body.get(username_field) or request.args.get(username_field)
                if isinstance(uname, str):
                    locked, user_reason = is_user_locked(uname)
                    if locked:
                        log_request(
                            username=uname,
                            operation="BLOCKED",
                            table_name=fn.__name__,
                            payload={"username": uname},
                            rows_returned=0,
                            success=False,
                            denial_reason=f"user_locked:{user_reason}",
                            backend="enforcement",
                            duration_ms=0,
                        )
                        return (
                            jsonify({"error": "user locked", "reason": user_reason}),
                            403,
                        )
            return fn(*args, **kwargs)

        wrapper.__name__ = fn.__name__
        return wrapper

    return deco


# ============================================================================
# ENDPOINTS POSTGRES (vulneráveis)
# ============================================================================


@app.route("/pg/login", methods=["POST"])
@enforce_block(username_field="username")
def pg_login():
    body = request.get_json(force=True, silent=True) or {}
    username = str(body.get("username", ""))
    password = str(body.get("password", ""))
    result = pg_login_vulnerable(username, password)
    log_id = log_request(
        username=username,
        operation="LOGIN",
        table_name="users",
        payload={"username": username, "password": "***", "raw_sql": result.raw_query},
        rows_returned=len(result.rows),
        success=result.success and len(result.rows) > 0,
        denial_reason=None if result.success else result.error,
        backend="postgres",
        duration_ms=result.duration_ms,
    )
    return jsonify(
        {
            "log_id": log_id,
            "backend": "postgres",
            "authenticated": result.success and len(result.rows) > 0,
            "rows": result.rows,
            "duration_ms": result.duration_ms,
            "error": result.error,
        }
    )


@app.route("/pg/search", methods=["GET"])
@enforce_block()
def pg_search():
    table = request.args.get("table", "clientes")
    term = request.args.get("q", "")
    result = pg_search_vulnerable(table, term)
    log_id = log_request(
        username=request.args.get("user", "anonymous"),
        operation="SEARCH",
        table_name=table,
        payload={"q": term, "raw_sql": result.raw_query},
        rows_returned=len(result.rows),
        success=result.success,
        denial_reason=None if result.success else result.error,
        backend="postgres",
        duration_ms=result.duration_ms,
    )
    return jsonify(
        {
            "log_id": log_id,
            "backend": "postgres",
            "rows": result.rows,
            "duration_ms": result.duration_ms,
            "error": result.error,
        }
    )


@app.route("/pg/query", methods=["POST"])
@enforce_block()
def pg_query():
    """Pior caso: SQL bruto. Usado para demonstrar exfiltração total."""
    body = request.get_json(force=True, silent=True) or {}
    sql = body.get("sql", "")
    result = pg_raw(sql)
    log_id = log_request(
        username=body.get("user", "anonymous"),
        operation="RAW_SQL",
        table_name="any",
        payload={"raw_sql": sql},
        rows_returned=len(result.rows),
        success=result.success,
        denial_reason=None if result.success else result.error,
        backend="postgres",
        duration_ms=result.duration_ms,
    )
    return jsonify(
        {
            "log_id": log_id,
            "backend": "postgres",
            "rows": result.rows[:500],
            "duration_ms": result.duration_ms,
            "error": result.error,
        }
    )


# ============================================================================
# ENDPOINTS MONGO (vulneráveis a NoSQL injection)
# ============================================================================


@app.route("/mongo/login", methods=["POST"])
@enforce_block(username_field="username")
def mongo_login():
    body = request.get_json(force=True, silent=True) or {}
    username = body.get("username", "")
    password = body.get("password", "")
    result = mongo_login_vulnerable(username, password)
    log_id = log_request(
        username=str(username),
        operation="LOGIN",
        table_name="users",
        payload={"username": username, "password": "***", "filter": result.raw_query},
        rows_returned=len(result.rows),
        success=result.success and len(result.rows) > 0,
        denial_reason=None if result.success else result.error,
        backend="mongo",
        duration_ms=result.duration_ms,
    )
    return jsonify(
        {
            "log_id": log_id,
            "backend": "mongo",
            "authenticated": result.success and len(result.rows) > 0,
            "rows": result.rows,
            "duration_ms": result.duration_ms,
            "error": result.error,
        }
    )


@app.route("/mongo/find", methods=["POST"])
@enforce_block()
def mongo_find():
    body = request.get_json(force=True, silent=True) or {}
    collection = body.get("collection", "clientes")
    filter_doc = body.get("filter", {})
    result = mongo_search_vulnerable(collection, filter_doc)
    log_id = log_request(
        username=body.get("user", "anonymous"),
        operation="FIND",
        table_name=collection,
        payload={"filter": filter_doc, "raw_query": result.raw_query},
        rows_returned=len(result.rows),
        success=result.success,
        denial_reason=None if result.success else result.error,
        backend="mongo",
        duration_ms=result.duration_ms,
    )
    return jsonify(
        {
            "log_id": log_id,
            "backend": "mongo",
            "rows": result.rows[:500],
            "duration_ms": result.duration_ms,
            "error": result.error,
        }
    )


# ============================================================================
# HEALTH / STATUS
# ============================================================================


@app.route("/health", methods=["GET"])
def health_endpoint():
    return jsonify(health())


@app.route("/status", methods=["GET"])
def status_endpoint():
    with get_connection() as conn:
        n_logs = conn.execute("SELECT COUNT(*) AS c FROM access_logs").fetchone()["c"]
        n_blocked = conn.execute("SELECT COUNT(*) AS c FROM blocked_ips").fetchone()["c"]
        try:
            n_locked = conn.execute(
                "SELECT COUNT(*) AS c FROM locked_users"
            ).fetchone()["c"]
        except sqlite3.OperationalError:
            n_locked = 0
    return jsonify(
        {
            "access_logs_count": n_logs,
            "blocked_ips_count": n_blocked,
            "locked_users_count": n_locked,
        }
    )


# ============================================================================
# BOOT
# ============================================================================


def main():
    parser = argparse.ArgumentParser(description="Servidor HTTP vulnerável do TCC.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    init_db(DEFAULT_DB_PATH, seed=True)
    print(f"[server] Postgres+Mongo health: {health()}")
    print(f"[server] Escutando em http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()
