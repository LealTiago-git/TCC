"""Proxy reverso que coloca apps OWASP (Juice Shop, crAPI) sob o mesmo
loop de defesa do server.py: loga cada request em access_logs e aplica
blocked_ips/locked_users ANTES de encaminhar ao upstream.

Assim o agente de IA (que só lê access_logs) e a dashboard passam a
enxergar e defender tráfego de alvos OWASP, não só do server.py.

Uso:
  python -m access_defense.proxy --port 9000 --upstream http://localhost:3000 --name juice-shop
  python -m access_defense.proxy --port 9001 --upstream http://localhost:8888 --name crapi
"""

from __future__ import annotations

import argparse
import json

import requests
from flask import Flask, Response, request

from .database import DEFAULT_DB_PATH, get_connection, init_db, utc_now
from .server import is_ip_blocked, is_user_locked

app = Flask(__name__)
UPSTREAM = ""
TARGET_NAME = ""

# Headers hop-by-hop que não devem ser repassados.
_HOP = {"content-length", "transfer-encoding", "connection", "host"}


def _log(path: str, method: str, body: str, status: int, user: str, denial: str | None) -> None:
    # ponytail: INSERT duplica o de server.log_request; não vale refatorar os
    # dois num helper compartilhado enquanto forem só 2 call sites.
    record_filter = f"proxy={TARGET_NAME} {method} {path} body={body}"[:4000]
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO access_logs (
                created_at, username, role, ip_address, user_agent, operation,
                table_name, record_filter, rows_returned, success,
                denial_reason, anomaly_score, anomaly_reasons
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utc_now(), user or "anonymous", "external",
                request.remote_addr or "unknown",
                request.headers.get("User-Agent", "")[:255],
                method, TARGET_NAME, record_filter,
                0, int(200 <= status < 400), denial, 0, json.dumps([]),
            ),
        )
        conn.commit()


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def proxy(path: str):
    ip = request.remote_addr or "unknown"
    raw_body = request.get_data(as_text=True)[:4000]
    user = (request.args.get("username") or request.args.get("email") or "anonymous")
    if request.is_json:
        body = request.get_json(silent=True) or {}
        user = str(body.get("username") or body.get("email") or user)

    # Enforcement ANTES de encaminhar.
    blocked, reason = is_ip_blocked(ip)
    if blocked:
        _log(path, request.method, raw_body, 403, user, f"ip_blocked:{reason}")
        return Response(f"ip blocked: {reason}", status=403)
    locked, lreason = is_user_locked(user)
    if locked:
        _log(path, request.method, raw_body, 403, user, f"user_locked:{lreason}")
        return Response(f"user locked: {lreason}", status=403)

    # Encaminha ao upstream.
    url = f"{UPSTREAM}/{path}"
    fwd_headers = {k: v for k, v in request.headers if k.lower() not in _HOP}
    try:
        upstream_resp = requests.request(
            request.method, url, headers=fwd_headers,
            params=request.args, data=request.get_data(),
            cookies=request.cookies, allow_redirects=False, timeout=15,
        )
    except requests.RequestException as exc:
        _log(path, request.method, raw_body, 502, user, f"upstream_error:{exc}")
        return Response(f"upstream error: {exc}", status=502)

    _log(path, request.method, raw_body, upstream_resp.status_code, user, None)
    resp_headers = [(k, v) for k, v in upstream_resp.headers.items() if k.lower() not in _HOP]
    return Response(upstream_resp.content, status=upstream_resp.status_code, headers=resp_headers)


def main() -> None:
    global UPSTREAM, TARGET_NAME
    parser = argparse.ArgumentParser(description="Proxy de defesa p/ alvos OWASP.")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--upstream", required=True, help="ex: http://localhost:3000")
    parser.add_argument("--name", required=True, help="tag do alvo, ex: juice-shop")
    args = parser.parse_args()

    UPSTREAM = args.upstream.rstrip("/")
    TARGET_NAME = args.name
    init_db(DEFAULT_DB_PATH, seed=False)
    print(f"[proxy] {args.host}:{args.port} -> {UPSTREAM} (alvo={TARGET_NAME})")
    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()
