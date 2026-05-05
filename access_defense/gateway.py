"""Controlled database gateway with audit logging and alert generation."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .agents import AgentRunner, AgentVerdict
from .anomaly import AccessSignals, AnomalyResult, evaluate_access_event
from .database import DATA_TABLES, DEFAULT_DB_PATH, get_connection, utc_now
from .security import verify_password


@dataclass(frozen=True)
class AccessResponse:
    """Result returned by every controlled database operation."""

    success: bool
    log_id: int
    table_name: str
    operation: str
    rows: list[dict[str, Any]]
    anomaly: AnomalyResult
    denial_reason: str | None = None


class AccessGateway:
    """Single entry point for all controlled access to business tables.

    The gateway deliberately centralizes authentication, authorization, SQL
    execution, audit logging, anomaly detection and optional AI review. This
    avoids direct table access outside the security workflow.
    """

    def __init__(
        self,
        db_path: str | Path = DEFAULT_DB_PATH,
        *,
        agent_runner: AgentRunner | None = None,
    ):
        self.db_path = Path(db_path)
        self.agent_runner = agent_runner or AgentRunner.disabled()

    def read_table(
        self,
        *,
        username: str,
        password: str,
        table_name: str,
        ip_address: str,
        user_agent: str = "manual-client",
        limit: int = 20,
        event_time: datetime | None = None,
    ) -> AccessResponse:
        """Read a permitted table through the audit gateway."""

        return self._handle_access(
            username=username,
            password=password,
            table_name=table_name,
            operation="READ",
            ip_address=ip_address,
            user_agent=user_agent,
            limit=limit,
            event_time=event_time,
        )

    def insert_transaction(
        self,
        *,
        username: str,
        password: str,
        cliente_id: int,
        valor: float,
        status: str,
        ip_address: str,
        user_agent: str = "manual-client",
        event_time: datetime | None = None,
    ) -> AccessResponse:
        """Insert a transaction when the user's role allows writes."""

        return self._handle_access(
            username=username,
            password=password,
            table_name="transacoes",
            operation="WRITE",
            ip_address=ip_address,
            user_agent=user_agent,
            write_payload={
                "cliente_id": cliente_id,
                "valor": valor,
                "status": status,
            },
            event_time=event_time,
        )

    def delete_transaction(
        self,
        *,
        username: str,
        password: str,
        transaction_id: int,
        ip_address: str,
        user_agent: str = "manual-client",
        event_time: datetime | None = None,
    ) -> AccessResponse:
        """Delete a transaction when the user's role allows destructive actions."""

        return self._handle_access(
            username=username,
            password=password,
            table_name="transacoes",
            operation="DELETE",
            ip_address=ip_address,
            user_agent=user_agent,
            record_filter=f"id={transaction_id}",
            delete_id=transaction_id,
            event_time=event_time,
        )

    def _handle_access(
        self,
        *,
        username: str,
        password: str,
        table_name: str,
        operation: str,
        ip_address: str,
        user_agent: str,
        limit: int = 20,
        write_payload: dict[str, Any] | None = None,
        record_filter: str | None = None,
        delete_id: int | None = None,
        event_time: datetime | None = None,
    ) -> AccessResponse:
        """Execute the full access-control workflow for one database action."""

        event_time = event_time or datetime.now().astimezone()
        created_at = event_time.replace(microsecond=0).isoformat()
        returned_rows: list[dict[str, Any]] = []
        access_succeeded = False
        denial_reason: str | None = None
        audited_role = "unknown"

        with get_connection(self.db_path) as conn:
            authenticated_user: sqlite3.Row | None = None
            defensive_denial_reason = self._defensive_denial_reason(
                conn,
                ip_address=ip_address,
            )

            if defensive_denial_reason is not None:
                audited_username = username or "anonymous"
                audited_role = "blocked"
                denial_reason = defensive_denial_reason
            else:
                authenticated_user = self._authenticate(conn, username, password)

            if defensive_denial_reason is None and authenticated_user is None:
                audited_username = username or "anonymous"
                audited_role = "unknown"
                denial_reason = "credenciais invalidas ou usuario desabilitado"
            elif authenticated_user is not None:
                audited_username = authenticated_user["username"]
                audited_role = authenticated_user["role"]
                denial_reason = self._authorize(
                    conn,
                    audited_role,
                    table_name,
                    operation,
                )

            if denial_reason is None:
                try:
                    returned_rows = self._execute_allowed_operation(
                        conn,
                        table_name=table_name,
                        operation=operation,
                        limit=limit,
                        write_payload=write_payload,
                        delete_id=delete_id,
                    )
                    access_succeeded = True
                except (sqlite3.Error, ValueError) as exc:
                    denial_reason = f"erro operacional: {exc}"

            returned_row_count = len(returned_rows)
            anomaly_signals = self._collect_signals(
                conn,
                username=audited_username,
                ip_address=ip_address,
                created_at=event_time,
            )
            anomaly_result = evaluate_access_event(
                event_time=event_time,
                username=audited_username,
                role=audited_role,
                ip_address=ip_address,
                user_agent=user_agent,
                operation=operation,
                table_name=table_name,
                rows_returned=returned_row_count,
                success=access_succeeded,
                denial_reason=denial_reason,
                signals=anomaly_signals,
            )
            access_log_id = self._insert_access_log(
                conn,
                created_at=created_at,
                username=audited_username,
                role=audited_role,
                ip_address=ip_address,
                user_agent=user_agent,
                operation=operation,
                table_name=table_name,
                record_filter=record_filter,
                rows_returned=returned_row_count,
                success=access_succeeded,
                denial_reason=denial_reason,
                anomaly=anomaly_result,
            )

            if authenticated_user is not None:
                self._update_ip_history(
                    conn,
                    username=audited_username,
                    ip_address=ip_address,
                    created_at=created_at,
                )

            if anomaly_result.should_alert:
                self._insert_rule_alert(conn, access_log_id, anomaly_result)
                self._run_agent_alerts(
                    conn,
                    access_log_id,
                    anomaly_result,
                    access_payload={
                        "created_at": created_at,
                        "username": audited_username,
                        "role": audited_role,
                        "ip_address": ip_address,
                        "user_agent": user_agent,
                        "operation": operation,
                        "table_name": table_name,
                        "rows_returned": returned_row_count,
                        "success": access_succeeded,
                        "denial_reason": denial_reason,
                        "anomaly_score": anomaly_result.score,
                        "anomaly_severity": anomaly_result.severity,
                        "anomaly_reasons": anomaly_result.reasons,
                    },
                )

        return AccessResponse(
            success=access_succeeded,
            log_id=access_log_id,
            table_name=table_name,
            operation=operation,
            rows=returned_rows,
            anomaly=anomaly_result,
            denial_reason=denial_reason,
        )

    def _defensive_denial_reason(
        self,
        conn: sqlite3.Connection,
        *,
        ip_address: str,
    ) -> str | None:
        """Return a denial reason when a defensive action blocks access."""

        service_status = conn.execute(
            """
            SELECT status, reason
            FROM service_state
            WHERE id = 1
            """
        ).fetchone()
        if service_status is not None and service_status["status"] == "shutdown":
            return f"servico em shutdown defensivo: {service_status['reason']}"

        blocked_ip = conn.execute(
            """
            SELECT reason
            FROM blocked_ips
            WHERE ip_address = ?
              AND (expires_at IS NULL OR expires_at > ?)
            """,
            (ip_address, utc_now()),
        ).fetchone()
        if blocked_ip is not None:
            return f"IP bloqueado por resposta defensiva: {blocked_ip['reason']}"
        return None

    def _authenticate(
        self,
        conn: sqlite3.Connection,
        username: str,
        password: str,
    ) -> sqlite3.Row | None:
        """Validate credentials and return the enabled user record."""

        row = conn.execute(
            """
            SELECT username, role, password_hash, enabled
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()
        if row is None or not row["enabled"]:
            return None
        if not verify_password(password, row["password_hash"]):
            return None
        return row

    def _authorize(
        self,
        conn: sqlite3.Connection,
        role: str,
        table_name: str,
        operation: str,
    ) -> str | None:
        """Return a denial reason when the role cannot perform the operation."""

        if table_name not in DATA_TABLES:
            return "tabela fora da lista permitida"

        row = conn.execute(
            """
            SELECT allowed
            FROM permissions
            WHERE role = ? AND table_name = ? AND operation = ?
            """,
            (role, table_name, operation),
        ).fetchone()
        if row is None or not row["allowed"]:
            return "perfil sem permissao para a operacao"
        return None

    def _execute_allowed_operation(
        self,
        conn: sqlite3.Connection,
        *,
        table_name: str,
        operation: str,
        limit: int,
        write_payload: dict[str, Any] | None,
        delete_id: int | None,
    ) -> list[dict[str, Any]]:
        """Run only whitelisted SQL operations after authorization succeeds."""

        if operation == "READ":
            safe_limit = max(1, min(int(limit), 500))
            columns = ", ".join(DATA_TABLES[table_name])
            rows = conn.execute(
                f"SELECT {columns} FROM {table_name} ORDER BY id LIMIT ?",
                (safe_limit,),
            ).fetchall()
            return [dict(row) for row in rows]

        if operation == "WRITE":
            if table_name != "transacoes" or write_payload is None:
                raise ValueError("escrita permitida apenas para transacoes no prototipo")
            conn.execute(
                """
                INSERT INTO transacoes (cliente_id, valor, status, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    int(write_payload["cliente_id"]),
                    float(write_payload["valor"]),
                    str(write_payload["status"]),
                    utc_now(),
                ),
            )
            return []

        if operation == "DELETE":
            if table_name != "transacoes" or delete_id is None:
                raise ValueError("exclusao permitida apenas para transacoes no prototipo")
            conn.execute("DELETE FROM transacoes WHERE id = ?", (int(delete_id),))
            return []

        raise ValueError("operacao desconhecida")

    def _collect_signals(
        self,
        conn: sqlite3.Connection,
        *,
        username: str,
        ip_address: str,
        created_at: datetime,
    ) -> AccessSignals:
        """Collect recent behavior used by the anomaly rules."""

        ip_seen = conn.execute(
            """
            SELECT 1 FROM user_ip_history
            WHERE username = ? AND ip_address = ?
            """,
            (username, ip_address),
        ).fetchone()

        window_start = (created_at - timedelta(minutes=10)).replace(microsecond=0).isoformat()
        recent_denied_count = conn.execute(
            """
            SELECT COUNT(*) AS total
            FROM access_logs
            WHERE created_at >= ?
              AND success = 0
              AND (username = ? OR ip_address = ?)
            """,
            (window_start, username, ip_address),
        ).fetchone()["total"]

        recent_access_count = conn.execute(
            """
            SELECT COUNT(*) AS total
            FROM access_logs
            WHERE created_at >= ?
              AND (username = ? OR ip_address = ?)
            """,
            (window_start, username, ip_address),
        ).fetchone()["total"]

        return AccessSignals(
            ip_seen_before=ip_seen is not None,
            recent_denied_count=int(recent_denied_count),
            recent_access_count=int(recent_access_count),
        )

    def _insert_access_log(
        self,
        conn: sqlite3.Connection,
        *,
        created_at: str,
        username: str,
        role: str,
        ip_address: str,
        user_agent: str,
        operation: str,
        table_name: str,
        record_filter: str | None,
        rows_returned: int,
        success: bool,
        denial_reason: str | None,
        anomaly: AnomalyResult,
    ) -> int:
        """Persist the audit record for both allowed and denied attempts."""

        cursor = conn.execute(
            """
            INSERT INTO access_logs (
                created_at, username, role, ip_address, user_agent, operation,
                table_name, record_filter, rows_returned, success, denial_reason,
                anomaly_score, anomaly_reasons
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                created_at,
                username,
                role,
                ip_address,
                user_agent,
                operation,
                table_name,
                record_filter,
                rows_returned,
                int(success),
                denial_reason,
                anomaly.score,
                json.dumps(anomaly.reasons, ensure_ascii=False),
            ),
        )
        return int(cursor.lastrowid)

    def _update_ip_history(
        self,
        conn: sqlite3.Connection,
        *,
        username: str,
        ip_address: str,
        created_at: str,
    ) -> None:
        """Record that a user has now used this source IP address."""

        conn.execute(
            """
            INSERT INTO user_ip_history
                (username, ip_address, first_seen, last_seen, total_accesses)
            VALUES (?, ?, ?, ?, 1)
            ON CONFLICT(username, ip_address)
            DO UPDATE SET
                last_seen = excluded.last_seen,
                total_accesses = total_accesses + 1
            """,
            (username, ip_address, created_at, created_at),
        )

    def _insert_rule_alert(
        self,
        conn: sqlite3.Connection,
        log_id: int,
        anomaly: AnomalyResult,
    ) -> None:
        """Create the deterministic alert generated by the rule engine."""

        conn.execute(
            """
            INSERT INTO security_alerts
                (created_at, access_log_id, severity, source, summary, verdict)
            VALUES (?, ?, ?, 'rules', ?, ?)
            """,
            (
                utc_now(),
                log_id,
                anomaly.severity,
                f"Acesso anomalo detectado com score {anomaly.score}",
                json.dumps({"reasons": anomaly.reasons}, ensure_ascii=False),
            ),
        )

    def _run_agent_alerts(
        self,
        conn: sqlite3.Connection,
        log_id: int,
        anomaly: AnomalyResult,
        *,
        access_payload: dict[str, Any],
    ) -> None:
        """Ask the selected AI agents to review an anomalous access event."""

        if not self.agent_runner.enabled():
            return

        verdicts = self.agent_runner.review_access(access_payload)
        for verdict in verdicts:
            summary = (
                f"Agente {verdict.agent_name} avaliou o alerta"
                if verdict.error is None
                else f"Agente {verdict.agent_name} indisponivel"
            )
            conn.execute(
                """
                INSERT INTO security_alerts
                    (created_at, access_log_id, severity, source, summary, verdict)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    utc_now(),
                    log_id,
                    anomaly.severity,
                    verdict.agent_name,
                    summary,
                    verdict.verdict if verdict.error is None else verdict.error,
                ),
            )
            self._insert_agent_log(conn, log_id, verdict)

    def _insert_agent_log(
        self,
        conn: sqlite3.Connection,
        access_log_id: int,
        verdict: AgentVerdict,
    ) -> None:
        """Persist one measured AI interaction and its session average."""

        session_row = conn.execute(
            """
            SELECT COUNT(*) AS total_cases,
                   COALESCE(SUM(duration_ms), 0) AS total_duration_ms
            FROM ai_agent_logs
            WHERE session_id = ? AND agent_name = ?
            """,
            (verdict.session_id, verdict.agent_name),
        ).fetchone()
        case_number = int(session_row["total_cases"]) + 1
        total_duration_ms = int(session_row["total_duration_ms"]) + verdict.duration_ms
        average_duration_ms = total_duration_ms / case_number

        conn.execute(
            """
            INSERT INTO ai_agent_logs (
                created_at, session_id, access_log_id, agent_name, model,
                provider_url, started_at, finished_at, duration_ms,
                session_case_number, session_total_duration_ms,
                session_average_duration_ms, success, error, result
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utc_now(),
                verdict.session_id,
                access_log_id,
                verdict.agent_name,
                verdict.model_name,
                verdict.provider_url,
                verdict.started_at,
                verdict.finished_at,
                verdict.duration_ms,
                case_number,
                total_duration_ms,
                average_duration_ms,
                int(verdict.error is None),
                verdict.error,
                verdict.verdict,
            ),
        )
