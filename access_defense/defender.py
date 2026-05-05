"""Defensive alert monitor and incident-response executor.

The monitor is the "AI on alert" component of the prototype. It watches
deterministic security alerts, asks the selected AI for a defensive explanation
when configured, executes local containment actions, and persists a full
history of what was said and what was done.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from .agents import AgentRunner
from .database import DEFAULT_DB_PATH, get_connection, utc_now


@dataclass(frozen=True)
class IncidentResponseResult:
    """One completed defensive response to one security alert."""

    response_log_id: int
    alert_id: int
    access_log_id: int
    agent_name: str
    attack_type: str
    severity: str
    ai_message: str
    executed_actions: list[str]
    service_status_after: str
    shutdown_requested: bool


class DefensiveMonitor:
    """Polls open alerts and executes defensive response playbooks."""

    def __init__(
        self,
        db_path: str | Path = DEFAULT_DB_PATH,
        *,
        agent_runner: AgentRunner | None = None,
        shutdown_on_critical: bool = False,
    ):
        self.db_path = Path(db_path)
        self.agent_runner = agent_runner or AgentRunner.disabled()
        self.shutdown_on_critical = shutdown_on_critical
        self.monitor_session_id = uuid4().hex

    def process_open_alerts(self, *, limit: int = 10) -> list[IncidentResponseResult]:
        """Process currently open rule alerts and return response summaries."""

        alert_rows = self._fetch_open_rule_alerts(limit=limit)
        response_results: list[IncidentResponseResult] = []
        for alert_row in alert_rows:
            response_results.append(self._process_alert(alert_row))
            if response_results[-1].shutdown_requested:
                break
        return response_results

    def service_is_shutdown(self) -> bool:
        """Return whether the prototype service is in defensive shutdown."""

        with get_connection(self.db_path) as connection:
            row = connection.execute(
                """
                SELECT status
                FROM service_state
                WHERE id = 1
                """
            ).fetchone()
        return row is not None and row["status"] == "shutdown"

    def _fetch_open_rule_alerts(self, *, limit: int) -> list[dict[str, Any]]:
        """Load alerts that still need a defensive response."""

        with get_connection(self.db_path) as connection:
            rows = connection.execute(
                """
                SELECT
                    alerts.id AS alert_id,
                    alerts.access_log_id,
                    alerts.severity,
                    alerts.summary,
                    alerts.verdict,
                    logs.created_at,
                    logs.username,
                    logs.role,
                    logs.ip_address,
                    logs.user_agent,
                    logs.operation,
                    logs.table_name,
                    logs.rows_returned,
                    logs.success,
                    logs.denial_reason,
                    logs.anomaly_score,
                    logs.anomaly_reasons
                FROM security_alerts AS alerts
                JOIN access_logs AS logs ON logs.id = alerts.access_log_id
                WHERE alerts.source = 'rules'
                  AND alerts.status = 'open'
                ORDER BY alerts.id
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def _process_alert(self, alert_row: dict[str, Any]) -> IncidentResponseResult:
        """Create a response plan, log it, execute actions and close the alert."""

        attack_type = _classify_attack_type(alert_row)
        planned_steps = _build_defensive_steps(attack_type, alert_row)
        shutdown_requested = _shutdown_is_required(
            attack_type=attack_type,
            severity=alert_row["severity"],
            shutdown_on_critical=self.shutdown_on_critical,
        )
        ai_message, agent_name = self._build_ai_message(
            alert_row=alert_row,
            attack_type=attack_type,
            planned_steps=planned_steps,
            shutdown_requested=shutdown_requested,
        )

        response_log_id = self._insert_pre_action_log(
            alert_row=alert_row,
            agent_name=agent_name,
            attack_type=attack_type,
            ai_message=ai_message,
            planned_steps=planned_steps,
            shutdown_requested=shutdown_requested,
        )
        executed_actions, service_status_after = self._execute_defensive_actions(
            alert_row=alert_row,
            attack_type=attack_type,
            shutdown_requested=shutdown_requested,
        )
        self._finalize_response_log(
            response_log_id=response_log_id,
            executed_actions=executed_actions,
            service_status_after=service_status_after,
        )

        return IncidentResponseResult(
            response_log_id=response_log_id,
            alert_id=int(alert_row["alert_id"]),
            access_log_id=int(alert_row["access_log_id"]),
            agent_name=agent_name,
            attack_type=attack_type,
            severity=str(alert_row["severity"]),
            ai_message=ai_message,
            executed_actions=executed_actions,
            service_status_after=service_status_after,
            shutdown_requested=shutdown_requested,
        )

    def _build_ai_message(
        self,
        *,
        alert_row: dict[str, Any],
        attack_type: str,
        planned_steps: list[str],
        shutdown_requested: bool,
    ) -> tuple[str, str]:
        """Return the selected AI's response text or a local fallback plan."""

        fallback_message = _format_step_by_step_message(
            attack_type=attack_type,
            planned_steps=planned_steps,
            shutdown_requested=shutdown_requested,
        )
        if not self.agent_runner.enabled():
            return fallback_message, "rules-fallback"

        incident_payload = _build_incident_payload(
            alert_row=alert_row,
            attack_type=attack_type,
            planned_steps=planned_steps,
            shutdown_requested=shutdown_requested,
        )
        verdicts = self.agent_runner.review_incident_response(incident_payload)
        if not verdicts:
            return fallback_message, "rules-fallback"

        first_verdict = verdicts[0]
        if first_verdict.error:
            unavailable_message = (
                f"Agente {first_verdict.agent_name} indisponivel: "
                f"{first_verdict.error}. Plano defensivo local aplicado:\n"
                f"{fallback_message}"
            )
            return unavailable_message, first_verdict.agent_name
        return first_verdict.verdict, first_verdict.agent_name

    def _insert_pre_action_log(
        self,
        *,
        alert_row: dict[str, Any],
        agent_name: str,
        attack_type: str,
        ai_message: str,
        planned_steps: list[str],
        shutdown_requested: bool,
    ) -> int:
        """Persist the response log before containment or shutdown actions."""

        with get_connection(self.db_path) as connection:
            cursor = connection.execute(
                """
                INSERT INTO incident_response_logs (
                    created_at, monitor_session_id, alert_id, access_log_id,
                    agent_name, attack_type, severity, ai_message, planned_steps,
                    executed_actions, service_status_after, shutdown_requested
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    utc_now(),
                    self.monitor_session_id,
                    alert_row["alert_id"],
                    alert_row["access_log_id"],
                    agent_name,
                    attack_type,
                    alert_row["severity"],
                    ai_message,
                    json.dumps(planned_steps, ensure_ascii=False),
                    json.dumps(["log pre-acao criado"], ensure_ascii=False),
                    "pending",
                    int(shutdown_requested),
                ),
            )
            return int(cursor.lastrowid)

    def _execute_defensive_actions(
        self,
        *,
        alert_row: dict[str, Any],
        attack_type: str,
        shutdown_requested: bool,
    ) -> tuple[list[str], str]:
        """Execute local containment actions and return an action summary."""

        source_ip = str(alert_row["ip_address"])
        reason = f"{attack_type} detectado no alerta {alert_row['alert_id']}"
        service_status_after = "active"
        executed_actions = [
            f"registrado plano defensivo antes das acoes para alerta {alert_row['alert_id']}",
            f"bloqueado IP {source_ip}",
            f"alerta {alert_row['alert_id']} marcado como contained",
        ]

        with get_connection(self.db_path) as connection:
            connection.execute(
                """
                INSERT INTO blocked_ips (ip_address, reason, source_alert_id, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(ip_address)
                DO UPDATE SET
                    reason = excluded.reason,
                    source_alert_id = excluded.source_alert_id,
                    created_at = excluded.created_at,
                    expires_at = NULL
                """,
                (source_ip, reason, alert_row["alert_id"], utc_now()),
            )
            connection.execute(
                """
                UPDATE security_alerts
                SET status = 'contained'
                WHERE id = ?
                """,
                (alert_row["alert_id"],),
            )

            if attack_type == "ddos":
                service_status_after = "rate_limited"
                connection.execute(
                    """
                    UPDATE service_state
                    SET status = ?, reason = ?, source_alert_id = ?, updated_at = ?
                    WHERE id = 1
                    """,
                    (
                        service_status_after,
                        "rate limit defensivo aplicado pelo monitor",
                        alert_row["alert_id"],
                        utc_now(),
                    ),
                )
                executed_actions.append("estado do servico alterado para rate_limited")

            if shutdown_requested:
                service_status_after = "shutdown"
                executed_actions.append(
                    "shutdown defensivo registrado apos persistir o historico"
                )
                connection.execute(
                    """
                    UPDATE service_state
                    SET status = 'shutdown',
                        reason = ?,
                        source_alert_id = ?,
                        updated_at = ?
                    WHERE id = 1
                    """,
                    (
                        f"shutdown defensivo por {attack_type}",
                        alert_row["alert_id"],
                        utc_now(),
                    ),
                )

        return executed_actions, service_status_after

    def _finalize_response_log(
        self,
        *,
        response_log_id: int,
        executed_actions: list[str],
        service_status_after: str,
    ) -> None:
        """Update the pre-action log with the actions actually completed."""

        with get_connection(self.db_path) as connection:
            connection.execute(
                """
                UPDATE incident_response_logs
                SET executed_actions = ?,
                    service_status_after = ?
                WHERE id = ?
                """,
                (
                    json.dumps(executed_actions, ensure_ascii=False),
                    service_status_after,
                    response_log_id,
                ),
            )


def reset_defense_state(db_path: str | Path = DEFAULT_DB_PATH) -> None:
    """Clear local containment state so new demonstrations can run normally."""

    with get_connection(db_path) as connection:
        connection.execute("DELETE FROM blocked_ips")
        connection.execute(
            """
            UPDATE service_state
            SET status = 'active',
                reason = 'reset manual do laboratorio',
                source_alert_id = NULL,
                updated_at = ?
            WHERE id = 1
            """,
            (utc_now(),),
        )


def _classify_attack_type(alert_row: dict[str, Any]) -> str:
    """Infer the simulated attack type from the audit event fields."""

    user_agent = str(alert_row["user_agent"]).lower()
    table_name = str(alert_row["table_name"]).lower()
    denial_reason = str(alert_row["denial_reason"] or "").lower()
    anomaly_reasons = str(alert_row["anomaly_reasons"]).lower()

    if "attack-sim/injection" in user_agent or "sql injection" in anomaly_reasons:
        return "injection"
    if "attack-sim/ddos" in user_agent or "ddos" in anomaly_reasons:
        return "ddos"
    if "attack-sim/brute-force" in user_agent or "credenciais invalidas" in denial_reason:
        return "brute-force"
    if "attack-sim/buffer-overflow" in user_agent or "buffer overflow" in anomaly_reasons:
        return "buffer-overflow"
    if (
        "attack-sim/privilege-escalation" in user_agent
        or "escalada de privilegio" in anomaly_reasons
        or table_name == "salarios"
    ):
        return "privilege-escalation"
    return "acesso-anomalo"


def _build_defensive_steps(
    attack_type: str,
    alert_row: dict[str, Any],
) -> list[str]:
    """Build the deterministic step-by-step response plan."""

    source_ip = alert_row["ip_address"]
    base_steps = [
        f"Confirmar o alerta {alert_row['alert_id']} e associar ao log {alert_row['access_log_id']}.",
        f"Isolar a origem {source_ip} bloqueando novos acessos desse IP no gateway.",
        "Registrar o plano antes de executar qualquer acao de contencao.",
    ]
    specific_steps = {
        "injection": [
            "Validar que o gateway rejeitou tabela fora da lista permitida.",
            "Manter consultas parametrizadas e whitelist de tabelas.",
        ],
        "ddos": [
            "Ativar rate limit defensivo no estado do servico.",
            "Continuar monitorando volume de acessos apos o bloqueio do IP.",
        ],
        "brute-force": [
            "Conter a origem das tentativas de senha invalida.",
            "Preservar evidencias sem alterar a senha do usuario legitimo.",
        ],
        "buffer-overflow": [
            "Bloquear a origem do payload excessivo.",
            "Registrar evidencia do tamanho anormal de entrada.",
        ],
        "privilege-escalation": [
            "Conter a origem da tentativa de acesso privilegiado.",
            "Validar que o perfil nao recebeu permissao indevida.",
        ],
    }
    closing_steps = [
        "Marcar o alerta como contained.",
        "Salvar historico completo do que foi dito e executado.",
    ]
    return base_steps + specific_steps.get(attack_type, []) + closing_steps


def _shutdown_is_required(
    *,
    attack_type: str,
    severity: str,
    shutdown_on_critical: bool,
) -> bool:
    """Decide whether this response should simulate a defensive shutdown."""

    if not shutdown_on_critical:
        return False
    return severity == "critical" or attack_type in {"ddos", "buffer-overflow"}


def _format_step_by_step_message(
    *,
    attack_type: str,
    planned_steps: list[str],
    shutdown_requested: bool,
) -> str:
    """Create the monitor's local step-by-step defensive narration."""

    lines = [f"Resposta defensiva para {attack_type}:"]
    for step_number, step in enumerate(planned_steps, start=1):
        lines.append(f"{step_number}. {step}")
    if shutdown_requested:
        lines.append(
            "Shutdown defensivo sera executado somente depois que este historico for salvo."
        )
    return "\n".join(lines)


def _build_incident_payload(
    *,
    alert_row: dict[str, Any],
    attack_type: str,
    planned_steps: list[str],
    shutdown_requested: bool,
) -> dict[str, Any]:
    """Build the payload sent to the selected incident-response AI."""

    return {
        "attack_type": attack_type,
        "alert": {
            "id": alert_row["alert_id"],
            "severity": alert_row["severity"],
            "summary": alert_row["summary"],
        },
        "access_log": {
            "id": alert_row["access_log_id"],
            "username": alert_row["username"],
            "role": alert_row["role"],
            "ip_address": alert_row["ip_address"],
            "user_agent": alert_row["user_agent"],
            "operation": alert_row["operation"],
            "table_name": alert_row["table_name"],
            "success": bool(alert_row["success"]),
            "denial_reason": alert_row["denial_reason"],
            "anomaly_score": alert_row["anomaly_score"],
            "anomaly_reasons": alert_row["anomaly_reasons"],
        },
        "local_plan_to_execute": planned_steps,
        "shutdown_requested": shutdown_requested,
    }
