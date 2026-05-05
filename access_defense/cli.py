"""Command-line interface for the TCC access-defense prototype.

The CLI intentionally keeps the common research workflow simple:

1. Create or update the SQLite schema with `init-db`.
2. Run controlled scenarios with `simulate`.
3. Review access logs, alerts and AI timing metrics with table commands.

AI execution is explicit through `--ai off|gemma3|qwen2.5|both`. The legacy
`--agents` flag still works and maps to `--ai both` for compatibility.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import textwrap
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .agents import (
    AGENT_BOTH,
    AGENT_GEMMA,
    AGENT_QWEN,
    AI_DISABLED,
    AI_MODE_CHOICES,
    AgentRunner,
)
from .database import DEFAULT_DB_PATH, get_connection, init_db
from .attacks import ATTACK_MODE_CHOICES, AttackStepResult, run_controlled_attack
from .defender import (
    DefensiveMonitor,
    IncidentResponseResult,
    reset_defense_state,
)
from .gateway import AccessGateway, AccessResponse


MAX_TABLE_CELL_WIDTH = 72


@dataclass(frozen=True)
class SimulationScenario:
    """One named scenario used by the demonstration command."""

    name: str
    execute: Callable[[], AccessResponse]


@dataclass(frozen=True)
class SimulationScenarioResult:
    """Compact result shown after a scenario is executed."""

    scenario_name: str
    access_log_id: int
    access_was_successful: bool
    anomaly_score: int
    anomaly_severity: str
    anomaly_reasons: list[str]


def main() -> None:
    """Parse arguments and dispatch the selected command."""

    parser = _build_argument_parser()
    arguments = parser.parse_args()
    database_path = Path(arguments.db)

    if arguments.command == "init-db":
        init_db(database_path)
        print(f"Banco inicializado em: {database_path.resolve()}")
        return

    if arguments.command == "simulate":
        init_db(database_path)
        selected_ai_mode = _resolve_ai_mode(arguments.ai_mode, arguments.legacy_agents)
        agent_runner = _build_agent_runner(selected_ai_mode)
        gateway = AccessGateway(database_path, agent_runner=agent_runner)

        _print_ai_mode_notice(selected_ai_mode, agent_runner)
        scenario_results = _run_simulation(gateway)
        _print_simulation_results(scenario_results)
        _print_security_alerts(_fetch_alerts(database_path, limit=20))
        if agent_runner.enabled():
            _print_ai_results(
                database_path,
                limit=20,
                session_id=agent_runner.session_id,
            )
        return

    if arguments.command == "attack":
        init_db(database_path)
        attack_results = run_controlled_attack(
            database_path,
            mode=arguments.mode,
            request_count=arguments.requests,
        )
        _print_attack_results(arguments.mode, attack_results)
        return

    if arguments.command == "monitor":
        init_db(database_path)
        selected_ai_mode = _resolve_ai_mode(arguments.ai_mode, arguments.legacy_agents)
        agent_runner = _build_agent_runner(selected_ai_mode)
        monitor = DefensiveMonitor(
            database_path,
            agent_runner=agent_runner,
            shutdown_on_critical=arguments.shutdown_on_critical,
        )
        _print_ai_mode_notice(selected_ai_mode, agent_runner)
        _run_monitor_command(
            monitor=monitor,
            once=arguments.once,
            poll_seconds=arguments.poll_seconds,
            limit=arguments.limit,
        )
        return

    if arguments.command == "access":
        init_db(database_path)
        selected_ai_mode = _resolve_ai_mode(arguments.ai_mode, arguments.legacy_agents)
        agent_runner = _build_agent_runner(selected_ai_mode)
        gateway = AccessGateway(database_path, agent_runner=agent_runner)

        access_response = gateway.read_table(
            username=arguments.username,
            password=arguments.password,
            table_name=arguments.table_name,
            ip_address=arguments.ip_address,
            user_agent=arguments.user_agent,
            limit=arguments.limit,
        )
        _print_access_response(access_response)
        if agent_runner.enabled():
            _print_ai_results(
                database_path,
                limit=10,
                session_id=agent_runner.session_id,
            )
        return

    if arguments.command == "insert-transaction":
        init_db(database_path)
        selected_ai_mode = _resolve_ai_mode(arguments.ai_mode, arguments.legacy_agents)
        agent_runner = _build_agent_runner(selected_ai_mode)
        gateway = AccessGateway(database_path, agent_runner=agent_runner)

        access_response = gateway.insert_transaction(
            username=arguments.username,
            password=arguments.password,
            cliente_id=arguments.cliente_id,
            valor=arguments.valor,
            status=arguments.status,
            ip_address=arguments.ip_address,
            user_agent=arguments.user_agent,
        )
        _print_access_response(access_response)
        if agent_runner.enabled():
            _print_ai_results(
                database_path,
                limit=10,
                session_id=agent_runner.session_id,
            )
        return

    if arguments.command == "show-logs":
        init_db(database_path)
        _print_access_logs(_fetch_logs(database_path, arguments.limit))
        return

    if arguments.command == "show-alerts":
        init_db(database_path)
        _print_security_alerts(_fetch_alerts(database_path, arguments.limit))
        return

    if arguments.command == "show-ai-results":
        init_db(database_path)
        session_id = None if arguments.all_sessions else _latest_agent_session_id(database_path)
        _print_ai_results(
            database_path,
            limit=arguments.limit,
            agent_name=arguments.agent,
            session_id=session_id,
        )
        return

    if arguments.command == "show-responses":
        init_db(database_path)
        _print_response_history(_fetch_response_history(database_path, arguments.limit))
        return

    if arguments.command == "reset-defense":
        init_db(database_path)
        reset_defense_state(database_path)
        print("Estado defensivo resetado: servico active e IPs bloqueados removidos.")
        return


def _build_argument_parser() -> argparse.ArgumentParser:
    """Create the full CLI parser with all supported subcommands."""

    parser = argparse.ArgumentParser(
        description="Controle e auditoria de acessos ao banco para TCC."
    )
    _add_db_argument(parser, default=str(DEFAULT_DB_PATH))

    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser(
        "init-db",
        help="Cria o banco e dados de demonstracao.",
    )
    _add_db_argument(init_parser)

    simulate_parser = subparsers.add_parser(
        "simulate",
        help="Executa cenarios de demonstracao.",
    )
    _add_db_argument(simulate_parser)
    _add_ai_arguments(simulate_parser)

    attack_parser = subparsers.add_parser(
        "attack",
        help="Gera um ataque controlado contra o laboratorio local.",
    )
    _add_db_argument(attack_parser)
    attack_parser.add_argument(
        "--mode",
        required=True,
        choices=ATTACK_MODE_CHOICES,
        help="Modo de ataque controlado a executar.",
    )
    attack_parser.add_argument(
        "--requests",
        type=int,
        default=30,
        help="Quantidade de requisicoes para ddos/brute-force. Maximo interno: 100.",
    )

    monitor_parser = subparsers.add_parser(
        "monitor",
        help="Mantem a defesa em alerta e responde a novos ataques.",
    )
    _add_db_argument(monitor_parser)
    _add_ai_arguments(monitor_parser)
    monitor_parser.add_argument(
        "--once",
        action="store_true",
        help="Processa alertas abertos uma vez e encerra.",
    )
    monitor_parser.add_argument(
        "--poll-seconds",
        type=float,
        default=2.0,
        help="Intervalo entre leituras de alertas no modo continuo.",
    )
    monitor_parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Quantidade maxima de alertas processados por ciclo.",
    )
    monitor_parser.add_argument(
        "--shutdown-on-critical",
        action="store_true",
        help="Simula shutdown defensivo para incidentes criticos ou de alto impacto.",
    )

    access_parser = subparsers.add_parser(
        "access",
        help="Executa uma leitura controlada.",
    )
    _add_db_argument(access_parser)
    _add_ai_arguments(access_parser)
    access_parser.add_argument("--username", required=True)
    access_parser.add_argument("--password", required=True)
    access_parser.add_argument("--table", required=True, dest="table_name")
    access_parser.add_argument("--ip", required=True, dest="ip_address")
    access_parser.add_argument("--limit", type=int, default=20)
    access_parser.add_argument("--user-agent", default="manual-client")

    insert_parser = subparsers.add_parser(
        "insert-transaction",
        help="Insere uma transacao.",
    )
    _add_db_argument(insert_parser)
    _add_ai_arguments(insert_parser)
    insert_parser.add_argument("--username", required=True)
    insert_parser.add_argument("--password", required=True)
    insert_parser.add_argument("--cliente-id", required=True, type=int)
    insert_parser.add_argument("--valor", required=True, type=float)
    insert_parser.add_argument("--status", default="analise")
    insert_parser.add_argument("--ip", required=True, dest="ip_address")
    insert_parser.add_argument("--user-agent", default="manual-client")

    logs_parser = subparsers.add_parser(
        "show-logs",
        help="Mostra ultimos logs de acesso.",
    )
    _add_db_argument(logs_parser)
    logs_parser.add_argument("--limit", type=int, default=10)

    alerts_parser = subparsers.add_parser(
        "show-alerts",
        help="Mostra alertas gerados.",
    )
    _add_db_argument(alerts_parser)
    alerts_parser.add_argument("--limit", type=int, default=10)

    ai_results_parser = subparsers.add_parser(
        "show-ai-results",
        help="Mostra medias e resultados dos agentes Gemma/Qwen.",
    )
    _add_db_argument(ai_results_parser)
    ai_results_parser.add_argument("--limit", type=int, default=20)
    ai_results_parser.add_argument(
        "--agent",
        choices=[AGENT_GEMMA, AGENT_QWEN],
        help="Filtra os resultados por uma IA especifica.",
    )
    ai_results_parser.add_argument(
        "--all-sessions",
        action="store_true",
        help="Mostra todas as sessoes. Por padrao, mostra a sessao mais recente.",
    )

    responses_parser = subparsers.add_parser(
        "show-responses",
        help="Mostra historico do que a defesa disse e executou.",
    )
    _add_db_argument(responses_parser)
    responses_parser.add_argument("--limit", type=int, default=20)

    reset_parser = subparsers.add_parser(
        "reset-defense",
        help="Remove bloqueios locais e reativa o servico apos testes.",
    )
    _add_db_argument(reset_parser)

    return parser


def _add_db_argument(
    parser: argparse.ArgumentParser,
    default: str | None = None,
) -> None:
    """Add the SQLite path argument to a parser or subparser."""

    argument_config: dict[str, Any] = {
        "help": "Caminho do arquivo SQLite. Padrao: access_control.db",
    }
    if default is None:
        argument_config["default"] = argparse.SUPPRESS
    else:
        argument_config["default"] = default
    parser.add_argument("--db", **argument_config)


def _add_ai_arguments(parser: argparse.ArgumentParser) -> None:
    """Add AI execution arguments to commands that may trigger agent reviews."""

    parser.add_argument(
        "--ai",
        dest="ai_mode",
        choices=AI_MODE_CHOICES,
        help=(
            "IA usada para revisar alertas: off, gemma3, qwen2.5 ou both. "
            "Padrao: off."
        ),
    )
    parser.add_argument(
        "--agents",
        action="store_true",
        dest="legacy_agents",
        help="Compatibilidade: equivale a --ai both.",
    )


def _resolve_ai_mode(
    requested_ai_mode: str | None,
    legacy_agents_flag: bool,
) -> str:
    """Resolve the preferred `--ai` option and the legacy `--agents` flag."""

    if requested_ai_mode:
        return requested_ai_mode
    if legacy_agents_flag:
        return AGENT_BOTH
    return AI_DISABLED


def _build_agent_runner(selected_ai_mode: str) -> AgentRunner:
    """Create an agent runner only when the command requested AI review."""

    if selected_ai_mode == AI_DISABLED:
        return AgentRunner.disabled()
    return AgentRunner.from_env(selected_ai_mode)


def _print_ai_mode_notice(selected_ai_mode: str, agent_runner: AgentRunner) -> None:
    """Show which AI mode is active before the simulation output."""

    if selected_ai_mode == AI_DISABLED:
        print("IA defensiva: desligada")
        return
    if not agent_runner.enabled():
        print(
            "IA defensiva: solicitada, mas AGENT_PROVIDER esta disabled/off "
            "ou nao foi configurado."
        )
        return
    if selected_ai_mode == AGENT_BOTH:
        print("IA defensiva: gemma3 e qwen2.5, executadas sequencialmente")
        return
    print(f"IA defensiva: {selected_ai_mode}")


def _run_simulation(gateway: AccessGateway) -> list[SimulationScenarioResult]:
    """Run deterministic demo scenarios and return compact results."""

    fixed_simulation_day = datetime(2026, 5, 4, tzinfo=timezone.utc)
    scenarios = _build_simulation_scenarios(gateway, fixed_simulation_day)
    scenario_results: list[SimulationScenarioResult] = []

    for scenario in scenarios:
        access_response = scenario.execute()
        scenario_results.append(
            SimulationScenarioResult(
                scenario_name=scenario.name,
                access_log_id=access_response.log_id,
                access_was_successful=access_response.success,
                anomaly_score=access_response.anomaly.score,
                anomaly_severity=access_response.anomaly.severity,
                anomaly_reasons=access_response.anomaly.reasons,
            )
        )
    return scenario_results


def _build_simulation_scenarios(
    gateway: AccessGateway,
    fixed_day: datetime,
) -> list[SimulationScenario]:
    """Create the access cases used in the default experiment."""

    scenarios = [
        SimulationScenario(
            "Leitura normal do analista",
            lambda: gateway.read_table(
                username="analista",
                password="analista123",
                table_name="clientes",
                ip_address="10.0.0.12",
                user_agent="Mozilla/5.0",
                limit=3,
                event_time=fixed_day.replace(hour=13, minute=10),
            ),
        ),
        SimulationScenario(
            "Analista tentando acessar tabela sensivel",
            lambda: gateway.read_table(
                username="analista",
                password="analista123",
                table_name="salarios",
                ip_address="10.0.0.12",
                user_agent="Mozilla/5.0",
                limit=5,
                event_time=fixed_day.replace(hour=14, minute=5),
            ),
        ),
        SimulationScenario(
            "Admin em horario incomum por IP novo",
            lambda: gateway.read_table(
                username="admin",
                password="admin123",
                table_name="salarios",
                ip_address="203.0.113.77",
                user_agent="curl/8.0",
                limit=100,
                event_time=fixed_day.replace(hour=2, minute=15),
            ),
        ),
    ]

    for attempt_number in range(1, 5):
        scenarios.append(
            SimulationScenario(
                f"Tentativa invalida {attempt_number}",
                lambda attempt=attempt_number: gateway.read_table(
                    username="analista",
                    password="senha-errada",
                    table_name="clientes",
                    ip_address="198.51.100.23",
                    user_agent="python-requests/2.31",
                    limit=1,
                    event_time=fixed_day.replace(hour=15, minute=attempt),
                ),
            )
        )
    return scenarios


def _print_simulation_results(results: list[SimulationScenarioResult]) -> None:
    """Print the simulation result table in execution order."""

    _print_ascii_table(
        "Cenarios executados",
        [
            {
                "log": result.access_log_id,
                "cenario": result.scenario_name,
                "acesso": "permitido" if result.access_was_successful else "bloqueado",
                "score": result.anomaly_score,
                "nivel": result.anomaly_severity,
                "motivos": "; ".join(result.anomaly_reasons),
            }
            for result in results
        ],
        ["log", "cenario", "acesso", "score", "nivel", "motivos"],
    )


def _print_access_response(access_response: AccessResponse) -> None:
    """Print the result of a single controlled access command."""

    _print_ascii_table(
        "Resultado do acesso",
        [
            {
                "campo": "log",
                "valor": access_response.log_id,
            },
            {
                "campo": "operacao",
                "valor": access_response.operation,
            },
            {
                "campo": "tabela",
                "valor": access_response.table_name,
            },
            {
                "campo": "status",
                "valor": "permitido" if access_response.success else "bloqueado",
            },
            {
                "campo": "score",
                "valor": access_response.anomaly.score,
            },
            {
                "campo": "nivel",
                "valor": access_response.anomaly.severity,
            },
            {
                "campo": "motivos",
                "valor": "; ".join(access_response.anomaly.reasons),
            },
            {
                "campo": "negacao",
                "valor": access_response.denial_reason or "",
            },
        ],
        ["campo", "valor"],
    )
    if access_response.rows:
        _print_ascii_table(
            "Registros retornados",
            access_response.rows,
            list(access_response.rows[0].keys()),
        )


def _print_attack_results(
    attack_mode: str,
    attack_results: list[AttackStepResult],
) -> None:
    """Print the access events generated by one controlled attack mode."""

    print(
        "\nAtaque controlado executado. "
        "Use o comando monitor em outro terminal para responder aos alertas."
    )
    _print_ascii_table(
        f"Resultado do ataque - {attack_mode}",
        [
            {
                "passo": result.step_number,
                "log": result.access_log_id,
                "acesso": "permitido" if result.success else "bloqueado",
                "score": result.anomaly_score,
                "nivel": result.anomaly_severity,
                "sinal esperado": result.expected_signal,
                "descricao": result.description,
            }
            for result in attack_results
        ],
        ["passo", "log", "acesso", "score", "nivel", "sinal esperado", "descricao"],
    )


def _run_monitor_command(
    *,
    monitor: DefensiveMonitor,
    once: bool,
    poll_seconds: float,
    limit: int,
) -> None:
    """Run the alert monitor once or continuously until interrupted."""

    print("Monitor defensivo em alerta. Pressione Ctrl+C para encerrar.")
    try:
        while True:
            response_results = monitor.process_open_alerts(limit=limit)
            if response_results:
                _print_monitor_responses(response_results)
            elif once:
                print("Nenhum alerta aberto para processar.")

            if once or monitor.service_is_shutdown():
                if monitor.service_is_shutdown():
                    print("Servico em shutdown defensivo. Monitor encerrado apos logar a resposta.")
                return

            time.sleep(max(0.5, poll_seconds))
    except KeyboardInterrupt:
        print("\nMonitor encerrado manualmente.")


def _print_monitor_responses(
    response_results: list[IncidentResponseResult],
) -> None:
    """Print what the monitor said and which actions it executed."""

    _print_ascii_table(
        "Respostas defensivas executadas",
        [
            {
                "resp": result.response_log_id,
                "alerta": result.alert_id,
                "log": result.access_log_id,
                "ia": result.agent_name,
                "ataque": result.attack_type,
                "nivel": result.severity,
                "servico": result.service_status_after,
                "shutdown": "sim" if result.shutdown_requested else "nao",
                "acoes": "; ".join(result.executed_actions),
                "fala": result.ai_message,
            }
            for result in response_results
        ],
        ["resp", "alerta", "log", "ia", "ataque", "nivel", "servico", "shutdown", "acoes", "fala"],
    )


def _fetch_logs(database_path: Path, limit: int) -> list[dict[str, Any]]:
    """Read the most recent access logs."""

    with get_connection(database_path) as connection:
        rows = connection.execute(
            """
            SELECT id, created_at, username, role, ip_address, operation, table_name,
                   rows_returned, success, denial_reason, anomaly_score, anomaly_reasons
            FROM access_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def _fetch_alerts(database_path: Path, limit: int) -> list[dict[str, Any]]:
    """Read the most recent security alerts."""

    try:
        with get_connection(database_path) as connection:
            rows = connection.execute(
                """
                SELECT id, created_at, access_log_id, severity, source, summary, verdict
                FROM security_alerts
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
    except sqlite3.OperationalError:
        return []
    return [dict(row) for row in rows]


def _fetch_response_history(database_path: Path, limit: int) -> list[dict[str, Any]]:
    """Read the most recent incident-response history rows."""

    with get_connection(database_path) as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                created_at,
                alert_id,
                access_log_id,
                agent_name,
                attack_type,
                severity,
                ai_message,
                executed_actions,
                service_status_after,
                shutdown_requested
            FROM incident_response_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def _print_access_logs(log_rows: list[dict[str, Any]]) -> None:
    """Print access logs with the most relevant audit fields."""

    _print_ascii_table(
        "Logs de acesso",
        [
            {
                "log": row["id"],
                "usuario": row["username"],
                "perfil": row["role"],
                "ip": row["ip_address"],
                "op": row["operation"],
                "tabela": row["table_name"],
                "status": "permitido" if row["success"] else "bloqueado",
                "score": row["anomaly_score"],
                "motivos": _parse_reasons(row["anomaly_reasons"]),
            }
            for row in log_rows
        ],
        ["log", "usuario", "perfil", "ip", "op", "tabela", "status", "score", "motivos"],
    )


def _print_security_alerts(alert_rows: list[dict[str, Any]]) -> None:
    """Print security alerts without exposing long JSON verdict payloads."""

    _print_ascii_table(
        "Alertas gerados",
        [
            {
                "alerta": row["id"],
                "log": row["access_log_id"],
                "nivel": row["severity"],
                "origem": row["source"],
                "resumo": row["summary"],
                "resultado": _alert_result_summary(row["source"], row.get("verdict")),
            }
            for row in alert_rows
        ],
        ["alerta", "log", "nivel", "origem", "resumo", "resultado"],
    )


def _print_response_history(response_rows: list[dict[str, Any]]) -> None:
    """Print the saved history of defensive responses."""

    _print_ascii_table(
        "Historico de resposta defensiva",
        [
            {
                "resp": row["id"],
                "alerta": row["alert_id"],
                "log": row["access_log_id"],
                "ia": row["agent_name"],
                "ataque": row["attack_type"],
                "nivel": row["severity"],
                "servico": row["service_status_after"],
                "shutdown": "sim" if row["shutdown_requested"] else "nao",
                "acoes": _parse_json_list(row["executed_actions"]),
                "fala": row["ai_message"],
            }
            for row in response_rows
        ],
        ["resp", "alerta", "log", "ia", "ataque", "nivel", "servico", "shutdown", "acoes", "fala"],
    )


def _alert_result_summary(source: str, verdict: str | None) -> str:
    """Summarize a rule or AI alert without dumping raw JSON."""

    if not verdict:
        return ""
    if source == "rules":
        try:
            parsed_verdict = json.loads(verdict)
        except json.JSONDecodeError:
            return _shorten(verdict, MAX_TABLE_CELL_WIDTH)
        reasons = parsed_verdict.get("reasons")
        if isinstance(reasons, list):
            return _shorten("; ".join(str(reason) for reason in reasons), MAX_TABLE_CELL_WIDTH)
    return _agent_result_summary(verdict, None)


def _latest_agent_session_id(database_path: Path) -> str | None:
    """Return the most recent AI session stored in the database."""

    with get_connection(database_path) as connection:
        row = connection.execute(
            """
            SELECT session_id
            FROM ai_agent_logs
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
    return None if row is None else str(row["session_id"])


def _fetch_agent_summary(
    database_path: Path,
    *,
    agent_name: str | None,
    session_id: str | None,
) -> list[dict[str, Any]]:
    """Calculate timing totals and averages grouped by AI and session."""

    where_sql, query_parameters = _agent_log_filters(
        agent_name=agent_name,
        session_id=session_id,
    )
    with get_connection(database_path) as connection:
        rows = connection.execute(
            f"""
            SELECT
                session_id,
                agent_name,
                model,
                COUNT(*) AS cases,
                SUM(success) AS successful_cases,
                SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS failed_cases,
                ROUND(SUM(duration_ms) / 1000.0, 3) AS total_seconds,
                ROUND(AVG(duration_ms) / 1000.0, 3) AS average_seconds,
                ROUND(MIN(duration_ms) / 1000.0, 3) AS minimum_seconds,
                ROUND(MAX(duration_ms) / 1000.0, 3) AS maximum_seconds
            FROM ai_agent_logs
            {where_sql}
            GROUP BY session_id, agent_name, model
            ORDER BY MAX(id) DESC, agent_name
            """,
            query_parameters,
        ).fetchall()
    return [dict(row) for row in rows]


def _fetch_agent_results(
    database_path: Path,
    *,
    agent_name: str | None,
    session_id: str | None,
) -> list[dict[str, Any]]:
    """Read measured AI interactions for the result tables."""

    where_sql, query_parameters = _agent_log_filters(
        agent_name=agent_name,
        session_id=session_id,
    )
    with get_connection(database_path) as connection:
        rows = connection.execute(
            f"""
            SELECT
                id,
                session_id,
                access_log_id,
                agent_name,
                model,
                duration_ms,
                session_case_number,
                session_average_duration_ms,
                success,
                error,
                result
            FROM ai_agent_logs
            {where_sql}
            ORDER BY agent_name, session_case_number, id
            """,
            query_parameters,
        ).fetchall()
    return [dict(row) for row in rows]


def _agent_log_filters(
    *,
    agent_name: str | None,
    session_id: str | None,
) -> tuple[str, list[Any]]:
    """Build safe SQL filters for optional AI report parameters."""

    filter_clauses: list[str] = []
    query_parameters: list[Any] = []
    if agent_name:
        filter_clauses.append("agent_name = ?")
        query_parameters.append(agent_name)
    if session_id:
        filter_clauses.append("session_id = ?")
        query_parameters.append(session_id)
    if not filter_clauses:
        return "", query_parameters
    return "WHERE " + " AND ".join(filter_clauses), query_parameters


def _print_ai_results(
    database_path: Path,
    *,
    limit: int,
    agent_name: str | None = None,
    session_id: str | None = None,
) -> None:
    """Print AI timing averages and per-case results grouped by model."""

    summary_rows = _fetch_agent_summary(
        database_path,
        agent_name=agent_name,
        session_id=session_id,
    )
    result_rows = _fetch_agent_results(
        database_path,
        agent_name=agent_name,
        session_id=session_id,
    )

    if not summary_rows:
        print("\nResultados das IAs:")
        print("(vazio)")
        return

    _print_ai_summary(summary_rows)
    for current_agent_name in _ordered_agent_names(result_rows):
        current_agent_rows = [
            row for row in result_rows if row["agent_name"] == current_agent_name
        ]
        _print_ai_case_results(current_agent_name, current_agent_rows[:limit], session_id)


def _print_ai_summary(summary_rows: list[dict[str, Any]]) -> None:
    """Print a compact comparison table with one row per AI/session."""

    _print_ascii_table(
        "Medias das IAs",
        [
            {
                "sessao": _short_session(row["session_id"]),
                "ia": row["agent_name"],
                "modelo": row["model"],
                "casos": row["cases"],
                "ok": row["successful_cases"],
                "erros": row["failed_cases"],
                "total_s": row["total_seconds"],
                "media_s": row["average_seconds"],
                "min_s": row["minimum_seconds"],
                "max_s": row["maximum_seconds"],
            }
            for row in _sort_rows_by_agent(summary_rows)
        ],
        ["sessao", "ia", "modelo", "casos", "ok", "erros", "total_s", "media_s", "min_s", "max_s"],
    )


def _print_ai_case_results(
    agent_name: str,
    result_rows: list[dict[str, Any]],
    filtered_session_id: str | None,
) -> None:
    """Print per-case timing results for one AI."""

    columns = ["ordem", "log", "tempo_s", "media_sessao_s", "status", "resultado"]
    if filtered_session_id is None:
        columns.insert(0, "sessao")

    table_rows: list[dict[str, Any]] = []
    for row in result_rows:
        table_row = {
            "sessao": _short_session(row["session_id"]),
            "ordem": row["session_case_number"],
            "log": row["access_log_id"],
            "tempo_s": f"{row['duration_ms'] / 1000.0:.3f}",
            "media_sessao_s": f"{row['session_average_duration_ms'] / 1000.0:.3f}",
            "status": "ok" if row["success"] else "erro",
            "resultado": _agent_result_summary(row["result"], row["error"]),
        }
        table_rows.append(table_row)

    _print_ascii_table(f"Resultados por caso - {agent_name}", table_rows, columns)


def _ordered_agent_names(result_rows: list[dict[str, Any]]) -> list[str]:
    """Return agent names in a stable order for the final report."""

    return list(dict.fromkeys(row["agent_name"] for row in _sort_rows_by_agent(result_rows)))


def _sort_rows_by_agent(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort mixed AI rows as Gemma first, then Qwen, then any future agent."""

    order = {AGENT_GEMMA: 0, AGENT_QWEN: 1}
    return sorted(
        rows,
        key=lambda row: (
            order.get(str(row["agent_name"]), 99),
            str(row["agent_name"]),
            str(row.get("session_id", "")),
            int(row.get("session_case_number", 0)),
        ),
    )


def _agent_result_summary(result: str | None, error: str | None) -> str:
    """Extract a short human-readable summary from an AI JSON response."""

    if error:
        return _shorten(f"erro: {error}", MAX_TABLE_CELL_WIDTH)
    if not result:
        return ""

    clean_text = _strip_markdown_code_block(result.strip())
    clean_text = _extract_json_object(clean_text)
    try:
        parsed_result = json.loads(clean_text)
    except json.JSONDecodeError:
        return _shorten(result, MAX_TABLE_CELL_WIDTH)

    if not isinstance(parsed_result, dict):
        return _shorten(result, MAX_TABLE_CELL_WIDTH)

    risk = str(parsed_result.get("risco", "")).strip()
    action = str(parsed_result.get("acao", "")).strip()
    if risk and action:
        return _shorten(f"risco={risk}; acao={action}", MAX_TABLE_CELL_WIDTH)
    return _shorten(json.dumps(parsed_result, ensure_ascii=False), MAX_TABLE_CELL_WIDTH)


def _strip_markdown_code_block(text: str) -> str:
    """Remove Markdown code fences commonly returned by chat models."""

    if not text.startswith("```"):
        return text
    lines = [line for line in text.splitlines() if not line.strip().startswith("```")]
    return "\n".join(lines).strip()


def _extract_json_object(text: str) -> str:
    """Extract the first JSON object from text when possible."""

    if "{" not in text or "}" not in text:
        return text
    return text[text.find("{") : text.rfind("}") + 1]


def _parse_reasons(raw_reasons: str) -> str:
    """Convert stored JSON anomaly reasons to a compact table cell."""

    try:
        parsed_reasons = json.loads(raw_reasons)
    except json.JSONDecodeError:
        return raw_reasons
    if not isinstance(parsed_reasons, list):
        return raw_reasons
    return "; ".join(str(reason) for reason in parsed_reasons)


def _parse_json_list(raw_value: str) -> str:
    """Convert a stored JSON list to a compact display string."""

    try:
        parsed_value = json.loads(raw_value)
    except json.JSONDecodeError:
        return raw_value
    if not isinstance(parsed_value, list):
        return raw_value
    return "; ".join(str(item) for item in parsed_value)


def _print_ascii_table(
    title: str,
    rows: list[dict[str, Any]],
    columns: list[str],
) -> None:
    """Render a list of dictionaries as a stable plain-text table."""

    print(f"\n{title}:")
    if not rows:
        print("(vazio)")
        return

    normalized_rows = [
        {
            column: _shorten(str(row.get(column, "")), MAX_TABLE_CELL_WIDTH)
            for column in columns
        }
        for row in rows
    ]
    column_widths = {
        column: max(len(column), *(len(row[column]) for row in normalized_rows))
        for column in columns
    }
    header = " | ".join(column.ljust(column_widths[column]) for column in columns)
    divider = "-+-".join("-" * column_widths[column] for column in columns)
    print(header)
    print(divider)
    for row in normalized_rows:
        print(" | ".join(row[column].ljust(column_widths[column]) for column in columns))


def _short_session(session_id: str) -> str:
    """Keep session identifiers readable in tables."""

    return session_id[:8]


def _shorten(value: str, width: int) -> str:
    """Collapse whitespace and shorten long table cells."""

    collapsed_value = " ".join(value.split())
    if len(collapsed_value) <= width:
        return collapsed_value
    return textwrap.shorten(collapsed_value, width=width, placeholder="...")


if __name__ == "__main__":
    main()
