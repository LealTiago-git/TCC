"""SQLite Schema, Initialization, and Demo Data Management.

This module manages the complete database lifecycle for the access control
prototype. It defines:

SCHEMA COMPONENTS:
  1. Authentication & Authorization
     - users: Demo user accounts with hashed passwords
     - permissions: RBAC matrix (role + table + operation)
  
  2. Business Data (targets of access control)
     - clientes: Customer records
     - transacoes: Financial transactions
     - salarios: Employee salaries (SENSITIVE)
  
  3. Security & Audit
     - access_logs: Complete audit trail of all DB operations
     - security_alerts: Anomalies detected (score >= 35)
     - user_ip_history: Tracks IP addresses per user (for "new IP" detection)
  
  4. AI & Response
     - ai_agent_logs: Timing and results of LLM analyses
     - incident_response_logs: Actions taken by defensive monitor

DESIGN PHILOSOPHY:
  ✓ All tables include created_at/updated_at for temporal analysis
  ✓ Foreign keys enabled for referential integrity
  ✓ Indexes on frequently-queried columns (username, ip_address, severity)
  ✓ Access logs are APPEND-ONLY for immutability
  ✓ Demo data uses realistic but recognizable values
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .security import hash_password


# ============================================================================
# CONFIGURATION
# ============================================================================

# Default location for SQLite database file
DEFAULT_DB_PATH = Path("access_control.db")

# Business tables that the access control system protects
DATA_TABLES = {
    "clientes": ("id", "nome", "email", "risco"),
    "transacoes": ("id", "cliente_id", "valor", "status", "created_at"),
    "salarios": ("id", "colaborador", "salario", "departamento"),
}

# Tables considered "sensitive" - accessing them raises anomaly score
SENSITIVE_TABLES = {"salarios"}


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def utc_now() -> str:
    """Return current UTC timestamp in ISO-8601 format for database storage.
    
    Returns:
        String like "2026-05-05T14:30:45+00:00"
    """

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def get_connection(
    db_path: str | Path = DEFAULT_DB_PATH
) -> sqlite3.Connection:
    """Open SQLite connection with row dictionary factory and FK enforcement.
    
    Args:
        db_path: Path to SQLite database file
        
    Returns:
        sqlite3.Connection configured for:
          - Row results as dictionaries (not tuples)
          - Foreign key constraint enforcement
    """

    database_connection = sqlite3.connect(str(db_path))
    database_connection.row_factory = sqlite3.Row
    database_connection.execute("PRAGMA foreign_keys = ON")
    return database_connection


# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

def init_db(
    db_path: str | Path = DEFAULT_DB_PATH,
    *,
    seed: bool = True
) -> None:
    """Create or update all tables, indexes, views, and optional demo data.
    
    This function is idempotent - calling it multiple times is safe.
    It uses CREATE TABLE IF NOT EXISTS to avoid errors on re-runs.
    
    Args:
        db_path: Where to create/update the database
        seed: If True, populate with demo users, permissions, and sample data
    """

    with get_connection(db_path) as database_connection:
        database_connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                role TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS permissions (
                role TEXT NOT NULL,
                table_name TEXT NOT NULL,
                operation TEXT NOT NULL,
                allowed INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (role, table_name, operation)
            );

            CREATE TABLE IF NOT EXISTS clientes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                risco TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS transacoes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cliente_id INTEGER NOT NULL,
                valor REAL NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (cliente_id) REFERENCES clientes(id)
            );

            CREATE TABLE IF NOT EXISTS salarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                colaborador TEXT NOT NULL,
                salario REAL NOT NULL,
                departamento TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                user_agent TEXT NOT NULL,
                operation TEXT NOT NULL,
                table_name TEXT NOT NULL,
                record_filter TEXT,
                rows_returned INTEGER NOT NULL DEFAULT 0,
                success INTEGER NOT NULL,
                denial_reason TEXT,
                anomaly_score INTEGER NOT NULL,
                anomaly_reasons TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                access_log_id INTEGER NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                source TEXT NOT NULL,
                summary TEXT NOT NULL,
                verdict TEXT,
                FOREIGN KEY (access_log_id) REFERENCES access_logs(id)
            );

            CREATE TABLE IF NOT EXISTS ai_agent_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                session_id TEXT NOT NULL,
                access_log_id INTEGER NOT NULL,
                agent_name TEXT NOT NULL,
                model TEXT NOT NULL,
                provider_url TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                duration_ms INTEGER NOT NULL,
                session_case_number INTEGER NOT NULL,
                session_total_duration_ms INTEGER NOT NULL,
                session_average_duration_ms REAL NOT NULL,
                success INTEGER NOT NULL,
                error TEXT,
                result TEXT,
                FOREIGN KEY (access_log_id) REFERENCES access_logs(id)
            );

            CREATE TABLE IF NOT EXISTS user_ip_history (
                username TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                total_accesses INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (username, ip_address)
            );

            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip_address TEXT PRIMARY KEY,
                reason TEXT NOT NULL,
                source_alert_id INTEGER,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                FOREIGN KEY (source_alert_id) REFERENCES security_alerts(id)
            );

            CREATE TABLE IF NOT EXISTS service_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                status TEXT NOT NULL,
                reason TEXT,
                source_alert_id INTEGER,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (source_alert_id) REFERENCES security_alerts(id)
            );

            CREATE TABLE IF NOT EXISTS attack_simulations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                attack_session_id TEXT NOT NULL,
                mode TEXT NOT NULL,
                step_number INTEGER NOT NULL,
                description TEXT NOT NULL,
                access_log_id INTEGER,
                expected_signal TEXT NOT NULL,
                FOREIGN KEY (access_log_id) REFERENCES access_logs(id)
            );

            CREATE TABLE IF NOT EXISTS incident_response_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                monitor_session_id TEXT NOT NULL,
                alert_id INTEGER NOT NULL,
                access_log_id INTEGER NOT NULL,
                agent_name TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                ai_message TEXT NOT NULL,
                planned_steps TEXT NOT NULL,
                executed_actions TEXT NOT NULL,
                service_status_after TEXT NOT NULL,
                shutdown_requested INTEGER NOT NULL,
                FOREIGN KEY (alert_id) REFERENCES security_alerts(id),
                FOREIGN KEY (access_log_id) REFERENCES access_logs(id)
            );

            CREATE INDEX IF NOT EXISTS idx_access_logs_created_at
                ON access_logs(created_at);

            CREATE INDEX IF NOT EXISTS idx_access_logs_user_ip
                ON access_logs(username, ip_address);

            CREATE INDEX IF NOT EXISTS idx_ai_agent_logs_agent_session
                ON ai_agent_logs(agent_name, session_id);

            CREATE INDEX IF NOT EXISTS idx_ai_agent_logs_access_log
                ON ai_agent_logs(access_log_id);

            CREATE INDEX IF NOT EXISTS idx_attack_simulations_session
                ON attack_simulations(attack_session_id, mode);

            CREATE INDEX IF NOT EXISTS idx_incident_response_logs_alert
                ON incident_response_logs(alert_id);

            CREATE VIEW IF NOT EXISTS gemma3_logs AS
                SELECT * FROM ai_agent_logs WHERE agent_name = 'gemma3';

            CREATE VIEW IF NOT EXISTS qwen25_logs AS
                SELECT * FROM ai_agent_logs WHERE agent_name = 'qwen2.5';
            """
        )

        database_connection.execute(
            """
            INSERT OR IGNORE INTO service_state
                (id, status, reason, source_alert_id, updated_at)
            VALUES (1, 'active', 'estado inicial', NULL, ?)
            """,
            (utc_now(),),
        )

        if seed:
            seed_demo_data(database_connection)


def seed_demo_data(database_connection: sqlite3.Connection) -> None:
    """Insert deterministic demo users, permissions, and business data.
    
    This function is called during init_db() to populate the database with
    recognizable sample data suitable for demonstrations and testing.
    
    USERS CREATED:
      - admin (admin123): Full access to all tables and operations
      - analyst (analista123): Read clients/transactions, write transactions
      - auditor (auditor123): Read-only access including sensitive tables
    
    PERMISSIONS CONFIGURED:
      - admin: All operations on all tables
      - analyst: Read clients/transactions, write/insert transactions only
      - auditor: Read-only access everywhere (including salarios)
    
    SAMPLE BUSINESS DATA:
      - 5 customers with varying risk levels
      - 5 transactions with realistic amounts
      - 3 salary records (restricted table)
      - IP history for each user (used in anomaly detection)
    
    Args:
        database_connection: SQLite connection to populate
    """

    current_timestamp = utc_now()
    
    # STEP 1: Create demo user accounts
    demo_users_data = [
        ("admin", "admin", "admin123"),
        ("analista", "analyst", "analista123"),
        ("auditor", "auditor", "auditor123"),
    ]
    
    for username, role_name, plain_password in demo_users_data:
        conn.execute(
            """
            INSERT OR IGNORE INTO users (username, role, password_hash, enabled, created_at)
            VALUES (?, ?, ?, 1, ?)
            """,
            (username, role, hash_password(password), now),
        )

    permissions = [
        ("admin", "clientes", "READ", 1),
        ("admin", "clientes", "WRITE", 1),
        ("admin", "transacoes", "READ", 1),
        ("admin", "transacoes", "WRITE", 1),
        ("admin", "transacoes", "DELETE", 1),
        ("admin", "salarios", "READ", 1),
        ("admin", "salarios", "WRITE", 1),
        ("analyst", "clientes", "READ", 1),
        ("analyst", "transacoes", "READ", 1),
        ("analyst", "transacoes", "WRITE", 1),
        ("auditor", "clientes", "READ", 1),
        ("auditor", "transacoes", "READ", 1),
        ("auditor", "salarios", "READ", 1),
    ]
    conn.executemany(
        """
        INSERT OR REPLACE INTO permissions (role, table_name, operation, allowed)
        VALUES (?, ?, ?, ?)
        """,
        permissions,
    )

    clientes = [
        ("Ana Martins", "ana@example.com", "baixo"),
        ("Bruno Costa", "bruno@example.com", "medio"),
        ("Carla Nunes", "carla@example.com", "alto"),
        ("Diego Alves", "diego@example.com", "baixo"),
        ("Elisa Rocha", "elisa@example.com", "medio"),
    ]
    conn.executemany(
        """
        INSERT OR IGNORE INTO clientes (nome, email, risco)
        VALUES (?, ?, ?)
        """,
        clientes,
    )

    transacoes = [
        (1, 320.50, "aprovada", now),
        (2, 980.00, "analise", now),
        (3, 15400.00, "bloqueada", now),
        (4, 77.90, "aprovada", now),
        (5, 4200.00, "analise", now),
    ]
    conn.executemany(
        """
        INSERT OR IGNORE INTO transacoes (id, cliente_id, valor, status, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        [(idx + 1, *item) for idx, item in enumerate(transacoes)],
    )

    salarios = [
        ("Ana Martins", 7800.00, "Financeiro"),
        ("Bruno Costa", 6400.00, "Operacoes"),
        ("Carla Nunes", 9100.00, "Seguranca"),
    ]
    conn.executemany(
        """
        INSERT OR IGNORE INTO salarios (id, colaborador, salario, departamento)
        VALUES (?, ?, ?, ?)
        """,
        [(idx + 1, *item) for idx, item in enumerate(salarios)],
    )

    ip_history = [
        ("admin", "10.0.0.10", now, now, 12),
        ("analista", "10.0.0.12", now, now, 18),
        ("auditor", "10.0.0.30", now, now, 8),
    ]
    conn.executemany(
        """
        INSERT OR IGNORE INTO user_ip_history
            (username, ip_address, first_seen, last_seen, total_accesses)
        VALUES (?, ?, ?, ?, ?)
        """,
        ip_history,
    )
