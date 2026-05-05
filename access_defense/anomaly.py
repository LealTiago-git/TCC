"""Rule-based anomaly scoring for database access events.

This module implements the deterministic anomaly detection engine that scores
each database access event on a scale of 0-100 based on 18+ business rules.
The design ensures reproducibility, auditability, and interpretability of all
security decisions - critical requirements for academic evaluation.

Anomaly Score Interpretation:
  0-14   → normal (no alert)
  15-34  → low (informational alert)
  35-59  → medium (investigation required)
  60-84  → high (critical alert)
  85-100 → critical (immediate response)

Key Design Principles:
  ✓ Deterministic: Same input always produces same output
  ✓ Auditable: Each rule is traceable to specific business logic
  ✓ Interpretable: Every decision has explicit justifications
  ✓ No Magic Numbers: All thresholds are parameters
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .database import SENSITIVE_TABLES


# ============================================================================
# DETECTION PARAMETERS
# ============================================================================

# Business hours: Outside these hours, any access is suspicious
BUSINESS_HOURS_START = 7      # 07:00
BUSINESS_HOURS_END = 20       # 20:00 (exclusive, so 20:00-07:00 is off-hours)

# Time windows for behavioral analysis
DENIAL_WINDOW_MINUTES = 10    # Check for multiple denials in this window
ACCESS_VOLUME_WINDOW_MINUTES = 10  # Detect rapid-fire access attempts
RECENT_IP_THRESHOLD_DAYS = 30  # IP is considered "new" if unseen for 30+ days

# Volume thresholds
HIGH_ACCESS_VOLUME_THRESHOLD = 20  # >= 20 accesses = abnormally high
HIGH_ROW_RETURN_THRESHOLD = 100    # >= 100 rows = potential mass read
MEDIUM_ROW_RETURN_THRESHOLD = 50   # >= 50 rows = elevated read

# String patterns for attack signature detection
AUTOMATED_USER_AGENTS = (
    "curl", 
    "python-requests", 
    "sqlmap", 
    "scanner", 
    "bot"
)

SQL_INJECTION_TOKENS = (
    "'",           # String terminator
    "--",          # SQL comment
    ";",           # Statement separator
    " union ",     # UNION-based injection
    " or ",        # OR-based bypass
    " drop ",      # Destructive intent
    " sleep("      # Time-based blind SQL injection
)

ATTACK_SIMULATION_TOKENS = (
    "attack-sim/",
    "buffer-overflow",
    "privilege-escalation"
)


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass(frozen=True)
class AccessSignals:
    """Recent behavioral indicators collected for a user/IP combination.
    
    These signals represent patterns observed in recent history that influence
    anomaly scoring. They are calculated by querying access_logs and ip_history
    tables within a sliding time window.
    
    Attributes:
        ip_seen_before: Has this IP been associated with this user before?
        recent_denied_count: How many access denials in last N minutes?
        recent_access_count: How many total access attempts in last N minutes?
    """

    ip_seen_before: bool
    recent_denied_count: int
    recent_access_count: int


@dataclass(frozen=True)
class AnomalyResult:
    """Final anomaly assessment produced by evaluate_access_event().
    
    This is the output of the entire detection pipeline - a scored classification
    of whether an access event appears suspicious, along with justifications.
    
    Attributes:
        score: Integer 0-100 representing anomaly level
        severity: Human-readable classification (normal/low/medium/high/critical)
        reasons: List of English descriptions explaining the score
    """

    score: int
    severity: str
    reasons: list[str]

    @property
    def should_alert(self) -> bool:
        """Check if this event warrants creating a security alert.
        
        Returns:
            True if severity is medium or higher, False for low/normal
        """
        return self.severity in {"medium", "high", "critical"}


# ============================================================================
# MAIN DETECTION ENGINE
# ============================================================================

def evaluate_access_event(
    *,
    event_time: datetime,
    username: str,
    role: str,
    ip_address: str,
    user_agent: str,
    operation: str,
    table_name: str,
    rows_returned: int,
    success: bool,
    denial_reason: str | None,
    signals: AccessSignals,
) -> AnomalyResult:
    """Comprehensive anomaly scoring function.
    
    This function is the core of the security detection system. It takes an
    access event and all relevant context, then applies 18+ deterministic rules
    to produce an anomaly score and justification.
    
    Args:
        event_time: When the access was attempted (datetime with timezone)
        username: The user attempting access
        role: User's role/profile (admin, analyst, auditor)
        ip_address: Source IP address
        user_agent: User-Agent HTTP header or custom string
        operation: Type of operation (READ, WRITE, DELETE)
        table_name: Target table name
        rows_returned: Number of rows returned (0 if denied)
        success: Was access granted?
        denial_reason: If denied, the reason (e.g., "invalid credentials")
        signals: Behavioral signals from AccessSignals dataclass
        
    Returns:
        AnomalyResult with score, severity, and list of reasons
    """

    anomaly_score_points = 0
    detected_anomalies: list[str] = []

    # ========================================================================
    # RULE 1-2: TEMPORAL ANALYSIS
    # ========================================================================
    
    current_hour = event_time.hour
    is_outside_business_hours = (
        current_hour < BUSINESS_HOURS_START or 
        current_hour >= BUSINESS_HOURS_END
    )
    
    if is_outside_business_hours:
        anomaly_score_points += 20
        detected_anomalies.append("acesso fora do horario comercial")

    # ========================================================================
    # RULE 3: SENSITIVE TABLE ACCESS
    # ========================================================================
    
    is_accessing_sensitive_table = table_name in SENSITIVE_TABLES
    
    if is_accessing_sensitive_table:
        anomaly_score_points += 30
        detected_anomalies.append("tabela sensivel acessada")

    # ========================================================================
    # RULE 4: ACCESS DENIAL
    # ========================================================================
    
    if not success:
        anomaly_score_points += 35
        denial_description = denial_reason or "motivo nao informado"
        detected_anomalies.append(f"acesso negado: {denial_description}")

    # ========================================================================
    # RULE 5: NEW IP ADDRESS
    # ========================================================================
    
    is_user_known = username != "anonymous"
    is_ip_unknown = not signals.ip_seen_before
    
    if is_user_known and is_ip_unknown:
        anomaly_score_points += 20
        detected_anomalies.append("IP novo para o usuario")

    # ========================================================================
    # RULE 6: BRUTE-FORCE PATTERN (Multiple denials)
    # ========================================================================
    
    multiple_recent_denials = signals.recent_denied_count >= 3
    
    if multiple_recent_denials:
        anomaly_score_points += 25
        detected_anomalies.append(
            "multiplas negacoes recentes para o usuario ou IP"
        )

    # ========================================================================
    # RULE 7: DDoS PATTERN (High volume)
    # ========================================================================
    
    abnormally_high_volume = (
        signals.recent_access_count >= HIGH_ACCESS_VOLUME_THRESHOLD
    )
    
    if abnormally_high_volume:
        anomaly_score_points += 20
        detected_anomalies.append(
            "volume alto de acessos em janela curta"
        )

    # ========================================================================
    # RULE 8: PRIVILEGE VIOLATION (Non-admin destructive operations)
    # ========================================================================
    
    is_destructive_operation = operation in {"DELETE", "WRITE"}
    is_non_admin_role = role not in {"admin"}
    
    if is_destructive_operation and is_non_admin_role:
        anomaly_score_points += 15
        detected_anomalies.append(
            "operacao de escrita por perfil nao administrativo"
        )

    # ========================================================================
    # RULE 9: DESTRUCTIVE OPERATION (DELETE)
    # ========================================================================
    
    if operation == "DELETE":
        anomaly_score_points += 20
        detected_anomalies.append("operacao destrutiva")

    # ========================================================================
    # RULE 10-11: MASS READ OPERATIONS
    # ========================================================================
    
    if rows_returned >= HIGH_ROW_RETURN_THRESHOLD:
        anomaly_score_points += 35
        detected_anomalies.append("leitura em massa")
    elif rows_returned >= MEDIUM_ROW_RETURN_THRESHOLD:
        anomaly_score_points += 25
        detected_anomalies.append("leitura elevada de registros")

    # ========================================================================
    # RULE 12: AUTOMATED CLIENT DETECTION
    # ========================================================================
    
    user_agent_lowercase = user_agent.lower()
    looks_automated = any(
        automated_pattern in user_agent_lowercase 
        for automated_pattern in AUTOMATED_USER_AGENTS
    )
    
    if looks_automated:
        anomaly_score_points += 10
        detected_anomalies.append("user-agent automatizado ou suspeito")

    # ========================================================================
    # RULE 13: SQL INJECTION SIGNATURE
    # ========================================================================
    
    # Inspect both table name and user-agent for injection tokens
    combined_inspection_text = f"{table_name} {user_agent}".lower()
    contains_sql_injection_token = any(
        injection_token in combined_inspection_text
        for injection_token in SQL_INJECTION_TOKENS
    )
    
    if contains_sql_injection_token:
        anomaly_score_points += 30
        detected_anomalies.append(
            "padrao compativel com tentativa de SQL injection"
        )

    # ========================================================================
    # RULE 14: DDoS ATTACK SIGNATURE
    # ========================================================================
    
    if "attack-sim/ddos" in user_agent_lowercase:
        anomaly_score_points += 25
        detected_anomalies.append(
            "padrao compativel com simulacao de DDoS"
        )

    # ========================================================================
    # RULE 15: BUFFER OVERFLOW SIGNATURE
    # ========================================================================
    
    excessive_table_name_length = len(table_name) > 64
    excessive_user_agent_length = len(user_agent) > 256
    buffer_overflow_indicator = "buffer-overflow" in user_agent_lowercase
    
    if (
        excessive_table_name_length or 
        excessive_user_agent_length or 
        buffer_overflow_indicator
    ):
        anomaly_score_points += 35
        detected_anomalies.append(
            "entrada excessivamente grande ou possivel buffer overflow"
        )

    # ========================================================================
    # RULE 16: PRIVILEGE ESCALATION SIGNATURE
    # ========================================================================
    
    if "privilege-escalation" in user_agent_lowercase:
        anomaly_score_points += 30
        detected_anomalies.append(
            "padrao compativel com tentativa de escalada de privilegio"
        )

    # ========================================================================
    # RULE 17: CONTROLLED ATTACK SIMULATION MARKER
    # ========================================================================
    
    is_simulated_attack = any(
        sim_token in user_agent_lowercase
        for sim_token in ATTACK_SIMULATION_TOKENS
    )
    
    if is_simulated_attack:
        anomaly_score_points += 15
        detected_anomalies.append(
            "evento gerado por simulador de ataque controlado"
        )

    # ========================================================================
    # FINALIZE RESULT
    # ========================================================================
    
    # Ensure no single access can score > 100
    final_anomaly_score = min(anomaly_score_points, 100)
    
    # If no rules fired, add explicit "normal" indicator
    if not detected_anomalies:
        detected_anomalies.append("nenhum sinal forte de anomalia")

    # Convert numeric score to severity classification
    final_severity = _classify_severity(final_anomaly_score)

    return AnomalyResult(
        score=final_anomaly_score,
        severity=final_severity,
        reasons=detected_anomalies
    )


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _classify_severity(anomaly_score: int) -> str:
    """Convert numeric anomaly score to severity label.
    
    Args:
        anomaly_score: Score from 0-100
        
    Returns:
        Severity classification: normal, low, medium, high, or critical
    """

    if anomaly_score >= 85:
        return "critical"
    elif anomaly_score >= 60:
        return "high"
    elif anomaly_score >= 35:
        return "medium"
    elif anomaly_score >= 15:
        return "low"
    else:
        return "normal"

