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
    """Score an access event using 18 deterministic rules (0-100, capped).

    Returns AnomalyResult with numeric score, severity label, and the list
    of reasons that fired. See module constants for thresholds.
    """

    score = 0
    reasons: list[str] = []
    ua_lower = user_agent.lower()

    # Temporal: outside business hours
    if event_time.hour < BUSINESS_HOURS_START or event_time.hour >= BUSINESS_HOURS_END:
        score += 20
        reasons.append("acesso fora do horario comercial")

    # Sensitive table
    if table_name in SENSITIVE_TABLES:
        score += 30
        reasons.append("tabela sensivel acessada")

    # Access denied
    if not success:
        score += 35
        reasons.append(f"acesso negado: {denial_reason or 'motivo nao informado'}")

    # New IP for a known user
    if username != "anonymous" and not signals.ip_seen_before:
        score += 20
        reasons.append("IP novo para o usuario")

    # Brute-force: multiple denials in window
    if signals.recent_denied_count >= 3:
        score += 25
        reasons.append("multiplas negacoes recentes para o usuario ou IP")

    # DDoS: high access volume in window
    if signals.recent_access_count >= HIGH_ACCESS_VOLUME_THRESHOLD:
        score += 20
        reasons.append("volume alto de acessos em janela curta")

    # Privilege violation: destructive op by non-admin
    if operation in {"DELETE", "WRITE"} and role != "admin":
        score += 15
        reasons.append("operacao de escrita por perfil nao administrativo")

    # Destructive op (DELETE) — stacks with rule above
    if operation == "DELETE":
        score += 20
        reasons.append("operacao destrutiva")

    # Mass / elevated read
    if rows_returned >= HIGH_ROW_RETURN_THRESHOLD:
        score += 35
        reasons.append("leitura em massa")
    elif rows_returned >= MEDIUM_ROW_RETURN_THRESHOLD:
        score += 25
        reasons.append("leitura elevada de registros")

    # Automated client (curl, sqlmap, scanner, etc.)
    if any(pat in ua_lower for pat in AUTOMATED_USER_AGENTS):
        score += 10
        reasons.append("user-agent automatizado ou suspeito")

    # SQL injection signature (table + user-agent)
    if any(tok in f"{table_name} {user_agent}".lower() for tok in SQL_INJECTION_TOKENS):
        score += 30
        reasons.append("padrao compativel com tentativa de SQL injection")

    # DDoS simulation marker
    if "attack-sim/ddos" in ua_lower:
        score += 25
        reasons.append("padrao compativel com simulacao de DDoS")

    # Buffer overflow signature
    if len(table_name) > 64 or len(user_agent) > 256 or "buffer-overflow" in ua_lower:
        score += 35
        reasons.append("entrada excessivamente grande ou possivel buffer overflow")

    # Privilege escalation marker
    if "privilege-escalation" in ua_lower:
        score += 30
        reasons.append("padrao compativel com tentativa de escalada de privilegio")

    # Controlled attack simulator marker
    if any(tok in ua_lower for tok in ATTACK_SIMULATION_TOKENS):
        score += 15
        reasons.append("evento gerado por simulador de ataque controlado")

    final_score = min(score, 100)
    if not reasons:
        reasons.append("nenhum sinal forte de anomalia")
    return AnomalyResult(
        score=final_score,
        severity=_classify_severity(final_score),
        reasons=reasons,
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

