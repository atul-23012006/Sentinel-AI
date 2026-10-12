from sqlalchemy.orm import Session

from app.config import settings
from app.models import AccessEvent, SecurityAlert

# Severity bands mirror the risk-score response table in README §8.
_SEVERITY_BANDS = (
    (settings.risk_block_threshold, "CRITICAL"),
    (settings.risk_mfa_threshold, "HIGH"),
    (settings.risk_monitor_threshold, "MEDIUM"),
)


def severity_for_score(risk_score: int) -> str | None:
    for threshold, severity in _SEVERITY_BANDS:
        if risk_score >= threshold:
            return severity
    return None


def create_alert_if_needed(
    db: Session,
    *,
    event: AccessEvent,
    risk_score: int,
    reasons: list[str],
) -> SecurityAlert | None:
    """Raises a SecurityAlert when the risk score crosses the monitoring
    threshold. Alerts below that threshold are not created - routine, low-risk
    activity is logged to access_events but should not flood the alert queue.
    """
    severity = severity_for_score(risk_score)
    if severity is None:
        return None

    alert = SecurityAlert(
        user_id=event.user_id,
        event_id=event.event_id,
        alert_type="BEHAVIORAL_ANOMALY",
        risk_score=risk_score,
        severity=severity,
        description="; ".join(reasons),
        status="OPEN",
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert
