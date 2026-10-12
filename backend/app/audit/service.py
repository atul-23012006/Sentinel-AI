from sqlalchemy.orm import Session

from app.models import AccessEvent


def log_access_event(
    db: Session,
    *,
    user_id: int | None,
    resource_id: int | None,
    action: str,
    policy_decision: str,
    final_decision: str,
    reason: str,
    location: str | None = None,
    device_id: str | None = None,
    risk_score: int | None = None,
) -> AccessEvent:
    event = AccessEvent(
        user_id=user_id,
        resource_id=resource_id,
        action=action,
        location=location,
        device_id=device_id,
        policy_decision=policy_decision,
        risk_score=risk_score,
        final_decision=final_decision,
        reason=reason,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event
