from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.auth.dependencies import require_role
from app.database import get_db
from app.models import AccessEvent, SecurityAlert, User
from app.schemas import AccessEventRead, AuditSummary

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/events", response_model=list[AccessEventRead])
def list_events(
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role("Administrator")),
    user_id: int | None = None,
    resource_id: int | None = None,
    final_decision: str | None = None,
    action: str | None = None,
    limit: int = Query(default=50, le=200, gt=0),
    offset: int = Query(default=0, ge=0),
):
    query = db.query(AccessEvent)
    if user_id is not None:
        query = query.filter(AccessEvent.user_id == user_id)
    if resource_id is not None:
        query = query.filter(AccessEvent.resource_id == resource_id)
    if final_decision is not None:
        query = query.filter(AccessEvent.final_decision == final_decision)
    if action is not None:
        query = query.filter(AccessEvent.action == action)

    return (
        query.order_by(AccessEvent.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.get("/events/{event_id}", response_model=AccessEventRead)
def get_event(
    event_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role("Administrator")),
):
    event = db.query(AccessEvent).filter(AccessEvent.event_id == event_id).first()
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access event not found")
    return event


@router.get("/summary", response_model=AuditSummary)
def summary(
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role("Administrator")),
):
    by_decision = dict(
        db.query(AccessEvent.final_decision, func.count(AccessEvent.event_id))
        .group_by(AccessEvent.final_decision)
        .all()
    )
    since = datetime.now(timezone.utc) - timedelta(hours=24)

    return AuditSummary(
        total_events=sum(by_decision.values()),
        allow_count=by_decision.get("ALLOW", 0),
        deny_count=by_decision.get("DENY", 0),
        mfa_required_count=by_decision.get("MFA_REQUIRED", 0),
        email_verification_count=by_decision.get("EMAIL_VERIFICATION_REQUIRED", 0),
        block_count=by_decision.get("BLOCK", 0),
        events_last_24h=db.query(AccessEvent).filter(AccessEvent.timestamp >= since).count(),
        open_alerts_count=db.query(SecurityAlert).filter(SecurityAlert.status == "OPEN").count(),
        pending_users_count=db.query(User).filter(User.account_status == "PENDING").count(),
    )
