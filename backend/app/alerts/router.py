from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.ai.service import explain_alert
from app.auth.dependencies import require_role
from app.database import get_db
from app.models import AccessEvent, SecurityAlert, User
from app.schemas import AlertExplanationRead, SecurityAlertRead, SecurityAlertUpdate

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=list[SecurityAlertRead])
def list_alerts(
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role("Administrator")),
    status_filter: str | None = Query(default=None, alias="status"),
    severity: str | None = None,
    user_id: int | None = None,
    limit: int = Query(default=50, le=200, gt=0),
    offset: int = Query(default=0, ge=0),
):
    query = db.query(SecurityAlert)
    if status_filter is not None:
        query = query.filter(SecurityAlert.status == status_filter)
    if severity is not None:
        query = query.filter(SecurityAlert.severity == severity)
    if user_id is not None:
        query = query.filter(SecurityAlert.user_id == user_id)

    return query.order_by(SecurityAlert.created_at.desc()).offset(offset).limit(limit).all()


def _get_alert_or_404(db: Session, alert_id: int) -> SecurityAlert:
    alert = db.query(SecurityAlert).filter(SecurityAlert.alert_id == alert_id).first()
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return alert


@router.get("/{alert_id}", response_model=SecurityAlertRead)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role("Administrator")),
):
    return _get_alert_or_404(db, alert_id)


@router.patch("/{alert_id}", response_model=SecurityAlertRead)
def update_alert(
    alert_id: int,
    payload: SecurityAlertUpdate,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role("Administrator")),
):
    alert = _get_alert_or_404(db, alert_id)
    alert.status = payload.status
    db.commit()
    db.refresh(alert)
    return alert


@router.get("/{alert_id}/explain", response_model=AlertExplanationRead)
def explain(
    alert_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role("Administrator")),
):
    alert = _get_alert_or_404(db, alert_id)
    event = db.query(AccessEvent).filter(AccessEvent.event_id == alert.event_id).first() if alert.event_id else None
    explanation, source = explain_alert(alert, event)
    return AlertExplanationRead(alert_id=alert.alert_id, explanation=explanation, source=source)
