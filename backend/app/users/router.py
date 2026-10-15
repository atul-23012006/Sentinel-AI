from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.auth.dependencies import require_role
from app.database import get_db
from app.models import User
from app.schemas import UserAdminUpdate, UserRead

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=list[UserRead])
def list_users(
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role("Administrator")),
):
    return db.query(User).all()


@router.get("/{user_id}", response_model=UserRead)
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role("Administrator")),
):
    user = db.query(User).filter(User.user_id == user_id).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.patch("/{user_id}", response_model=UserRead)
def update_user(
    user_id: int,
    payload: UserAdminUpdate,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role("Administrator")),
):
    """Admin-only: trust a device (ABAC, README §4.2), reactivate a locked
    account (README §4.1's account_status), or change a user's role/
    department/clearance_level - these are otherwise only self-declared at
    registration with no approval step, so changing them later is
    deliberately admin-gated rather than self-service. Resetting
    account_status to ACTIVE also clears failed_login_count and
    blocked_request_count so neither lockout counter immediately re-trips -
    this is the "admin verification and confirmation" step that unlocks an
    account the repeated-abuse escalation in app/resources/router.py locked.
    """
    user = db.query(User).filter(User.user_id == user_id).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if payload.device_trust is not None:
        user.device_trust = payload.device_trust
    if payload.account_status is not None:
        user.account_status = payload.account_status
        if payload.account_status == "ACTIVE":
            user.failed_login_count = 0
            user.blocked_request_count = 0
    if payload.role is not None:
        user.role = payload.role
    if payload.department is not None:
        user.department = payload.department
    if payload.clearance_level is not None:
        user.clearance_level = payload.clearance_level

    db.commit()
    db.refresh(user)
    return user
