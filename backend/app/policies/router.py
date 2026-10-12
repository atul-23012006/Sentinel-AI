from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.auth.dependencies import require_role
from app.database import get_db
from app.models import Policy, User
from app.schemas import PolicyCreate, PolicyRead, PolicyUpdate

router = APIRouter(prefix="/policies", tags=["policies"])

# Admin-only: policy rows are security configuration (today, exclusively
# OBAC rules - see engine.py's evaluate_obac), not end-user data.


@router.post("", response_model=PolicyRead, status_code=status.HTTP_201_CREATED)
def create_policy(
    payload: PolicyCreate,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role("Administrator")),
):
    policy = Policy(**payload.model_dump())
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return policy


@router.get("", response_model=list[PolicyRead])
def list_policies(
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role("Administrator")),
    policy_type: str | None = None,
):
    query = db.query(Policy)
    if policy_type is not None:
        query = query.filter(Policy.policy_type == policy_type)
    return query.order_by(Policy.priority.desc(), Policy.created_at.desc()).all()


def _get_policy_or_404(db: Session, policy_id: int) -> Policy:
    policy = db.query(Policy).filter(Policy.policy_id == policy_id).first()
    if policy is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found")
    return policy


@router.get("/{policy_id}", response_model=PolicyRead)
def get_policy(
    policy_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role("Administrator")),
):
    return _get_policy_or_404(db, policy_id)


@router.patch("/{policy_id}", response_model=PolicyRead)
def update_policy(
    policy_id: int,
    payload: PolicyUpdate,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role("Administrator")),
):
    policy = _get_policy_or_404(db, policy_id)
    if payload.enabled is not None:
        policy.enabled = payload.enabled
    if payload.priority is not None:
        policy.priority = payload.priority
    db.commit()
    db.refresh(policy)
    return policy


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_policy(
    policy_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role("Administrator")),
):
    policy = _get_policy_or_404(db, policy_id)
    db.delete(policy)
    db.commit()
