from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.alerts.service import create_alert_if_needed
from app.audit.service import log_access_event
from app.auth.dependencies import get_current_user, require_role
from app.config import settings
from app.database import get_db
from app.models import Resource, ResourceGrant, User
from app.policies.engine import HybridPolicyEngine
from app.risk.engine import risk_engine
from app.schemas import (
    AccessDecisionRead,
    AccessRequest,
    ResourceCreate,
    ResourceGrantCreate,
    ResourceGrantRead,
    ResourceRead,
    ResourceUpdate,
)

router = APIRouter(prefix="/resources", tags=["resources"])

# create/list/get below are ownership-agnostic metadata operations - anyone
# authenticated can see that a resource exists. Whether they may actually act
# on it is decided by POST /{resource_id}/access, which runs every request
# through the hybrid policy engine (RBAC+MAC+ABAC+TBAC+OBAC) and logs the decision.
_policy_engine = HybridPolicyEngine()


def _adaptive_decision(policy_decision: str, risk_score: int) -> str:
    """Maps a PASSing policy decision + behavioral risk score to a final
    decision per README §8/§9. A policy DENY is never overridden by a low
    risk score - authorization and behavioral risk are separate, and policy
    denial always wins. A policy ALLOW can still be escalated: a user having
    permission does not mean their current behavior is safe.
    """
    if policy_decision == "DENY":
        return "DENY"
    if risk_score >= settings.risk_block_threshold:
        return "BLOCK"
    if risk_score >= settings.risk_mfa_threshold:
        return "MFA_REQUIRED"
    return "ALLOW"


@router.post("", response_model=ResourceRead, status_code=status.HTTP_201_CREATED)
def create_resource(
    payload: ResourceCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    resource = Resource(
        resource_name=payload.resource_name,
        owner_id=current_user.user_id,
        classification=payload.classification,
        department=payload.department,
        required_role=payload.required_role,
    )
    db.add(resource)
    db.commit()
    db.refresh(resource)
    return resource


@router.get("", response_model=list[ResourceRead])
def list_resources(
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
):
    return db.query(Resource).all()


def _get_resource_or_404(db: Session, resource_id: int) -> Resource:
    resource = db.query(Resource).filter(Resource.resource_id == resource_id).first()
    if resource is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")
    return resource


@router.get("/{resource_id}", response_model=ResourceRead)
def get_resource(
    resource_id: int,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
):
    return _get_resource_or_404(db, resource_id)


@router.patch("/{resource_id}", response_model=ResourceRead)
def update_resource(
    resource_id: int,
    payload: ResourceUpdate,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role("Administrator")),
):
    """Admin-only: reclassifying a resource, moving it to another department,
    or changing its RBAC-required role after creation. There was previously
    no way to do this at all once a resource existed.
    """
    resource = _get_resource_or_404(db, resource_id)

    if payload.resource_name is not None:
        resource.resource_name = payload.resource_name
    if payload.classification is not None:
        resource.classification = payload.classification
    if payload.department is not None:
        resource.department = payload.department
    if payload.clear_required_role:
        resource.required_role = None
    elif payload.required_role is not None:
        resource.required_role = payload.required_role

    db.commit()
    db.refresh(resource)
    return resource


@router.delete("/{resource_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_resource(
    resource_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role("Administrator")),
):
    resource = _get_resource_or_404(db, resource_id)
    db.delete(resource)
    db.commit()


@router.post("/{resource_id}/grants", response_model=ResourceGrantRead, status_code=status.HTTP_201_CREATED)
def create_grant(
    resource_id: int,
    payload: ResourceGrantCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_role("Administrator")),
):
    """Admin-only: explicitly grant one user access to this resource,
    bypassing RBAC/MAC/ABAC/TBAC/OBAC for them specifically (see
    evaluate_grant in app/policies/engine.py) - does NOT bypass the
    behavioral risk engine. Scope to a single action via `action`, or leave
    it null to cover every action on this resource.
    """
    resource = _get_resource_or_404(db, resource_id)
    grant = ResourceGrant(
        user_id=payload.user_id,
        resource_id=resource.resource_id,
        action=payload.action,
        granted_by=admin.user_id,
        reason=payload.reason,
        expires_at=payload.expires_at,
    )
    db.add(grant)
    db.commit()
    db.refresh(grant)
    return grant


@router.get("/{resource_id}/grants", response_model=list[ResourceGrantRead])
def list_grants(
    resource_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role("Administrator")),
):
    _get_resource_or_404(db, resource_id)
    return (
        db.query(ResourceGrant)
        .filter(ResourceGrant.resource_id == resource_id)
        .order_by(ResourceGrant.created_at.desc())
        .all()
    )


@router.delete("/{resource_id}/grants/{grant_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_grant(
    resource_id: int,
    grant_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role("Administrator")),
):
    grant = (
        db.query(ResourceGrant)
        .filter(ResourceGrant.grant_id == grant_id, ResourceGrant.resource_id == resource_id)
        .first()
    )
    if grant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Grant not found")
    db.delete(grant)
    db.commit()


@router.post("/{resource_id}/access", response_model=AccessDecisionRead)
def request_access(
    resource_id: int,
    payload: AccessRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    resource = _get_resource_or_404(db, resource_id)

    evaluation = _policy_engine.evaluate(current_user, resource, payload.action, db=db)

    failures = evaluation.failures
    if not failures:
        reason = "All hybrid policies passed"
    elif evaluation.final_decision == "ALLOW":
        # A GRANT result overrode an otherwise-DENY base decision (see
        # HybridPolicyEngine.evaluate) - `failures` still lists what the
        # attribute-based policies said, for audit transparency.
        reason = "Access explicitly granted by admin despite: " + "; ".join(
            f"{f.policy_type}: {f.reason}" for f in failures
        )
    else:
        reason = "; ".join(f"{f.policy_type}: {f.reason}" for f in failures)

    risk_result = risk_engine.score(
        db,
        current_user,
        action=payload.action,
        device_id=payload.device_id,
        location=payload.location,
    )
    final_decision = _adaptive_decision(evaluation.final_decision, risk_result.score)
    if final_decision != evaluation.final_decision:
        reason = f"{reason}; Adaptive response: risk score {risk_result.score}/100 ({'; '.join(risk_result.reasons)})"

    event = log_access_event(
        db,
        user_id=current_user.user_id,
        resource_id=resource.resource_id,
        action=payload.action,
        policy_decision=evaluation.final_decision,
        final_decision=final_decision,
        reason=reason,
        location=payload.location,
        device_id=payload.device_id,
        risk_score=risk_result.score,
    )

    alert = None
    if evaluation.final_decision == "ALLOW":
        alert = create_alert_if_needed(db, event=event, risk_score=risk_result.score, reasons=risk_result.reasons)

    return AccessDecisionRead(
        event_id=event.event_id,
        final_decision=final_decision,
        policy_results=[
            {"policy_type": r.policy_type, "decision": r.decision, "reason": r.reason} for r in evaluation.results
        ],
        risk_score=risk_result.score,
        risk_reasons=risk_result.reasons,
        mfa_setup_required=final_decision == "MFA_REQUIRED" and not current_user.otp_secret,
        alert_id=alert.alert_id if alert else None,
    )
