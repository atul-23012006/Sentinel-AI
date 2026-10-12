import pyotp
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.audit.service import log_access_event
from app.auth.dependencies import get_current_user
from app.auth.security import create_access_token, hash_password, verify_password
from app.config import settings
from app.database import get_db
from app.models import AccessEvent, User
from app.schemas import MFASetupRead, MFAVerifyRequest, Token, UserCreate, UserLogin, UserRead

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already taken")
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role=payload.role,
        department=payload.department,
        clearance_level=payload.clearance_level,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=Token)
def login(payload: UserLogin, db: Session = Depends(get_db)):
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid username or password",
        headers={"WWW-Authenticate": "Bearer"},
    )

    user = db.query(User).filter(User.username == payload.username).first()
    if user is None:
        # No user_id to attach - still logged so repeated attempts against
        # unknown usernames (enumeration/brute-force) show up in the audit trail.
        log_access_event(
            db,
            user_id=None,
            resource_id=None,
            action="LOGIN",
            policy_decision="DENY",
            final_decision="DENY",
            reason=f"Unknown username '{payload.username}'",
        )
        raise unauthorized

    if user.account_status != "ACTIVE":
        log_access_event(
            db,
            user_id=user.user_id,
            resource_id=None,
            action="LOGIN",
            policy_decision="DENY",
            final_decision="DENY",
            reason=f"Account status is {user.account_status}",
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is not active")

    if not verify_password(payload.password, user.password_hash):
        user.failed_login_count += 1
        locked_out = user.failed_login_count >= settings.max_failed_logins
        if locked_out:
            user.account_status = "LOCKED"
        db.commit()
        log_access_event(
            db,
            user_id=user.user_id,
            resource_id=None,
            action="LOGIN",
            policy_decision="DENY",
            final_decision="DENY",
            reason="Account locked after repeated failed logins" if locked_out else "Invalid password",
        )
        raise unauthorized

    user.failed_login_count = 0
    db.commit()
    log_access_event(
        db,
        user_id=user.user_id,
        resource_id=None,
        action="LOGIN",
        policy_decision="ALLOW",
        final_decision="ALLOW",
        reason="Login successful",
    )

    token = create_access_token(subject=str(user.user_id), extra_claims={"role": user.role})
    return Token(access_token=token)


@router.get("/me", response_model=UserRead)
def me(current_user: User = Depends(get_current_user)):
    return current_user


@router.get("/mfa/setup", response_model=MFASetupRead)
def mfa_setup(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Provisions a TOTP secret for step-up authentication (README §9), the
    same way an authenticator app (e.g. Google Authenticator) would be paired.
    Idempotent: calling this again returns the existing secret rather than
    rotating it, so a previously paired authenticator app stays valid.
    """
    if not current_user.otp_secret:
        current_user.otp_secret = pyotp.random_base32()
        db.commit()
        db.refresh(current_user)

    uri = pyotp.TOTP(current_user.otp_secret).provisioning_uri(
        name=current_user.username, issuer_name="SentinelAI"
    )
    return MFASetupRead(otp_secret=current_user.otp_secret, otpauth_uri=uri)


@router.post("/mfa/verify", response_model=UserRead)
def mfa_verify(
    payload: MFAVerifyRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Completes the adaptive step-up challenge (README §9) for an access
    event this user triggered that the risk engine flagged as MFA_REQUIRED.
    On success, the event is upgraded to ALLOW and the verification is itself
    audited.
    """
    event = (
        db.query(AccessEvent)
        .filter(AccessEvent.event_id == payload.event_id, AccessEvent.user_id == current_user.user_id)
        .first()
    )
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access event not found")
    if event.final_decision != "MFA_REQUIRED":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This event is not awaiting MFA")
    if not current_user.otp_secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA is not set up for this account")

    totp = pyotp.TOTP(current_user.otp_secret)
    if not totp.verify(payload.code, valid_window=1):
        log_access_event(
            db,
            user_id=current_user.user_id,
            resource_id=event.resource_id,
            action="MFA_VERIFY",
            policy_decision="DENY",
            final_decision="DENY",
            reason=f"Invalid MFA code for event {event.event_id}",
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA code")

    event.final_decision = "ALLOW"
    event.reason = f"{event.reason}; MFA verified"
    db.commit()
    log_access_event(
        db,
        user_id=current_user.user_id,
        resource_id=event.resource_id,
        action="MFA_VERIFY",
        policy_decision="ALLOW",
        final_decision="ALLOW",
        reason=f"MFA verified for event {event.event_id}",
    )
    return current_user
