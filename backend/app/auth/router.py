from datetime import datetime, timezone

import pyotp
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.audit.service import log_access_event
from app.auth import email_service
from app.auth.dependencies import get_current_user
from app.auth.security import create_access_token, hash_password, verify_password
from app.config import settings
from app.database import get_db
from app.models import AccessEvent, User
from app.schemas import (
    EmailVerifyRequest,
    MFASetupRead,
    MFAVerifyRequest,
    Token,
    UserCreate,
    UserLogin,
    UserRead,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    """New accounts start PENDING and can't log in until an Administrator
    approves them (see login() below and PATCH /users/{id}) - the very
    first user ever registered is auto-activated as a one-time bootstrap,
    since there's no admin yet to approve them. Every other admin learns
    about a new pending account by email (or the backend console if SMTP
    isn't configured - see app/auth/email_service.py).
    """
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already taken")
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    is_bootstrap_user = db.query(User).count() == 0
    account_status = "ACTIVE" if (is_bootstrap_user or not settings.require_admin_approval) else "PENDING"

    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role=payload.role,
        department=payload.department,
        clearance_level=payload.clearance_level,
        account_status=account_status,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    if account_status == "PENDING":
        admin_emails = [
            u.email
            for u in db.query(User).filter(User.role == "Administrator", User.account_status == "ACTIVE").all()
        ]
        for admin_email in admin_emails:
            email_service.send_registration_pending_notification(admin_email, user.username, user.user_id)

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
        messages = {
            "PENDING": "Account is awaiting administrator approval",
            "LOCKED": "Account is locked",
            "DISABLED": "Account is disabled",
        }
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=messages.get(user.account_status, "Account is not active"),
        )

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
    current_user.blocked_request_count = 0
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


@router.post("/email-verify/verify", response_model=UserRead)
def email_verify(
    payload: EmailVerifyRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Completes the email-based step-up challenge issued when a user with
    no TOTP configured triggers EMAIL_VERIFICATION_REQUIRED (see
    app/resources/router.py). On success, upgrades the event to ALLOW and
    resets the repeated-abuse counter, mirroring mfa_verify above.
    """
    event = (
        db.query(AccessEvent)
        .filter(AccessEvent.event_id == payload.event_id, AccessEvent.user_id == current_user.user_id)
        .first()
    )
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access event not found")
    if event.final_decision != "EMAIL_VERIFICATION_REQUIRED":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="This event is not awaiting email verification"
        )
    if not current_user.email_otp_hash or not current_user.email_otp_expires_at:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No verification code is pending")
    expires_at = current_user.email_otp_expires_at
    if expires_at.tzinfo is None:
        # SQLite (used in tests) stores DateTime(timezone=True) values naive;
        # Postgres round-trips them tz-aware. Normalize before comparing.
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expires_at:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Verification code has expired")

    if not verify_password(payload.code, current_user.email_otp_hash):
        log_access_event(
            db,
            user_id=current_user.user_id,
            resource_id=event.resource_id,
            action="EMAIL_VERIFY",
            policy_decision="DENY",
            final_decision="DENY",
            reason=f"Invalid email verification code for event {event.event_id}",
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid verification code")

    event.final_decision = "ALLOW"
    event.reason = f"{event.reason}; email verification confirmed"
    current_user.email_otp_hash = None
    current_user.email_otp_expires_at = None
    current_user.blocked_request_count = 0
    db.commit()
    log_access_event(
        db,
        user_id=current_user.user_id,
        resource_id=event.resource_id,
        action="EMAIL_VERIFY",
        policy_decision="ALLOW",
        final_decision="ALLOW",
        reason=f"Email verification confirmed for event {event.event_id}",
    )
    return current_user
