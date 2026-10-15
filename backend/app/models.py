from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

CLEARANCE_LEVELS = ("PUBLIC", "CONFIDENTIAL", "SECRET", "TOP_SECRET")


class User(Base):
    __tablename__ = "users"

    user_id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(64), nullable=False)
    department: Mapped[str] = mapped_column(String(64), nullable=False)
    clearance_level: Mapped[str] = mapped_column(String(32), nullable=False, default="PUBLIC")
    device_trust: Mapped[str] = mapped_column(String(32), nullable=False, default="UNTRUSTED")
    account_status: Mapped[str] = mapped_column(String(32), nullable=False, default="ACTIVE")
    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    blocked_request_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    otp_secret: Mapped[str | None] = mapped_column(String(64))
    email_otp_hash: Mapped[str | None] = mapped_column(String(255))
    email_otp_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        CheckConstraint(f"clearance_level IN {CLEARANCE_LEVELS}"),
        CheckConstraint("device_trust IN ('TRUSTED', 'UNTRUSTED')"),
        CheckConstraint("account_status IN ('ACTIVE', 'LOCKED', 'DISABLED')"),
    )


class Resource(Base):
    __tablename__ = "resources"

    resource_id: Mapped[int] = mapped_column(primary_key=True)
    resource_name: Mapped[str] = mapped_column(String(255), nullable=False)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.user_id", ondelete="SET NULL"))
    classification: Mapped[str] = mapped_column(String(32), nullable=False, default="PUBLIC")
    department: Mapped[str] = mapped_column(String(64), nullable=False)
    required_role: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (CheckConstraint(f"classification IN {CLEARANCE_LEVELS}"),)


class Policy(Base):
    __tablename__ = "policies"

    policy_id: Mapped[int] = mapped_column(primary_key=True)
    policy_type: Mapped[str] = mapped_column(String(16), nullable=False)
    policy_name: Mapped[str] = mapped_column(String(255), nullable=False)
    rule_definition: Mapped[dict] = mapped_column(JSON, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (CheckConstraint("policy_type IN ('RBAC', 'MAC', 'ABAC', 'TBAC', 'OBAC')"),)


class AccessEvent(Base):
    __tablename__ = "access_events"

    event_id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.user_id", ondelete="SET NULL"))
    resource_id: Mapped[int | None] = mapped_column(ForeignKey("resources.resource_id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    location: Mapped[str | None] = mapped_column(String(255))
    device_id: Mapped[str | None] = mapped_column(String(255))
    policy_decision: Mapped[str] = mapped_column(String(16), nullable=False)
    risk_score: Mapped[int | None] = mapped_column(Integer)
    final_decision: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        CheckConstraint("policy_decision IN ('ALLOW', 'DENY')"),
        CheckConstraint(
            "final_decision IN ('ALLOW', 'MFA_REQUIRED', 'EMAIL_VERIFICATION_REQUIRED', 'BLOCK', 'DENY')"
        ),
        CheckConstraint("risk_score BETWEEN 0 AND 100"),
    )


class ResourceGrant(Base):
    """An explicit, admin-issued exception that overrides a policy DENY for
    one (user, resource[, action]) - a deliberate "break-glass"/bypass
    mechanism layered on top of the attribute-based RBAC/MAC/ABAC/TBAC/OBAC
    engine (see evaluate_grant in app/policies/engine.py). It does NOT bypass
    the behavioral risk engine/adaptive response - an explicitly granted user
    acting suspiciously can still be challenged or blocked.
    """

    __tablename__ = "resource_grants"

    grant_id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False)
    resource_id: Mapped[int] = mapped_column(ForeignKey("resources.resource_id", ondelete="CASCADE"), nullable=False)
    action: Mapped[str | None] = mapped_column(String(32))  # NULL = applies to every action
    granted_by: Mapped[int | None] = mapped_column(ForeignKey("users.user_id", ondelete="SET NULL"))
    reason: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    alert_id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.user_id", ondelete="SET NULL"))
    event_id: Mapped[int | None] = mapped_column(ForeignKey("access_events.event_id", ondelete="SET NULL"))
    alert_type: Mapped[str] = mapped_column(String(64), nullable=False)
    risk_score: Mapped[int | None] = mapped_column(Integer)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="OPEN")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        CheckConstraint("severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')"),
        CheckConstraint("status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED')"),
    )
