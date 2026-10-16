from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)
    role: str
    department: str
    clearance_level: str = "PUBLIC"


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    user_id: int
    username: str
    email: EmailStr
    role: str
    department: str
    clearance_level: str
    device_trust: str
    account_status: str
    created_at: datetime


class UserLogin(BaseModel):
    username: str
    password: str


class UserAdminUpdate(BaseModel):
    """Admin-only account management: trusting a device, reactivating a
    locked account, and changing a user's role/department/clearance are all
    security decisions, not self-service actions - these fields are only
    ever self-declared at registration otherwise, with no approval step.
    """

    device_trust: str | None = Field(default=None, pattern="^(TRUSTED|UNTRUSTED)$")
    account_status: str | None = Field(default=None, pattern="^(PENDING|ACTIVE|LOCKED|DISABLED)$")
    role: str | None = Field(default=None, min_length=1, max_length=64)
    department: str | None = Field(default=None, min_length=1, max_length=64)
    clearance_level: str | None = Field(default=None, pattern="^(PUBLIC|CONFIDENTIAL|SECRET|TOP_SECRET)$")


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ResourceCreate(BaseModel):
    resource_name: str
    classification: str = "PUBLIC"
    department: str
    required_role: str | None = None


class ResourceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    resource_id: int
    resource_name: str
    owner_id: int | None
    classification: str
    department: str
    required_role: str | None
    created_at: datetime


class ResourceUpdate(BaseModel):
    """Admin-only: reclassifying a resource is a security decision, not a
    routine metadata edit - mirrors UserAdminUpdate's rationale.
    """

    resource_name: str | None = Field(default=None, min_length=1, max_length=255)
    classification: str | None = Field(default=None, pattern="^(PUBLIC|CONFIDENTIAL|SECRET|TOP_SECRET)$")
    department: str | None = Field(default=None, min_length=1, max_length=64)
    required_role: str | None = None
    clear_required_role: bool = False  # set true to explicitly null out required_role (vs "field omitted")


class AccessRequest(BaseModel):
    action: str = Field(min_length=1, max_length=32)
    device_id: str | None = None
    location: str | None = None


class PolicyResultRead(BaseModel):
    policy_type: str
    decision: str
    reason: str


class AccessDecisionRead(BaseModel):
    event_id: int
    final_decision: str
    policy_results: list[PolicyResultRead]
    risk_score: int | None = None
    risk_reasons: list[str] = Field(default_factory=list)
    mfa_setup_required: bool = False
    account_locked: bool = False
    email_verification_hint: str | None = None
    alert_id: int | None = None


class AccessEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_id: int
    user_id: int | None
    resource_id: int | None
    action: str
    timestamp: datetime
    location: str | None
    device_id: str | None
    policy_decision: str
    risk_score: int | None
    final_decision: str
    reason: str | None


class AuditSummary(BaseModel):
    total_events: int
    allow_count: int
    deny_count: int
    mfa_required_count: int
    email_verification_count: int = 0
    block_count: int
    events_last_24h: int
    open_alerts_count: int = 0
    pending_users_count: int = 0


class MFASetupRead(BaseModel):
    otp_secret: str
    otpauth_uri: str


class MFAVerifyRequest(BaseModel):
    event_id: int
    code: str = Field(min_length=6, max_length=6)


class EmailVerifyRequest(BaseModel):
    event_id: int
    code: str = Field(min_length=6, max_length=6)


class SecurityAlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    alert_id: int
    user_id: int | None
    event_id: int | None
    alert_type: str
    risk_score: int | None
    severity: str
    description: str | None
    status: str
    created_at: datetime


class SecurityAlertUpdate(BaseModel):
    status: str = Field(pattern="^(OPEN|ACKNOWLEDGED|RESOLVED)$")


class AlertExplanationRead(BaseModel):
    alert_id: int
    explanation: str
    source: str  # "llm" | "template"


class PolicyCreate(BaseModel):
    policy_type: str = Field(pattern="^(RBAC|MAC|ABAC|TBAC|OBAC)$")
    policy_name: str = Field(min_length=1, max_length=255)
    rule_definition: dict
    priority: int = 0
    enabled: bool = True


class PolicyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    policy_id: int
    policy_type: str
    policy_name: str
    rule_definition: dict
    priority: int
    enabled: bool
    created_at: datetime


class PolicyUpdate(BaseModel):
    enabled: bool | None = None
    priority: int | None = None


class ResourceGrantCreate(BaseModel):
    user_id: int
    action: str | None = Field(default=None, max_length=32)  # None = all actions
    reason: str | None = Field(default=None, max_length=1000)
    expires_at: datetime | None = None


class ResourceGrantRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    grant_id: int
    user_id: int
    resource_id: int
    action: str | None
    granted_by: int | None
    reason: str | None
    expires_at: datetime | None
    created_at: datetime
