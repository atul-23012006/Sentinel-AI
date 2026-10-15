from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://sentinelai:sentinelai@localhost:5432/sentinelai"
    jwt_secret_key: str = "change-me-in-.env"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    max_failed_logins: int = 5
    tbac_start_hour: int = 9
    tbac_end_hour: int = 18

    # Risk engine (Phase 4/5)
    risk_model_path: str = "app/risk/artifacts/isolation_forest.joblib"
    risk_monitor_threshold: int = 31  # >= this: ALLOW but flagged for monitoring
    risk_mfa_threshold: int = 61  # >= this: step-up authentication required
    risk_block_threshold: int = 81  # >= this: automatic block

    # Repeated-abuse lockout: mirrors max_failed_logins, but for resource
    # access instead of login attempts. Every step-up challenge (MFA or
    # email) or BLOCK increments this counter; it resets on any ALLOW or
    # completed step-up verification. Crossing the threshold converts the
    # triggering request into a hard BLOCK and locks the account pending
    # admin reactivation (same account_status="LOCKED" mechanism as
    # failed_login_count).
    max_blocked_requests: int = 5

    # Rapid-fire / burst detection: independent of the ML-blended risk score.
    # Once a user has made max_burst_requests-or-more resource-access attempts
    # (READ/DOWNLOAD/WRITE/DELETE, any outcome) within burst_window_seconds,
    # the *next* request is forced to BLOCK and raises a dedicated
    # RAPID_FIRE_ACCESS alert - this is a deterministic rate-limit, not a
    # probabilistic risk signal, so it fires even when risk_score is low.
    max_burst_requests: int = 10
    burst_window_seconds: int = 60

    # Email step-up verification: used in place of TOTP MFA when a user
    # hasn't configured an authenticator app yet (otp_secret is NULL).
    email_otp_expire_minutes: int = 10
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from_email: str | None = None

    # AI analyst (Phase 6) - optional; falls back to a template-based
    # explanation when no key is configured so the feature works offline.
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-sonnet-5"


settings = Settings()
