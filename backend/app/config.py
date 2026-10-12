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

    # AI analyst (Phase 6) - optional; falls back to a template-based
    # explanation when no key is configured so the feature works offline.
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-sonnet-5"


settings = Settings()
