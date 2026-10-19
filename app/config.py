from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_env: Literal["development", "production"] = "development"
    demo_login_enabled: bool = False
    session_secret: str | None = None
    session_https_only: bool = False
    oidc_issuer_url: str | None = None
    oidc_metadata_url: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None
    oidc_redirect_uri: str = "http://localhost:8000/auth/callback"
    jwks_url: str | None = None
    jwt_audience: str | None = None
    database_url: str | None = None
    redis_url: str | None = None
    rate_limit_requests: int = Field(default=60, ge=1)
    rate_limit_window_seconds: int = Field(default=60, ge=1)
    m2m_ip_rate_limit_requests: int = Field(default=300, ge=1)
    browser_risk_threshold: int = Field(default=50, ge=1, le=100)
    security_event_retention_days: int = Field(default=90, ge=1, le=3650)

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


@lru_cache
def get_settings() -> Settings:
    return Settings()
