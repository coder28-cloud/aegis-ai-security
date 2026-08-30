# backend/app/config.py
"""
Centralized, validated application configuration.

All environment-driven config MUST be accessed through the `settings`
singleton defined here. Never call os.getenv() directly elsewhere in
the codebase — this is the single source of truth, and it fails loudly
at import time if required values are missing or malformed.
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field, PostgresDsn, RedisDsn, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Typed application settings, populated from environment variables
    and/or a .env file. Any missing required field raises a
    pydantic.ValidationError at process startup — not at request time.
    """

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",  # ignore unrelated env vars (e.g. PATH, HOME)
    )

    # --- App metadata ---
    APP_NAME: str = "AegisDevSec"
    ENVIRONMENT: Literal["development", "staging", "production"] = "development"
    DEBUG: bool = False
    CORS_ORIGINS: list[str] = ["http://localhost:3000"]

    # --- Database ---
    DATABASE_URL: PostgresDsn = Field(
        ...,
        description="Async SQLAlchemy connection string, e.g. "
        "postgresql+asyncpg://user:pass@host:5432/dbname",
    )
    DB_POOL_SIZE: int = 5
    DB_MAX_OVERFLOW: int = 10
    DB_POOL_TIMEOUT_SECONDS: int = 30

    # --- Redis / Celery broker ---
    REDIS_URL: RedisDsn = Field(..., description="Redis connection string")

    # --- Secrets (never logged, never defaulted) ---
    OPENAI_API_KEY: SecretStr = Field(default=SecretStr(""))
    GITHUB_TOKEN: SecretStr = Field(default=SecretStr(""))
    GITHUB_WEBHOOK_SECRET: SecretStr = Field(default=SecretStr(""))
    JWT_SECRET_KEY: SecretStr = Field(default=SecretStr("dev-only-insecure-key"))

    # --- JWT config ---
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60

    # --- Scanner tool settings ---
    SCANNER_TIMEOUT_SECONDS: int = 120
    SCAN_WORKSPACE_DIR: str = "/tmp/aegis_scans"

    @field_validator("DATABASE_URL")
    @classmethod
    def _require_asyncpg_driver(cls, v: PostgresDsn) -> PostgresDsn:
        """
        Guard against a common footgun: someone pastes a plain
        'postgresql://...' URL (sync driver) instead of
        'postgresql+asyncpg://...'. Our engine is async-only, so this
        must fail at startup, not with a confusing runtime error
        three layers deep in SQLAlchemy.
        """
        if v.scheme != "postgresql+asyncpg":
            raise ValueError(
                f"DATABASE_URL must use the 'postgresql+asyncpg' scheme, "
                f"got '{v.scheme}'. This app uses an async DB engine only."
            )
        return v

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    def model_post_init(self, __context) -> None:
        if self.is_production and self.JWT_SECRET_KEY.get_secret_value() == "dev-only-insecure-key":
            raise ValueError(
                "JWT_SECRET_KEY is still set to the insecure dev default while "
                "ENVIRONMENT=production. Set a real, random secret in your .env "
                "or platform's secret manager before deploying."
            )


@lru_cache
def get_settings() -> Settings:
    """
    Returns a cached Settings singleton.

    Why lru_cache instead of a bare module-level instance? This makes
    settings trivially overridable in tests via FastAPI's dependency
    override system (app.dependency_overrides[get_settings] = ...),
    without needing to monkeypatch a module-level object. Cost: O(1)
    after first call, negligible.
    """
    return Settings()


# Module-level singleton for convenience imports (`from app.config import settings`)
settings = get_settings()