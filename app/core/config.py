"""
Application configuration using Pydantic Settings.

All configuration is loaded from environment variables with validation.
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = Field(default="FastAPI Auth", description="Application name")
    app_env: Literal["development", "staging", "production"] = Field(
        default="development", description="Application environment"
    )
    debug: bool = Field(default=False, description="Debug mode")

    # Server
    host: str = Field(default="0.0.0.0", description="Server host")
    port: int = Field(default=8000, ge=1, le=65535, description="Server port")

    # Database
    database_url: str = Field(
        default="postgresql+asyncpg://postgres:postgres@localhost:5432/auth_db",
        description="PostgreSQL connection string",
    )

    # JWT
    jwt_secret_key: str = Field(
        min_length=32,
        description="Secret key for JWT signing (min 32 characters)",
    )
    jwt_algorithm: str = Field(default="HS256", description="JWT algorithm")
    access_token_expire_minutes: int = Field(
        default=15, ge=1, description="Access token expiration in minutes"
    )
    refresh_token_expire_days: int = Field(
        default=7, ge=1, description="Refresh token expiration in days"
    )

    # Google OAuth
    google_client_id: str = Field(default="", description="Google OAuth client ID")
    google_client_secret: str = Field(default="", description="Google OAuth client secret")
    google_redirect_uri: str = Field(
        default="http://localhost:8000/api/v1/auth/google/callback",
        description="Google OAuth redirect URI",
    )
    # Frontend URL for OAuth callback redirect
    frontend_url: str = Field(
        default="http://localhost:8000",
        description="Frontend URL for OAuth redirects",
    )

    # CORS
    cors_origins: str = Field(
        default="http://localhost:3000", description="Comma-separated allowed origins"
    )

    # Security
    rate_limit_per_minute: int = Field(
        default=60, ge=1, description="Rate limit per minute"
    )
    password_min_length: int = Field(
        default=8, ge=6, description="Minimum password length"
    )
    max_login_attempts: int = Field(
        default=5, ge=1, description="Max failed login attempts before lockout"
    )
    lockout_duration_minutes: int = Field(
        default=15, ge=1, description="Account lockout duration in minutes"
    )

    @computed_field
    @property
    def cors_origins_list(self) -> list[str]:
        """Parse CORS origins from comma-separated string."""
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @computed_field
    @property
    def is_development(self) -> bool:
        """Check if running in development mode."""
        return self.app_env == "development"

    @computed_field
    @property
    def is_production(self) -> bool:
        """Check if running in production mode."""
        return self.app_env == "production"

    @computed_field
    @property
    def google_oauth_enabled(self) -> bool:
        """Check if Google OAuth is configured."""
        return bool(self.google_client_id and self.google_client_secret)


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


settings = get_settings()
