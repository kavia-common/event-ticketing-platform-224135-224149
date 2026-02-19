from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    postgres_url: str = Field(
        ...,
        alias="POSTGRES_URL",
        description="SQLAlchemy database URL, e.g. postgresql+asyncpg://user:pass@host:port/db",
    )

    jwt_secret: str = Field(..., alias="JWT_SECRET", description="JWT signing secret")
    jwt_algorithm: str = Field(
        "HS256", alias="JWT_ALGORITHM", description="JWT signing algorithm"
    )
    jwt_access_token_expires_minutes: int = Field(
        60,
        alias="JWT_ACCESS_TOKEN_EXPIRES_MINUTES",
        description="Access token expiry in minutes",
    )
    jwt_refresh_token_expires_days: int = Field(
        30,
        alias="JWT_REFRESH_TOKEN_EXPIRES_DAYS",
        description="Refresh token expiry in days",
    )

    site_url: str = Field(
        "http://localhost:3000",
        alias="SITE_URL",
        description="Public site URL used in emails and Stripe return URLs",
    )

    stripe_secret_key: str | None = Field(
        default=None,
        alias="STRIPE_SECRET_KEY",
        description="Stripe secret key (sk_...)",
    )
    stripe_webhook_secret: str | None = Field(
        default=None,
        alias="STRIPE_WEBHOOK_SECRET",
        description="Stripe webhook signing secret (whsec_...)",
    )

    smtp_host: str | None = Field(default=None, alias="SMTP_HOST")
    smtp_port: int = Field(default=587, alias="SMTP_PORT")
    smtp_user: str | None = Field(default=None, alias="SMTP_USER")
    smtp_password: str | None = Field(default=None, alias="SMTP_PASSWORD")
    smtp_from: str = Field(
        default="Tickety <no-reply@tickety.local>", alias="SMTP_FROM"
    )
    smtp_use_tls: bool = Field(default=True, alias="SMTP_USE_TLS")


_settings: Settings | None = None


# PUBLIC_INTERFACE
def get_settings() -> Settings:
    """Return cached settings object."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
