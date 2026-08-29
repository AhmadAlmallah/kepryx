"""Application configuration - all settings from environment."""

import json
from functools import lru_cache
from ipaddress import ip_network
from typing import Any

from pydantic import Field, model_validator
from pydantic.fields import FieldInfo
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)
from sqlalchemy.engine import URL

_LIST_SETTINGS = {
    "ALLOWED_HOSTS",
    "CORS_ORIGINS",
    "SCAN_NETWORKS",
    "TRUSTED_PROXY_CIDRS",
    "MANAGEMENT_CIDRS",
    "CONNECTOR_ALLOWED_CIDRS",
}


def _parse_list_setting(field_name: str, value: Any) -> Any:
    """Accept JSON arrays and the common comma-delimited environment format."""
    if field_name not in _LIST_SETTINGS or not isinstance(value, str):
        return value

    raw = value.strip()
    if not raw:
        return []
    if raw.startswith("["):
        return json.loads(raw)
    return [item.strip() for item in raw.split(",") if item.strip()]


class _LenientListEnvSource(EnvSettingsSource):
    def prepare_field_value(
        self,
        field_name: str,
        field: FieldInfo,
        value: Any,
        value_is_complex: bool,
    ) -> Any:
        parsed = _parse_list_setting(field_name, value)
        if parsed is not value:
            return parsed
        return super().prepare_field_value(field_name, field, value, value_is_complex)


class _LenientListDotEnvSource(DotEnvSettingsSource):
    def prepare_field_value(
        self,
        field_name: str,
        field: FieldInfo,
        value: Any,
        value_is_complex: bool,
    ) -> Any:
        parsed = _parse_list_setting(field_name, value)
        if parsed is not value:
            return parsed
        return super().prepare_field_value(field_name, field, value, value_is_complex)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True, extra="ignore")

    # App
    APP_NAME: str = "KEPRYX"
    ENVIRONMENT: str = "production"
    DEBUG: bool = False
    API_V1_PREFIX: str = "/api/v1"

    # Security
    SECRET_KEY: str
    JWT_SECRET: str
    ENCRYPTION_KEY: str
    JWT_ALGORITHM: str = "HS256"
    JWT_ISSUER: str = "kepryx"
    JWT_AUDIENCE: str = "kepryx-api"
    JWT_ACCESS_TTL_MIN: int = 30
    JWT_REFRESH_TTL_DAYS: int = 7
    PASSWORD_MIN_LEN: int = 14
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MIN: int = 15
    SESSION_TIMEOUT_MIN: int = 30
    TRUSTED_PROXY_CIDRS: list[str] = ["127.0.0.1/32", "::1/128"]
    # Admin and other privileged management operations are restricted to these
    # client CIDRs after trusted-proxy header handling.
    MANAGEMENT_CIDRS: list[str] = ["127.0.0.1/32", "::1/128", "172.29.0.0/24"]
    ALLOW_INSECURE_CONNECTORS: bool = False
    # Private connector targets require deliberate network authorization.
    CONNECTOR_ALLOWED_CIDRS: list[str] = []

    # CORS
    CORS_ORIGINS: list[str] = ["https://kepryx.local"]
    ALLOWED_HOSTS: list[str] = ["kepryx.local", "localhost", "127.0.0.1"]

    # Database
    POSTGRES_HOST: str = "postgres"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "kepryx"
    POSTGRES_USER: str = "kepryx"
    POSTGRES_PASSWORD: str
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 10

    # Redis
    REDIS_URL: str

    # AI providers. Ollama is local and can be reached from Docker Desktop through the host name.
    AI_PROVIDER: str = "disabled"
    AI_BASE_URL: str = "http://host.docker.internal:11434"
    AI_API_KEY: str = "ollama"
    AI_MODEL: str = "qwen3:14b"
    AI_TIMEOUT_SEC: int = Field(default=180, ge=5, le=900)
    AI_CONTEXT_LENGTH: int = Field(default=8192, ge=1024, le=131072)
    AI_THINKING: bool = False
    AI_MAX_CONCURRENCY: int = Field(default=2, ge=1, le=16)

    # Legacy cloud provider settings retained for optional provider selection.
    ANTHROPIC_API_KEY: str = ""
    ANTHROPIC_MODEL: str = "claude-sonnet-4-20250514"
    NVD_API_KEY: str = ""
    NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    EPSS_BASE_URL: str = "https://api.first.org/data/v1/epss"
    KEV_FEED_URL: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    OSV_BASE_URL: str = "https://api.osv.dev/v1/query"
    EOL_BASE_URL: str = "https://endoflife.date/api"

    # Scanning
    SCAN_NETWORKS: list[str] = []  # Explicit authorization boundary; empty disables scanning
    NMAP_TIMING: int = Field(default=4, ge=0, le=5)
    SCAN_TIMEOUT_SEC: int = Field(default=3600, ge=1, le=86400)
    MAX_SCAN_HOSTS: int = Field(default=4096, ge=1, le=1048576)

    # Retention. Destructive deletion is opt-in and must match approved policy.
    RETENTION_DELETE_ENABLED: bool = False
    AUDIT_LOG_RETENTION_DAYS: int = Field(default=2555, ge=1)
    AUDIT_LOG_ARCHIVE_DAYS: int = Field(default=365, ge=1)
    INACTIVE_ASSET_DAYS: int = Field(default=90, ge=1)
    INACTIVE_USER_FLAG_DAYS: int = Field(default=365, ge=1)

    # Notifications
    SLACK_WEBHOOK_URL: str = ""
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "kepryx@example.com"
    PAGERDUTY_KEY: str = ""

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        del env_settings, dotenv_settings
        return (
            init_settings,
            _LenientListEnvSource(settings_cls),
            _LenientListDotEnvSource(
                settings_cls,
                env_file=settings_cls.model_config.get("env_file"),
                env_file_encoding=settings_cls.model_config.get("env_file_encoding"),
            ),
            file_secret_settings,
        )

    @model_validator(mode="after")
    def validate_security_settings(self) -> "Settings":
        if self.AUDIT_LOG_ARCHIVE_DAYS >= self.AUDIT_LOG_RETENTION_DAYS:
            raise ValueError("AUDIT_LOG_ARCHIVE_DAYS must be less than retention days")
        if self.ENVIRONMENT.lower() == "production":
            values = {
                "SECRET_KEY": self.SECRET_KEY,
                "JWT_SECRET": self.JWT_SECRET,
                "ENCRYPTION_KEY": self.ENCRYPTION_KEY,
            }
            weak = [name for name, value in values.items() if len(value) < 32]
            if weak:
                raise ValueError(f"Production security keys must be at least 32 characters: {weak}")
            if len(set(values.values())) != len(values):
                raise ValueError("SECRET_KEY, JWT_SECRET, and ENCRYPTION_KEY must be distinct")
            if self.JWT_ALGORITHM != "HS256":
                raise ValueError("Production currently supports JWT_ALGORITHM=HS256 only")
        for field_name in (
            "TRUSTED_PROXY_CIDRS",
            "MANAGEMENT_CIDRS",
            "CONNECTOR_ALLOWED_CIDRS",
            "SCAN_NETWORKS",
        ):
            for cidr in getattr(self, field_name):
                try:
                    ip_network(cidr, strict=False)
                except ValueError as exc:
                    raise ValueError(f"{field_name} contains an invalid CIDR: {cidr}") from exc
        return self

    @property
    def db_url(self) -> str:
        return URL.create(
            "postgresql+asyncpg",
            username=self.POSTGRES_USER,
            password=self.POSTGRES_PASSWORD,
            host=self.POSTGRES_HOST,
            port=self.POSTGRES_PORT,
            database=self.POSTGRES_DB,
        ).render_as_string(hide_password=False)

    @property
    def db_url_sync(self) -> str:
        return URL.create(
            "postgresql+psycopg",
            username=self.POSTGRES_USER,
            password=self.POSTGRES_PASSWORD,
            host=self.POSTGRES_HOST,
            port=self.POSTGRES_PORT,
            database=self.POSTGRES_DB,
        ).render_as_string(hide_password=False)


@lru_cache
def get_settings() -> Settings:
    # BaseSettings resolves required values from environment sources at runtime;
    # the Pydantic mypy plugin cannot infer that source behavior.
    return Settings()  # type: ignore[call-arg]


settings = get_settings()
