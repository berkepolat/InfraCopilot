from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


def read_secret_file(path: str | None) -> str | None:
    """Reads a Docker secret file; returns None when no path is configured."""
    if not path:
        return None
    return Path(path).read_text(encoding="utf-8").strip()


class ServiceSettings(BaseSettings):
    """Configuration common to every backend service. Secrets are only ever read from *_FILE paths."""

    model_config = SettingsConfigDict(extra="ignore", case_sensitive=False)

    service_name: str = "eeap-service"
    eeap_env: str = "dev"
    eeap_role: str = "api"
    log_level: str = "INFO"

    database_url: str | None = None
    database_password_file: str | None = None
    db_schema: str | None = None

    redis_url: str = "redis://redis:6379/0"
    redis_password_file: str | None = None

    internal_token_public_key_file: str | None = None

    minio_endpoint: str | None = None

    worker_consumer_groups: str = ""
    worker_metrics_port: int = 9100
    worker_heartbeat_path: str = "/tmp/worker.heartbeat"

    @property
    def consumer_groups(self) -> list[str]:
        return [g.strip() for g in self.worker_consumer_groups.split(",") if g.strip()]

    def database_password(self) -> str | None:
        return read_secret_file(self.database_password_file)

    def redis_password(self) -> str | None:
        return read_secret_file(self.redis_password_file)

    def internal_token_public_key(self) -> str | None:
        return read_secret_file(self.internal_token_public_key_file)
