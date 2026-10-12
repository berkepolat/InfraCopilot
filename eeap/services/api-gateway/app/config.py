from __future__ import annotations

import ipaddress

from eeap_shared.utils.settings import ServiceSettings, read_secret_file


def parse_rate(value: str) -> tuple[int, int]:
    """'10/minute' -> (10, 60)."""
    count, _, unit = value.partition("/")
    seconds = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}[unit.strip().rstrip("s") or "minute"]
    return int(count), seconds


class GatewaySettings(ServiceSettings):
    service_name: str = "api-gateway"

    jwt_signing_key_file: str | None = None
    jwt_public_key_file: str | None = None
    internal_token_private_key_file: str | None = None

    jwt_issuer: str = "eeap-gateway"
    jwt_audience: str = "eeap-api"
    access_token_ttl_seconds: int = 900
    refresh_token_ttl_seconds: int = 28800

    lockout_threshold: int = 5
    lockout_minutes: int = 15

    rate_limit_login_per_ip: str = "10/minute"
    rate_limit_login_per_user: str = "5/minute"
    rate_limit_user: str = "600/minute"

    trusted_proxy_cidrs: str = "172.16.0.0/12"
    max_body_bytes: int = 1_048_576

    asset_service_url: str = "http://asset-service:8000"
    assessment_service_url: str = "http://assessment-service:8000"
    relationship_engine_url: str = "http://relationship-engine:8000"
    ai_engine_url: str = "http://ai-engine:8000"
    reporting_service_url: str = "http://reporting-service:8000"

    def jwt_signing_key(self) -> str:
        return read_secret_file(self.jwt_signing_key_file) or ""

    def jwt_public_key(self) -> str:
        return read_secret_file(self.jwt_public_key_file) or ""

    def internal_token_private_key(self) -> str:
        return read_secret_file(self.internal_token_private_key_file) or ""

    def trusted_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return [ipaddress.ip_network(c.strip()) for c in self.trusted_proxy_cidrs.split(",") if c.strip()]

    def upstreams(self) -> dict[str, tuple[str, str]]:
        """Upstream key -> (internal token audience, base URL)."""
        return {
            "asset": ("asset-service", self.asset_service_url),
            "assessment": ("assessment-service", self.assessment_service_url),
            "relationship": ("relationship-engine", self.relationship_engine_url),
            "ai": ("ai-engine", self.ai_engine_url),
            "reporting": ("reporting-service", self.reporting_service_url),
        }


settings = GatewaySettings()
